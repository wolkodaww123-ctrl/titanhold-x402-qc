// End-to-end x402 flow against a LOCAL MOCK facilitator (no chain, no funds, no real keys).
// A throwaway buyer key is generated per run and never stored.
import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { wrapFetchWithPaymentFromConfig } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm";

const NETWORK = "eip155:84532";
const PAY_TO = privateKeyToAccount(generatePrivateKey()).address; // throwaway receiving address
const PNG = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==", "base64");

const calls = [];
let fac, server, base, mod;

before(async () => {
  fac = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const path = new URL(req.url, "http://x").pathname;
      calls.push(path);
      res.setHeader("content-type", "application/json");
      if (path === "/supported") return res.end(JSON.stringify({ kinds: [{ x402Version: 2, scheme: "exact", network: NETWORK }], extensions: [], signers: {} }));
      if (path === "/verify") return res.end(JSON.stringify({ isValid: true, payer: JSON.parse(body).paymentPayload?.payload?.authorization?.from }));
      if (path === "/settle") return res.end(JSON.stringify({ success: true, transaction: "0x" + "ab".repeat(32), network: NETWORK, payer: "0x0" }));
      res.statusCode = 404; res.end("{}");
    });
  });
  await new Promise((r) => fac.listen(0, "127.0.0.1", r));
  Object.assign(process.env, {
    PAY_TO, X402_NETWORK: NETWORK, QC_BACKEND: "mock",
    FACILITATOR_URL: `http://127.0.0.1:${fac.address().port}`,
  });
  mod = await import("../server.mjs");
  server = mod.app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => { server?.close(); fac?.close(); });

const post = (f, path, body) => f(`${base}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

test("free routes answer without payment", async () => {
  const r = await fetch(`${base}/`);
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.payment.network, NETWORK);
  assert.equal(j.payment.payTo, PAY_TO);
});

test("unpaid call gets 402 with price, network, payTo and bazaar metadata", async () => {
  const r = await post(fetch, "/v1/check/image", { data: PNG.toString("base64") });
  assert.equal(r.status, 402);
  const hdr = r.headers.get("payment-required");
  assert.ok(hdr, "PAYMENT-REQUIRED header present");
  const pr = JSON.parse(Buffer.from(hdr, "base64").toString());
  const a = pr.accepts[0];
  assert.equal(a.network, NETWORK);
  assert.equal(a.payTo, PAY_TO);
  assert.equal(a.amount, "20000"); // $0.02 in 6-decimal USDC
  assert.ok(pr.extensions?.bazaar, "bazaar discovery extension advertised");
});

test("paid call returns a verdict and settles through the facilitator", async () => {
  const buyer = privateKeyToAccount(generatePrivateKey());
  const pay = wrapFetchWithPaymentFromConfig(fetch, { schemes: [{ network: NETWORK, client: new ExactEvmScheme(buyer) }] });
  const r = await post(pay, "/v1/check/image", { data: PNG.toString("base64"), brief: "1x1 test image" });
  assert.equal(r.status, 200);
  const v = await r.json();
  assert.equal(v.pass, true);
  assert.equal(v.model, "mock");
  assert.ok(calls.includes("/verify") && calls.includes("/settle"), `facilitator calls: ${calls}`);
});

test("bad input after payment is rejected with 4xx and is NOT settled", async () => {
  const before = calls.filter((c) => c === "/settle").length;
  const buyer = privateKeyToAccount(generatePrivateKey());
  const pay = wrapFetchWithPaymentFromConfig(fetch, { schemes: [{ network: NETWORK, client: new ExactEvmScheme(buyer) }] });
  const r = await post(pay, "/v1/check/image", { data: Buffer.from("not an image").toString("base64") });
  assert.equal(r.status, 415);
  assert.equal(calls.filter((c) => c === "/settle").length, before, "no settlement on error");
});

test("SSRF: private URL is refused", async () => {
  const buyer = privateKeyToAccount(generatePrivateKey());
  const pay = wrapFetchWithPaymentFromConfig(fetch, { schemes: [{ network: NETWORK, client: new ExactEvmScheme(buyer) }] });
  const r = await post(pay, "/v1/check/image", { url: "https://127.0.0.1/x.png" });
  assert.ok(r.status >= 400 && r.status < 500);
});
