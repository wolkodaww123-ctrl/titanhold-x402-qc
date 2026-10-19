// Demo buyer agent: received an AI image from a seller, pays $0.02 via x402 for a QC verdict,
// then decides whether to release or hold the seller's payment.
// usage: BUYER_PRIVATE_KEY=0x... node demo/buyer.mjs <https-url-or-local-file> [brief]
// The buyer key must be a SEPARATE throwaway demo wallet (testnet USDC on Base Sepolia by default). Never a main wallet key.
import { readFile } from "node:fs/promises";
import { wrapFetchWithPaymentFromConfig, decodePaymentResponseHeader } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm";
import { privateKeyToAccount } from "viem/accounts";

const [src, brief = ""] = process.argv.slice(2);
const API = process.env.QC_URL ?? "http://127.0.0.1:8091";
const NETWORK = process.env.X402_NETWORK ?? "eip155:84532"; // eip155:8453 = Base mainnet
if (!src || !process.env.BUYER_PRIVATE_KEY) { console.error("usage: BUYER_PRIVATE_KEY=0x... node demo/buyer.mjs <url|file> [brief]"); process.exit(1); }
const account = privateKeyToAccount(process.env.BUYER_PRIVATE_KEY);
const pay = wrapFetchWithPaymentFromConfig(fetch, { schemes: [{ network: NETWORK, client: new ExactEvmScheme(account) }] });
const isVideo = /\.(mp4|mov|webm)$/i.test(src);
const body = src.startsWith("https://") ? { url: src, brief } : { data: (await readFile(src)).toString("base64"), brief };

console.log(`buyer ${account.address} -> ${API}/v1/check/${isVideo ? "video" : "image"}`);
const r = await pay(`${API}/v1/check/${isVideo ? "video" : "image"}`, {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
});
const verdict = await r.json();
const receipt = r.headers.get("PAYMENT-RESPONSE");
if (receipt) { try { const s = decodePaymentResponseHeader(receipt); console.log("paid, tx:", s.transaction, "on", s.network); } catch {} }
console.log(JSON.stringify(verdict, null, 2));
console.log(verdict.pass ? "=> RELEASE payment to seller" : "=> HOLD payment, ask seller to fix:\n - " + (verdict.reasons ?? []).join("\n - "));
