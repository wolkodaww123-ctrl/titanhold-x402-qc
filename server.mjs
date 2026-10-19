// TITANHOLD x402 QC endpoint: "check an AI deliverable before you pay".
// Paid per call in USDC via x402 (Base Sepolia by default, Base mainnet by env). Wraps titanhold-quality-gate (MIT).
// Intended to run next to a local Ollama vision model behind a tunnel/reverse proxy.
import express from "express";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { lookup } from "node:dns/promises";
import net from "node:net";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { declareDiscoveryExtension, bazaarResourceServerExtension } from "@x402/extensions/bazaar";
import { declareBuilderCodeExtension, builderCodeResourceServerExtension } from "@x402/extensions/builder-code";
import { qcCheck, ollamaBackend } from "titanhold-quality-gate";

const env = process.env;
const PORT = Number(env.PORT ?? 8091);
const HOST = env.HOST ?? "127.0.0.1";
const NETWORK = env.X402_NETWORK ?? "eip155:84532"; // Base Sepolia (testnet) by default; eip155:8453 = Base mainnet
const IS_MAINNET = NETWORK === "eip155:8453";
// Receiving address (public address only, never a private key). Required: there is no default.
const PAY_TO = env.PAY_TO;
// Facilitator URL. No account or API key needed for either default:
// - mainnet: PayAI (https://facilitator.payai.network), keyless exact/USDC on Base, gas paid by the facilitator,
//   free allowance per receiving wallet, own Bazaar catalog at /discovery/resources.
//   Keyless fallback: https://facilitator.openx402.ai
// - testnet: https://x402.org/facilitator (Base Sepolia only).
const FACILITATOR = env.FACILITATOR_URL ?? (IS_MAINNET ? "https://facilitator.payai.network" : "https://x402.org/facilitator");
if (!/^https?:\/\//.test(FACILITATOR)) { console.error("FACILITATOR_URL must be an http(s) URL of an x402 facilitator."); process.exit(1); }
const PRICE_IMAGE = env.PRICE_IMAGE ?? "$0.02";
const PRICE_VIDEO = env.PRICE_VIDEO ?? "$0.10";
const BUILDER_CODE = env.BUILDER_CODE; // optional Base Builder Code (dashboard.base.org), lowercase letters/digits/_
const MAX_BYTES = Number(env.MAX_BYTES ?? 40 * 1024 * 1024);
const MAX_QUEUE = Number(env.MAX_QUEUE ?? 4);
const PUBLIC_URL = env.PUBLIC_URL ?? `http://${HOST}:${PORT}`;
const CONTACT_EMAIL = env.CONTACT_EMAIL ?? "hennadii@titanhold.app";
const usd = (p) => String(p).replace(/^\$/, ""); // "$0.02" -> "0.02" (OpenAPI x-payment-info amount is decimal USD)
if (!PAY_TO || !/^0x[0-9a-fA-F]{40}$/.test(PAY_TO)) { console.error("Set PAY_TO to the 0x... address that should receive USDC (public address only)."); process.exit(1); }

const IMG_EXT = { "image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp" };
const VID_EXT = { "video/mp4": ".mp4", "video/quicktime": ".mov", "video/webm": ".webm" };

// ---------- input handling ----------
class InputError extends Error { constructor(msg, status = 400) { super(msg); this.status = status; } }

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v = ip.toLowerCase();
  return v === "::1" || v === "::" || v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80") ||
    (v.startsWith("::ffff:") && isPrivateIp(v.slice(7)));
}

async function fetchPublic(url) {
  let u;
  try { u = new URL(url); } catch { throw new InputError("url is not a valid URL"); }
  if (u.protocol !== "https:") throw new InputError("only https:// URLs are accepted");
  const addrs = await lookup(u.hostname, { all: true }).catch(() => []);
  if (!addrs.length) throw new InputError("url host does not resolve");
  if (addrs.some((a) => isPrivateIp(a.address))) throw new InputError("url points to a private address");
  const r = await fetch(u, { redirect: "error", signal: AbortSignal.timeout(20000) }).catch((e) => {
    throw new InputError(`could not download url: ${e.message}`, 422);
  });
  if (!r.ok) throw new InputError(`url returned HTTP ${r.status}`, 422);
  const len = Number(r.headers.get("content-length") ?? 0);
  if (len > MAX_BYTES) throw new InputError(`file larger than ${MAX_BYTES} bytes`, 413);
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > MAX_BYTES) throw new InputError(`file larger than ${MAX_BYTES} bytes`, 413);
  return { buf, type: (r.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase(), name: u.pathname };
}

function sniff(buf) {
  if (buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return "image/png";
  if (buf[0] === 0xff && buf[1] === 0xd8) return "image/jpeg";
  if (buf.subarray(0, 4).toString() === "RIFF" && buf.subarray(8, 12).toString() === "WEBP") return "image/webp";
  if (buf.subarray(4, 8).toString() === "ftyp") return buf.subarray(8, 12).toString() === "qt  " ? "video/quicktime" : "video/mp4";
  if (buf.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))) return "video/webm";
  return "";
}

async function loadInput(body, kind) {
  let buf;
  if (typeof body?.url === "string") buf = (await fetchPublic(body.url)).buf;
  else if (typeof body?.data === "string") buf = Buffer.from(body.data, "base64");
  else throw new InputError('send JSON {"url": "https://..."} or {"data": "<base64>"}');
  if (!buf.length) throw new InputError("empty file");
  if (buf.length > MAX_BYTES) throw new InputError(`file larger than ${MAX_BYTES} bytes`, 413);
  const type = sniff(buf); // trust bytes, not headers
  const table = kind === "image" ? IMG_EXT : VID_EXT;
  if (!table[type]) throw new InputError(`expected ${kind === "image" ? "PNG/JPEG/WebP image" : "MP4/MOV/WebM video"}, got ${type || "unknown format"}`, 415);
  return { buf, ext: table[type] };
}

function qcOptions(body) {
  const o = {};
  if (typeof body?.brief === "string") o.brief = body.brief.slice(0, 500);
  if (Number.isFinite(body?.minScore)) o.minScore = Math.max(0, Math.min(100, body.minScore));
  if (Number.isInteger(body?.frames)) o.videoFrames = Math.max(2, Math.min(8, body.frames));
  return o;
}

// ---------- single-GPU job queue ----------
let running = 0; const waiters = [];
async function withSlot(fn) {
  if (running >= 1) {
    if (waiters.length >= MAX_QUEUE) throw new InputError("busy, try again in a minute (you were not charged)", 503);
    await new Promise((res) => waiters.push(res));
  }
  running++;
  try { return await fn(); } finally { running--; waiters.shift()?.(); }
}

// QC_BACKEND=mock returns a fixed verdict (for tests and payment-flow demos only, never for real checks).
const mockBackend = { name: "mock", async inspect() { return { score: 100, defects: [] }; } };
const backend = env.QC_BACKEND === "mock" ? mockBackend : ollamaBackend(); // OLLAMA_URL / QG_MODEL env, defaults 127.0.0.1:11434 / qwen2.5vl:7b

async function runCheck(req, res, kind) {
  let dir;
  try {
    const { buf, ext } = await loadInput(req.body, kind);
    dir = await mkdtemp(join(tmpdir(), "qc-"));
    const file = join(dir, `deliverable${ext}`);
    await writeFile(file, buf);
    const r = await withSlot(() => qcCheck(file, { ...qcOptions(req.body), backend }));
    res.json({
      pass: r.pass, score: r.score, kind: r.kind, framesChecked: r.framesChecked,
      defects: r.defects, reasons: r.reasons, model: r.backend,
      note: "Automated vision check. Treat 'pass: false' as 'needs a human look', not a final verdict.",
    });
  } catch (e) {
    // Any status >= 400 means x402 does NOT settle: the caller is not charged.
    const status = e instanceof InputError ? e.status : 502;
    res.status(status).json({ error: e instanceof InputError ? e.message : "QC backend unavailable, you were not charged" });
    if (!(e instanceof InputError)) console.error(new Date().toISOString(), "qc error", e);
  } finally {
    if (dir) rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

// ---------- app ----------
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", "loopback");
// Body parse errors (bad JSON, wrong type) must not block the 402 challenge: unpaid probes always get 402 first.
// After payment, runCheck rejects a missing/invalid body with 4xx, which is not settled.
const jsonParser = express.json({ limit: Math.ceil(MAX_BYTES * 1.4) });
app.use((req, res, next) => jsonParser(req, res, (err) => {
  if (err && err.type === "entity.too.large") return res.status(413).json({ error: `body larger than allowed (${MAX_BYTES} byte file cap)` });
  if (err) req.body = undefined;
  next();
}));

const inputSchema = {
  url: "https URL of the delivered file (or use data)",
  data: "base64 file bytes (alternative to url)",
  brief: "optional: what was ordered, e.g. 'red 2-door coupe at night'",
  minScore: "optional 0-100, default 70",
};

// Discovery metadata (bazaar extension): catalogued by the facilitator after the first settled paid call
// (PayAI: GET https://facilitator.payai.network/discovery/resources) and read by x402scan when the URL is registered.
// Text is descriptive only: it must not read as an instruction to an agent.
const verdictExample = {
  pass: false, score: 55, kind: "image", framesChecked: 1,
  defects: [{ type: "vehicle_geometry", severity: "major", detail: "car has three doors" }],
  reasons: ["major vehicle_geometry: car has three doors"], model: "ollama:qwen2.5vl:7b",
};
const discovery = (extra = {}) => declareDiscoveryExtension({
  method: "POST",
  bodyType: "json",
  input: { url: "https://example.com/render.png", brief: "red 2-door coupe at night", minScore: 70, ...extra },
  inputSchema: {
    properties: {
      url: { type: "string", description: "https URL of the delivered file. Alternative: data (base64)." },
      data: { type: "string", description: "Base64 file bytes. Alternative to url." },
      brief: { type: "string", description: "What was ordered, used to judge the file against the brief. Max 500 chars." },
      minScore: { type: "number", description: "Fail below this 0-100 score. Default 70." },
      ...(extra.frames ? { frames: { type: "integer", description: "Video frames to sample, 2-8. Default 6." } } : {}),
    },
  },
  output: { example: verdictExample },
});
const builder = BUILDER_CODE ? declareBuilderCodeExtension(BUILDER_CODE) : {};
const routes = {
  "POST /v1/check/image": {
    accepts: { scheme: "exact", price: PRICE_IMAGE, network: NETWORK, payTo: PAY_TO },
    description: "Machine-readable defect check of an AI-generated image (extra fingers, garbled text, wrong vehicle geometry, physics) for a buyer deciding whether to pay the seller. Returns pass, score and typed defects.",
    mimeType: "application/json",
    extensions: { ...discovery(), ...builder },
  },
  "POST /v1/check/video": {
    accepts: { scheme: "exact", price: PRICE_VIDEO, network: NETWORK, payTo: PAY_TO },
    description: "Machine-readable defect check of a short AI-generated video (sampled frames plus frame-to-frame flicker) for a buyer deciding whether to pay the seller. Returns pass, score and typed defects.",
    mimeType: "application/json",
    extensions: { ...discovery({ frames: 6 }), ...builder },
  },
};

// ---------- OpenAPI discovery doc (x402scan: https://www.x402scan.com/discovery/spec) ----------
const checkBodySchema = (video) => ({
  type: "object",
  description: "Send exactly one of url or data.",
  properties: {
    url: { type: "string", format: "uri", pattern: "^https://", description: "https URL of the delivered file. Alternative: data (base64)." },
    data: { type: "string", contentEncoding: "base64", description: "Base64 file bytes. Alternative to url." },
    brief: { type: "string", maxLength: 500, description: "Optional: what was ordered, used to judge the file against the brief." },
    minScore: { type: "number", minimum: 0, maximum: 100, default: 70, description: "Optional: fail below this 0-100 score." },
    ...(video ? { frames: { type: "integer", minimum: 2, maximum: 8, default: 6, description: "Optional: video frames to sample." } } : {}),
  },
  oneOf: [{ required: ["url"] }, { required: ["data"] }],
  example: video
    ? { url: "https://example.com/clip.mp4", brief: "car driving through a city at night", frames: 6 }
    : { url: "https://example.com/render.png", brief: "red 2-door coupe at night", minScore: 70 },
});
const verdictSchema = {
  type: "object",
  properties: {
    pass: { type: "boolean", description: "true when score >= minScore and no major defect" },
    score: { type: "number", minimum: 0, maximum: 100 },
    kind: { type: "string", enum: ["image", "video"] },
    framesChecked: { type: "integer" },
    defects: {
      type: "array",
      items: {
        type: "object",
        properties: {
          type: { type: "string" }, severity: { type: "string" }, detail: { type: "string" }, frame: { type: "integer" },
        },
        required: ["type", "severity", "detail"],
      },
    },
    reasons: { type: "array", items: { type: "string" } },
    model: { type: "string" },
    note: { type: "string" },
  },
  required: ["pass", "score", "defects", "reasons"],
  example: verdictExample,
};
const errorSchema = { type: "object", properties: { error: { type: "string" } }, required: ["error"] };
const paidOp = (kind, price, summary, description) => ({
  operationId: `check${kind[0].toUpperCase()}${kind.slice(1)}`,
  summary,
  description,
  tags: ["Quality check"],
  "x-payment-info": { price: { mode: "fixed", currency: "USD", amount: usd(price) }, protocols: [{ x402: {} }] },
  requestBody: { required: true, content: { "application/json": { schema: checkBodySchema(kind === "video") } } },
  responses: {
    200: { description: "Verdict (payment settled)", content: { "application/json": { schema: verdictSchema } } },
    400: { description: "Invalid input (not charged)", content: { "application/json": { schema: errorSchema } } },
    402: { description: "Payment Required" },
    415: { description: "Unsupported file format (not charged)", content: { "application/json": { schema: errorSchema } } },
    503: { description: "Busy, retry later (not charged)", content: { "application/json": { schema: errorSchema } } },
  },
});
const openapi = {
  openapi: "3.1.0",
  info: {
    title: "TITANHOLD AI Quality Check",
    version: "0.2.0",
    description: "Paid check of an AI-generated image or short video for typical generation defects (extra fingers, garbled text, wrong vehicle geometry, physics, flicker). Runs a local vision model; files are deleted after the check.",
    "x-guidance": [
      `POST ${PUBLIC_URL}/v1/check/image with a JSON body: {"url": "https://.../file.png"} or {"data": "<base64 PNG/JPEG/WebP>"}, optionally "brief" (what was ordered) and "minScore" (0-100, default 70).`,
      `The first call returns HTTP 402 with an x402 payment challenge: pay ${PRICE_IMAGE} in USDC on Base via x402 and repeat the request with the payment header.`,
      `The paid call returns JSON {pass, score, defects:[{type, severity, detail}], reasons}. Treat pass=false as "needs a human look".`,
      `For short videos (MP4/MOV/WebM) use POST /v1/check/video (${PRICE_VIDEO}), same body plus optional "frames" (2-8).`,
      "You are charged only when a verdict is returned (HTTP 200); input errors, busy (503) and model errors are not settled.",
    ].join(" "),
    contact: { name: "TITANHOLD LLC", email: CONTACT_EMAIL, url: "https://titanhold.app" },
    license: { name: "MIT", url: "https://opensource.org/licenses/MIT" },
  },
  servers: [{ url: PUBLIC_URL }],
  paths: {
    "/v1/check/image": { post: paidOp("image", PRICE_IMAGE, "Check an AI-generated image before you pay",
      "Defect check of a PNG/JPEG/WebP image. Returns pass, score and typed defects.") },
    "/v1/check/video": { post: paidOp("video", PRICE_VIDEO, "Check a short AI-generated video before you pay",
      "Defect check of a short MP4/MOV/WebM video (sampled frames plus frame-to-frame flicker). Returns pass, score and typed defects.") },
  },
};
const FAVICON = join(dirname(fileURLToPath(import.meta.url)), "public", "favicon.ico");
app.get("/favicon.ico", (_req, res) => res.type("image/x-icon").sendFile(FAVICON, { maxAge: "7d" }));
app.get("/openapi.json", (_req, res) => { res.set("access-control-allow-origin", "*"); res.json(openapi); });

app.get("/", (_req, res) => res.json({
  service: "TITANHOLD QC: check an AI deliverable before you pay",
  source: "https://github.com/wolkodaww123-ctrl/titanhold-quality-gate",
  payment: { protocol: "x402", network: NETWORK, asset: "USDC", payTo: PAY_TO },
  endpoints: {
    [`POST ${PUBLIC_URL}/v1/check/image`]: { price: PRICE_IMAGE, input: inputSchema },
    [`POST ${PUBLIC_URL}/v1/check/video`]: { price: PRICE_VIDEO, input: { ...inputSchema, frames: "optional 2-8, default 6" } },
  },
  output: { pass: "boolean", score: "0-100", defects: "[{type, severity, detail, frame?}]", reasons: "string[]" },
  openapi: `${PUBLIC_URL}/openapi.json`,
  charging: "You are charged only when a verdict is returned (HTTP 200). Errors and 'busy' are free.",
}));

app.get("/health", async (_req, res) => {
  if (env.QC_BACKEND === "mock") return res.json({ ok: true, backend: "mock", queue: waiters.length, running });
  const url = (env.OLLAMA_URL ?? "http://127.0.0.1:11434") + "/api/tags";
  const ok = await fetch(url, { signal: AbortSignal.timeout(3000) }).then((r) => r.ok).catch(() => false);
  res.status(ok ? 200 : 503).json({ ok, queue: waiters.length, running });
});

const resourceServer = new x402ResourceServer(new HTTPFacilitatorClient({ url: FACILITATOR }))
  .register(NETWORK, new ExactEvmScheme())
  .registerExtension(bazaarResourceServerExtension);
if (BUILDER_CODE) resourceServer.registerExtension(builderCodeResourceServerExtension);
app.use(paymentMiddleware(routes, resourceServer));

app.post("/v1/check/image", (req, res) => runCheck(req, res, "image"));
app.post("/v1/check/video", (req, res) => runCheck(req, res, "video"));

export { app };
if (import.meta.url === `file://${process.argv[1]}`) {
  app.listen(PORT, HOST, () =>
    console.log(`x402 QC listening on http://${HOST}:${PORT} | network ${NETWORK} | payTo ${PAY_TO} | facilitator ${FACILITATOR}`));
}
