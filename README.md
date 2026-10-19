# titanhold-x402-qc: check an AI deliverable before you pay

A small paid HTTP endpoint ([x402](https://github.com/x402-foundation/x402), USDC) that checks an AI-generated image or short video for typical generation defects and returns a machine-readable verdict. A buyer agent calls it after delivery and before releasing payment to the seller.

It wraps the open-source [titanhold-quality-gate](https://github.com/wolkodaww123-ctrl/titanhold-quality-gate) (MIT) and runs a **local** vision model (Ollama, default `qwen2.5vl:7b`). Files are not sent to a third-party AI API and are deleted right after the check.

> **Status: prototype.** The x402 payment flow is tested end to end against a local mock facilitator and the 402 challenge against the public Base Sepolia facilitator. It has **not** processed a real paid call yet. Vision models miss defects and sometimes flag clean images: treat `pass: false` as "needs a human look", not a final verdict.

| Route | Default price | Input (JSON) |
|---|---|---|
| `POST /v1/check/image` | $0.02 | `url` (https) or `data` (base64), optional `brief`, `minScore` |
| `POST /v1/check/video` | $0.10 | same + optional `frames` (2-8) |
| `GET /`, `GET /health` | free | service info / model status |

Output: `{ pass, score, defects: [{type, severity, detail, frame?}], reasons, model }`.
You are charged only when a verdict is returned (HTTP 200). Input errors (4xx), "busy" (503) and model errors (502) are not settled.

## Run (testnet first)

```bash
cp .env.example .env     # set PAY_TO to your public receiving address
npm ci
ollama pull qwen2.5vl:7b # needs ffmpeg/ffprobe on PATH for video
node --env-file=.env server.mjs
```

Defaults to **Base Sepolia** (`eip155:84532`) and the public facilitator `https://x402.org/facilitator`. For Base mainnet set `X402_NETWORK=eip155:8453`; the mainnet default facilitator is the Coinbase CDP facilitator (`FACILITATOR_URL=cdp`, needs `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET`, Node >= 22 and `npm i @coinbase/cdp-sdk @x402/svm`). That path is the one that feeds the [x402 Bazaar](https://docs.cdp.coinbase.com/x402/seller/get-discovered); it is not exercised by the included tests.

Optional: `BUILDER_CODE` adds a [Base Builder Code](https://docs.cdp.coinbase.com/x402/core-concepts/builder-codes) to settlements.

## Test

```bash
npm test   # mock facilitator + throwaway keys: 402 challenge, paid call, no settlement on bad input, SSRF block
```

## Demo buyer

```bash
BUYER_PRIVATE_KEY=0x... QC_URL=http://127.0.0.1:8091 node demo/buyer.mjs render.png "red 2-door coupe"
```

Use a separate throwaway wallet with testnet USDC (Circle faucet, Base Sepolia). Never a main wallet key.

## Security notes

- `url` input: https only, DNS result must be public (private/loopback/link-local blocked), no redirects, size cap.
- One job at a time with a small queue; extra requests get 503 and are not charged.
- No private key is ever read by the server. `PAY_TO` is a public address.

## Hire TITANHOLD

Need custom AI media pipelines, QC integration, x402 paid endpoints or ComfyUI/Flux workflows? TITANHOLD LLC is a US-registered studio working async, **written communication only**.

- Site: https://titanhold.app
- Email: hennadii@titanhold.app

## License

MIT, see [LICENSE](LICENSE).
