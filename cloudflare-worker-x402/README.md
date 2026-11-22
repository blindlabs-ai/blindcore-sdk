# BlindCore Cloudflare Worker `x402 v2` Template

Licensed under the Apache License, Version 2.0. Copyright 2026 Blind Labs (https://blindlabs.ai).

Zero-dependency TypeScript Cloudflare Worker template that puts an edge-routed
`x402 v2` / `L402` / `sBTC` confidential scoring endpoint (`POST /score`) in
front of the BlindCore Tri-Rail Payment Gateway.

Built for **Cloudflare Workers AI**, **x402 / Bazaar** agent builders, and
**Cloudflare Research** engineers evaluating zero-plaintext edge ML
(`BlindJSONB` `SKLEARN_MNB` scoring in ~`9.12 ms` server-side compute with
zero plaintext exposure at the edge or origin).

## Why Use This Pattern?

- **Zero external npm dependencies**: Pure Web Fetch API + `ExportedHandler`
  (`src/index.ts`). No bundler bloat, sub-millisecond Worker cold start.
- **Pass-through `HTTP 402` negotiation**: Unauthenticated `POST /score`
  surfaces live `PAYMENT-REQUIRED` (`x402 v2` + `extensions.bazaar`),
  `WWW-Authenticate: L402`, and `X-Stacks-Payment-Required` headers untouched.
- **Exact `bodySha256` preservation**: Forwards encrypted `BlindJSONB` payloads
  byte-for-byte so client-signed `PAYMENT-SIGNATURE` commitments stay valid.
- **Settlement verification**: Inspects upstream `PAYMENT-RESPONSE` and
  `SETTLE_PROOF` headers/body on `HTTP 200` and emits
  `X-BlindCore-Settle-Verified: true` alongside `X-BlindCore-Settle-Proof`.

## 30-Second Quickstart

### 1. Run Locally (`npx wrangler dev`)

```bash
cd cloudflare-worker-x402
npx wrangler dev
```

### 2. Check Health & `x402 v2` Discovery (`GET /`)

```bash
curl -s http://127.0.0.1:8787/ | jq .
```

### 3. Trigger Live Tri-Rail `HTTP 402` Quote (`POST /score`)

```bash
curl -i -X POST http://127.0.0.1:8787/score \
  -H "Content-Type: application/json" \
  -d '{"op":"SKLEARN_MNB","table":"bt_agent_corpus"}'
```

You will receive `HTTP 402 Payment Required` with:
- `PAYMENT-REQUIRED` (Base64 `x402 v2` quote including `extensions.bazaar`)
- `X-Bazaar-Discoverable: true`
- `WWW-Authenticate: L402 ...` (Bitcoin Lightning rail)
- `X-Stacks-Payment-Required` (Stacks `sBTC` rail)

### 4. Retry With Payment or Prepaid Session

Pass either an `x402 v2` `PAYMENT-SIGNATURE` header from Coinbase AgentKit /
wallet signer or a prepaid `X-BlindCore-Session` token:

```bash
curl -i -X POST http://127.0.0.1:8787/score \
  -H "Content-Type: application/json" \
  -H "X-BlindCore-Session: <your-prepaid-session-token>" \
  -d '{"op":"SKLEARN_MNB","table":"bt_agent_corpus","cohorts":[...]}'
```

### 5. Deploy to Cloudflare Edge (`npx wrangler deploy`)

```bash
# Optional: attach a Worker-managed prepaid session secret (never commit tokens)
npx wrangler secret put BLINDCORE_SESSION_TOKEN

# Deploy to Cloudflare's global edge network
npx wrangler deploy
```

## Environment Variables & Secrets

| Name | Kind | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `BLINDCORE_GATE_URL` | `[vars]` in `wrangler.toml` | `https://api.blindlabs.ai/testnet` | Upstream BlindCore Tri-Rail Gateway URL |
| `BLINDCORE_SESSION_TOKEN` | Wrangler secret | *(unset)* | Optional fallback `X-BlindCore-Session` when edge callers omit payment headers |

## License

Licensed under the Apache License, Version 2.0 (see root [LICENSE](../LICENSE) and [NOTICE](../NOTICE)). Copyright 2026 Blind Labs (https://blindlabs.ai).
