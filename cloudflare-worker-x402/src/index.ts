// BlindCore x402 v2 Confidential Compute Edge Worker (Zero External Dependencies)
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Blind Labs (https://blindlabs.ai)

export interface Env {
  BLINDCORE_GATE_URL?: string;
  BLINDCORE_SESSION_TOKEN?: string;
}

const DEFAULT_GATE_URL = "https://api.blindlabs.ai/testnet";
const DEFAULT_MNB_PROBE = JSON.stringify({ op: "SKLEARN_MNB", table: "bt_edge_probe" });

function verifySettleProof(res: Response, bodyText: string): { verified: boolean; ref: string } {
  const hdrProof = res.headers.get("X-BlindCore-Settle-Proof") || res.headers.get("SETTLE_PROOF") || "";
  const payRespB64 = res.headers.get("PAYMENT-RESPONSE") || "";
  let payRespOk = false;
  let payHash = res.headers.get("X-BlindCore-Payment-Hash") || "";
  if (payRespB64) {
    try {
      const dec = JSON.parse(atob(payRespB64)) as { success?: boolean; paymentHash?: string };
      payRespOk = dec.success === true && typeof dec.paymentHash === "string" && dec.paymentHash.length >= 16;
      if (dec.paymentHash) payHash = dec.paymentHash;
    } catch { /* ignore malformed header */ }
  }
  let bodyProof = "";
  try {
    const parsed = JSON.parse(bodyText) as { settle_proof?: { digest?: string; settle_digest?: string }; receipt_hex?: string };
    bodyProof = parsed.settle_proof?.digest || parsed.settle_proof?.settle_digest || parsed.receipt_hex || "";
  } catch { /* non-JSON body */ }
  const ref = hdrProof || bodyProof || payHash;
  return { verified: Boolean(hdrProof || bodyProof || payRespOk), ref };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const gateUrl = (env.BLINDCORE_GATE_URL || DEFAULT_GATE_URL).replace(/\/+$/, "");
    const { pathname } = new URL(request.url);

    if (request.method === "GET" && pathname === "/") {
      return Response.json({
        service: "blindcore-x402-worker",
        status: "ok",
        x402Version: 2,
        gateUrl,
        routes: { health: "GET /", score: "POST /score" },
        discovery: { x402: `${gateUrl}/.well-known/x402.json`, llms: `${gateUrl}/llms.txt` },
      });
    }

    if (request.method === "POST" && pathname === "/score") {
      const rawBody = await request.text();
      const body = rawBody.trim().length > 0 ? rawBody : DEFAULT_MNB_PROBE;
      const fwd = new Headers({ "Content-Type": "application/json" });
      for (const h of ["PAYMENT-SIGNATURE", "X-PAYMENT", "X-BlindCore-Session", "Authorization", "X-Stacks-Payment-Tx"]) {
        const v = request.headers.get(h);
        if (v) fwd.set(h, v);
      }
      if (!fwd.has("PAYMENT-SIGNATURE") && !fwd.has("X-BlindCore-Session") && !fwd.has("Authorization") && !fwd.has("X-Stacks-Payment-Tx") && env.BLINDCORE_SESSION_TOKEN) {
        fwd.set("X-BlindCore-Session", env.BLINDCORE_SESSION_TOKEN);
      }

      const upstream = await fetch(`${gateUrl}/api/v1/blind/jsonb/query`, { method: "POST", headers: fwd, body });
      const text = await upstream.text();
      const out = new Headers({ "Content-Type": upstream.headers.get("Content-Type") || "application/json" });

      if (upstream.status === 402) {
        for (const h of ["PAYMENT-REQUIRED", "WWW-Authenticate", "X-Stacks-Payment-Required"]) {
          const v = upstream.headers.get(h);
          if (v) out.set(h, v);
        }
        try {
          const quote = JSON.parse(text) as { extensions?: { bazaar?: { discoverable?: boolean } } };
          if (quote.extensions?.bazaar?.discoverable) out.set("X-Bazaar-Discoverable", "true");
        } catch { /* pass through raw 402 payload */ }
        return new Response(text, { status: 402, headers: out });
      }

      for (const h of ["PAYMENT-RESPONSE", "X-BlindCore-Rail", "X-BlindCore-Payment-Hash", "X-BlindCore-Settle-Proof", "SETTLE_PROOF"]) {
        const v = upstream.headers.get(h);
        if (v) out.set(h, v);
      }
      if (upstream.ok) {
        const settle = verifySettleProof(upstream, text);
        out.set("X-BlindCore-Settle-Verified", settle.verified ? "true" : "false");
        if (settle.ref) out.set("X-BlindCore-Settle-Proof", settle.ref);
      }
      return new Response(text, { status: upstream.status, headers: out });
    }

    return Response.json({ error: "Not found. Use GET / or POST /score." }, { status: 404 });
  },
};
