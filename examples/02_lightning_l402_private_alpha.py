#!/usr/bin/env python3
"""
BlindCore Grant Showcase #2: Lightning L402 Private Alpha Cohort Analytics
Copyright 2026 Blind Labs (https://blindlabs.ai). Licensed under the Apache License, Version 2.0.

Demonstrates Bitcoin Lightning L402 (macaroon:preimage) pay-per-query
confidential analytics with zero third-party pip dependencies:
  1. Unpaid probe receives HTTP 402 + WWW-Authenticate: L402 macaroon + invoice.
  2. Settles 8-sat Lightning invoice, verifies SHA-256(preimage) == payment_hash,
     and executes encrypted k_min_tkms-guarded WEIGHTED_SUM across private alpha
     trading cohorts (zero plaintext stored).
  3. Counterfactual k_min_tkms privacy guard check: an under-sized cohort
     (cohort_size < k_min_tkms) triggers HTTP 422 abort and X-BlindCore-Settlement:
     aborted (zero leakage, zero replay lock).
  4. Verifies settled L402 token replay is deterministically rejected (HTTP 402).
  5. Emits verifiable SETTLE_PROOF + 96-byte NSAU0001 receipt JSON.

Usage:
  python3 examples/02_lightning_l402_private_alpha.py --mode local
  BLINDCORE_L402_TOKEN="<macaroon>:<preimage_hex>" \
      python3 examples/02_lightning_l402_private_alpha.py --mode testnet --gate-url https://blindcore.dev
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import struct
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gate.blindcore_trirail_gate import (  # noqa: E402
    GateConfig,
    PRICING_TIERS,
    b64_json_decode,
    build_server,
    sha256_hex,
)


# ---------------------------------------------------------------------------
# Constants (Local Demo Fixtures - Zero Live Keys)
# ---------------------------------------------------------------------------

DEMO_UPSTREAM_TOKEN = "demo-local-upstream-token-02"
DEMO_GATE_HMAC_HEX = "22" * 32
K_MIN_TKMS = 5
DEMO_L402_SEED = "demo-lightning-l402-seed-02"


# ---------------------------------------------------------------------------
# Verifiable 96-Byte NSAU0001 Receipt & L402 SETTLE_PROOF Helpers
# ---------------------------------------------------------------------------

def build_nsau0001_receipt(
    epoch_seq: int,
    fee_sats: int,
    timestamp_sec: int,
    table_name: str,
    payment_hash: str,
    gate_mac: str,
) -> dict[str, Any]:
    table_hash = hashlib.sha256(table_name.encode("utf-8")).digest()
    header = (
        b"NSAU0001"
        + struct.pack(">QQQ", epoch_seq, fee_sats, timestamp_sec)
        + table_hash
    )
    binding = hashlib.sha256(
        header + payment_hash.encode("utf-8") + gate_mac.encode("utf-8")
    ).digest()
    raw = header + binding
    assert len(raw) == 96
    return {
        "magic": "NSAU0001",
        "receipt_bytes_len": len(raw),
        "epoch_seq": epoch_seq,
        "fee_sats": fee_sats,
        "timestamp_sec": timestamp_sec,
        "table_hash": "0x" + table_hash.hex(),
        "payment_hash": payment_hash,
        "gate_mac": gate_mac,
        "receipt_hex": raw.hex(),
        "receipt_hash": "0x" + hashlib.sha256(raw).hexdigest(),
        "verified": (raw[:8] == b"NSAU0001" and len(raw) == 96),
    }


def verify_nsau0001_receipt(receipt: dict[str, Any]) -> bool:
    raw = bytes.fromhex(str(receipt["receipt_hex"]))
    if len(raw) != 96 or raw[:8] != b"NSAU0001":
        return False
    expected_binding = hashlib.sha256(
        raw[:64]
        + str(receipt["payment_hash"]).encode("utf-8")
        + str(receipt["gate_mac"]).encode("utf-8")
    ).digest()
    return hmac.compare_digest(raw[64:96], expected_binding)


def build_l402_settle_proof(
    *,
    epoch_seq: int,
    payer: str,
    table_hash_hex: str,
    receipt_hash_hex: str,
    payment_hash: str,
    preimage_hex: str,
    fee_sats: int,
    op_tier: int,
) -> dict[str, Any]:
    preimage_check = sha256_hex(bytes.fromhex(preimage_hex)) == payment_hash
    digest = hashlib.sha256(
        f"BlindCoreL402Settle-v2|{epoch_seq}|{payer}|{table_hash_hex}|{receipt_hash_hex}|{payment_hash}|{fee_sats}|{op_tier}".encode("utf-8")
    ).hexdigest()
    return {
        "scheme": "L402-PREIMAGE-HTLC-V2",
        "network": "bitcoin:lightning",
        "epoch_seq": epoch_seq,
        "payer": payer,
        "table_hash": table_hash_hex,
        "receipt_hash": receipt_hash_hex,
        "payment_hash": payment_hash,
        "preimage_sha256_verified": preimage_check,
        "fee_sats": fee_sats,
        "op_tier": op_tier,
        "settle_digest": "0x" + digest,
    }


# ---------------------------------------------------------------------------
# Ephemeral Local Mock Upstream (--mode local)
# ---------------------------------------------------------------------------

class _LocalHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64


class _LocalAlphaUpstreamState:
    def __init__(self) -> None:
        self.epoch_seq = 108


class _LocalAlphaUpstreamHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b""
        if self.headers.get("Authorization", "") != f"Bearer {DEMO_UPSTREAM_TOKEN}":
            self._reply(401, {"error": "unauthorized upstream caller"})
            return

        rail = self.headers.get("X-BlindCore-Rail", "")
        payer = self.headers.get("X-BlindCore-Payer", "")
        pay_hash = self.headers.get("X-BlindCore-Payment-Hash", "")
        fee_micro = self.headers.get("X-BlindCore-Fee-Micro", "0")
        ts = int(self.headers.get("X-BlindCore-Ts", "0"))
        gate_mac = self.headers.get("X-BlindCore-Gate-Mac", "")

        body_hash = sha256_hex(body)
        expected_mac = hmac.new(
            bytes.fromhex(DEMO_GATE_HMAC_HEX),
            f"{rail}|{payer}|{pay_hash}|{fee_micro}|{ts}|{body_hash}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(gate_mac, expected_mac):
            self._reply(403, {"error": "invalid X-BlindCore-Gate-Mac"})
            return

        parsed = json.loads(body.decode("utf-8")) if body else {}
        cohort_size = int(parsed.get("cohort_size", 0))
        k_min = int(parsed.get("k_min_tkms", K_MIN_TKMS))
        if cohort_size < k_min:
            self._reply(
                422,
                {
                    "error": "k_min_tkms cohort cardinality guard aborted query",
                    "cohort_size": cohort_size,
                    "k_min_tkms": k_min,
                    "plaintext_leaked": False,
                },
            )
            return

        state: _LocalAlphaUpstreamState = self.server.state  # type: ignore[attr-defined]
        state.epoch_seq += 1
        table = str(parsed.get("table", "private_alpha_flows_v1"))
        weights = [int(w) for w in parsed.get("weights_bps", [4000, 3500, 2500])]
        # Deterministic encrypted cohort alpha aggregate (bps)
        signal_basis = [142, 88, 215]
        weighted_bps = sum(w * s for w, s in zip(weights, signal_basis)) // max(1, sum(weights))
        receipt = build_nsau0001_receipt(
            state.epoch_seq,
            PRICING_TIERS["SUM"].sats,
            ts,
            table,
            pay_hash,
            gate_mac,
        )
        self._reply(
            200,
            {
                "status": "ok",
                "op": "WEIGHTED_SUM",
                "table": table,
                "plaintext_stored": False,
                "k_min_tkms": k_min,
                "cohort_size": cohort_size,
                "cohort_guard_passed": True,
                "epoch_seq": state.epoch_seq,
                "encrypted_alpha_signal_bps": weighted_bps,
                "payer": payer,
                "nsau0001_receipt": receipt,
            },
        )

    def _reply(self, status: int, obj: dict[str, Any]) -> None:
        raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def _http_post(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    req_hdrs = {"Content-Type": "application/json"}
    if headers:
        req_hdrs.update(headers)
    req = urllib.request.Request(url, data=raw, method="POST", headers=req_hdrs)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return (
                int(resp.status),
                {k.lower(): v for k, v in resp.headers.items()},
                json.loads(resp.read().decode("utf-8")),
            )
    except urllib.error.HTTPError as exc:
        body_raw = exc.read().decode("utf-8", errors="replace")
        try:
            body_obj = json.loads(body_raw)
        except Exception:
            body_obj = {"raw": body_raw}
        return int(exc.code), {k.lower(): v for k, v in exc.headers.items()}, body_obj


# ---------------------------------------------------------------------------
# Main Showcase Flow
# ---------------------------------------------------------------------------

def run_local() -> dict[str, Any]:
    os.environ["BLINDCORE_GATE_QUIET"] = "1"
    tmpdir = tempfile.TemporaryDirectory()
    up_srv = _LocalHTTPServer(("127.0.0.1", 0), _LocalAlphaUpstreamHandler)
    up_srv.state = _LocalAlphaUpstreamState()  # type: ignore[attr-defined]
    threading.Thread(target=up_srv.serve_forever, daemon=True).start()
    up_port = up_srv.server_address[1]

    cfg = GateConfig(
        listen_host="127.0.0.1",
        listen_port=0,
        public_base_url="https://blindcore.dev",
        upstream_url=f"http://127.0.0.1:{up_port}",
        upstream_token=DEMO_UPSTREAM_TOKEN,
        gate_hmac_key_hex=DEMO_GATE_HMAC_HEX,
        db_path=os.path.join(tmpdir.name, "l402_demo.sqlite"),
        l402_macaroon_secret="demo-local-l402-secret-02",
        session_secret="demo-local-session-secret-02",
        test_mode=True,
        test_l402_seed=DEMO_L402_SEED,
    )
    gate_srv = build_server(cfg)
    gate_url = f"http://127.0.0.1:{gate_srv.server_address[1]}"
    threading.Thread(target=gate_srv.serve_forever, daemon=True).start()

    try:
        query_url = f"{gate_url}/api/v1/blind/jsonb/query"
        valid_payload = {
            "table": "private_alpha_flows_v1",
            "op": "WEIGHTED_SUM",
            "k_min_tkms": K_MIN_TKMS,
            "cohort_size": 24,
            "weights_bps": [4500, 3500, 2000],
        }

        # Step 1: Unpaid probe -> HTTP 402 + L402 macaroon challenge
        st_402, hdrs_402, quote_402 = _http_post(query_url, valid_payload)
        assert st_402 == 402, f"expected 402, got {st_402}"
        www_auth = hdrs_402.get("www-authenticate", "")
        m_mac = re.search(r'L402 macaroon="([^"]+)"', www_auth)
        m_inv = re.search(r'invoice="([^"]+)"', www_auth)
        assert m_mac is not None and m_inv is not None, f"missing L402 challenge: {www_auth}"
        mac_b64 = m_mac.group(1)
        invoice = m_inv.group(1)
        tok_id = b64_json_decode(mac_b64)["identifier"]["token_id"]
        preimage_hex = gate_srv.engine.derive_test_preimage_hex(tok_id)
        l402_auth = f"L402 {mac_b64}:{preimage_hex}"

        # Step 2: Paid WEIGHTED_SUM query with L402 macaroon:preimage (8 sats)
        st_200, hdrs_200, body_200 = _http_post(
            query_url,
            valid_payload,
            headers={"Authorization": l402_auth},
        )
        assert st_200 == 200, f"expected 200, got {st_200}: {body_200}"
        receipt = body_200["nsau0001_receipt"]
        assert verify_nsau0001_receipt(receipt), "NSAU0001 receipt verification failed"
        pay_resp = b64_json_decode(hdrs_200["payment-response"])
        settle_proof = build_l402_settle_proof(
            epoch_seq=body_200["epoch_seq"],
            payer=body_200["payer"],
            table_hash_hex=receipt["table_hash"],
            receipt_hash_hex=receipt["receipt_hash"],
            payment_hash=receipt["payment_hash"],
            preimage_hex=preimage_hex,
            fee_sats=PRICING_TIERS["SUM"].sats,
            op_tier=PRICING_TIERS["SUM"].op_tier_id,
        )
        assert settle_proof["preimage_sha256_verified"]

        # Step 3: Replay of settled L402 token MUST be rejected (HTTP 402)
        st_replay, _, _ = _http_post(
            query_url,
            valid_payload,
            headers={"Authorization": l402_auth},
        )
        assert st_replay == 402, f"expected 402 on L402 replay, got {st_replay}"

        # Step 4: Counterfactual k_min_tkms privacy guard abort check (cohort_size=2 < 5)
        small_cohort_payload = {
            "table": "private_alpha_flows_v1",
            "op": "WEIGHTED_SUM",
            "k_min_tkms": K_MIN_TKMS,
            "cohort_size": 2,
            "weights_bps": [5000, 5000],
        }
        st_402_b, hdrs_402_b, _ = _http_post(query_url, small_cohort_payload)
        assert st_402_b == 402
        m_mac_b = re.search(r'L402 macaroon="([^"]+)"', hdrs_402_b["www-authenticate"])
        assert m_mac_b is not None
        mac_b = m_mac_b.group(1)
        tok_b = b64_json_decode(mac_b)["identifier"]["token_id"]
        pre_b = gate_srv.engine.derive_test_preimage_hex(tok_b)
        st_abort, hdrs_abort, body_abort = _http_post(
            query_url,
            small_cohort_payload,
            headers={"Authorization": f"L402 {mac_b}:{pre_b}"},
        )
        assert st_abort == 422, f"expected 422 k_min_tkms abort, got {st_abort}"
        assert hdrs_abort.get("x-blindcore-settlement") == "aborted"

        return {
            "showcase": "02_lightning_l402_private_alpha",
            "mode": "local",
            "network": "bitcoin:lightning",
            "steps": {
                "1_l402_challenge": {
                    "http_status": st_402,
                    "tier": quote_402["accepts"][0]["extra"]["tier"],
                    "sats_required": PRICING_TIERS["SUM"].sats,
                    "invoice_prefix": invoice[:24] + "...",
                },
                "2_encrypted_weighted_sum": {
                    "http_status": st_200,
                    "plaintext_stored": body_200["plaintext_stored"],
                    "cohort_size": body_200["cohort_size"],
                    "k_min_tkms": body_200["k_min_tkms"],
                    "encrypted_alpha_signal_bps": body_200["encrypted_alpha_signal_bps"],
                    "payment_response": pay_resp,
                },
                "3_l402_replay_check": {
                    "http_status": st_replay,
                    "replay_blocked": True,
                },
                "4_counterfactual_k_min_tkms_guard": {
                    "http_status": st_abort,
                    "settlement_header": hdrs_abort.get("x-blindcore-settlement"),
                    "error": body_abort.get("error"),
                    "plaintext_leaked": body_abort.get("plaintext_leaked"),
                },
            },
            "NSAU0001": receipt,
            "SETTLE_PROOF": settle_proof,
        }
    finally:
        gate_srv.shutdown()
        gate_srv.server_close()
        gate_srv.engine.close()
        up_srv.shutdown()
        up_srv.server_close()
        tmpdir.cleanup()


def run_testnet(gate_url: str) -> dict[str, Any]:
    l402_token = os.environ.get("BLINDCORE_L402_TOKEN", "").strip()
    query_url = f"{gate_url.rstrip('/')}/api/v1/blind/jsonb/query"
    payload = {
        "table": "private_alpha_flows_v1",
        "op": "WEIGHTED_SUM",
        "k_min_tkms": K_MIN_TKMS,
        "cohort_size": 24,
        "weights_bps": [4500, 3500, 2000],
    }
    hdrs = {"Authorization": f"L402 {l402_token}"} if l402_token else {}
    status, resp_hdrs, body = _http_post(query_url, payload, headers=hdrs)
    return {
        "showcase": "02_lightning_l402_private_alpha",
        "mode": "testnet",
        "gate_url": gate_url,
        "credential_mode": "l402_token" if l402_token else "402_quote_discovery",
        "http_status": status,
        "www_authenticate": resp_hdrs.get("www-authenticate"),
        "body": body,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="BlindCore Lightning L402 Private Alpha Demo")
    parser.add_argument("--mode", choices=("local", "testnet"), default="local")
    parser.add_argument(
        "--gate-url",
        default=os.environ.get("BLINDCORE_GATE_URL", "https://blindcore.dev"),
        help="Target BlindCore Tri-Rail Gate URL (used in --mode testnet)",
    )
    args = parser.parse_args()
    out = run_local() if args.mode == "local" else run_testnet(args.gate_url)
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
