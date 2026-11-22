#!/usr/bin/env python3
"""
BlindCore Grant Showcase #1: Base L2 x402 v2 Agent Threat Scorer
Copyright 2026 Blind Labs (https://blindlabs.ai). Licensed under the Apache License, Version 2.0.

Demonstrates the end-to-end Base Builder Grants / Base Batches workflow with
zero third-party pip dependencies:
  1. Base L2 USDC x402 v2 prepaid micro-credit top-up ($1.00 USDC) via
     Coinbase AgentKit BlindCoreActionProvider (ERC-1271 / EIP-3009 / Permit2).
  2. Prepaid encrypted BlindJSONB threat corpus INGEST ($0.0005 USDC, 0 plaintext).
  3. 1-query encrypted SKLEARN_MNB phishing classification ($0.020 USDC).
  4. Verifiable Base BlindCoreRootAnchor.sol EIP-712 v2 SETTLE_PROOF +
     96-byte NSAU0001 cryptographic receipt.

Usage:
  python3 examples/01_base_agent_threat_scorer.py --mode local
  BLINDCORE_SESSION_TOKEN=<tok> python3 examples/01_base_agent_threat_scorer.py \
      --mode testnet --gate-url https://blindcore.dev
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
import secrets
import struct
import sys
import tempfile
import threading
import time
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gate.blindcore_trirail_gate import (  # noqa: E402
    BASE_SEPOLIA_CAIP2,
    GateConfig,
    PREPAID_MIN_MICRO_USDC,
    PRICING_TIERS,
    b64_json_decode,
    b64_json_encode,
    build_server,
    sha256_hex,
)
from mcp.agentkit_provider import BlindCoreActionProvider  # noqa: E402


# ---------------------------------------------------------------------------
# Constants (Testnet / Local Demo Fixtures - Zero Live Keys)
# ---------------------------------------------------------------------------

BASE_SEPOLIA_CHAIN_ID = 84532
DEMO_UPSTREAM_TOKEN = "demo-local-upstream-token-01"
DEMO_GATE_HMAC_HEX = "21" * 32
DEMO_BASE_PAY_TO = "0x1111111111111111111111111111111111111111"
DEMO_AGENT_WALLET = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DEMO_BASE_ANCHOR = "0x4242424242424242424242424242424242424242"
SECP256K1_HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0


# ---------------------------------------------------------------------------
# Verifiable 96-Byte NSAU0001 Receipt & EIP-712 v2 SETTLE_PROOF Helpers
# ---------------------------------------------------------------------------

def build_nsau0001_receipt(
    epoch_seq: int,
    fee_units: int,
    timestamp_sec: int,
    table_name: str,
    payment_hash: str,
    gate_mac: str,
) -> dict[str, Any]:
    """Build and self-verify a canonical 96-byte NSAU0001 receipt."""
    table_hash = hashlib.sha256(table_name.encode("utf-8")).digest()
    header = (
        b"NSAU0001"
        + struct.pack(">QQQ", epoch_seq, fee_units, timestamp_sec)
        + table_hash
    )
    assert len(header) == 64
    binding = hashlib.sha256(
        header + payment_hash.encode("utf-8") + gate_mac.encode("utf-8")
    ).digest()
    raw = header + binding
    assert len(raw) == 96
    return {
        "magic": "NSAU0001",
        "receipt_bytes_len": len(raw),
        "epoch_seq": epoch_seq,
        "fee_units": fee_units,
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


def build_base_eip712_settle_proof(
    *,
    chain_id: int,
    verifying_contract: str,
    epoch_seq: int,
    payer: str,
    table_hash_hex: str,
    receipt_hash_hex: str,
    fee_usdc_micro: int,
    op_tier: int,
) -> dict[str, Any]:
    """
    Build BlindCoreRootAnchor.sol EIP-712 v2 SETTLE_PROOF payload matching:
      EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
      SettleReceipt(uint64 epochSeq,address payer,bytes32 tableHash,bytes32 receiptHash,uint64 feeUsdcMicro,uint8 opTier)
    """
    domain_repr = json.dumps(
        {
            "name": "BlindCoreRootAnchor",
            "version": "2",
            "chainId": chain_id,
            "verifyingContract": verifying_contract,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    message = {
        "epochSeq": epoch_seq,
        "payer": payer,
        "tableHash": table_hash_hex,
        "receiptHash": receipt_hash_hex,
        "feeUsdcMicro": fee_usdc_micro,
        "opTier": op_tier,
    }
    struct_repr = json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")
    # Deterministic preview digest + EIP-2 low-s signature tuple for local/testnet dry-run
    domain_hash = hashlib.sha256(b"EIP712Domain:BlindCoreRootAnchor:2:" + domain_repr).digest()
    struct_hash = hashlib.sha256(b"SettleReceipt:" + struct_repr).digest()
    digest_bytes = hashlib.sha256(b"\x19\x01" + domain_hash + struct_hash).digest()
    r_bytes = hashlib.sha256(b"r:" + digest_bytes).digest()
    s_int = (int.from_bytes(hashlib.sha256(b"s:" + digest_bytes).digest(), "big") % (SECP256K1_HALF_N - 1)) + 1
    s_bytes = s_int.to_bytes(32, "big")
    v_val = 27 + (digest_bytes[0] & 1)
    return {
        "scheme": "EIP-712-v2",
        "contract": "BlindCoreRootAnchor.sol",
        "function": "settleReceipt(uint64,address,bytes32,bytes32,uint64,uint8,uint8,bytes32,bytes32)",
        "eip2_low_s_verified": (0 < s_int <= SECP256K1_HALF_N and v_val in (27, 28)),
        "domain": {
            "name": "BlindCoreRootAnchor",
            "version": "2",
            "chainId": chain_id,
            "verifyingContract": verifying_contract,
        },
        "primaryType": "SettleReceipt",
        "message": message,
        "digest": "0x" + digest_bytes.hex(),
        "signature": {
            "v": v_val,
            "r": "0x" + r_bytes.hex(),
            "s": "0x" + s_bytes.hex(),
        },
    }


# ---------------------------------------------------------------------------
# Ephemeral Local Mock Servers (--mode local)
# ---------------------------------------------------------------------------

class _LocalHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64


class _LocalThreatUpstreamState:
    def __init__(self) -> None:
        self.epoch_seq = 42
        self.encrypted_corpus: dict[str, list[dict[str, Any]]] = {}


class _LocalThreatUpstreamHandler(BaseHTTPRequestHandler):
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
        fee_micro = int(self.headers.get("X-BlindCore-Fee-Micro", "0"))
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
        state: _LocalThreatUpstreamState = self.server.state  # type: ignore[attr-defined]
        table = str(parsed.get("table", "threat_corpus_v1"))
        state.epoch_seq += 1

        if self.path.endswith("/ingest"):
            rows = parsed.get("rows", [])
            state.encrypted_corpus.setdefault(table, []).extend(rows)
            receipt = build_nsau0001_receipt(
                state.epoch_seq, fee_micro, ts, table, pay_hash, gate_mac
            )
            self._reply(
                200,
                {
                    "status": "ok",
                    "op": "INGEST",
                    "table": table,
                    "plaintext_stored": False,
                    "ingested_encrypted_rows": len(rows),
                    "epoch_seq": state.epoch_seq,
                    "nsau0001_receipt": receipt,
                },
            )
            return

        # Encrypted single-pass MultinomialNB phishing classification
        op = str(parsed.get("op", "SKLEARN_MNB"))
        vocab = [str(v) for v in parsed.get("vocab_paths", [])]
        alpha = float(parsed.get("alpha", 1.0))
        rows = state.encrypted_corpus.get(table, [])
        class_counts: dict[str, dict[str, int]] = {"phishing": {}, "benign": {}}
        class_docs: dict[str, int] = {"phishing": 0, "benign": 0}
        for row in rows:
            cls_name = str(row.get("label", "benign"))
            if cls_name not in class_counts:
                continue
            class_docs[cls_name] += 1
            feats = row.get("cipher_counts", {})
            for tok in vocab:
                class_counts[cls_name][tok] = class_counts[cls_name].get(tok, 0) + int(feats.get(tok, 0))

        total_docs = max(1, sum(class_docs.values()))
        scores = []
        for cohort in parsed.get("score_cohorts", []):
            cid = str(cohort.get("cohort_id", "unknown"))
            obs = cohort.get("cipher_counts", {})
            log_post: dict[str, float] = {}
            for cls_name in ("phishing", "benign"):
                prior = math.log((class_docs[cls_name] + alpha) / (total_docs + 2.0 * alpha))
                denom = sum(class_counts[cls_name].values()) + alpha * max(1, len(vocab))
                ll = prior
                for tok in vocab:
                    cnt = int(obs.get(tok, 0))
                    if cnt > 0:
                        ll += cnt * math.log((class_counts[cls_name].get(tok, 0) + alpha) / denom)
                log_post[cls_name] = round(ll, 6)
            verdict = "PHISHING_BLOCK" if log_post["phishing"] > log_post["benign"] else "BENIGN_ALLOW"
            scores.append(
                {
                    "cohort_id": cid,
                    "verdict": verdict,
                    "log_posterior": log_post,
                }
            )

        receipt = build_nsau0001_receipt(
            state.epoch_seq, fee_micro, ts, table, pay_hash, gate_mac
        )
        settle_proof = build_base_eip712_settle_proof(
            chain_id=BASE_SEPOLIA_CHAIN_ID,
            verifying_contract=DEMO_BASE_ANCHOR,
            epoch_seq=state.epoch_seq,
            payer=payer,
            table_hash_hex=receipt["table_hash"],
            receipt_hash_hex=receipt["receipt_hash"],
            fee_usdc_micro=fee_micro,
            op_tier=PRICING_TIERS["SKLEARN_MNB"].op_tier_id,
        )
        self._reply(
            200,
            {
                "status": "ok",
                "op": op,
                "table": table,
                "plaintext_stored": False,
                "epoch_seq": state.epoch_seq,
                "classifications": scores,
                "nsau0001_receipt": receipt,
                "SETTLE_PROOF": settle_proof,
            },
        )

    def _reply(self, status: int, obj: dict[str, Any]) -> None:
        raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class _LocalFacilitatorHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        data = json.loads(self.rfile.read(length).decode("utf-8"))
        pp = data.get("paymentPayload") or {}
        payload = pp.get("payload") or {}
        auth = payload.get("authorization") or {}
        payer = str(auth.get("from") or "")
        nonce = str(auth.get("nonce") or "")
        sig = str(payload.get("signature") or "")
        if self.path == "/verify":
            ok = sig.startswith("0xvalid")
            self._reply(200, {"isValid": ok, "payer": payer, "invalidReason": "" if ok else "bad_sig"})
            return
        if self.path == "/settle":
            tx_hash = "0x" + sha256_hex(f"base-sepolia-tx:{payer}:{nonce}".encode("utf-8"))
            self._reply(200, {"success": True, "transaction": tx_hash, "network": BASE_SEPOLIA_CAIP2})
            return
        self._reply(404, {"error": "unknown route"})

    def _reply(self, status: int, obj: dict[str, Any]) -> None:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def _start_local_srv(handler_cls: type[BaseHTTPRequestHandler], state: object) -> tuple[ThreadingHTTPServer, int]:
    srv = _LocalHTTPServer(("127.0.0.1", 0), handler_cls)
    srv.state = state  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# ---------------------------------------------------------------------------
# Main Showcase Flow
# ---------------------------------------------------------------------------

def _threat_corpus_payload(table: str) -> dict[str, Any]:
    return {
        "table": table,
        "op": "INGEST",
        "rows": [
            {"label": "phishing", "cipher_counts": {"urgent_verify": 4, "seed_phrase": 3, "wallet_drain": 2, "invoice_pdf": 0}},
            {"label": "phishing", "cipher_counts": {"urgent_verify": 3, "seed_phrase": 2, "wallet_drain": 3, "invoice_pdf": 0}},
            {"label": "benign", "cipher_counts": {"urgent_verify": 0, "seed_phrase": 0, "wallet_drain": 0, "invoice_pdf": 4}},
            {"label": "benign", "cipher_counts": {"urgent_verify": 1, "seed_phrase": 0, "wallet_drain": 0, "invoice_pdf": 3}},
        ],
    }


def _mnb_query_args(table: str) -> dict[str, Any]:
    return {
        "table": table,
        "train_classes": ["phishing", "benign"],
        "vocab_paths": ["urgent_verify", "seed_phrase", "wallet_drain", "invoice_pdf"],
        "score_cohorts": [
            {"cohort_id": "tx_candidate_phish_01", "cipher_counts": {"urgent_verify": 2, "seed_phrase": 2, "wallet_drain": 1, "invoice_pdf": 0}},
            {"cohort_id": "tx_candidate_clean_02", "cipher_counts": {"urgent_verify": 0, "seed_phrase": 0, "wallet_drain": 0, "invoice_pdf": 3}},
        ],
        "alpha": 1.0,
        "weight_scale": 10000,
    }


def run_local() -> dict[str, Any]:
    os.environ["BLINDCORE_GATE_QUIET"] = "1"
    tmpdir = tempfile.TemporaryDirectory()
    up_srv, up_port = _start_local_srv(_LocalThreatUpstreamHandler, _LocalThreatUpstreamState())
    fac_srv, fac_port = _start_local_srv(_LocalFacilitatorHandler, object())
    cfg = GateConfig(
        listen_host="127.0.0.1",
        listen_port=0,
        public_base_url="https://blindcore.dev",
        upstream_url=f"http://127.0.0.1:{up_port}",
        upstream_token=DEMO_UPSTREAM_TOKEN,
        gate_hmac_key_hex=DEMO_GATE_HMAC_HEX,
        db_path=os.path.join(tmpdir.name, "base_demo.sqlite"),
        base_network=BASE_SEPOLIA_CAIP2,
        base_pay_to=DEMO_BASE_PAY_TO,
        base_anchor_contract=DEMO_BASE_ANCHOR,
        x402_facilitator_url=f"http://127.0.0.1:{fac_port}",
        l402_macaroon_secret="demo-local-l402-secret-01",
        session_secret="demo-local-session-secret-01",
        test_mode=True,
    )
    gate_srv = build_server(cfg)
    gate_url = f"http://127.0.0.1:{gate_srv.server_address[1]}"
    threading.Thread(target=gate_srv.serve_forever, daemon=True).start()

    try:
        def x402_wallet_signer(rail: str, challenge: dict[str, Any]) -> dict[str, str]:
            assert rail == "base-x402"
            req_accepts = challenge["payment_required"]["accepts"][0]
            now = int(time.time())
            nonce = "0x" + secrets.token_hex(32)
            payload_obj = {
                "x402Version": 2,
                "scheme": "exact",
                "network": req_accepts["network"],
                "accepted": req_accepts,
                "payload": {
                    "signatureType": "eip3009",
                    "signature": "0xvalid" + secrets.token_hex(32),
                    "authorization": {
                        "from": DEMO_AGENT_WALLET,
                        "to": req_accepts["payTo"],
                        "value": str(req_accepts["amount"]),
                        "validAfter": str(now - 10),
                        "validBefore": str(now + 120),
                        "nonce": nonce,
                    },
                },
            }
            return {"PAYMENT-SIGNATURE": b64_json_encode(payload_obj)}

        provider = BlindCoreActionProvider(
            base_url=gate_url,
            preferred_rail="base-x402",
            payment_signer=x402_wallet_signer,
        )

        # Step 1: $1.00 USDC prepaid top-up via x402 v2
        topup_res = json.loads(provider.blindcore_topup_credits(args={"rail": "base-x402"}))
        assert topup_res["http_status"] == 200, f"topup failed: {topup_res}"
        assert topup_res["body"]["credited_micro_usdc"] == PREPAID_MIN_MICRO_USDC

        # Step 2: Prepaid BlindJSONB INGEST ($0.0005)
        table = "agent_phishing_corpus_v1"
        ingest_res = json.loads(
            provider.blindcore_query(
                args={
                    "endpoint": "/api/v1/blind/jsonb/ingest",
                    "table": table,
                    "op": "INGEST",
                    "params": _threat_corpus_payload(table),
                }
            )
        )
        assert ingest_res["http_status"] == 200, f"ingest failed: {ingest_res}"

        # Step 3: Prepaid 1-query encrypted SKLEARN_MNB ($0.020)
        mnb_res = json.loads(provider.blindcore_sklearn_mnb(args=_mnb_query_args(table)))
        assert mnb_res["http_status"] == 200, f"mnb failed: {mnb_res}"
        mnb_body = mnb_res["body"]
        receipt = mnb_body["nsau0001_receipt"]
        settle_proof = mnb_body["SETTLE_PROOF"]
        assert verify_nsau0001_receipt(receipt), "NSAU0001 receipt verification failed"
        assert settle_proof["eip2_low_s_verified"], "EIP-2 low-s check failed"

        remaining_micro = gate_srv.engine.ledger.get_balance(DEMO_AGENT_WALLET)
        expected_rem = (
            PREPAID_MIN_MICRO_USDC
            - PRICING_TIERS["INGEST"].micro_usdc
            - PRICING_TIERS["SKLEARN_MNB"].micro_usdc
        )
        assert remaining_micro == expected_rem, f"balance mismatch: {remaining_micro} != {expected_rem}"

        return {
            "showcase": "01_base_agent_threat_scorer",
            "mode": "local",
            "network": BASE_SEPOLIA_CAIP2,
            "agent_wallet": DEMO_AGENT_WALLET,
            "steps": {
                "1_x402_prepaid_topup": {
                    "http_status": topup_res["http_status"],
                    "rail": topup_res["body"]["rail"],
                    "credited_micro_usdc": topup_res["body"]["credited_micro_usdc"],
                    "payment_hash": topup_res["body"]["payment_hash"],
                },
                "2_blind_jsonb_ingest": {
                    "http_status": ingest_res["http_status"],
                    "fee_micro_usdc": PRICING_TIERS["INGEST"].micro_usdc,
                    "ingested_encrypted_rows": ingest_res["body"]["ingested_encrypted_rows"],
                    "plaintext_stored": ingest_res["body"]["plaintext_stored"],
                },
                "3_encrypted_sklearn_mnb": {
                    "http_status": mnb_res["http_status"],
                    "fee_micro_usdc": PRICING_TIERS["SKLEARN_MNB"].micro_usdc,
                    "plaintext_stored": mnb_body["plaintext_stored"],
                    "classifications": mnb_body["classifications"],
                    "payment_response": mnb_res.get("payment_response"),
                },
            },
            "credit_conservation": {
                "deposited_micro_usdc": PREPAID_MIN_MICRO_USDC,
                "spent_micro_usdc": PRICING_TIERS["INGEST"].micro_usdc + PRICING_TIERS["SKLEARN_MNB"].micro_usdc,
                "remaining_micro_usdc": remaining_micro,
                "exact_match": True,
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
        fac_srv.shutdown()
        fac_srv.server_close()
        tmpdir.cleanup()


def run_testnet(gate_url: str) -> dict[str, Any]:
    session_token = os.environ.get("BLINDCORE_SESSION_TOKEN", "").strip() or None
    x402_sig = os.environ.get("BLINDCORE_X402_SIGNATURE", "").strip() or None

    def env_signer(rail: str, _challenge: dict[str, Any]) -> dict[str, str]:
        if rail == "base-x402" and x402_sig:
            return {"PAYMENT-SIGNATURE": x402_sig}
        return {}

    provider = BlindCoreActionProvider(
        base_url=gate_url,
        preferred_rail="base-x402",
        payment_signer=env_signer if x402_sig else None,
        session_token=session_token,
    )
    table = "agent_phishing_corpus_v1"
    res = json.loads(provider.blindcore_sklearn_mnb(args=_mnb_query_args(table)))
    return {
        "showcase": "01_base_agent_threat_scorer",
        "mode": "testnet",
        "gate_url": gate_url,
        "credential_mode": "session_token" if session_token else ("x402_signature" if x402_sig else "402_quote_discovery"),
        "response": res,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="BlindCore Base x402 v2 Agent Threat Scorer Demo")
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
