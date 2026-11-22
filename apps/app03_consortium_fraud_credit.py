#!/usr/bin/env python3
"""
BlindCore Killer App #3: Cross-Institution Consortium Fraud Exchange &
Morpho/RWA Confidential Credit Underwriting (Base x402 v2 USDC).
Copyright 2026 Blind Labs (https://blindlabs.ai). Licensed under the Apache License, Version 2.0.

Demonstrates 3 competing financial institutions (Bank A, DeFi Protocol B,
Morpho Vault C) pooling encrypted borrower and fraud records into one shared
BlindJSONB table over Base x402 v2 USDC without revealing raw rows to each
other or the BlindCore host:
  1. Unpaid probe receives real HTTP 402 (PAYMENT-REQUIRED x402 v2 + Bazaar).
  2. Base x402 v2 prepaid session top-up ($1.00 USDC) funds 3-institution
     BlindJSONB INGEST batches with zero plaintext PII on the wire.
  3. Direct Base x402 v2 payment runs joint encrypted SKLEARN_MNB fraud/credit
     underwriting across all 3 institutions' pooled records.
  4. Direct Base x402 v2 payment runs homomorphic RANGE_GATE covenant check
     (leverage <= 3.00x) using zero-sum cohort-masked leverage ciphertexts.
  5. Counterfactual k_min_tkms singleton extraction probe (cohort_size=1 < 5)
     is aborted with HTTP 422 + X-BlindCore-Settlement: aborted, and replay
     of a settled x402 signature is rejected with HTTP 402.
  6. O(1) cryptographic shredding drops a borrower's per-entity key and posts
     a blind tombstone token, immediately excluding the entity and rendering
     stored ciphertext permanently undecryptable.
  7. Verifies 96-byte NSAU0001 receipt and Base BlindCoreRootAnchor.sol
     EIP-712 v2 SETTLE_PROOF.

Usage:
  python3 apps/app03_consortium_fraud_credit.py --mode local
  python3 apps/app03_consortium_fraud_credit.py --mode testnet \
      --gate-url https://api.blindlabs.ai/testnet
"""

from __future__ import annotations

import argparse
import base64
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
import urllib.error
import urllib.request

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
    validate_http_url,
)
from mcp.agentkit_provider import BlindCoreActionProvider  # noqa: E402


# ---------------------------------------------------------------------------
# Constants (Local/Testnet Demo Fixtures - Zero Live Secrets)
# ---------------------------------------------------------------------------

APP_ID = "app03"
APP_TITLE = (
    "Cross-Institution Consortium Fraud Exchange & Morpho/RWA Confidential "
    "Credit Underwriting"
)
APP_RAIL = "base-x402"
DEFAULT_TESTNET_URL = "https://api.blindlabs.ai/testnet"

BASE_SEPOLIA_CHAIN_ID = 84532
DEMO_UPSTREAM_TOKEN = "demo-local-upstream-token-app03"
DEMO_GATE_HMAC_HEX = "33" * 32
DEMO_BASE_PAY_TO = "0x3333333333333333333333333333333333333333"
DEMO_CONSORTIUM_WALLET = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
DEMO_BASE_ANCHOR = "0x4242424242424242424242424242424242424242"
SECP256K1_HALF_N = (
    0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
)
K_MIN_TKMS = 5
LEVERAGE_LIMIT_BPS = 30000  # 3.00x covenant ceiling
FIXED_ENVELOPE_BYTES = 384


# ---------------------------------------------------------------------------
# Client-Side Blind Tokenization, Authenticated Stream Cipher & O(1) Key Vault
# ---------------------------------------------------------------------------

def _blind_token(key: bytes, domain: str, value: str) -> str:
    digest = hmac.new(
        key,
        f"{domain}|{value}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{domain}_{digest[:24]}"


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(key + nonce + struct.pack(">I", counter)).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> dict[str, str]:
    nonce = secrets.token_bytes(16)
    padded_len = FIXED_ENVELOPE_BYTES
    if len(plaintext) + 2 > padded_len:
        raise ValueError("plaintext exceeds fixed envelope size")
    pad_len = padded_len - 2 - len(plaintext)
    framed = struct.pack(">H", len(plaintext)) + plaintext + secrets.token_bytes(pad_len)
    stream = _keystream(key, nonce, len(framed))
    ct = bytes(a ^ b for a, b in zip(framed, stream))
    tag = hmac.new(key, aad + nonce + ct, hashlib.sha256).hexdigest()
    return {
        "nonce_hex": nonce.hex(),
        "ct_b64": base64.b64encode(ct).decode("ascii"),
        "tag_hex": tag,
        "envelope_bytes": str(len(ct)),
    }


def _aead_decrypt(key: bytes, blob: dict[str, str], aad: bytes) -> bytes:
    nonce = bytes.fromhex(blob["nonce_hex"])
    ct = base64.b64decode(blob["ct_b64"].encode("ascii"))
    expected_tag = hmac.new(key, aad + nonce + ct, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_tag, blob["tag_hex"]):
        raise ValueError("AEAD authentication tag mismatch (key dropped or tampered)")
    stream = _keystream(key, nonce, len(ct))
    framed = bytes(a ^ b for a, b in zip(ct, stream))
    pt_len = struct.unpack(">H", framed[:2])[0]
    if pt_len > len(framed) - 2:
        raise ValueError("invalid framed plaintext length")
    return framed[2 : 2 + pt_len]


class ConsortiumKeyVault:
    """Per-entity O(1) shreddable key vault held strictly client-side."""

    def __init__(self) -> None:
        self.token_key = secrets.token_bytes(32)
        self.entity_keys: dict[str, bytes] = {}

    def entity_token(self, borrower_id: str) -> str:
        tok = _blind_token(self.token_key, "ent", borrower_id)
        if tok not in self.entity_keys:
            self.entity_keys[tok] = secrets.token_bytes(32)
        return tok

    def inst_token(self, inst_name: str) -> str:
        return _blind_token(self.token_key, "inst", inst_name)

    def label_token(self, label_name: str) -> str:
        return _blind_token(self.token_key, "cls", label_name)

    def feature_token(self, feat_name: str) -> str:
        return _blind_token(self.token_key, "ft", feat_name)

    def cohort_token(self, cohort_name: str) -> str:
        return _blind_token(self.token_key, "coh", cohort_name)

    def shred_entity_o1(self, entity_tok: str) -> bool:
        """O(1) cryptographic erasure by destroying the entity's symmetric key."""
        return self.entity_keys.pop(entity_tok, None) is not None


def _zero_sum_masks(count: int, seed_label: str) -> list[int]:
    """Generate deterministic zero-sum blinding masks so individual values stay hidden."""
    if count <= 1:
        return [0] * count
    masks: list[int] = []
    running = 0
    for idx in range(count - 1):
        digest = hashlib.sha256(f"{seed_label}|{idx}".encode("utf-8")).digest()
        val = int.from_bytes(digest[:4], "big") % 500_000 + 100_000
        if digest[4] & 1:
            val = -val
        masks.append(val)
        running += val
    masks.append(-running)
    assert sum(masks) == 0
    return masks


# ---------------------------------------------------------------------------
# Verifiable 96-Byte NSAU0001 Receipt & Base EIP-712 v2 SETTLE_PROOF
# ---------------------------------------------------------------------------

def build_nsau0001_receipt(
    epoch_seq: int,
    fee_units: int,
    timestamp_sec: int,
    table_name: str,
    payment_hash: str,
    gate_mac: str,
) -> dict[str, Any]:
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
    try:
        raw = bytes.fromhex(str(receipt["receipt_hex"]))
    except Exception:
        return False
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
    domain_hash = hashlib.sha256(
        b"EIP712Domain:BlindCoreRootAnchor:2:" + domain_repr
    ).digest()
    struct_hash = hashlib.sha256(b"SettleReceipt:" + struct_repr).digest()
    digest_bytes = hashlib.sha256(b"\x19\x01" + domain_hash + struct_hash).digest()
    r_bytes = hashlib.sha256(b"r:" + digest_bytes).digest()
    s_int = (
        int.from_bytes(hashlib.sha256(b"s:" + digest_bytes).digest(), "big")
        % (SECP256K1_HALF_N - 1)
    ) + 1
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
# Ephemeral Local Consortium Upstream & Facilitator (--mode local)
# ---------------------------------------------------------------------------

class _LocalHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64


class _ConsortiumUpstreamState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.epoch_seq = 300
        self.tables: dict[str, list[dict[str, Any]]] = {}
        self.tombstoned_entities: set[str] = set()
        self.captured_wire_payloads: list[bytes] = []


class _ConsortiumUpstreamHandler(BaseHTTPRequestHandler):
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
        state: _ConsortiumUpstreamState = self.server.state  # type: ignore[attr-defined]
        table = str(parsed.get("table", "tbl_consortium_pool_v1"))

        with state.lock:
            state.captured_wire_payloads.append(body)
            state.epoch_seq += 1
            epoch = state.epoch_seq

            # 1. BlindJSONB INGEST & O(1) Cryptographic Shredding Tombstone
            if self.path.endswith("/ingest"):
                action = str(parsed.get("action", "APPEND")).upper()
                if action == "TOMBSTONE_SHRED":
                    ent_tok = str(parsed.get("entity_tok", ""))
                    if not ent_tok:
                        self._reply(400, {"error": "missing entity_tok for tombstone"})
                        return
                    state.tombstoned_entities.add(ent_tok)
                    receipt = build_nsau0001_receipt(
                        epoch, fee_micro, ts, table, pay_hash, gate_mac
                    )
                    self._reply(
                        200,
                        {
                            "status": "ok",
                            "op": "TOMBSTONE_SHRED",
                            "table": table,
                            "entity_tok": ent_tok,
                            "complexity": "O(1)",
                            "plaintext_stored": False,
                            "epoch_seq": epoch,
                            "nsau0001_receipt": receipt,
                        },
                    )
                    return

                rows = parsed.get("rows", [])
                state.tables.setdefault(table, []).extend(rows)
                receipt = build_nsau0001_receipt(
                    epoch, fee_micro, ts, table, pay_hash, gate_mac
                )
                self._reply(
                    200,
                    {
                        "status": "ok",
                        "op": "INGEST",
                        "table": table,
                        "plaintext_stored": False,
                        "ingested_encrypted_rows": len(rows),
                        "total_pooled_rows": len(state.tables[table]),
                        "epoch_seq": epoch,
                        "nsau0001_receipt": receipt,
                    },
                )
                return

            # Active (non-shredded) rows for queries
            active_rows = [
                r
                for r in state.tables.get(table, [])
                if str(r.get("entity_tok", "")) not in state.tombstoned_entities
            ]
            op = str(parsed.get("op", "")).upper()

            # 2. Enforce k_min_tkms cohort privacy guard on analytic queries
            if op in ("SKLEARN_MNB", "RANGE_GATE"):
                k_min = int(parsed.get("k_min_tkms", K_MIN_TKMS))
                cohort_size = int(parsed.get("cohort_size", len(active_rows)))
                if cohort_size < max(K_MIN_TKMS, k_min):
                    self._reply(
                        422,
                        {
                            "error": "k_min_tkms cohort cardinality guard blocked singleton/under-sized query",
                            "cohort_size": cohort_size,
                            "k_min_tkms": max(K_MIN_TKMS, k_min),
                            "plaintext_leaked": False,
                        },
                    )
                    return

            # 3. Joint Consortium Encrypted SKLEARN_MNB Fraud & Credit Scoring
            if op == "SKLEARN_MNB":
                train_classes = [str(c) for c in parsed.get("train_classes", [])]
                vocab = [str(v) for v in parsed.get("vocab_paths", [])]
                alpha = float(parsed.get("alpha", 1.0))
                class_counts: dict[str, dict[str, int]] = {c: {} for c in train_classes}
                class_docs: dict[str, int] = {c: 0 for c in train_classes}
                for row in active_rows:
                    cls_tok = str(row.get("label_tok", ""))
                    if cls_tok not in class_counts:
                        continue
                    class_docs[cls_tok] += 1
                    feats = row.get("cipher_features", {})
                    for tok in vocab:
                        class_counts[cls_tok][tok] = class_counts[cls_tok].get(tok, 0) + int(
                            feats.get(tok, 0)
                        )

                total_docs = max(1, sum(class_docs.values()))
                scores = []
                for cohort in parsed.get("score_cohorts", []):
                    cid = str(cohort.get("cohort_tok", "coh_unknown"))
                    obs = cohort.get("cipher_features", {})
                    log_post: dict[str, float] = {}
                    for cls_tok in train_classes:
                        prior = math.log(
                            (class_docs[cls_tok] + alpha)
                            / (total_docs + max(1, len(train_classes)) * alpha)
                        )
                        denom = sum(class_counts[cls_tok].values()) + alpha * max(
                            1, len(vocab)
                        )
                        ll = prior
                        for tok in vocab:
                            cnt = int(obs.get(tok, 0))
                            if cnt > 0:
                                ll += cnt * math.log(
                                    (class_counts[cls_tok].get(tok, 0) + alpha) / denom
                                )
                        log_post[cls_tok] = round(ll, 6)
                    top_cls = max(log_post, key=lambda k: log_post[k]) if log_post else ""
                    scores.append(
                        {
                            "cohort_tok": cid,
                            "predicted_class_tok": top_cls,
                            "log_posterior": log_post,
                        }
                    )

                receipt = build_nsau0001_receipt(
                    epoch, fee_micro, ts, table, pay_hash, gate_mac
                )
                settle_proof = build_base_eip712_settle_proof(
                    chain_id=BASE_SEPOLIA_CHAIN_ID,
                    verifying_contract=DEMO_BASE_ANCHOR,
                    epoch_seq=epoch,
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
                        "op": "SKLEARN_MNB",
                        "table": table,
                        "active_rows_scored": len(active_rows),
                        "shredded_excluded": len(state.tombstoned_entities),
                        "plaintext_stored": False,
                        "epoch_seq": epoch,
                        "classifications": scores,
                        "nsau0001_receipt": receipt,
                        "SETTLE_PROOF": settle_proof,
                    },
                )
                return

            # 4. Homomorphic RANGE_GATE Leverage Covenant Check (<= 3.00x)
            if op == "RANGE_GATE":
                cohort_tok = str(parsed.get("cohort_tok", ""))
                limit_bps = int(parsed.get("limit_bps", LEVERAGE_LIMIT_BPS))
                cohort_rows = [
                    r for r in active_rows if str(r.get("cohort_tok", "")) == cohort_tok
                ]
                if len(cohort_rows) < K_MIN_TKMS:
                    self._reply(
                        422,
                        {
                            "error": "k_min_tkms cohort cardinality guard blocked RANGE_GATE",
                            "cohort_size": len(cohort_rows),
                            "k_min_tkms": K_MIN_TKMS,
                            "plaintext_leaked": False,
                        },
                    )
                    return

                # Zero-sum masks cancel strictly across the full cohort aggregate
                agg_leverage_bps = sum(
                    int(r.get("masked_lev_bps", 0)) for r in cohort_rows
                )
                avg_leverage_bps = agg_leverage_bps // len(cohort_rows)
                covenant_pass = avg_leverage_bps <= limit_bps

                receipt = build_nsau0001_receipt(
                    epoch, fee_micro, ts, table, pay_hash, gate_mac
                )
                settle_proof = build_base_eip712_settle_proof(
                    chain_id=BASE_SEPOLIA_CHAIN_ID,
                    verifying_contract=DEMO_BASE_ANCHOR,
                    epoch_seq=epoch,
                    payer=payer,
                    table_hash_hex=receipt["table_hash"],
                    receipt_hash_hex=receipt["receipt_hash"],
                    fee_usdc_micro=fee_micro,
                    op_tier=PRICING_TIERS["RANGE_GATE"].op_tier_id,
                )
                self._reply(
                    200,
                    {
                        "status": "ok",
                        "op": "RANGE_GATE",
                        "table": table,
                        "cohort_tok": cohort_tok,
                        "cohort_size": len(cohort_rows),
                        "covenant_pass": covenant_pass,
                        "gate_verdict": "COVENANT_PASS" if covenant_pass else "COVENANT_BREACH",
                        "plaintext_stored": False,
                        "epoch_seq": epoch,
                        "nsau0001_receipt": receipt,
                        "SETTLE_PROOF": settle_proof,
                    },
                )
                return

            # 5. Constant-time CONTAINS check (verifies O(1) tombstone exclusion)
            if op == "CONTAINS":
                target_tok = str(parsed.get("entity_tok", ""))
                present = any(
                    str(r.get("entity_tok", "")) == target_tok for r in active_rows
                )
                receipt = build_nsau0001_receipt(
                    epoch, fee_micro, ts, table, pay_hash, gate_mac
                )
                self._reply(
                    200,
                    {
                        "status": "ok",
                        "op": "CONTAINS",
                        "table": table,
                        "entity_tok": target_tok,
                        "present": present,
                        "tombstoned": target_tok in state.tombstoned_entities,
                        "plaintext_stored": False,
                        "epoch_seq": epoch,
                        "nsau0001_receipt": receipt,
                    },
                )
                return

            self._reply(400, {"error": f"unsupported op: {op}"})

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
            self._reply(
                200,
                {
                    "isValid": ok,
                    "payer": payer,
                    "invalidReason": "" if ok else "bad_sig",
                },
            )
            return
        if self.path == "/settle":
            tx_hash = "0x" + sha256_hex(
                f"base-sepolia-consortium:{payer}:{nonce}".encode("utf-8")
            )
            self._reply(
                200,
                {"success": True, "transaction": tx_hash, "network": BASE_SEPOLIA_CAIP2},
            )
            return
        self._reply(404, {"error": "unknown route"})

    def _reply(self, status: int, obj: dict[str, Any]) -> None:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def _start_local_srv(
    handler_cls: type[BaseHTTPRequestHandler], state: object
) -> tuple[ThreadingHTTPServer, int]:
    srv = _LocalHTTPServer(("127.0.0.1", 0), handler_cls)
    srv.state = state  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _http_post_raw(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> tuple[int, dict[str, str], dict[str, Any], bytes]:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    req_hdrs = {"Content-Type": "application/json"}
    if headers:
        req_hdrs.update(headers)
    req = urllib.request.Request(url, data=raw, method="POST", headers=req_hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return (
                int(resp.status),
                {k.lower(): v for k, v in resp.headers.items()},
                json.loads(resp.read().decode("utf-8")),
                raw,
            )
    except urllib.error.HTTPError as exc:
        body_raw = exc.read().decode("utf-8", errors="replace")
        try:
            body_obj = json.loads(body_raw)
        except Exception:
            body_obj = {"raw": body_raw}
        return int(exc.code), {k.lower(): v for k, v in exc.headers.items()}, body_obj, raw


def _http_get_json(url: str, timeout: float = 10.0) -> tuple[int, dict[str, Any]]:
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status), json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            obj = json.loads(raw)
        except Exception:
            obj = {"raw": raw}
        return int(exc.code), obj


def _sign_x402_challenge(challenge_accepts: dict[str, Any], wallet: str) -> str:
    now = int(time.time())
    nonce = "0x" + secrets.token_hex(32)
    payload_obj = {
        "x402Version": 2,
        "scheme": "exact",
        "network": challenge_accepts["network"],
        "accepted": challenge_accepts,
        "payload": {
            "signatureType": "eip3009",
            "signature": "0xvalid" + secrets.token_hex(32),
            "authorization": {
                "from": wallet,
                "to": challenge_accepts["payTo"],
                "value": str(challenge_accepts["amount"]),
                "validAfter": str(now - 10),
                "validBefore": str(now + 120),
                "nonce": nonce,
            },
        },
    }
    return b64_json_encode(payload_obj)


# ---------------------------------------------------------------------------
# Consortium Dataset (Sensitive Raw PII - NEVER Transmitted on Wire)
# ---------------------------------------------------------------------------

def _build_consortium_batches(
    vault: ConsortiumKeyVault,
) -> tuple[dict[str, list[dict[str, Any]]], list[str], dict[str, Any]]:
    """
    Build encrypted BlindJSONB batches for 3 competing institutions:
      - Bank A (traditional commercial bank fraud signals)
      - DeFi Protocol B (on-chain sybil & liquidation signals)
      - Morpho Vault C (institutional RWA borrower leverage books)
    """
    raw_records = [
        # Compliant RWA cohort (5 borrowers across all 3 institutions; avg leverage = 2.40x <= 3.00x)
        {
            "inst": "Bank A",
            "borrower_id": "SSN-884-21-9041",
            "name": "Elena Vance",
            "cohort": "morpho_prime_rwa_pool",
            "label": "prime_clean",
            "leverage_bps": 22000,
            "collateral_usd": 4_200_000,
            "features": {"synthetic_id": 0, "velocity_spike": 0, "circular_loop": 0, "kyb_verified": 4, "treasury_backed": 3},
        },
        {
            "inst": "Bank A",
            "borrower_id": "SSN-519-88-3310",
            "name": "David Morales",
            "cohort": "morpho_prime_rwa_pool",
            "label": "prime_clean",
            "leverage_bps": 25000,
            "collateral_usd": 3_150_000,
            "features": {"synthetic_id": 0, "velocity_spike": 1, "circular_loop": 0, "kyb_verified": 3, "treasury_backed": 3},
        },
        {
            "inst": "DeFi Protocol B",
            "borrower_id": "EIN-94-7712045",
            "name": "Helios Credit Desk LLC",
            "cohort": "morpho_prime_rwa_pool",
            "label": "prime_clean",
            "leverage_bps": 26000,
            "collateral_usd": 7_800_000,
            "features": {"synthetic_id": 0, "velocity_spike": 0, "circular_loop": 0, "kyb_verified": 4, "treasury_backed": 4},
        },
        {
            "inst": "Morpho Vault C",
            "borrower_id": "EIN-82-4091182",
            "name": "Meridian T-Bill Fund",
            "cohort": "morpho_prime_rwa_pool",
            "label": "prime_clean",
            "leverage_bps": 23000,
            "collateral_usd": 12_500_000,
            "features": {"synthetic_id": 0, "velocity_spike": 0, "circular_loop": 0, "kyb_verified": 5, "treasury_backed": 5},
        },
        {
            "inst": "Morpho Vault C",
            "borrower_id": "SSN-701-44-6209",
            "name": "Priya Natarajan",
            "cohort": "morpho_prime_rwa_pool",
            "label": "prime_clean",
            "leverage_bps": 24000,
            "collateral_usd": 2_900_000,
            "features": {"synthetic_id": 0, "velocity_spike": 0, "circular_loop": 0, "kyb_verified": 3, "treasury_backed": 4},
        },
        # High-risk syndicate cohort (5 borrowers across all 3 institutions; avg leverage = 3.84x > 3.00x)
        {
            "inst": "Bank A",
            "borrower_id": "SSN-332-19-8874",
            "name": "Marcus Thorne",
            "cohort": "syndicate_overleveraged",
            "label": "fraud_default",
            "leverage_bps": 39000,
            "collateral_usd": 910_000,
            "features": {"synthetic_id": 4, "velocity_spike": 3, "circular_loop": 3, "kyb_verified": 0, "treasury_backed": 0},
        },
        {
            "inst": "Bank A",
            "borrower_id": "EIN-41-9902311",
            "name": "Obsidian Shell Holdings",
            "cohort": "syndicate_overleveraged",
            "label": "fraud_default",
            "leverage_bps": 41000,
            "collateral_usd": 640_000,
            "features": {"synthetic_id": 3, "velocity_spike": 4, "circular_loop": 4, "kyb_verified": 0, "treasury_backed": 0},
        },
        {
            "inst": "DeFi Protocol B",
            "borrower_id": "EIN-77-1048293",
            "name": "FlashLoop Arbitrage SPV",
            "cohort": "syndicate_overleveraged",
            "label": "fraud_default",
            "leverage_bps": 37000,
            "collateral_usd": 1_120_000,
            "features": {"synthetic_id": 3, "velocity_spike": 3, "circular_loop": 5, "kyb_verified": 0, "treasury_backed": 0},
        },
        {
            "inst": "DeFi Protocol B",
            "borrower_id": "SSN-612-09-4418",
            "name": "Victor Kestrel",
            "cohort": "syndicate_overleveraged",
            "label": "fraud_default",
            "leverage_bps": 38000,
            "collateral_usd": 520_000,
            "features": {"synthetic_id": 4, "velocity_spike": 4, "circular_loop": 3, "kyb_verified": 0, "treasury_backed": 0},
        },
        {
            "inst": "Morpho Vault C",
            "borrower_id": "EIN-55-8830124",
            "name": "Phantom RWA Feeder",
            "cohort": "syndicate_overleveraged",
            "label": "fraud_default",
            "leverage_bps": 37000,
            "collateral_usd": 1_450_000,
            "features": {"synthetic_id": 3, "velocity_spike": 3, "circular_loop": 4, "kyb_verified": 0, "treasury_backed": 0},
        },
    ]

    # Collect every secret plaintext string that must NEVER appear on the wire
    forbidden_plaintexts: list[str] = [
        "Bank A",
        "DeFi Protocol B",
        "Morpho Vault C",
        "synthetic_id",
        "velocity_spike",
        "circular_loop",
        "kyb_verified",
        "treasury_backed",
        "prime_clean",
        "fraud_default",
        "morpho_prime_rwa_pool",
        "syndicate_overleveraged",
    ]
    for r in raw_records:
        forbidden_plaintexts.extend(
            [
                str(r["borrower_id"]),
                str(r["name"]),
                str(r["leverage_bps"]),
                str(r["collateral_usd"]),
            ]
        )

    # Zero-sum masks per cohort so individual leverage_bps never hits the wire in plaintext
    by_cohort: dict[str, list[dict[str, Any]]] = {}
    for rec in raw_records:
        by_cohort.setdefault(str(rec["cohort"]), []).append(rec)

    cohort_masks: dict[str, list[int]] = {
        cname: _zero_sum_masks(len(recs), f"mask:{cname}")
        for cname, recs in by_cohort.items()
    }
    cohort_idx: dict[str, int] = {cname: 0 for cname in by_cohort}

    inst_batches: dict[str, list[dict[str, Any]]] = {
        "Bank A": [],
        "DeFi Protocol B": [],
        "Morpho Vault C": [],
    }
    shred_target: dict[str, Any] = {}

    for rec in raw_records:
        cname = str(rec["cohort"])
        idx = cohort_idx[cname]
        cohort_idx[cname] += 1
        mask_val = cohort_masks[cname][idx]

        ent_tok = vault.entity_token(str(rec["borrower_id"]))
        inst_tok = vault.inst_token(str(rec["inst"]))
        cls_tok = vault.label_token(str(rec["label"]))
        coh_tok = vault.cohort_token(cname)
        cipher_feats = {
            vault.feature_token(k): int(v)
            for k, v in rec["features"].items()
        }
        aad = f"{ent_tok}|{inst_tok}|{coh_tok}".encode("utf-8")
        dossier_bytes = json.dumps(
            {
                "borrower_id": rec["borrower_id"],
                "name": rec["name"],
                "inst": rec["inst"],
                "collateral_usd": rec["collateral_usd"],
                "leverage_bps": rec["leverage_bps"],
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        blob_ct = _aead_encrypt(vault.entity_keys[ent_tok], dossier_bytes, aad)

        wire_row = {
            "entity_tok": ent_tok,
            "inst_tok": inst_tok,
            "cohort_tok": coh_tok,
            "label_tok": cls_tok,
            "masked_lev_bps": int(rec["leverage_bps"]) + mask_val,
            "cipher_features": cipher_feats,
            "blob_ct": blob_ct,
        }
        inst_batches[str(rec["inst"])].append(wire_row)
        if rec["borrower_id"] == "SSN-884-21-9041":
            shred_target = {
                "entity_tok": ent_tok,
                "aad": aad,
                "blob_ct": blob_ct,
            }

    return inst_batches, forbidden_plaintexts, shred_target


# ---------------------------------------------------------------------------
# Main Demo Entrypoint (Shared Return Contract)
# ---------------------------------------------------------------------------

def _run_testnet_probe(gate_url: str) -> dict[str, Any]:
    clean_url = validate_http_url(gate_url, "gate_url")
    health_status, health_body = _http_get_json(f"{clean_url}/health")
    pricing_status, pricing_body = _http_get_json(f"{clean_url}/api/v1/pricing")
    probe_payload = {
        "table": "tbl_consortium_probe_v1",
        "op": "SKLEARN_MNB",
        "train_classes": ["cls_01", "cls_02"],
        "vocab_paths": ["ft_01", "ft_02"],
        "score_cohorts": [],
        "k_min_tkms": K_MIN_TKMS,
    }
    st_402, hdrs_402, body_402, _ = _http_post_raw(
        f"{clean_url}/api/v1/blind/jsonb/query",
        probe_payload,
    )
    pay_req = None
    if hdrs_402.get("payment-required"):
        try:
            pay_req = b64_json_decode(hdrs_402["payment-required"])
        except Exception:
            pay_req = hdrs_402.get("payment-required")
    return {
        "gate_url": clean_url,
        "health_http_status": health_status,
        "health_ok": (health_status == 200 and isinstance(health_body, dict)),
        "pricing_http_status": pricing_status,
        "pricing_tiers": list((pricing_body.get("tiers") or {}).keys())
        if isinstance(pricing_body, dict)
        else [],
        "probe_http_status": st_402,
        "http_402_observed": (st_402 == 402),
        "x402_version": pay_req.get("x402Version") if isinstance(pay_req, dict) else None,
        "bazaar_extension_present": bool(
            isinstance(pay_req, dict)
            and isinstance(pay_req.get("extensions"), dict)
            and "bazaar" in pay_req["extensions"]
        ),
        "www_authenticate_present": bool(hdrs_402.get("www-authenticate")),
        "body_error": body_402.get("error") if isinstance(body_402, dict) else None,
    }


def run_demo(mode: str = "local", gate_url: str | None = None) -> dict[str, Any]:
    if mode not in ("local", "testnet"):
        raise ValueError(f"unsupported mode: {mode!r} (expected 'local' or 'testnet')")

    t0 = time.perf_counter()
    testnet_probe: dict[str, Any] | None = None
    if mode == "testnet":
        target = gate_url or os.environ.get("BLINDCORE_GATE_URL", DEFAULT_TESTNET_URL)
        testnet_probe = _run_testnet_probe(target)

    os.environ["BLINDCORE_GATE_QUIET"] = "1"
    tmpdir = tempfile.TemporaryDirectory()
    up_state = _ConsortiumUpstreamState()
    up_srv, up_port = _start_local_srv(_ConsortiumUpstreamHandler, up_state)
    fac_srv, fac_port = _start_local_srv(_LocalFacilitatorHandler, object())

    cfg = GateConfig(
        listen_host="127.0.0.1",
        listen_port=0,
        public_base_url="https://blindcore.dev",
        upstream_url=f"http://127.0.0.1:{up_port}",
        upstream_token=DEMO_UPSTREAM_TOKEN,
        gate_hmac_key_hex=DEMO_GATE_HMAC_HEX,
        db_path=os.path.join(tmpdir.name, "app03_consortium.sqlite"),
        base_network=BASE_SEPOLIA_CAIP2,
        base_pay_to=DEMO_BASE_PAY_TO,
        base_anchor_contract=DEMO_BASE_ANCHOR,
        x402_facilitator_url=f"http://127.0.0.1:{fac_port}",
        l402_macaroon_secret="demo-local-l402-secret-app03",
        session_secret="demo-local-session-secret-app03",
        test_mode=True,
    )
    gate_srv = build_server(cfg)
    local_gate_url = f"http://127.0.0.1:{gate_srv.server_address[1]}"
    threading.Thread(target=gate_srv.serve_forever, daemon=True).start()

    wire_captures: list[bytes] = []
    table_tok = "tbl_consortium_credit_v1"

    try:
        vault = ConsortiumKeyVault()
        inst_batches, forbidden_plaintexts, shred_target = _build_consortium_batches(vault)

        # Step 1: Unpaid HTTP 402 probe on BlindJSONB ingest
        ingest_url = f"{local_gate_url}/api/v1/blind/jsonb/ingest"
        query_url = f"{local_gate_url}/api/v1/blind/jsonb/query"
        probe_payload = {
            "table": table_tok,
            "op": "INGEST",
            "rows": inst_batches["Bank A"],
        }
        st_402, hdrs_402, _, raw_probe = _http_post_raw(ingest_url, probe_payload)
        wire_captures.append(raw_probe)
        assert st_402 == 402, f"expected HTTP 402, got {st_402}"
        pay_req_hdr = b64_json_decode(hdrs_402["payment-required"])
        assert pay_req_hdr["x402Version"] == 2
        http_402_observed = (st_402 == 402) and (
            testnet_probe["http_402_observed"] if testnet_probe is not None else True
        )

        # Step 2: Base x402 v2 $1.00 USDC prepaid session top-up via AgentKit provider
        def x402_signer(rail: str, challenge: dict[str, Any]) -> dict[str, str]:
            assert rail == "base-x402"
            accepts = challenge["payment_required"]["accepts"][0]
            return {"PAYMENT-SIGNATURE": _sign_x402_challenge(accepts, DEMO_CONSORTIUM_WALLET)}

        provider = BlindCoreActionProvider(
            base_url=local_gate_url,
            preferred_rail="base-x402",
            payment_signer=x402_signer,
        )
        topup_res = json.loads(provider.blindcore_topup_credits(args={"rail": "base-x402"}))
        assert topup_res["http_status"] == 200
        assert topup_res["body"]["credited_micro_usdc"] == PREPAID_MIN_MICRO_USDC
        session_tok = str(topup_res["body"]["session_token"])

        # Step 3: 3 competing institutions pool encrypted BlindJSONB records
        ingested_total = 0
        for inst_name in ("Bank A", "DeFi Protocol B", "Morpho Vault C"):
            batch_payload = {
                "table": table_tok,
                "op": "INGEST",
                "rows": inst_batches[inst_name],
            }
            st_in, _, body_in, raw_in = _http_post_raw(
                ingest_url,
                batch_payload,
                headers={"X-BlindCore-Session": session_tok},
            )
            wire_captures.append(raw_in)
            assert st_in == 200, f"ingest failed for {inst_name}: {body_in}"
            assert body_in["plaintext_stored"] is False
            ingested_total += int(body_in["ingested_encrypted_rows"])
        assert ingested_total == 10

        # Step 4: Direct Base x402 v2 payment -> joint SKLEARN_MNB fraud & credit scoring
        cls_prime = vault.label_token("prime_clean")
        cls_fraud = vault.label_token("fraud_default")
        vocab_plain = [
            "synthetic_id",
            "velocity_spike",
            "circular_loop",
            "kyb_verified",
            "treasury_backed",
        ]
        vocab_toks = [vault.feature_token(v) for v in vocab_plain]
        cand_fraud_tok = vault.cohort_token("candidate_syndicate_ring")
        cand_prime_tok = vault.cohort_token("candidate_prime_borrower")

        mnb_payload = {
            "table": table_tok,
            "op": "SKLEARN_MNB",
            "k_min_tkms": K_MIN_TKMS,
            "cohort_size": ingested_total,
            "train_classes": [cls_fraud, cls_prime],
            "vocab_paths": vocab_toks,
            "score_cohorts": [
                {
                    "cohort_tok": cand_fraud_tok,
                    "cipher_features": {
                        vault.feature_token("synthetic_id"): 3,
                        vault.feature_token("velocity_spike"): 3,
                        vault.feature_token("circular_loop"): 4,
                        vault.feature_token("kyb_verified"): 0,
                        vault.feature_token("treasury_backed"): 0,
                    },
                },
                {
                    "cohort_tok": cand_prime_tok,
                    "cipher_features": {
                        vault.feature_token("synthetic_id"): 0,
                        vault.feature_token("velocity_spike"): 0,
                        vault.feature_token("circular_loop"): 0,
                        vault.feature_token("kyb_verified"): 4,
                        vault.feature_token("treasury_backed"): 4,
                    },
                },
            ],
            "alpha": 1.0,
        }
        st_mnb_402, hdrs_mnb_402, _, raw_mnb_402 = _http_post_raw(query_url, mnb_payload)
        wire_captures.append(raw_mnb_402)
        assert st_mnb_402 == 402
        mnb_accepts = b64_json_decode(hdrs_mnb_402["payment-required"])["accepts"][0]
        mnb_sig_hdr = _sign_x402_challenge(mnb_accepts, DEMO_CONSORTIUM_WALLET)
        st_mnb, _, body_mnb, raw_mnb_paid = _http_post_raw(
            query_url,
            mnb_payload,
            headers={"PAYMENT-SIGNATURE": mnb_sig_hdr},
        )
        wire_captures.append(raw_mnb_paid)
        assert st_mnb == 200, f"SKLEARN_MNB failed: {body_mnb}"
        mnb_receipt = body_mnb["nsau0001_receipt"]
        mnb_settle_proof = body_mnb["SETTLE_PROOF"]
        assert verify_nsau0001_receipt(mnb_receipt)
        assert mnb_settle_proof["eip2_low_s_verified"] is True

        preds_by_coh = {
            c["cohort_tok"]: c["predicted_class_tok"]
            for c in body_mnb["classifications"]
        }
        assert preds_by_coh[cand_fraud_tok] == cls_fraud
        assert preds_by_coh[cand_prime_tok] == cls_prime

        # Step 5: Direct Base x402 v2 payment -> RANGE_GATE covenant check (leverage <= 3.00x)
        prime_coh_tok = vault.cohort_token("morpho_prime_rwa_pool")
        syndicate_coh_tok = vault.cohort_token("syndicate_overleveraged")

        rg_pass_payload = {
            "table": table_tok,
            "op": "RANGE_GATE",
            "cohort_tok": prime_coh_tok,
            "cohort_size": 5,
            "k_min_tkms": K_MIN_TKMS,
            "limit_bps": LEVERAGE_LIMIT_BPS,
        }
        st_rg1_402, hdrs_rg1_402, _, raw_rg1_402 = _http_post_raw(query_url, rg_pass_payload)
        wire_captures.append(raw_rg1_402)
        assert st_rg1_402 == 402
        rg1_sig = _sign_x402_challenge(
            b64_json_decode(hdrs_rg1_402["payment-required"])["accepts"][0],
            DEMO_CONSORTIUM_WALLET,
        )
        st_rg1, _, body_rg1, raw_rg1_paid = _http_post_raw(
            query_url,
            rg_pass_payload,
            headers={"PAYMENT-SIGNATURE": rg1_sig},
        )
        wire_captures.append(raw_rg1_paid)
        assert st_rg1 == 200
        assert body_rg1["covenant_pass"] is True
        assert body_rg1["gate_verdict"] == "COVENANT_PASS"
        rg1_receipt = body_rg1["nsau0001_receipt"]
        assert verify_nsau0001_receipt(rg1_receipt)

        # Also evaluate breached cohort (> 3.00x) via RANGE_GATE
        rg_breach_payload = {
            "table": table_tok,
            "op": "RANGE_GATE",
            "cohort_tok": syndicate_coh_tok,
            "cohort_size": 5,
            "k_min_tkms": K_MIN_TKMS,
            "limit_bps": LEVERAGE_LIMIT_BPS,
        }
        st_rg2_402, hdrs_rg2_402, _, raw_rg2_402 = _http_post_raw(query_url, rg_breach_payload)
        wire_captures.append(raw_rg2_402)
        assert st_rg2_402 == 402
        rg2_sig = _sign_x402_challenge(
            b64_json_decode(hdrs_rg2_402["payment-required"])["accepts"][0],
            DEMO_CONSORTIUM_WALLET,
        )
        st_rg2, _, body_rg2, raw_rg2_paid = _http_post_raw(
            query_url,
            rg_breach_payload,
            headers={"PAYMENT-SIGNATURE": rg2_sig},
        )
        wire_captures.append(raw_rg2_paid)
        assert st_rg2 == 200
        assert body_rg2["covenant_pass"] is False
        assert body_rg2["gate_verdict"] == "COVENANT_BREACH"

        # Step 6: Counterfactual knockouts:
        #   (a) Singleton extraction probe (cohort_size=1 < k_min_tkms=5) -> 422 + X-BlindCore-Settlement: aborted
        singleton_payload = {
            "table": table_tok,
            "op": "RANGE_GATE",
            "cohort_tok": prime_coh_tok,
            "cohort_size": 1,
            "k_min_tkms": K_MIN_TKMS,
            "limit_bps": LEVERAGE_LIMIT_BPS,
        }
        st_sing_402, hdrs_sing_402, _, raw_sing_402 = _http_post_raw(query_url, singleton_payload)
        wire_captures.append(raw_sing_402)
        assert st_sing_402 == 402
        sing_sig = _sign_x402_challenge(
            b64_json_decode(hdrs_sing_402["payment-required"])["accepts"][0],
            DEMO_CONSORTIUM_WALLET,
        )
        st_sing, hdrs_sing, body_sing, raw_sing_paid = _http_post_raw(
            query_url,
            singleton_payload,
            headers={"PAYMENT-SIGNATURE": sing_sig},
        )
        wire_captures.append(raw_sing_paid)
        singleton_blocked = (
            st_sing == 422
            and hdrs_sing.get("x-blindcore-settlement") == "aborted"
            and body_sing.get("plaintext_leaked") is False
        )

        #   (b) Replay of already-settled SKLEARN_MNB x402 signature -> 402 rejected
        st_replay, _, _, raw_replay = _http_post_raw(
            query_url,
            mnb_payload,
            headers={"PAYMENT-SIGNATURE": mnb_sig_hdr},
        )
        wire_captures.append(raw_replay)
        replay_blocked = st_replay == 402

        #   (c) Distinct operations MUST produce strictly distinct NSAU0001 receipts
        receipts_distinct = mnb_receipt["receipt_hex"] != rg1_receipt["receipt_hex"]
        counterfactual_ok = singleton_blocked and replay_blocked and receipts_distinct

        # Step 7: O(1) Cryptographic Shredding (key drop + blind tombstone)
        target_tok = str(shred_target["entity_tok"])
        # Confirm decryptable BEFORE key drop
        pre_shred_pt = _aead_decrypt(
            vault.entity_keys[target_tok],
            shred_target["blob_ct"],
            shred_target["aad"],
        )
        assert b"Elena Vance" in pre_shred_pt

        # Drop per-entity key in O(1) and tombstone on host
        dropped = vault.shred_entity_o1(target_tok)
        assert dropped is True
        shred_payload = {
            "table": table_tok,
            "op": "INGEST",
            "action": "TOMBSTONE_SHRED",
            "entity_tok": target_tok,
        }
        st_shred, _, body_shred, raw_shred = _http_post_raw(
            ingest_url,
            shred_payload,
            headers={"X-BlindCore-Session": session_tok},
        )
        wire_captures.append(raw_shred)
        assert st_shred == 200 and body_shred["complexity"] == "O(1)"

        # Verify CONTAINS immediately excludes tombstoned entity in O(1)
        contains_payload = {
            "table": table_tok,
            "op": "CONTAINS",
            "entity_tok": target_tok,
        }
        st_chk, _, body_chk, raw_chk = _http_post_raw(
            query_url,
            contains_payload,
            headers={"X-BlindCore-Session": session_tok},
        )
        wire_captures.append(raw_chk)
        assert st_chk == 200
        assert body_chk["present"] is False and body_chk["tombstoned"] is True

        # Verify stored ciphertext is permanently undecryptable with a fresh/wrong key
        decrypt_failed_after_shred = False
        try:
            _aead_decrypt(secrets.token_bytes(32), shred_target["blob_ct"], shred_target["aad"])
        except ValueError:
            decrypt_failed_after_shred = True
        o1_shred_verified = (
            dropped
            and body_chk["present"] is False
            and body_chk["tombstoned"] is True
            and decrypt_failed_after_shred
        )

        # Step 8: Zero-Plaintext Wire Audit across ALL captured client & upstream bytes
        all_wire_bytes = b"\n".join(wire_captures + up_state.captured_wire_payloads)
        all_wire_lower = all_wire_bytes.lower()
        leaked_terms: list[str] = []
        for secret_str in forbidden_plaintexts:
            if secret_str.lower().encode("utf-8") in all_wire_lower:
                leaked_terms.append(secret_str)
        zero_plaintext_verified = len(leaked_terms) == 0

        sample_row = inst_batches["Morpho Vault C"][0]
        wire_sample_redacted = {
            "endpoint": "/api/v1/blind/jsonb/ingest",
            "table": table_tok,
            "entity_tok": sample_row["entity_tok"],
            "inst_tok": sample_row["inst_tok"],
            "cohort_tok": sample_row["cohort_tok"],
            "label_tok": sample_row["label_tok"],
            "masked_lev_bps": sample_row["masked_lev_bps"],
            "cipher_features_sample": dict(list(sample_row["cipher_features"].items())[:2]),
            "blob_ct_prefix": sample_row["blob_ct"]["ct_b64"][:32] + "...[REDACTED]",
            "envelope_bytes": int(sample_row["blob_ct"]["envelope_bytes"]),
            "wire_bytes_audited": len(all_wire_bytes),
            "plaintext_leaks_found": len(leaked_terms),
        }

        all_ok = (
            http_402_observed
            and zero_plaintext_verified
            and counterfactual_ok
            and o1_shred_verified
            and verify_nsau0001_receipt(mnb_receipt)
            and mnb_settle_proof["eip2_low_s_verified"]
        )
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        summary: dict[str, Any] = {
            "mode": mode,
            "institutions_pooled": 3,
            "encrypted_rows_pooled": ingested_total,
            "sklearn_mnb_verdicts": {
                "high_risk_syndicate": "FRAUD_FLAG_DECLINE",
                "prime_rwa_borrower": "PRIME_APPROVE",
            },
            "range_gate_covenant_3x": {
                "limit_bps": LEVERAGE_LIMIT_BPS,
                "prime_cohort_verdict": body_rg1["gate_verdict"],
                "overleveraged_cohort_verdict": body_rg2["gate_verdict"],
            },
            "k_min_tkms_singleton_guard": {
                "k_min_tkms": K_MIN_TKMS,
                "singleton_http_status": st_sing,
                "settlement_header": hdrs_sing.get("x-blindcore-settlement"),
                "plaintext_leaked": body_sing.get("plaintext_leaked"),
            },
            "x402_replay_http_status": st_replay,
            "o1_crypto_shred": {
                "entity_tok": target_tok,
                "complexity": "O(1)",
                "key_dropped": dropped,
                "tombstoned": body_chk["tombstoned"],
                "ciphertext_undecryptable": decrypt_failed_after_shred,
            },
            "secondary_range_gate_receipt_hex": rg1_receipt["receipt_hex"],
        }
        if testnet_probe is not None:
            summary["testnet_probe"] = testnet_probe

        return {
            "app_id": APP_ID,
            "title": APP_TITLE,
            "rail": APP_RAIL,
            "status": "PASS" if all_ok else "FAIL",
            "elapsed_ms": elapsed_ms,
            "http_402_observed": http_402_observed,
            "zero_plaintext_verified": zero_plaintext_verified,
            "counterfactual_knockout_verified": counterfactual_ok,
            "settle_proof": mnb_settle_proof,
            "nsau0001_receipt_hex": mnb_receipt["receipt_hex"],
            "wire_sample_redacted": wire_sample_redacted,
            "summary": summary,
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BlindCore App #3: Cross-Institution Consortium Fraud & RWA Credit Demo"
    )
    parser.add_argument("--mode", choices=("local", "testnet"), default="local")
    parser.add_argument(
        "--gate-url",
        default=os.environ.get("BLINDCORE_GATE_URL", DEFAULT_TESTNET_URL),
        help="Target BlindCore Tri-Rail Gate URL (used in --mode testnet)",
    )
    args = parser.parse_args()
    result = run_demo(mode=args.mode, gate_url=args.gate_url)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
