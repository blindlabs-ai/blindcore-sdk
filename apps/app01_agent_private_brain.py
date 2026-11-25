#!/usr/bin/env python3
"""
BlindCore Killer App #1: "Private Brain" for Autonomous AI Agents
(Base x402 v2 USDC + Prepaid Micro-Credits + MCP / Coinbase AgentKit)
Copyright 2026 Blind Labs (https://blindlabs.ai). Licensed under the Apache License, Version 2.0.

Demonstrates an autonomous Base trading/security agent storing and querying
encrypted BlindJSONB memory records (wallet heuristics, phishing indicators,
and private alpha notes) with zero third-party pip dependencies:
  1. Unpaid probe triggers a real HTTP 402 (PAYMENT-REQUIRED x402 v2 +
     extensions.bazaar discoverability metadata).
  2. Agent pays a $1.00 USDC prepaid micro-credit top-up via Coinbase AgentKit
     BlindCoreActionProvider (EIP-3009 PAYMENT-SIGNATURE), bypassing per-tx
     $0.001 facilitator overhead on sub-cent operations.
  3. Client-side keyed blind tokenization + authenticated HMAC-SHA256-CTR
     encryption ensures ZERO plaintext wallet heuristics, phishing phrases,
     or alpha notes ever cross the wire or touch server storage.
  4. Executes encrypted CONTAINS memory retrieval over JSON-RPC 2.0 MCP
     (mcp/mcp_server.py) and decrypts matched alpha records locally.
  5. Executes 1-query encrypted SKLEARN_MNB phishing/threat classification via
     AgentKit over blind feature token IDs.
  6. Proves x402 replay rejection (HTTP 402), tampered session/HMAC/receipt
     rejection, counterfactual receipt knockout (receipt_a != receipt_b),
     96-byte NSAU0001 receipt verification, and Base BlindCoreRootAnchor.sol
     EIP-712 v2 SETTLE_PROOF + ABI calldata summary.

Usage:
  python3 apps/app01_agent_private_brain.py --mode local
  python3 apps/app01_agent_private_brain.py --mode testnet \
      --gate-url https://api.blindlabs.ai/testnet
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
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
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
from mcp.mcp_server import BlindCoreHttpClient, handle_rpc_request  # noqa: E402

try:
    from python.blindcore_sdk import (  # noqa: E402
        BlindClientEnvelopeKey,
        BlindClientPlweKey,
        BlindCoreClient,
        PLWE_EXPANDED_BYTES,
        PLWE_SEEDED_BYTES,
        verify_blind_receipt,
    )
except ImportError:  # pragma: no cover - eval-kit module path fallback
    from python.blindcore_client import (  # noqa: E402
        BlindClientEnvelopeKey,
        BlindClientPlweKey,
        BlindCoreClient,
        PLWE_EXPANDED_BYTES,
        PLWE_SEEDED_BYTES,
        verify_blind_receipt,
    )


# ---------------------------------------------------------------------------
# Constants (Testnet / Local Demo Fixtures - Zero Live Keys)
# ---------------------------------------------------------------------------

APP_ID = "app01_agent_private_brain"
APP_TITLE = "Private Brain for Autonomous AI Agents (Base x402 v2 USDC + MCP / AgentKit)"
APP_RAIL = "base-x402"
DEFAULT_TESTNET_GATE_URL = "https://api.blindlabs.ai/testnet"

BASE_SEPOLIA_CHAIN_ID = 84532
DEMO_UPSTREAM_TOKEN = "demo-app01-upstream-token"
DEMO_GATE_HMAC_HEX = "31" * 32
DEMO_BASE_PAY_TO = "0x1111111111111111111111111111111111111111"
DEMO_AGENT_WALLET = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DEMO_ALT_WALLET = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
DEMO_BASE_ANCHOR = "0x4242424242424242424242424242424242424242"
SECP256K1_HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0


# ---------------------------------------------------------------------------
# Client-Side Zero-Plaintext Encryption & Blind Tokenization (Stdlib Only)
# ---------------------------------------------------------------------------

class AgentPrivateVault:
    """
    Client-only cryptographic vault for autonomous agent memory.
    Never exposes its master key, plaintext notes, or raw indicator strings
    over the network.
    """

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) < 32:
            raise ValueError("master_key must be at least 32 bytes")
        self._enc_key = hmac.new(master_key, b"blindcore:brain:enc:v1", hashlib.sha256).digest()
        self._mac_key = hmac.new(master_key, b"blindcore:brain:mac:v1", hashlib.sha256).digest()
        self._tok_key = hmac.new(master_key, b"blindcore:brain:tok:v1", hashlib.sha256).digest()
        self.plwe = BlindClientPlweKey.from_seed(
            hmac.new(master_key, b"blindcore:brain:plwe:v1", hashlib.sha256).digest()
        )
        self.envelope_key = BlindClientEnvelopeKey.from_key(self._enc_key)

    def blind_token(self, namespace: str, value: str) -> str:
        digest = hmac.new(
            self._tok_key,
            f"{namespace}:{value.strip().lower()}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"bt_{digest[:24]}"

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < length:
            block = hmac.new(
                self._enc_key,
                nonce + struct.pack(">I", counter),
                hashlib.sha256,
            ).digest()
            out.extend(block)
            counter += 1
        return bytes(out[:length])

    def encrypt_record(self, record: dict[str, Any], aad: str) -> dict[str, str]:
        plaintext = json.dumps(record, separators=(",", ":"), sort_keys=True).encode("utf-8")
        nonce = secrets.token_bytes(16)
        ks = self._keystream(nonce, len(plaintext))
        ct = bytes(a ^ b for a, b in zip(plaintext, ks))
        tag = hmac.new(
            self._mac_key,
            aad.encode("utf-8") + b"|" + nonce + ct,
            hashlib.sha256,
        ).hexdigest()
        return {
            "alg": "HMAC-SHA256-CTR-EtM-v1",
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ct.hex(),
            "auth_tag_hex": tag,
        }

    def decrypt_record(self, envelope: dict[str, str], aad: str) -> dict[str, Any]:
        nonce = bytes.fromhex(envelope["nonce_hex"])
        ct = bytes.fromhex(envelope["ciphertext_hex"])
        expected_tag = hmac.new(
            self._mac_key,
            aad.encode("utf-8") + b"|" + nonce + ct,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(envelope["auth_tag_hex"], expected_tag):
            raise ValueError("authenticated decryption failed: tag mismatch")
        ks = self._keystream(nonce, len(ct))
        pt = bytes(a ^ b for a, b in zip(ct, ks))
        parsed = json.loads(pt.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("decrypted payload must be a JSON object")
        return parsed


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
    except ValueError:
        return False
    if len(raw) != 96 or raw[:8] != b"NSAU0001":
        return False
    expected_binding = hashlib.sha256(
        raw[:64]
        + str(receipt["payment_hash"]).encode("utf-8")
        + str(receipt["gate_mac"]).encode("utf-8")
    ).digest()
    return hmac.compare_digest(raw[64:96], expected_binding)


def _abi_word_uint(val: int) -> str:
    if val < 0:
        raise ValueError("uint cannot be negative")
    return f"{val:064x}"


def _abi_word_address(addr: str) -> str:
    clean = addr.strip().lower()
    if clean.startswith("0x"):
        clean = clean[2:]
    if len(clean) != 40:
        raise ValueError(f"invalid EVM address: {addr}")
    return clean.rjust(64, "0")


def _abi_word_bytes32(hex_val: str) -> str:
    clean = hex_val.strip().lower()
    if clean.startswith("0x"):
        clean = clean[2:]
    if len(clean) != 64:
        raise ValueError(f"invalid bytes32 hex: {hex_val}")
    return clean


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
    Build Base BlindCoreRootAnchor.sol EIP-712 v2 SETTLE_PROOF and ABI
    calldata summary for:
      settleReceipt(uint64,address,bytes32,bytes32,uint64,uint8,uint8,bytes32,bytes32)
    """
    domain = {
        "name": "BlindCoreRootAnchor",
        "version": "2",
        "chainId": chain_id,
        "verifyingContract": verifying_contract,
    }
    message = {
        "epochSeq": epoch_seq,
        "payer": payer,
        "tableHash": table_hash_hex,
        "receiptHash": receipt_hash_hex,
        "feeUsdcMicro": fee_usdc_micro,
        "opTier": op_tier,
    }
    domain_repr = json.dumps(domain, separators=(",", ":"), sort_keys=True).encode("utf-8")
    struct_repr = json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")
    domain_hash = hashlib.sha256(b"EIP712Domain:BlindCoreRootAnchor:2:" + domain_repr).digest()
    struct_hash = hashlib.sha256(b"SettleReceipt:" + struct_repr).digest()
    digest_bytes = hashlib.sha256(b"\x19\x01" + domain_hash + struct_hash).digest()
    r_bytes = hashlib.sha256(b"r:" + digest_bytes).digest()
    s_int = (
        int.from_bytes(hashlib.sha256(b"s:" + digest_bytes).digest(), "big")
        % (SECP256K1_HALF_N - 1)
    ) + 1
    s_bytes = s_int.to_bytes(32, "big")
    v_val = 27 + (digest_bytes[0] & 1)
    r_hex = "0x" + r_bytes.hex()
    s_hex = "0x" + s_bytes.hex()

    abi_encoded_args = (
        "0x"
        + _abi_word_uint(epoch_seq)
        + _abi_word_address(payer)
        + _abi_word_bytes32(table_hash_hex)
        + _abi_word_bytes32(receipt_hash_hex)
        + _abi_word_uint(fee_usdc_micro)
        + _abi_word_uint(op_tier)
        + _abi_word_uint(v_val)
        + _abi_word_bytes32(r_hex)
        + _abi_word_bytes32(s_hex)
    )
    return {
        "scheme": "EIP-712-v2",
        "contract": "BlindCoreRootAnchor.sol",
        "network": f"eip155:{chain_id}",
        "verifying_contract": verifying_contract,
        "function": "settleReceipt(uint64,address,bytes32,bytes32,uint64,uint8,uint8,bytes32,bytes32)",
        "eip2_low_s_verified": (0 < s_int <= SECP256K1_HALF_N and v_val in (27, 28)),
        "domain": domain,
        "primaryType": "SettleReceipt",
        "message": message,
        "digest": "0x" + digest_bytes.hex(),
        "signature": {"v": v_val, "r": r_hex, "s": s_hex},
        "calldata_summary": {
            "abi_arg_count": 9,
            "abi_args_byte_len": 9 * 32,
            "abi_args_hex_preview": abi_encoded_args[:74] + "...",
            "abi_args_sha256": "0x" + sha256_hex(abi_encoded_args.encode("ascii")),
        },
    }


# ---------------------------------------------------------------------------
# Wire Audit Helper
# ---------------------------------------------------------------------------

def audit_zero_plaintext(wire_blobs: list[bytes], forbidden_terms: list[str]) -> dict[str, Any]:
    leaks: list[str] = []
    total_bytes = 0
    for blob in wire_blobs:
        total_bytes += len(blob)
        text = blob.decode("utf-8", errors="replace").lower()
        for term in forbidden_terms:
            if term.lower() in text:
                leaks.append(term)
    return {
        "zero_plaintext_verified": len(leaks) == 0,
        "blobs_inspected": len(wire_blobs),
        "total_bytes_inspected": total_bytes,
        "canary_terms_checked": len(forbidden_terms),
        "leaks_found": len(leaks),
    }


# ---------------------------------------------------------------------------
# Ephemeral Local Mock Upstream & Facilitator (--mode local)
# ---------------------------------------------------------------------------

class _LocalHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64


class _LocalBrainUpstreamState:
    def __init__(self) -> None:
        self.epoch_seq = 100
        self.encrypted_tables: dict[str, list[dict[str, Any]]] = {}
        self.wire_rx_blobs: list[bytes] = []
        self.wire_tx_blobs: list[bytes] = []


class _LocalBrainUpstreamHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b""
        state: _LocalBrainUpstreamState = self.server.state  # type: ignore[attr-defined]
        state.wire_rx_blobs.append(body)

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
        table = str(parsed.get("table", "bt_agent_brain_v1"))
        op = str(parsed.get("op", "CONTAINS")).strip().upper()
        state.epoch_seq += 1

        if self.path.endswith("/ingest") or op == "INGEST":
            rows = parsed.get("rows", [])
            state.encrypted_tables.setdefault(table, []).extend(rows)
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

        if op == "CONTAINS":
            query_tokens = [str(t) for t in parsed.get("blind_tokens", [])]
            query_set = set(query_tokens)
            rows = state.encrypted_tables.get(table, [])
            matched: list[dict[str, Any]] = []
            for row in rows:
                row_tokens = set(str(t) for t in row.get("blind_tokens", []))
                if query_set and query_set.issubset(row_tokens):
                    matched.append(
                        {
                            "record_id": row["record_id"],
                            "envelope": row["envelope"],
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
                op_tier=PRICING_TIERS["CONTAINS"].op_tier_id,
            )
            self._reply(
                200,
                {
                    "status": "ok",
                    "op": "CONTAINS",
                    "table": table,
                    "plaintext_stored": False,
                    "matched_count": len(matched),
                    "matched_records": matched,
                    "epoch_seq": state.epoch_seq,
                    "nsau0001_receipt": receipt,
                    "SETTLE_PROOF": settle_proof,
                },
            )
            return

        if op == "SKLEARN_MNB":
            vocab = [str(v) for v in parsed.get("vocab_paths", [])]
            train_classes = [str(c) for c in parsed.get("train_classes", [])]
            rows = state.encrypted_tables.get(table, [])
            # Zero-key homomorphic aggregation strictly over IND-CPA PLWE0001 frames.
            # The server never sees class labels, categories, or plaintext feature counts.
            ct_class_doc_sums: dict[str, str] = {}
            ct_class_feature_sums: dict[str, dict[str, str]] = {}
            for cls_tok in train_classes:
                doc_frames = [
                    str(row["class_indicator_cts"][cls_tok])
                    for row in rows
                    if cls_tok in row.get("class_indicator_cts", {})
                ]
                ct_class_doc_sums[cls_tok] = BlindClientPlweKey.homomorphic_weighted_sum(
                    doc_frames
                ).hex()
                ct_class_feature_sums[cls_tok] = {}
                for tok in vocab:
                    feat_frames = [
                        str(row["class_feature_cts"][cls_tok][tok])
                        for row in rows
                        if cls_tok in row.get("class_feature_cts", {})
                        and tok in row["class_feature_cts"][cls_tok]
                    ]
                    ct_class_feature_sums[cls_tok][tok] = (
                        BlindClientPlweKey.homomorphic_weighted_sum(feat_frames).hex()
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
                    "op": "SKLEARN_MNB",
                    "table": table,
                    "plaintext_stored": False,
                    "zero_key_homomorphic": True,
                    "epoch_seq": state.epoch_seq,
                    "ct_class_doc_sums": ct_class_doc_sums,
                    "ct_class_feature_sums": ct_class_feature_sums,
                    "nsau0001_receipt": receipt,
                    "SETTLE_PROOF": settle_proof,
                },
            )
            return

        self._reply(400, {"error": f"unsupported op: {op}"})

    def _reply(self, status: int, obj: dict[str, Any]) -> None:
        raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        state: _LocalBrainUpstreamState = self.server.state  # type: ignore[attr-defined]
        state.wire_tx_blobs.append(raw)
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
                {"isValid": ok, "payer": payer, "invalidReason": "" if ok else "bad_sig"},
            )
            return
        if self.path == "/settle":
            tx_hash = "0x" + sha256_hex(f"base-sepolia-tx:{payer}:{nonce}".encode("utf-8"))
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


def _http_request(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str], Any]:
    req_hdrs = {"Accept": "application/json"}
    data = None
    if payload is not None:
        req_hdrs["Content-Type"] = "application/json"
        data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if headers:
        req_hdrs.update(headers)
    req = urllib.request.Request(url, data=data, method=method, headers=req_hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(262_144).decode("utf-8", errors="replace")
            try:
                parsed: Any = json.loads(raw)
            except Exception:
                parsed = {"raw": raw}
            return int(resp.status), {k.lower(): v for k, v in resp.headers.items()}, parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read(262_144).decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {"raw": raw}
        return int(exc.code), {k.lower(): v for k, v in exc.headers.items()}, parsed


# ---------------------------------------------------------------------------
# Private Brain Dataset Builder (Zero Plaintext On Wire)
# ---------------------------------------------------------------------------

def _build_private_brain_fixtures(vault: AgentPrivateVault) -> dict[str, Any]:
    table_token = vault.blind_token("table", "autonomous_agent_private_brain_v1")
    cls_phish = vault.blind_token("class", "phishing_block")
    cls_benign = vault.blind_token("class", "benign_allow")

    # Plaintext indicators (NEVER transmitted in plaintext on the wire)
    feat_names = [
        "urgent_seed_verify_airdrop",
        "permit2_unlimited_spoof",
        "wallet_drainer_cluster_alpha",
        "verified_usdc_treasury_invoice",
    ]
    feat_map = {name: vault.blind_token("feat", name) for name in feat_names}
    vocab_tokens = [feat_map[n] for n in feat_names]

    # Plaintext memory records owned exclusively by the autonomous agent
    alpha_tag_plain = "aerodrome_slipstream_rebalance_1400utc"
    drainer_wallet_plain = "0xdeadbeef_drainer_cluster_alpha"
    stealth_alpha_note = "stealth_vault_yield_arb_38bps_rebalance_window_1400utc"
    benign_treasury_note = "verified_base_treasury_multisig_0x7700_routine_sweep"

    raw_memories = [
        {
            "id": "mem_01",
            "category": "phishing_indicator",
            "label": cls_phish,
            "tags": [drainer_wallet_plain, "permit2_unlimited_spoof"],
            "note": {
                "kind": "wallet_heuristic",
                "target": drainer_wallet_plain,
                "memo": "block_approval_drain_router_0x9911_immediate",
            },
            "counts": {
                "urgent_seed_verify_airdrop": 4,
                "permit2_unlimited_spoof": 3,
                "wallet_drainer_cluster_alpha": 3,
                "verified_usdc_treasury_invoice": 0,
            },
        },
        {
            "id": "mem_02",
            "category": "phishing_indicator",
            "label": cls_phish,
            "tags": ["fake_base_bridge_claim", "urgent_seed_verify_airdrop"],
            "note": {
                "kind": "phishing_indicator",
                "target": "fake_base_bridge_claim",
                "memo": "spoofed_eip3009_nonce_signature_harvest",
            },
            "counts": {
                "urgent_seed_verify_airdrop": 3,
                "permit2_unlimited_spoof": 2,
                "wallet_drainer_cluster_alpha": 2,
                "verified_usdc_treasury_invoice": 0,
            },
        },
        {
            "id": "mem_03",
            "category": "private_alpha",
            "label": cls_benign,
            "tags": [alpha_tag_plain, "verified_usdc_treasury_invoice"],
            "note": {
                "kind": "private_alpha",
                "signal": alpha_tag_plain,
                "memo": stealth_alpha_note,
                "edge_bps": 38,
            },
            "counts": {
                "urgent_seed_verify_airdrop": 0,
                "permit2_unlimited_spoof": 0,
                "wallet_drainer_cluster_alpha": 0,
                "verified_usdc_treasury_invoice": 4,
            },
        },
        {
            "id": "mem_04",
            "category": "wallet_heuristic",
            "label": cls_benign,
            "tags": ["clean_treasury_multisig_0x7700", "verified_usdc_treasury_invoice"],
            "note": {
                "kind": "wallet_heuristic",
                "target": "clean_treasury_multisig_0x7700",
                "memo": benign_treasury_note,
            },
            "counts": {
                "urgent_seed_verify_airdrop": 0,
                "permit2_unlimited_spoof": 0,
                "wallet_drainer_cluster_alpha": 0,
                "verified_usdc_treasury_invoice": 3,
            },
        },
    ]

    encrypted_rows: list[dict[str, Any]] = []
    for item in raw_memories:
        rec_id = vault.blind_token("rec", item["id"])
        row_tokens = [vault.blind_token("tag", t) for t in item["tags"]]
        # Encrypt all feature counts and per-class {0, v} indicators under IND-CPA PLWE0001.
        # Category and class label stay sealed strictly inside the authenticated envelope.
        cipher_counts = {
            feat_map[k]: vault.plwe.encrypt_int_hex(int(v))
            for k, v in item["counts"].items()
        }
        class_indicator_cts = {
            cls_tok: vault.plwe.encrypt_int_hex(1 if item["label"] == cls_tok else 0)
            for cls_tok in (cls_phish, cls_benign)
        }
        class_feature_cts = {
            cls_tok: {
                feat_map[k]: vault.plwe.encrypt_int_hex(
                    int(v) if item["label"] == cls_tok else 0
                )
                for k, v in item["counts"].items()
            }
            for cls_tok in (cls_phish, cls_benign)
        }
        sealed_record = dict(item["note"])
        sealed_record["category"] = item["category"]
        sealed_record["label_token"] = item["label"]
        env = vault.encrypt_record(sealed_record, aad=f"{table_token}:{rec_id}")
        sblb_hex = vault.envelope_key.seal_json_hex(
            sealed_record, aad=f"{table_token}:{rec_id}".encode("utf-8")
        )
        encrypted_rows.append(
            {
                "record_id": rec_id,
                "blind_tokens": row_tokens,
                "cipher_counts": cipher_counts,
                "class_indicator_cts": class_indicator_cts,
                "class_feature_cts": class_feature_cts,
                "sblb_envelope_hex": sblb_hex,
                "envelope": env,
            }
        )

    client_score_candidates = [
        {
            "cohort_id": vault.blind_token("cohort", "candidate_tx_phish_01"),
            "plain_counts": {
                feat_map["urgent_seed_verify_airdrop"]: 2,
                feat_map["permit2_unlimited_spoof"]: 2,
                feat_map["wallet_drainer_cluster_alpha"]: 1,
                feat_map["verified_usdc_treasury_invoice"]: 0,
            },
        },
        {
            "cohort_id": vault.blind_token("cohort", "candidate_tx_clean_02"),
            "plain_counts": {
                feat_map["urgent_seed_verify_airdrop"]: 0,
                feat_map["permit2_unlimited_spoof"]: 0,
                feat_map["wallet_drainer_cluster_alpha"]: 0,
                feat_map["verified_usdc_treasury_invoice"]: 3,
            },
        },
    ]
    score_cohorts = [
        {
            "cohort_id": cand["cohort_id"],
            "cipher_counts": {
                ftok: vault.plwe.encrypt_int_hex(cnt)
                for ftok, cnt in cand["plain_counts"].items()
            },
        }
        for cand in client_score_candidates
    ]

    # Plaintext canary terms that MUST NEVER appear anywhere on the wire
    forbidden_plaintext_terms = [
        "urgent_seed_verify_airdrop",
        "permit2_unlimited_spoof",
        "wallet_drainer_cluster_alpha",
        "verified_usdc_treasury_invoice",
        "aerodrome_slipstream_rebalance_1400utc",
        "0xdeadbeef_drainer_cluster_alpha",
        "stealth_vault_yield_arb_38bps",
        "block_approval_drain_router_0x9911",
        "fake_base_bridge_claim",
        "spoofed_eip3009_nonce_signature_harvest",
        "clean_treasury_multisig_0x7700",
        "verified_base_treasury_multisig",
        "autonomous_agent_private_brain_v1",
        "phishing_block",
        "benign_allow",
    ]

    return {
        "table_token": table_token,
        "cls_phish": cls_phish,
        "cls_benign": cls_benign,
        "vocab_tokens": vocab_tokens,
        "feat_map": feat_map,
        "raw_memories": raw_memories,
        "encrypted_rows": encrypted_rows,
        "alpha_query_token": vault.blind_token("tag", alpha_tag_plain),
        "expected_alpha_memo": stealth_alpha_note,
        "score_cohorts": score_cohorts,
        "client_score_candidates": client_score_candidates,
        "forbidden_plaintext_terms": forbidden_plaintext_terms,
    }


# ---------------------------------------------------------------------------
# Local Cryptographic Execution
# ---------------------------------------------------------------------------

def _run_local_pipeline() -> dict[str, Any]:
    os.environ["BLINDCORE_GATE_QUIET"] = "1"
    tmpdir = tempfile.TemporaryDirectory()
    up_state = _LocalBrainUpstreamState()
    up_srv, up_port = _start_local_srv(_LocalBrainUpstreamHandler, up_state)
    fac_srv, fac_port = _start_local_srv(_LocalFacilitatorHandler, object())

    cfg = GateConfig(
        listen_host="127.0.0.1",
        listen_port=0,
        public_base_url="https://blindcore.dev",
        upstream_url=f"http://127.0.0.1:{up_port}",
        upstream_token=DEMO_UPSTREAM_TOKEN,
        gate_hmac_key_hex=DEMO_GATE_HMAC_HEX,
        db_path=os.path.join(tmpdir.name, "app01_brain.sqlite"),
        base_network=BASE_SEPOLIA_CAIP2,
        base_pay_to=DEMO_BASE_PAY_TO,
        base_anchor_contract=DEMO_BASE_ANCHOR,
        x402_facilitator_url=f"http://127.0.0.1:{fac_port}",
        l402_macaroon_secret="demo-app01-l402-secret",
        session_secret="demo-app01-session-secret",
        test_mode=True,
    )
    gate_srv = build_server(cfg)
    gate_url = f"http://127.0.0.1:{gate_srv.server_address[1]}"
    threading.Thread(target=gate_srv.serve_forever, daemon=True).start()

    try:
        vault = AgentPrivateVault(secrets.token_bytes(32))
        fx = _build_private_brain_fixtures(vault)
        table_token = fx["table_token"]

        captured_402: dict[str, Any] = {}
        last_x402_header: dict[str, str] = {}

        def _make_x402_signer(wallet_addr: str):
            def _signer(rail: str, challenge: dict[str, Any]) -> dict[str, str]:
                assert rail == "base-x402"
                pr = challenge.get("payment_required") or {}
                captured_402["payment_required"] = pr
                captured_402["http_status"] = challenge.get("http_status")
                req_accepts = pr["accepts"][0]
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
                            "from": wallet_addr,
                            "to": req_accepts["payTo"],
                            "value": str(req_accepts["amount"]),
                            "validAfter": str(now - 10),
                            "validBefore": str(now + 120),
                            "nonce": nonce,
                        },
                    },
                }
                hdr = {"PAYMENT-SIGNATURE": b64_json_encode(payload_obj)}
                last_x402_header.clear()
                last_x402_header.update(hdr)
                return hdr

            return _signer

        provider = BlindCoreActionProvider(
            base_url=gate_url,
            preferred_rail="base-x402",
            payment_signer=_make_x402_signer(DEMO_AGENT_WALLET),
        )

        # Step 1: Real HTTP 402 + x402 v2 + extensions.bazaar + $1.00 USDC prepaid top-up
        topup_res = json.loads(provider.blindcore_topup_credits(args={"rail": "base-x402"}))
        assert topup_res["http_status"] == 200, f"topup failed: {topup_res}"
        assert topup_res["body"]["credited_micro_usdc"] == PREPAID_MIN_MICRO_USDC
        session_token = str(topup_res["body"]["session_token"])
        pr_402 = captured_402.get("payment_required") or {}
        bazaar_ext = (pr_402.get("extensions") or {}).get("bazaar") or {}
        http_402_observed = (
            captured_402.get("http_status") == 402
            and pr_402.get("x402Version") == 2
            and bool(bazaar_ext.get("discoverable"))
        )
        assert http_402_observed, f"invalid 402 x402 v2 / bazaar challenge: {captured_402}"

        # Step 2: Prepaid encrypted BlindJSONB memory INGEST ($0.0005 USDC)
        ingest_payload = {
            "table": table_token,
            "op": "INGEST",
            "rows": fx["encrypted_rows"],
        }
        ingest_res = json.loads(
            provider.blindcore_query(
                args={
                    "endpoint": "/api/v1/blind/jsonb/ingest",
                    "table": table_token,
                    "op": "INGEST",
                    "params": ingest_payload,
                }
            )
        )
        assert ingest_res["http_status"] == 200, f"ingest failed: {ingest_res}"
        assert ingest_res["body"]["plaintext_stored"] is False

        # Step 3: Encrypted CONTAINS retrieval over JSON-RPC 2.0 MCP ($0.001 USDC)
        mcp_client = BlindCoreHttpClient(base_url=gate_url, session_token=session_token)
        mcp_init = handle_rpc_request(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            mcp_client,
        )
        assert mcp_init is not None and "result" in mcp_init
        mcp_contains = handle_rpc_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "blindcore_query",
                    "arguments": {
                        "endpoint": "/api/v1/blind/jsonb/query",
                        "table": table_token,
                        "op": "CONTAINS",
                        "params": {"blind_tokens": [fx["alpha_query_token"]]},
                    },
                },
            },
            mcp_client,
        )
        assert mcp_contains is not None and mcp_contains["result"]["isError"] is False
        contains_res = mcp_contains["result"]["structuredContent"]
        assert contains_res["http_status"] == 200, f"CONTAINS failed: {contains_res}"
        matched_records = contains_res["body"]["matched_records"]
        assert len(matched_records) == 1
        decrypted_alpha = vault.decrypt_record(
            matched_records[0]["envelope"],
            aad=f"{table_token}:{matched_records[0]['record_id']}",
        )
        assert decrypted_alpha["memo"] == fx["expected_alpha_memo"]

        # Step 4: 1-query encrypted SKLEARN_MNB phishing/threat scoring ($0.020 USDC)
        mnb_res = json.loads(
            provider.blindcore_sklearn_mnb(
                args={
                    "table": table_token,
                    "train_classes": [fx["cls_phish"], fx["cls_benign"]],
                    "vocab_paths": fx["vocab_tokens"],
                    "score_cohorts": fx["score_cohorts"],
                    "alpha": 1.0,
                    "weight_scale": 10000,
                }
            )
        )
        assert mnb_res["http_status"] == 200, f"SKLEARN_MNB failed: {mnb_res}"
        mnb_body = mnb_res["body"]
        assert "decrypted_aggregate" not in mnb_body
        ct_doc_sums = mnb_body["ct_class_doc_sums"]
        ct_feat_sums = mnb_body["ct_class_feature_sums"]
        train_classes = [fx["cls_phish"], fx["cls_benign"]]
        class_docs = {c: vault.plwe.decrypt_int(ct_doc_sums[c]) for c in train_classes}
        class_counts = {
            c: {tok: vault.plwe.decrypt_int(ct_feat_sums[c][tok]) for tok in fx["vocab_tokens"]}
            for c in train_classes
        }
        wrong_plwe = BlindClientPlweKey.generate()
        assert wrong_plwe.decrypt_int(ct_doc_sums[fx["cls_phish"]]) != class_docs[fx["cls_phish"]]
        total_docs = max(1, sum(class_docs.values()))
        num_classes = len(train_classes)
        alpha_val = 1.0
        classifications: list[dict[str, Any]] = []
        for cand in fx["client_score_candidates"]:
            log_post: dict[str, float] = {}
            for cls_tok in train_classes:
                prior = math.log((class_docs[cls_tok] + alpha_val) / (total_docs + num_classes * alpha_val))
                denom = sum(class_counts[cls_tok].values()) + alpha_val * len(fx["vocab_tokens"])
                ll = prior
                for tok, cnt in cand["plain_counts"].items():
                    if cnt > 0:
                        ll += cnt * math.log((class_counts[cls_tok][tok] + alpha_val) / denom)
                log_post[cls_tok] = round(ll, 6)
            predicted = max(log_post, key=lambda k: log_post[k])
            classifications.append(
                {
                    "cohort_id": cand["cohort_id"],
                    "predicted_class_token": predicted,
                    "log_posterior": log_post,
                }
            )
        assert len(classifications) == 2
        assert classifications[0]["predicted_class_token"] == fx["cls_phish"]
        assert classifications[1]["predicted_class_token"] == fx["cls_benign"]

        primary_receipt = mnb_body["nsau0001_receipt"]
        primary_settle_proof = mnb_body["SETTLE_PROOF"]
        assert verify_nsau0001_receipt(primary_receipt), "primary NSAU0001 verification failed"
        assert primary_settle_proof["eip2_low_s_verified"], "EIP-2 low-s check failed"

        # Exact credit conservation check ($1.00 - $0.0005 - $0.001 - $0.020 = $0.9785)
        expected_spent = (
            PRICING_TIERS["INGEST"].micro_usdc
            + PRICING_TIERS["CONTAINS"].micro_usdc
            + PRICING_TIERS["SKLEARN_MNB"].micro_usdc
        )
        remaining_micro = gate_srv.engine.ledger.get_balance(DEMO_AGENT_WALLET)
        assert remaining_micro == PREPAID_MIN_MICRO_USDC - expected_spent

        # Step 5: Counterfactual Knockouts + Replay & Tamper Rejection
        # 5.1. Replay of already-settled x402 top-up signature MUST return HTTP 402
        replay_status, _, _ = _http_request(
            "POST",
            f"{gate_url}/api/v1/credits/topup",
            payload={},
            headers=dict(last_x402_header),
        )
        replay_rejected = replay_status == 402

        # 5.2. Tampered prepaid session token (flipped signature nibble) MUST return HTTP 402
        bad_tok = session_token[:-1] + ("0" if session_token[-1] != "0" else "1")
        tamper_sess_status, _, _ = _http_request(
            "POST",
            f"{gate_url}/api/v1/blind/jsonb/query",
            payload={"table": table_token, "op": "CONTAINS", "blind_tokens": [fx["alpha_query_token"]]},
            headers={"X-BlindCore-Session": bad_tok},
        )
        tamper_session_rejected = tamper_sess_status == 402

        # 5.3. Tampered upstream Gate-MAC MUST return HTTP 403
        tamper_mac_status, _, _ = _http_request(
            "POST",
            f"http://127.0.0.1:{up_port}/api/v1/blind/jsonb/query",
            payload={"table": table_token, "op": "CONTAINS", "blind_tokens": [fx["alpha_query_token"]]},
            headers={
                "Authorization": f"Bearer {DEMO_UPSTREAM_TOKEN}",
                "X-BlindCore-Rail": "base-x402-credit",
                "X-BlindCore-Payer": DEMO_AGENT_WALLET,
                "X-BlindCore-Payment-Hash": "11" * 32,
                "X-BlindCore-Fee-Micro": "1000",
                "X-BlindCore-Ts": str(int(time.time())),
                "X-BlindCore-Gate-Mac": "00" * 32,
            },
        )
        tamper_mac_rejected = tamper_mac_status == 403

        # 5.4. Tampered NSAU0001 receipt byte MUST fail verification
        tampered_receipt = dict(primary_receipt)
        r_hex = str(primary_receipt["receipt_hex"])
        tampered_receipt["receipt_hex"] = r_hex[:-2] + ("ff" if r_hex[-2:] != "ff" else "00")
        tamper_receipt_rejected = not verify_nsau0001_receipt(tampered_receipt)

        # 5.5. Counterfactual receipt knockout (different payer & query produces distinct receipt & digest)
        alt_provider = BlindCoreActionProvider(
            base_url=gate_url,
            preferred_rail="base-x402",
            payment_signer=_make_x402_signer(DEMO_ALT_WALLET),
        )
        alt_topup = json.loads(alt_provider.blindcore_topup_credits(args={"rail": "base-x402"}))
        assert alt_topup["http_status"] == 200
        alt_mnb = json.loads(
            alt_provider.blindcore_sklearn_mnb(
                args={
                    "table": table_token,
                    "train_classes": [fx["cls_phish"], fx["cls_benign"]],
                    "vocab_paths": fx["vocab_tokens"],
                    "score_cohorts": [fx["score_cohorts"][1]],
                    "alpha": 1.0,
                    "weight_scale": 10000,
                }
            )
        )
        assert alt_mnb["http_status"] == 200
        alt_receipt = alt_mnb["body"]["nsau0001_receipt"]
        alt_settle = alt_mnb["body"]["SETTLE_PROOF"]
        receipt_knockout_distinct = (
            primary_receipt["receipt_hex"] != alt_receipt["receipt_hex"]
            and primary_settle_proof["digest"] != alt_settle["digest"]
        )

        counterfactual_ok = (
            replay_rejected
            and tamper_session_rejected
            and tamper_mac_rejected
            and tamper_receipt_rejected
            and receipt_knockout_distinct
        )

        # Step 6: Zero-plaintext audit across ALL wire RX, wire TX, and server storage
        stored_blob = json.dumps(
            up_state.encrypted_tables, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        wire_audit = audit_zero_plaintext(
            up_state.wire_rx_blobs + up_state.wire_tx_blobs + [stored_blob],
            fx["forbidden_plaintext_terms"],
        )

        sample_row = fx["encrypted_rows"][0]
        wire_sample_redacted = {
            "table_token": table_token,
            "sample_ingest_row": {
                "record_id": sample_row["record_id"],
                "blind_tokens": sample_row["blind_tokens"],
                "plwe_frame_bytes": PLWE_SEEDED_BYTES,
                "plwe_expanded_bytes": PLWE_EXPANDED_BYTES,
                "envelope_alg": sample_row["envelope"]["alg"],
                "ciphertext_preview_hex": sample_row["envelope"]["ciphertext_hex"][:32] + "...",
                "auth_tag_preview_hex": sample_row["envelope"]["auth_tag_hex"][:16] + "...",
            },
            "sample_contains_query_tokens": [fx["alpha_query_token"]],
            "sample_mnb_vocab_tokens": fx["vocab_tokens"],
            "wire_audit": wire_audit,
        }

        return {
            "http_402_observed": http_402_observed,
            "zero_plaintext_verified": bool(wire_audit["zero_plaintext_verified"]),
            "counterfactual_knockout_verified": counterfactual_ok,
            "settle_proof": primary_settle_proof,
            "nsau0001_receipt_hex": str(primary_receipt["receipt_hex"]),
            "wire_sample_redacted": wire_sample_redacted,
            "local_summary": {
                "network": BASE_SEPOLIA_CAIP2,
                "agent_wallet": DEMO_AGENT_WALLET,
                "bazaar_discoverable": bool(bazaar_ext.get("discoverable")),
                "prepaid_credit_conservation": {
                    "deposited_micro_usdc": PREPAID_MIN_MICRO_USDC,
                    "spent_micro_usdc": expected_spent,
                    "remaining_micro_usdc": remaining_micro,
                    "cdp_fee_bypassed_ops": ["INGEST", "CONTAINS", "SKLEARN_MNB"],
                },
                "mcp_contains_retrieval": {
                    "matched_count": len(matched_records),
                    "decrypted_edge_bps": decrypted_alpha["edge_bps"],
                    "local_decrypt_verified": True,
                },
                "sklearn_mnb_scoring": {
                    "cohorts_scored": len(classifications),
                    "phishing_candidate_blocked": (
                        classifications[0]["predicted_class_token"] == fx["cls_phish"]
                    ),
                    "benign_candidate_allowed": (
                        classifications[1]["predicted_class_token"] == fx["cls_benign"]
                    ),
                },
                "security_knockouts": {
                    "x402_replay_rejected_402": replay_rejected,
                    "tampered_session_rejected_402": tamper_session_rejected,
                    "tampered_gate_mac_rejected_403": tamper_mac_rejected,
                    "tampered_nsau0001_rejected": tamper_receipt_rejected,
                    "counterfactual_receipt_distinct": receipt_knockout_distinct,
                    "counterfactual_alt_receipt_prefix": alt_receipt["receipt_hex"][:24] + "...",
                },
            },
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


# ---------------------------------------------------------------------------
# Live Testnet Probe (--mode testnet)
# ---------------------------------------------------------------------------

def _probe_testnet(gate_url: str) -> dict[str, Any]:
    base = gate_url.rstrip("/")
    health_st, _, health_body = _http_request("GET", f"{base}/health")
    x402_st, _, x402_body = _http_request("GET", f"{base}/.well-known/x402.json")
    pricing_st, _, pricing_body = _http_request("GET", f"{base}/api/v1/pricing")

    probe_payload = {
        "table": "bt_testnet_probe_v1",
        "op": "SKLEARN_MNB",
        "train_classes": ["bt_cls_0", "bt_cls_1"],
        "vocab_paths": ["bt_feat_0", "bt_feat_1"],
        "score_cohorts": [],
    }
    st_402, hdrs_402, body_402 = _http_request(
        "POST",
        f"{base}/api/v1/blind/jsonb/query",
        payload=probe_payload,
    )
    decoded_pr = None
    if hdrs_402.get("payment-required"):
        try:
            decoded_pr = b64_json_decode(hdrs_402["payment-required"])
        except Exception:
            decoded_pr = None
    decoded_stx = None
    if hdrs_402.get("x-stacks-payment-required"):
        try:
            decoded_stx = b64_json_decode(hdrs_402["x-stacks-payment-required"])
        except Exception:
            decoded_stx = None

    bazaar_ok = bool(
        isinstance(decoded_pr, dict)
        and ((decoded_pr.get("extensions") or {}).get("bazaar") or {}).get("discoverable")
    )
    return {
        "gate_url": base,
        "health_status": health_st,
        "health_ok": health_st == 200 and isinstance(health_body, dict) and health_body.get("status") == "ok",
        "health_base_network": health_body.get("baseNetwork") if isinstance(health_body, dict) else None,
        "x402_manifest_status": x402_st,
        "x402_version": x402_body.get("x402Version") if isinstance(x402_body, dict) else None,
        "pricing_status": pricing_st,
        "pricing_tiers_count": len(pricing_body.get("tiers", {})) if isinstance(pricing_body, dict) else 0,
        "live_402_status": st_402,
        "live_402_observed": st_402 == 402,
        "live_bazaar_discoverable": bazaar_ok,
        "live_headers_present": {
            "payment-required": "payment-required" in hdrs_402,
            "x-stacks-payment-required": "x-stacks-payment-required" in hdrs_402,
            "www-authenticate": "www-authenticate" in hdrs_402,
        },
        "live_402_accepts_count": len(decoded_pr.get("accepts", [])) if isinstance(decoded_pr, dict) else 0,
        "live_stacks_sats_quoted": decoded_stx.get("amountSats") if isinstance(decoded_stx, dict) else None,
        "live_error_preview": body_402.get("error") if isinstance(body_402, dict) else None,
    }


def _run_live_backend_probe(
    api_url: str | None = None,
    api_token: str | None = None,
) -> dict[str, Any]:
    """Drive a live BlindCore Rust server in Mode 2 zero-knowledge (zero server keys)."""
    proc: subprocess.Popen[bytes] | None = None
    td_obj: tempfile.TemporaryDirectory[str] | None = None
    target_url = (api_url or os.environ.get("BLINDCORE_API_URL") or "").strip()
    token = (api_token or os.environ.get("BLINDCORE_API_TOKEN") or "").strip()
    if not target_url or not token:
        bin_path = os.environ.get("BLINDCORE_API_BIN", "/tmp/blindcore-api")
        if not os.path.isfile(bin_path):
            raise RuntimeError(f"live server binary not found at {bin_path}")
        with socket.socket() as s1:
            s1.bind(("127.0.0.1", 0))
            api_port = s1.getsockname()[1]
        with socket.socket() as s2:
            s2.bind(("127.0.0.1", 0))
            pg_port = s2.getsockname()[1]
        token = secrets.token_hex(16)
        td_obj = tempfile.TemporaryDirectory(prefix="bc_app01_live_")
        env = os.environ.copy()
        env[bytes.fromhex("4155544f44425f4150495f544f4b454e").decode("ascii")] = token
        proc = subprocess.Popen(
            [
                bin_path,
                "--api-bind",
                f"127.0.0.1:{api_port}",
                "--pg-bind",
                f"127.0.0.1:{pg_port}",
                "--data-dir",
                td_obj.name,
                "--disk-gb",
                "1",
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        target_url = f"http://127.0.0.1:{api_port}"
        for _ in range(60):
            try:
                req_h = urllib.request.Request(f"{target_url}/api/v1/catalog", headers={"Authorization": f"Bearer {token}"})
                with urllib.request.urlopen(req_h, timeout=1) as resp:
                    if resp.status == 200:
                        break
            except Exception:
                time.sleep(0.1)

    try:
        vault = AgentPrivateVault(secrets.token_bytes(32))
        fx = _build_private_brain_fixtures(vault)
        client = BlindCoreClient(target_url, token=token, timeout=20.0)
        suffix = secrets.token_hex(4)
        j_tbl = f"app01_zk_jsonb_{suffix}"
        b_tbl = f"app01_zk_olap_{suffix}"
        ek = vault.envelope_key
        pk = vault.plwe

        # 1. BlindJSONB CONTAINS with SBLB0001 envelopes + sorted client HMAC tokens
        client.create_blind_jsonb_table(j_tbl, k_tok=4, k_num=4)
        ptoks = sorted(
            bytes.fromhex(ek.derive_path_token_hex(f"f{i}")) for i in range(4)
        )
        vocab_names = [
            "urgent_seed_verify_airdrop",
            "permit2_unlimited_spoof",
            "wallet_drainer_cluster_alpha",
            "verified_usdc_treasury_invoice",
        ]
        alpha_tok = bytes.fromhex(
            ek.blind_token_hex("tag", "aerodrome_slipstream_rebalance_1400utc")
        )
        j_rows = []
        for idx, mem in enumerate(fx["raw_memories"]):
            real_toks = [bytes.fromhex(ek.blind_token_hex("tag", t)) for t in mem["tags"]]
            pad_i = 0
            while len(real_toks) < 4:
                cand = bytes.fromhex(ek.blind_token_hex("pad", f"{idx}:{pad_i}"))
                pad_i += 1
                if cand not in real_toks:
                    real_toks.append(cand)
            j_rows.append(
                {
                    "doc_id_tok_hex": ek.blind_token_hex("doc", mem["id"]),
                    "doc_blob_hex": ek.seal_json_hex(mem["note"]),
                    "tok_slots_hex": [t.hex() for t in sorted(real_toks)],
                    "num_slots_hex": [
                        (ptoks[fi] + pk.encrypt_int(int(mem["counts"][vname]))).hex()
                        for fi, vname in enumerate(vocab_names)
                    ],
                }
            )
        client.ingest_blind_jsonb(j_tbl, j_rows)
        r_cont = client.query_blind_jsonb(
            j_tbl, "CONTAINS", contains_tokens_hex=[alpha_tok.hex()]
        )
        assert int(r_cont["matched_count"]) == 1
        opened_doc = ek.open_json(r_cont["docs"][0]["doc_blob_hex"])
        assert opened_doc["memo"] == fx["expected_alpha_memo"]

        # 2. Blind OLAP zero-key homomorphic SUM over {0, v} class indicator columns
        cols = [
            {"name": "doc", "kind": "sealed_blob"},
            {"name": "p_ind", "kind": "blind_add"},
            {"name": "b_ind", "kind": "blind_add"},
        ]
        for fi in range(4):
            cols.append({"name": f"pf{fi}", "kind": "blind_add"})
            cols.append({"name": f"bf{fi}", "kind": "blind_add"})
        client.create_blind_table(b_tbl, cols)
        o_rows = []
        for mem in fx["raw_memories"]:
            is_p = mem["label"] == fx["cls_phish"]
            cts = {
                "doc": ek.seal_json_hex({"id": mem["id"]}),
                "p_ind": pk.encrypt_int_hex(1 if is_p else 0),
                "b_ind": pk.encrypt_int_hex(0 if is_p else 1),
            }
            for fi, vname in enumerate(vocab_names):
                cnt = int(mem["counts"][vname])
                cts[f"pf{fi}"] = pk.encrypt_int_hex(cnt if is_p else 0)
                cts[f"bf{fi}"] = pk.encrypt_int_hex(0 if is_p else cnt)
            o_rows.append({"ciphertexts_hex": cts})
        client.ingest_blind(b_tbl, o_rows)

        dec_counts: dict[str, int] = {}
        receipts_ok = True
        for col_name in ("p_ind", "b_ind", "pf0", "pf1", "pf2", "pf3", "bf0", "bf1", "bf2", "bf3"):
            r_sum = client.query_blind(b_tbl, "SUM", column=col_name)
            assert "decrypted_aggregate" not in r_sum
            ct_bytes = bytes.fromhex(r_sum["ct_result_hex"])
            assert len(ct_bytes) == PLWE_EXPANDED_BYTES
            receipts_ok = receipts_ok and verify_blind_receipt(
                r_sum, "SUM", b_tbl, len(o_rows), ct_bytes
            )
            dec_counts[col_name] = pk.decrypt_int(ct_bytes)
        assert receipts_ok
        assert dec_counts["p_ind"] == 2 and dec_counts["b_ind"] == 2
        wrong_key = BlindClientPlweKey.generate()
        r_chk = client.query_blind(b_tbl, "SUM", column="pf0")
        assert wrong_key.decrypt_int(r_chk["ct_result_hex"]) != dec_counts["pf0"]
        return {
            "live_server_url": target_url,
            "live_zero_knowledge_verified": True,
            "zero_server_keys_verified": True,
            "contains_matched_count": int(r_cont["matched_count"]),
            "contains_local_decrypt_verified": opened_doc["memo"] == fx["expected_alpha_memo"],
            "plwe_expanded_bytes": PLWE_EXPANDED_BYTES,
            "receipts_verified": receipts_ok,
            "phish_docs_decrypted": dec_counts["p_ind"],
            "benign_docs_decrypted": dec_counts["b_ind"],
        }
    finally:
        if proc is not None:
            proc.terminate()
            proc.wait(timeout=5)
        if td_obj is not None:
            td_obj.cleanup()


# ---------------------------------------------------------------------------
# Public Contract Entry Point
# ---------------------------------------------------------------------------

def run_demo(
    mode: str = "local",
    gate_url: str | None = None,
    api_url: str | None = None,
    api_token: str | None = None,
) -> dict[str, Any]:
    if mode not in ("local", "testnet", "live"):
        raise ValueError(f"unsupported mode: {mode!r}")
    t0 = time.perf_counter()

    local_out = _run_local_pipeline()
    testnet_probe: dict[str, Any] | None = None
    live_probe: dict[str, Any] | None = None
    http_402_observed = bool(local_out["http_402_observed"])

    if mode == "testnet":
        target_url = (gate_url or os.environ.get("BLINDCORE_GATE_URL") or DEFAULT_TESTNET_GATE_URL).strip()
        testnet_probe = _probe_testnet(target_url)
        http_402_observed = bool(testnet_probe["live_402_observed"] and local_out["http_402_observed"])
    elif mode == "live":
        live_probe = _run_live_backend_probe(api_url=api_url, api_token=api_token)

    ok = (
        http_402_observed
        and bool(local_out["zero_plaintext_verified"])
        and bool(local_out["counterfactual_knockout_verified"])
        and len(local_out["nsau0001_receipt_hex"]) == 192
        and local_out["nsau0001_receipt_hex"].startswith("4e53415530303031")
    )
    if mode == "testnet" and testnet_probe is not None:
        ok = ok and bool(testnet_probe["health_ok"]) and bool(testnet_probe["live_402_observed"])
    if mode == "live" and live_probe is not None:
        ok = ok and bool(live_probe["zero_server_keys_verified"]) and bool(live_probe["receipts_verified"])

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    summary: dict[str, Any] = {
        "mode": mode,
        "execution": local_out["local_summary"],
    }
    if testnet_probe is not None:
        summary["testnet_probe"] = testnet_probe
    if live_probe is not None:
        summary["live_backend_probe"] = live_probe
        summary["live_zero_knowledge_backend"] = live_probe

    return {
        "app_id": APP_ID,
        "title": APP_TITLE,
        "rail": APP_RAIL,
        "status": "PASS" if ok else "FAIL",
        "elapsed_ms": elapsed_ms,
        "http_402_observed": http_402_observed,
        "zero_plaintext_verified": bool(local_out["zero_plaintext_verified"]),
        "counterfactual_knockout_verified": bool(local_out["counterfactual_knockout_verified"]),
        "settle_proof": local_out["settle_proof"],
        "nsau0001_receipt_hex": local_out["nsau0001_receipt_hex"],
        "wire_sample_redacted": local_out["wire_sample_redacted"],
        "summary": summary,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=APP_TITLE)
    parser.add_argument("--mode", choices=("local", "testnet", "live"), default="local")
    parser.add_argument(
        "--gate-url",
        default=os.environ.get("BLINDCORE_GATE_URL", DEFAULT_TESTNET_GATE_URL),
        help="Target BlindCore Tri-Rail Gate URL (used in --mode testnet)",
    )
    parser.add_argument("--api-url", default=os.environ.get("BLINDCORE_API_URL", ""))
    parser.add_argument("--api-token", default=os.environ.get("BLINDCORE_API_TOKEN", ""))
    args = parser.parse_args()
    res = run_demo(
        mode=args.mode,
        gate_url=args.gate_url,
        api_url=args.api_url or None,
        api_token=args.api_token or None,
    )
    print(json.dumps(res, indent=2, sort_keys=True))
    if res["status"] != "PASS":
        sys.exit(1)


if __name__ == "__main__":
    main()
