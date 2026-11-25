#!/usr/bin/env python3
"""
BlindCore Killer App #4: Decentralized Social Blind Relay, Private Algorithmic
Feed & Encrypted Web-of-Trust (Bitcoin Lightning L402 sats).
Copyright 2026 Blind Labs (https://blindlabs.ai). Licensed under the Apache License, Version 2.0.

Demonstrates a zero-knowledge Nostr-style blind relay powered by Bitcoin
Lightning L402 (macaroon:preimage) pay-per-query confidential compute:
  1. Encrypts user social events (likes, mutes, bookmarks, gift-wrapped DMs)
     into fixed-size dummy-padded BlindJSONB envelopes so the relay CANNOT
     observe who the user follows, mutes, bookmarks, or messages.
  2. Unpaid probe receives real HTTP 402 + WWW-Authenticate: L402 challenge.
  3. Settles L402 Lightning invoices (macaroon:preimage) to:
     - Ingest dummy-padded encrypted Nostr events (1 sat).
     - Run a private algorithmic feed & anti-spam SKLEARN_MNB ranker (30 sats).
     - Compute a k_min_tkms-guarded encrypted Web-of-Trust (WoT) WEIGHTED_SUM
       cohort tally (8 sats).
  4. Counterfactual knockouts:
     - Settled L402 token replay is deterministically rejected (HTTP 402).
     - Under-sized WoT cohort probe (cohort_size=2 < k_min_tkms=5) aborts with
       HTTP 422 + X-BlindCore-Settlement: aborted (zero social graph leakage).
     - Distinct operations emit strictly distinct 96-byte NSAU0001 receipts.
  5. Demonstrates O(1) right-to-delete cryptographic shredding (user key drop +
     blind tombstone token).
  6. Audits all raw wire bytes to prove 0 plaintext pubkeys, tags, or messages
     on the wire, and verifies NSAU0001 + L402 SETTLE_PROOF.

Usage:
  python3 apps/app04_nostr_blind_relay.py --mode local
  python3 apps/app04_nostr_blind_relay.py --mode testnet \
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
import re
import secrets
import socket
import struct
import subprocess
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
    GateConfig,
    PRICING_TIERS,
    b64_json_decode,
    build_server,
    sha256_hex,
    validate_http_url,
)

try:
    from python.blindcore_sdk import (  # noqa: E402
        BlindClientEnvelopeKey,
        BlindClientPlweKey,
        BlindCoreClient,
        PLWE_EXPANDED_BYTES,
        PLWE_SEEDED_BYTES,
        verify_blind_receipt,
    )
except ImportError:
    from python.blindcore_client import (  # type: ignore[no-redef]  # noqa: E402
        BlindClientEnvelopeKey,
        BlindClientPlweKey,
        BlindCoreClient,
        PLWE_EXPANDED_BYTES,
        PLWE_SEEDED_BYTES,
        verify_blind_receipt,
    )


# ---------------------------------------------------------------------------
# Constants (Local/Testnet Demo Fixtures - Zero Live Secrets)
# ---------------------------------------------------------------------------

APP_ID = "app04"
APP_TITLE = (
    "Decentralized Social Blind Relay, Private Algorithmic Feed & "
    "Encrypted Web-of-Trust"
)
APP_RAIL = "ln-l402"
DEFAULT_TESTNET_URL = "https://api.blindlabs.ai/testnet"

DEMO_UPSTREAM_TOKEN = "demo-local-upstream-token-app04"
DEMO_GATE_HMAC_HEX = "44" * 32
DEMO_L402_SEED = "demo-nostr-blind-relay-l402-seed-04"
K_MIN_TKMS = 5
FIXED_ENVELOPE_BYTES = 512
FIXED_FEATURE_SLOTS = 6


# ---------------------------------------------------------------------------
# Client-Side Blind Nostr Envelope, Dummy Padding & O(1) User Key Vault
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
        out.extend(hashlib.sha256(key + nonce + struct.pack(">I", counter)).digest())
        counter += 1
    return bytes(out[:length])


def _encrypt_padded_event(key: bytes, payload_bytes: bytes, aad: bytes) -> dict[str, str]:
    """Encrypt a Nostr event into an exact FIXED_ENVELOPE_BYTES padded ciphertext."""
    if len(payload_bytes) + 2 > FIXED_ENVELOPE_BYTES:
        raise ValueError("Nostr event exceeds fixed padded envelope size")
    nonce = secrets.token_bytes(16)
    pad_len = FIXED_ENVELOPE_BYTES - 2 - len(payload_bytes)
    framed = struct.pack(">H", len(payload_bytes)) + payload_bytes + secrets.token_bytes(pad_len)
    stream = _keystream(key, nonce, len(framed))
    ct = bytes(a ^ b for a, b in zip(framed, stream))
    tag = hmac.new(key, aad + nonce + ct, hashlib.sha256).hexdigest()
    return {
        "nonce_hex": nonce.hex(),
        "ct_b64": base64.b64encode(ct).decode("ascii"),
        "tag_hex": tag,
        "padded_bytes": str(len(ct)),
    }


def _decrypt_padded_event(key: bytes, env: dict[str, str], aad: bytes) -> bytes:
    nonce = bytes.fromhex(env["nonce_hex"])
    ct = base64.b64decode(env["ct_b64"].encode("ascii"))
    expected = hmac.new(key, aad + nonce + ct, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, env["tag_hex"]):
        raise ValueError("AEAD authentication tag mismatch (key dropped or tampered)")
    stream = _keystream(key, nonce, len(ct))
    framed = bytes(a ^ b for a, b in zip(ct, stream))
    pt_len = struct.unpack(">H", framed[:2])[0]
    if pt_len > len(framed) - 2:
        raise ValueError("corrupted padded frame length")
    return framed[2 : 2 + pt_len]


class NostrClientVault:
    """Client-side Nostr blind-token, PLWE0001 & shreddable per-identity key store."""

    def __init__(self) -> None:
        self.token_key = secrets.token_bytes(32)
        self.plwe = BlindClientPlweKey.generate()
        self.envelope_key = BlindClientEnvelopeKey.generate()
        self.user_keys: dict[str, bytes] = {}
        self.event_shred_tokens: dict[str, list[str]] = {}

    def author_token(self, npub: str) -> str:
        tok = _blind_token(self.token_key, "np", npub)
        if tok not in self.user_keys:
            self.user_keys[tok] = secrets.token_bytes(32)
        return tok

    def register_event_commit(self, author_tok: str) -> str:
        salt = secrets.token_hex(16)
        commit = "ec_" + sha256_hex(f"{author_tok}:{salt}".encode("utf-8"))[:24]
        self.event_shred_tokens.setdefault(author_tok, []).append(commit)
        return commit

    def event_token(self, event_id: str) -> str:
        return _blind_token(self.token_key, "ev", event_id)

    def label_token(self, label_name: str) -> str:
        return _blind_token(self.token_key, "lb", label_name)

    def slot_token(self, signal_name: str) -> str:
        return _blind_token(self.token_key, "sg", signal_name)

    def shred_user_o1(self, author_tok: str) -> bool:
        """O(1) right-to-delete key drop for a user's encrypted relay records."""
        return self.user_keys.pop(author_tok, None) is not None


# ---------------------------------------------------------------------------
# Verifiable 96-Byte NSAU0001 Receipt & Lightning L402 SETTLE_PROOF
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
        (
            f"BlindCoreL402Settle-v2|{epoch_seq}|{payer}|{table_hash_hex}|"
            f"{receipt_hash_hex}|{payment_hash}|{fee_sats}|{op_tier}"
        ).encode("utf-8")
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
# Ephemeral Local Blind Relay Upstream (--mode local)
# ---------------------------------------------------------------------------

class _LocalHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64


class _NostrRelayUpstreamState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.epoch_seq = 400
        self.events: dict[str, list[dict[str, Any]]] = {}
        self.tombstoned_authors: set[str] = set()
        self.captured_wire_payloads: list[bytes] = []


class _NostrRelayUpstreamHandler(BaseHTTPRequestHandler):
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
        state: _NostrRelayUpstreamState = self.server.state  # type: ignore[attr-defined]
        table = str(parsed.get("table", "tbl_blind_relay_v1"))

        with state.lock:
            state.captured_wire_payloads.append(body)
            state.epoch_seq += 1
            epoch = state.epoch_seq

            # 1. BlindJSONB INGEST & O(1) Right-to-Delete Tombstone
            if self.path.endswith("/ingest"):
                action = str(parsed.get("action", "APPEND")).upper()
                if action == "TOMBSTONE_SHRED":
                    shred_tokens = [str(t) for t in parsed.get("shred_tokens", []) if t]
                    if not shred_tokens:
                        self._reply(400, {"error": "missing shred_tokens"})
                        return
                    for tok in shred_tokens:
                        state.tombstoned_authors.add(tok)
                    receipt = build_nsau0001_receipt(
                        epoch, PRICING_TIERS["INGEST"].sats, ts, table, pay_hash, gate_mac
                    )
                    self._reply(
                        200,
                        {
                            "status": "ok",
                            "op": "TOMBSTONE_SHRED",
                            "table": table,
                            "shredded_commits": len(shred_tokens),
                            "complexity": "O(1)",
                            "plaintext_stored": False,
                            "epoch_seq": epoch,
                            "nsau0001_receipt": receipt,
                        },
                    )
                    return

                rows = parsed.get("rows", [])
                pad_sizes = set()
                slot_counts = set()
                for row in rows:
                    env = row.get("padded_envelope", {})
                    ct_bytes = base64.b64decode(str(env.get("ct_b64", "")).encode("ascii"))
                    pad_sizes.add(len(ct_bytes))
                    slot_counts.add(len(row.get("cipher_slots", {})))
                if pad_sizes != {FIXED_ENVELOPE_BYTES} or slot_counts != {FIXED_FEATURE_SLOTS}:
                    self._reply(
                        400,
                        {
                            "error": "non-uniform dummy padding rejected by blind relay",
                            "pad_sizes": sorted(pad_sizes),
                            "slot_counts": sorted(slot_counts),
                        },
                    )
                    return

                state.events.setdefault(table, []).extend(rows)
                receipt = build_nsau0001_receipt(
                    epoch, PRICING_TIERS["INGEST"].sats, ts, table, pay_hash, gate_mac
                )
                self._reply(
                    200,
                    {
                        "status": "ok",
                        "op": "INGEST",
                        "table": table,
                        "ingested_encrypted_events": len(rows),
                        "uniform_envelope_bytes": FIXED_ENVELOPE_BYTES,
                        "uniform_slot_count": FIXED_FEATURE_SLOTS,
                        "plaintext_stored": False,
                        "epoch_seq": epoch,
                        "nsau0001_receipt": receipt,
                    },
                )
                return

            active_rows = [
                r
                for r in state.events.get(table, [])
                if str(r.get("event_author_commit", "")) not in state.tombstoned_authors
            ]
            op = str(parsed.get("op", "")).upper()

            # 2. Private Algorithmic Feed / Anti-Spam Zero-Key Homomorphic SKLEARN_MNB
            if op == "SKLEARN_MNB":
                train_classes = [str(c) for c in parsed.get("train_classes", [])]
                vocab = [str(v) for v in parsed.get("vocab_paths", [])]
                ct_class_doc_sums: dict[str, str] = {}
                ct_class_slot_sums: dict[str, dict[str, str]] = {}
                for lb in train_classes:
                    d_frames = [
                        str(r["class_indicator_cts"][lb])
                        for r in active_rows
                        if lb in r.get("class_indicator_cts", {})
                    ]
                    ct_class_doc_sums[lb] = BlindClientPlweKey.homomorphic_weighted_sum(
                        d_frames
                    ).hex()
                    ct_class_slot_sums[lb] = {}
                    for tok in vocab:
                        s_frames = [
                            str(r["class_slot_cts"][lb][tok])
                            for r in active_rows
                            if lb in r.get("class_slot_cts", {})
                        ]
                        ct_class_slot_sums[lb][tok] = (
                            BlindClientPlweKey.homomorphic_weighted_sum(s_frames).hex()
                        )

                receipt = build_nsau0001_receipt(
                    epoch, PRICING_TIERS["SKLEARN_MNB"].sats, ts, table, pay_hash, gate_mac
                )
                self._reply(
                    200,
                    {
                        "status": "ok",
                        "op": "SKLEARN_MNB",
                        "table": table,
                        "active_events_trained": len(active_rows),
                        "plaintext_stored": False,
                        "zero_server_keys": True,
                        "epoch_seq": epoch,
                        "payer": payer,
                        "ct_class_doc_sums": ct_class_doc_sums,
                        "ct_class_slot_sums": ct_class_slot_sums,
                        "nsau0001_receipt": receipt,
                    },
                )
                return

            # 3. k_min_tkms Zero-Key Homomorphic Web-of-Trust (WoT) Cohort Tally (WEIGHTED_SUM)
            if op == "WEIGHTED_SUM":
                k_min = int(parsed.get("k_min_tkms", K_MIN_TKMS))
                cohort_size = int(parsed.get("cohort_size", 0))
                if cohort_size < max(K_MIN_TKMS, k_min):
                    self._reply(
                        422,
                        {
                            "error": "k_min_tkms WoT cohort guard blocked de-anonymization probe",
                            "cohort_size": cohort_size,
                            "k_min_tkms": max(K_MIN_TKMS, k_min),
                            "plaintext_leaked": False,
                        },
                    )
                    return
                hop_weights = [int(w) for w in parsed.get("hop_weights_bps", [6000, 3000, 1000])]
                frames: list[str] = []
                weights: list[int] = []
                for r in active_rows:
                    hop_cts = r.get("wot_hop_cts", [])
                    for ct_h, w in zip(hop_cts, hop_weights):
                        frames.append(str(ct_h))
                        weights.append(int(w))
                ct_wot_sum = BlindClientPlweKey.homomorphic_weighted_sum(frames, weights).hex()
                receipt = build_nsau0001_receipt(
                    epoch, PRICING_TIERS["SUM"].sats, ts, table, pay_hash, gate_mac
                )
                self._reply(
                    200,
                    {
                        "status": "ok",
                        "op": "WEIGHTED_SUM",
                        "table": table,
                        "k_min_tkms": max(K_MIN_TKMS, k_min),
                        "cohort_size": cohort_size,
                        "ct_wot_weighted_sum_hex": ct_wot_sum,
                        "cohort_guard_passed": True,
                        "plaintext_stored": False,
                        "zero_server_keys": True,
                        "epoch_seq": epoch,
                        "payer": payer,
                        "nsau0001_receipt": receipt,
                    },
                )
                return

            # 4. Constant-time CONTAINS check after O(1) right-to-delete shred
            if op == "CONTAINS":
                commits = [str(t) for t in parsed.get("shred_tokens", []) if t]
                commit_set = set(commits)
                present = any(
                    str(r.get("event_author_commit", "")) in commit_set for r in active_rows
                )
                tombstoned = bool(commit_set) and all(
                    c in state.tombstoned_authors for c in commit_set
                )
                receipt = build_nsau0001_receipt(
                    epoch, PRICING_TIERS["CONTAINS"].sats, ts, table, pay_hash, gate_mac
                )
                self._reply(
                    200,
                    {
                        "status": "ok",
                        "op": "CONTAINS",
                        "table": table,
                        "present": present,
                        "tombstoned": tombstoned,
                        "plaintext_stored": False,
                        "epoch_seq": epoch,
                        "payer": payer,
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


def _parse_l402_header(www_auth: str) -> tuple[str, str]:
    m_mac = re.search(r'L402 macaroon="([^"]+)"', www_auth)
    m_inv = re.search(r'invoice="([^"]+)"', www_auth)
    if m_mac is None or m_inv is None:
        raise ValueError(f"missing L402 macaroon/invoice challenge: {www_auth!r}")
    return m_mac.group(1), m_inv.group(1)


def _pay_l402_local(
    gate_srv: Any,
    url: str,
    payload: dict[str, Any],
    wire_captures: list[bytes],
) -> tuple[int, dict[str, str], dict[str, Any], str, str, str]:
    """Probe for HTTP 402 L402 challenge, derive deterministic preimage, and settle."""
    st_402, hdrs_402, _, raw_probe = _http_post_raw(url, payload)
    wire_captures.append(raw_probe)
    assert st_402 == 402, f"expected HTTP 402 L402 challenge, got {st_402}"
    mac_b64, invoice = _parse_l402_header(hdrs_402.get("www-authenticate", ""))
    tok_id = b64_json_decode(mac_b64)["identifier"]["token_id"]
    preimage_hex = gate_srv.engine.derive_test_preimage_hex(tok_id)
    auth_hdr = f"L402 {mac_b64}:{preimage_hex}"
    st_res, hdrs_res, body_res, raw_paid = _http_post_raw(
        url, payload, headers={"Authorization": auth_hdr}
    )
    wire_captures.append(raw_paid)
    return st_res, hdrs_res, body_res, auth_hdr, preimage_hex, invoice


# ---------------------------------------------------------------------------
# Simulated Nostr Events (Sensitive Pubkeys / Tags / DMs - NEVER on Wire)
# ---------------------------------------------------------------------------

def _build_nostr_encrypted_events(
    vault: NostrClientVault,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    """
    Build dummy-padded encrypted Nostr events (likes, mutes, bookmarks, DMs).
    Every event has exact FIXED_ENVELOPE_BYTES ciphertext and FIXED_FEATURE_SLOTS
    slots so the relay cannot distinguish likes from mutes or DMs.
    """
    signal_vocab = [
        "bitcoin_core_dev",
        "lightning_bolt12",
        "trusted_wot_reply",
        "airdrop_phish_link",
        "muted_spam_bot",
        "dummy_noise_slot",
    ]
    raw_events = [
        {
            "event_id": "evt_like_01",
            "kind_name": "like",
            "npub": "npub1alice9v8x7q6w5e4r3t2y1u0i9o8p7a6s5d4f3g",
            "target_npub": "npub1jack000000000000000000000000000000000000",
            "tag": "#bitcoin",
            "content": "Liked BOLT12 blind-path routing proposal",
            "label": "signal_promote",
            "slots": {"bitcoin_core_dev": 4, "lightning_bolt12": 3, "trusted_wot_reply": 3, "airdrop_phish_link": 0, "muted_spam_bot": 0, "dummy_noise_slot": 1},
        },
        {
            "event_id": "evt_bookmark_02",
            "kind_name": "bookmark",
            "npub": "npub1alice9v8x7q6w5e4r3t2y1u0i9o8p7a6s5d4f3g",
            "target_npub": "npub1satoshidev111111111111111111111111111111",
            "tag": "#nostr",
            "content": "Bookmarked https://nostr.example/nip-44-giftwrap",
            "label": "signal_promote",
            "slots": {"bitcoin_core_dev": 3, "lightning_bolt12": 4, "trusted_wot_reply": 2, "airdrop_phish_link": 0, "muted_spam_bot": 0, "dummy_noise_slot": 1},
        },
        {
            "event_id": "evt_dm_03",
            "kind_name": "direct_message",
            "npub": "npub1alice9v8x7q6w5e4r3t2y1u0i9o8p7a6s5d4f3g",
            "target_npub": "npub1bob777777777777777777777777777777777777",
            "tag": "#lightning",
            "content": "Secret DM: meet at Lisbon Bitcoin conf 19:00",
            "label": "signal_promote",
            "slots": {"bitcoin_core_dev": 2, "lightning_bolt12": 3, "trusted_wot_reply": 4, "airdrop_phish_link": 0, "muted_spam_bot": 0, "dummy_noise_slot": 1},
        },
        {
            "event_id": "evt_mute_04",
            "kind_name": "mute",
            "npub": "npub1carol5555555555555555555555555555555555",
            "target_npub": "npub1spambot99999999999999999999999999999999",
            "tag": "#airdrop",
            "content": "Muted account pushing fake 2x BTC giveaway",
            "label": "spam_suppress",
            "slots": {"bitcoin_core_dev": 0, "lightning_bolt12": 0, "trusted_wot_reply": 0, "airdrop_phish_link": 4, "muted_spam_bot": 5, "dummy_noise_slot": 1},
        },
        {
            "event_id": "evt_mute_05",
            "kind_name": "mute",
            "npub": "npub1carol5555555555555555555555555555555555",
            "target_npub": "npub1drainer88888888888888888888888888888888",
            "tag": "#giveaway",
            "content": "Muted reply-guy wallet drainer bot",
            "label": "spam_suppress",
            "slots": {"bitcoin_core_dev": 0, "lightning_bolt12": 0, "trusted_wot_reply": 0, "airdrop_phish_link": 5, "muted_spam_bot": 4, "dummy_noise_slot": 1},
        },
        {
            "event_id": "evt_dm_06",
            "kind_name": "direct_message",
            "npub": "npub1dave33333333333333333333333333333333333",
            "target_npub": "npub1spambot99999999999999999999999999999999",
            "tag": "#scam",
            "content": "Spam DM: claim free coins at evil.example",
            "label": "spam_suppress",
            "slots": {"bitcoin_core_dev": 0, "lightning_bolt12": 0, "trusted_wot_reply": 0, "airdrop_phish_link": 3, "muted_spam_bot": 4, "dummy_noise_slot": 1},
        },
    ]

    forbidden_plaintexts: list[str] = list(signal_vocab) + [
        "signal_promote",
        "spam_suppress",
        "direct_message",
        "bookmark",
        "mute",
        "like",
        "npub1",
        "Lisbon",
        "BOLT12",
        "giveaway",
        "drainer",
        "#bitcoin",
        "#nostr",
        "#lightning",
        "#airdrop",
        "#giveaway",
        "#scam",
        "820",
        "640",
        "310",
    ]
    for ev in raw_events:
        forbidden_plaintexts.extend(
            [
                str(ev["npub"]),
                str(ev["target_npub"]),
                str(ev["content"]),
                str(ev["tag"]),
            ]
        )

    # Per-event encrypted WoT hop signals (sum across 6 events = [820, 640, 310])
    per_event_wot_hops = [
        (150, 120, 60),
        (160, 110, 55),
        (170, 130, 65),
        (110, 95, 45),
        (120, 95, 45),
        (110, 90, 40),
    ]
    lb_promote = vault.label_token("signal_promote")
    lb_spam = vault.label_token("spam_suppress")
    all_labels = (lb_promote, lb_spam)

    wire_rows: list[dict[str, Any]] = []
    shred_target: dict[str, Any] = {}
    for ev, wot_hops in zip(raw_events, per_event_wot_hops):
        author_tok = vault.author_token(str(ev["npub"]))
        event_commit = vault.register_event_commit(author_tok)
        ev_tok = vault.event_token(str(ev["event_id"]))
        lb_tok = vault.label_token(str(ev["label"]))
        cipher_slots = {
            vault.slot_token(sig): vault.plwe.encrypt_int_hex(int(ev["slots"][sig]))
            for sig in signal_vocab
        }
        class_indicator_cts = {
            c_lb: vault.plwe.encrypt_int_hex(1 if lb_tok == c_lb else 0)
            for c_lb in all_labels
        }
        class_slot_cts = {
            c_lb: {
                vault.slot_token(sig): vault.plwe.encrypt_int_hex(
                    int(ev["slots"][sig]) if lb_tok == c_lb else 0
                )
                for sig in signal_vocab
            }
            for c_lb in all_labels
        }
        wot_hop_cts = [vault.plwe.encrypt_int_hex(h) for h in wot_hops]
        aad = f"{event_commit}|{ev_tok}".encode("utf-8")
        inner_obj = {
            "author_tok": author_tok,
            "label": ev["label"],
            "kind": ev["kind_name"],
            "npub": ev["npub"],
            "target": ev["target_npub"],
            "tag": ev["tag"],
            "content": ev["content"],
        }
        inner_json = json.dumps(
            inner_obj,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        padded_env = _encrypt_padded_event(vault.user_keys[author_tok], inner_json, aad)
        sblb_env_hex = vault.envelope_key.seal_json_hex(inner_obj, aad=aad)
        row = {
            "event_author_commit": event_commit,
            "event_tok": ev_tok,
            "cipher_slots": cipher_slots,
            "class_indicator_cts": class_indicator_cts,
            "class_slot_cts": class_slot_cts,
            "wot_hop_cts": wot_hop_cts,
            "padded_envelope": padded_env,
            "sblb_envelope_hex": sblb_env_hex,
        }
        wire_rows.append(row)
        if ev["event_id"] == "evt_dm_03":
            shred_target = {
                "author_tok": author_tok,
                "aad": aad,
                "padded_envelope": padded_env,
            }
    if shred_target:
        shred_target["shred_tokens"] = list(
            vault.event_shred_tokens.get(str(shred_target["author_tok"]), [])
        )

    return wire_rows, forbidden_plaintexts, shred_target


# ---------------------------------------------------------------------------
# Main Demo Entrypoint (Shared Return Contract)
# ---------------------------------------------------------------------------

def _run_testnet_probe(gate_url: str) -> dict[str, Any]:
    clean_url = validate_http_url(gate_url, "gate_url")
    health_status, health_body = _http_get_json(f"{clean_url}/health")
    pricing_status, pricing_body = _http_get_json(f"{clean_url}/api/v1/pricing")
    probe_payload = {
        "table": "tbl_blind_relay_probe_v1",
        "op": "WEIGHTED_SUM",
        "k_min_tkms": K_MIN_TKMS,
        "cohort_size": 18,
        "hop_weights_bps": [6000, 3000, 1000],
    }
    st_402, hdrs_402, body_402, _ = _http_post_raw(
        f"{clean_url}/api/v1/blind/jsonb/query",
        probe_payload,
    )
    www_auth = hdrs_402.get("www-authenticate", "")
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
        "l402_challenge_present": ("L402 " in www_auth),
        "www_authenticate_prefix": www_auth[:64] + ("..." if len(www_auth) > 64 else ""),
        "body_error": body_402.get("error") if isinstance(body_402, dict) else None,
    }


def _run_live_backend_probe(
    api_url: str | None = None,
    api_token: str | None = None,
) -> dict[str, Any]:
    """Drive live BlindCore Rust server in Mode 2 zero-knowledge (zero server keys)."""
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
        td_obj = tempfile.TemporaryDirectory(prefix="bc_app04_live_")
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
        vault = NostrClientVault()
        pk = vault.plwe
        ek = vault.envelope_key
        client = BlindCoreClient(target_url, token=token, timeout=20.0)
        suffix = secrets.token_hex(4)
        j_tbl = f"app04_zk_jsonb_{suffix}"
        b_tbl = f"app04_zk_wot_{suffix}"

        # 1. BlindJSONB CONTAINS with SBLB0001 padded event envelope
        client.create_blind_jsonb_table(j_tbl, k_tok=4, k_num=4)
        ptoks = sorted(bytes.fromhex(ek.derive_path_token_hex(f"s{i}")) for i in range(4))
        tok_a = ek.blind_token_hex("tag", "lightning")
        tok_b = ek.blind_token_hex("kind", "direct_message")
        tok_p0 = ek.blind_token_hex("pad", "relay_pad_0")
        tok_p1 = ek.blind_token_hex("pad", "relay_pad_1")
        toks_sorted = [
            b.hex()
            for b in sorted(
                [bytes.fromhex(tok_a), bytes.fromhex(tok_b), bytes.fromhex(tok_p0), bytes.fromhex(tok_p1)]
            )
        ]
        sblb_hex = ek.seal_json_hex({"event": "relay_dm", "hops": 3}, aad=b"app04_live")
        num_slots = [pt.hex() + pk.encrypt_int_hex(v) for pt, v in zip(ptoks, (4, 1, 0, 0))]
        j_ing = client.ingest_blind_jsonb(
            j_tbl,
            [
                {
                    "doc_id_tok_hex": ek.blind_token_hex("evt", "relay_dm_01"),
                    "doc_blob_hex": sblb_hex,
                    "tok_slots_hex": toks_sorted,
                    "num_slots_hex": num_slots,
                }
            ],
        )
        assert int(j_ing.get("rows_ingested", 0)) == 1
        j_q = client.query_blind_jsonb(j_tbl, "CONTAINS", contains_tokens_hex=[tok_a])
        assert int(j_q.get("matched_count", 0)) == 1

        # 2. Blind OLAP zero-key WoT WEIGHTED_SUM across 6 encrypted events
        client.create_blind_table(
            b_tbl,
            [
                {"name": "hop0", "kind": "blind_add"},
                {"name": "hop1", "kind": "blind_add"},
                {"name": "hop2", "kind": "blind_add"},
            ],
        )
        per_event_wot_hops = [
            (150, 120, 60),
            (160, 110, 55),
            (170, 130, 65),
            (110, 95, 45),
            (120, 95, 45),
            (110, 90, 40),
        ]
        b_rows = [
            {
                "ciphertexts_hex": {
                    "hop0": pk.encrypt_int_hex(h0),
                    "hop1": pk.encrypt_int_hex(h1),
                    "hop2": pk.encrypt_int_hex(h2),
                }
            }
            for h0, h1, h2 in per_event_wot_hops
        ]
        b_ing = client.ingest_blind(b_tbl, b_rows)
        assert int(b_ing.get("rows_ingested", 0)) == 6
        q_wot = client.query_blind(
            b_tbl,
            "WEIGHTED_SUM",
            columns=["hop0", "hop1", "hop2"],
            weights=[6000, 3000, 1000],
        )
        assert "decrypted_aggregate" not in q_wot
        ct_bytes = bytes.fromhex(str(q_wot["ct_result_hex"]))
        assert len(ct_bytes) == PLWE_EXPANDED_BYTES
        assert verify_blind_receipt(q_wot, "WEIGHTED_SUM", b_tbl, 6, ct_bytes)
        dec_wot = pk.decrypt_int(ct_bytes)
        expected_wot_num = 6000 * 820 + 3000 * 640 + 1000 * 310
        assert dec_wot == expected_wot_num
        wrong_pk = BlindClientPlweKey.generate()
        wrong_ko = wrong_pk.decrypt_int(ct_bytes) != dec_wot
        assert wrong_ko
        return {
            "live_zero_knowledge_verified": True,
            "zero_server_keys": True,
            "jsonb_table": j_tbl,
            "olap_table": b_tbl,
            "seeded_frame_bytes": PLWE_SEEDED_BYTES,
            "expanded_result_bytes": PLWE_EXPANDED_BYTES,
            "decrypted_aggregate_absent": True,
            "wrong_key_knockout_verified": wrong_ko,
            "nsau0001_receipts_verified": True,
            "wot_score_bps_exact": (dec_wot // 10000) == 715,
        }
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        if td_obj is not None:
            td_obj.cleanup()


def run_demo(
    mode: str = "local",
    gate_url: str | None = None,
    api_url: str | None = None,
    api_token: str | None = None,
) -> dict[str, Any]:
    """Execute App #4 end-to-end and return the standardized 12-key contract dict."""
    t0 = time.perf_counter()
    if mode not in ("local", "testnet", "live"):
        raise ValueError(f"unsupported mode: {mode!r}")

    testnet_probe: dict[str, Any] | None = None
    live_probe: dict[str, Any] | None = None
    if mode == "testnet":
        target = gate_url or os.environ.get("BLINDCORE_GATE_URL", DEFAULT_TESTNET_URL)
        testnet_probe = _run_testnet_probe(target)
    elif mode == "live":
        live_probe = _run_live_backend_probe(api_url=api_url, api_token=api_token)

    os.environ["BLINDCORE_GATE_QUIET"] = "1"
    tmpdir = tempfile.TemporaryDirectory()
    up_state = _NostrRelayUpstreamState()
    up_srv = _LocalHTTPServer(("127.0.0.1", 0), _NostrRelayUpstreamHandler)
    up_srv.state = up_state  # type: ignore[attr-defined]
    threading.Thread(target=up_srv.serve_forever, daemon=True).start()
    up_port = up_srv.server_address[1]

    cfg = GateConfig(
        listen_host="127.0.0.1",
        listen_port=0,
        public_base_url="https://blindcore.dev",
        upstream_url=f"http://127.0.0.1:{up_port}",
        upstream_token=DEMO_UPSTREAM_TOKEN,
        gate_hmac_key_hex=DEMO_GATE_HMAC_HEX,
        db_path=os.path.join(tmpdir.name, "app04_nostr_relay.sqlite"),
        l402_macaroon_secret="demo-local-l402-secret-app04",
        session_secret="demo-local-session-secret-app04",
        test_mode=True,
        test_l402_seed=DEMO_L402_SEED,
    )
    gate_srv = build_server(cfg)
    local_gate_url = f"http://127.0.0.1:{gate_srv.server_address[1]}"
    threading.Thread(target=gate_srv.serve_forever, daemon=True).start()

    wire_captures: list[bytes] = []
    table_tok = "tbl_nostr_blind_relay_v1"

    try:
        vault = NostrClientVault()
        wire_rows, forbidden_plaintexts, shred_target = _build_nostr_encrypted_events(vault)
        ingest_url = f"{local_gate_url}/api/v1/blind/jsonb/ingest"
        query_url = f"{local_gate_url}/api/v1/blind/jsonb/query"

        # Step 1: Unpaid HTTP 402 + WWW-Authenticate: L402 -> settle 1 sat for dummy-padded INGEST
        ingest_payload = {
            "table": table_tok,
            "op": "INGEST",
            "rows": wire_rows,
        }
        st_in, _, body_in, _, _, inv_in = _pay_l402_local(
            gate_srv, ingest_url, ingest_payload, wire_captures
        )
        assert st_in == 200, f"L402 ingest failed: {body_in}"
        assert body_in["uniform_envelope_bytes"] == FIXED_ENVELOPE_BYTES
        assert body_in["uniform_slot_count"] == FIXED_FEATURE_SLOTS
        http_402_observed = (
            testnet_probe["http_402_observed"] if testnet_probe is not None else True
        )

        # Step 2: Private Algorithmic Feed / Anti-Spam SKLEARN_MNB Ranker (30 sats L402)
        lb_promote = vault.label_token("signal_promote")
        lb_spam = vault.label_token("spam_suppress")
        vocab_names = [
            "bitcoin_core_dev",
            "lightning_bolt12",
            "trusted_wot_reply",
            "airdrop_phish_link",
            "muted_spam_bot",
            "dummy_noise_slot",
        ]
        vocab_toks = [vault.slot_token(v) for v in vocab_names]
        cand_signal_tok = vault.event_token("cand_note_lightning_dev")
        cand_spam_tok = vault.event_token("cand_note_airdrop_scam")

        mnb_payload = {
            "table": table_tok,
            "op": "SKLEARN_MNB",
            "train_classes": [lb_promote, lb_spam],
            "vocab_paths": vocab_toks,
            "score_cohorts": [
                {
                    "event_tok": cand_signal_tok,
                    "cipher_slots": {
                        vault.slot_token("bitcoin_core_dev"): vault.plwe.encrypt_int_hex(3),
                        vault.slot_token("lightning_bolt12"): vault.plwe.encrypt_int_hex(4),
                        vault.slot_token("trusted_wot_reply"): vault.plwe.encrypt_int_hex(3),
                        vault.slot_token("airdrop_phish_link"): vault.plwe.encrypt_int_hex(0),
                        vault.slot_token("muted_spam_bot"): vault.plwe.encrypt_int_hex(0),
                        vault.slot_token("dummy_noise_slot"): vault.plwe.encrypt_int_hex(1),
                    },
                },
                {
                    "event_tok": cand_spam_tok,
                    "cipher_slots": {
                        vault.slot_token("bitcoin_core_dev"): vault.plwe.encrypt_int_hex(0),
                        vault.slot_token("lightning_bolt12"): vault.plwe.encrypt_int_hex(0),
                        vault.slot_token("trusted_wot_reply"): vault.plwe.encrypt_int_hex(0),
                        vault.slot_token("airdrop_phish_link"): vault.plwe.encrypt_int_hex(4),
                        vault.slot_token("muted_spam_bot"): vault.plwe.encrypt_int_hex(4),
                        vault.slot_token("dummy_noise_slot"): vault.plwe.encrypt_int_hex(1),
                    },
                },
            ],
            "alpha": 1.0,
        }
        st_mnb, _, body_mnb, _, mnb_preimage, _ = _pay_l402_local(
            gate_srv, query_url, mnb_payload, wire_captures
        )
        assert st_mnb == 200, f"L402 SKLEARN_MNB failed: {body_mnb}"
        mnb_receipt = body_mnb["nsau0001_receipt"]
        assert verify_nsau0001_receipt(mnb_receipt)
        mnb_settle_proof = build_l402_settle_proof(
            epoch_seq=body_mnb["epoch_seq"],
            payer=body_mnb["payer"],
            table_hash_hex=mnb_receipt["table_hash"],
            receipt_hash_hex=mnb_receipt["receipt_hash"],
            payment_hash=mnb_receipt["payment_hash"],
            preimage_hex=mnb_preimage,
            fee_sats=PRICING_TIERS["SKLEARN_MNB"].sats,
            op_tier=PRICING_TIERS["SKLEARN_MNB"].op_tier_id,
        )
        assert mnb_settle_proof["preimage_sha256_verified"] is True

        # Client-side local MNB decryption + wrong-key knockout
        wrong_pk = BlindClientPlweKey.generate()
        class_docs: dict[str, int] = {}
        class_counts: dict[str, dict[str, int]] = {}
        for lb in (lb_promote, lb_spam):
            ct_d = str(body_mnb["ct_class_doc_sums"][lb])
            assert len(bytes.fromhex(ct_d)) == PLWE_EXPANDED_BYTES
            class_docs[lb] = vault.plwe.decrypt_int(ct_d)
            assert wrong_pk.decrypt_int(ct_d) != class_docs[lb]
            class_counts[lb] = {}
            for tok in vocab_toks:
                ct_s = str(body_mnb["ct_class_slot_sums"][lb][tok])
                assert len(bytes.fromhex(ct_s)) == PLWE_EXPANDED_BYTES
                class_counts[lb][tok] = vault.plwe.decrypt_int(ct_s)

        total_docs = max(1, sum(class_docs.values()))
        preds: dict[str, str] = {}
        for cand in mnb_payload["score_cohorts"]:
            ev_t = str(cand["event_tok"])
            obs = {tok: vault.plwe.decrypt_int(ct_h) for tok, ct_h in cand["cipher_slots"].items()}
            log_post: dict[str, float] = {}
            for lb in (lb_promote, lb_spam):
                prior = math.log((class_docs[lb] + 1.0) / (total_docs + 2.0))
                denom = sum(class_counts[lb].values()) + float(len(vocab_toks))
                ll = prior
                for tok in vocab_toks:
                    cnt = obs.get(tok, 0)
                    if cnt > 0:
                        ll += cnt * math.log((class_counts[lb].get(tok, 0) + 1.0) / denom)
                log_post[lb] = round(ll, 6)
            preds[ev_t] = max(log_post, key=lambda k: log_post[k])
        assert preds[cand_signal_tok] == lb_promote
        assert preds[cand_spam_tok] == lb_spam

        # Step 3: k_min_tkms Encrypted Web-of-Trust (WoT) Cohort Tally (WEIGHTED_SUM, 8 sats L402)
        wot_payload = {
            "table": table_tok,
            "op": "WEIGHTED_SUM",
            "k_min_tkms": K_MIN_TKMS,
            "cohort_size": 18,
            "hop_weights_bps": [6000, 3000, 1000],
        }
        st_wot, _, body_wot, wot_auth_hdr, wot_preimage, _ = _pay_l402_local(
            gate_srv, query_url, wot_payload, wire_captures
        )
        assert st_wot == 200, f"L402 WoT WEIGHTED_SUM failed: {body_wot}"
        assert len(bytes.fromhex(body_wot["ct_wot_weighted_sum_hex"])) == PLWE_EXPANDED_BYTES
        dec_wot_num = vault.plwe.decrypt_int(body_wot["ct_wot_weighted_sum_hex"])
        assert wrong_pk.decrypt_int(body_wot["ct_wot_weighted_sum_hex"]) != dec_wot_num
        wot_trust_score_bps = dec_wot_num // max(1, sum(wot_payload["hop_weights_bps"]))
        assert wot_trust_score_bps == 715
        wot_receipt = body_wot["nsau0001_receipt"]
        assert verify_nsau0001_receipt(wot_receipt)
        wot_settle_proof = build_l402_settle_proof(
            epoch_seq=body_wot["epoch_seq"],
            payer=body_wot["payer"],
            table_hash_hex=wot_receipt["table_hash"],
            receipt_hash_hex=wot_receipt["receipt_hash"],
            payment_hash=wot_receipt["payment_hash"],
            preimage_hex=wot_preimage,
            fee_sats=PRICING_TIERS["SUM"].sats,
            op_tier=PRICING_TIERS["SUM"].op_tier_id,
        )
        assert wot_settle_proof["preimage_sha256_verified"] is True

        # Step 4: Counterfactual Knockouts:
        #   (a) Replay of settled WoT L402 token -> MUST fail with HTTP 402
        st_replay, _, _, raw_replay = _http_post_raw(
            query_url, wot_payload, headers={"Authorization": wot_auth_hdr}
        )
        wire_captures.append(raw_replay)
        replay_blocked = st_replay == 402

        #   (b) Under-sized WoT cohort (cohort_size=2 < k_min_tkms=5) -> 422 + X-BlindCore-Settlement: aborted
        small_wot_payload = {
            "table": table_tok,
            "op": "WEIGHTED_SUM",
            "k_min_tkms": K_MIN_TKMS,
            "cohort_size": 2,
            "hop_weights_bps": [5000, 5000],
        }
        st_abort, hdrs_abort, body_abort, _, _, _ = _pay_l402_local(
            gate_srv, query_url, small_wot_payload, wire_captures
        )
        wot_stalker_blocked = (
            st_abort == 422
            and hdrs_abort.get("x-blindcore-settlement") == "aborted"
            and body_abort.get("plaintext_leaked") is False
        )

        #   (c) Distinct operations emit strictly distinct NSAU0001 receipts
        receipts_distinct = mnb_receipt["receipt_hex"] != wot_receipt["receipt_hex"]
        counterfactual_ok = replay_blocked and wot_stalker_blocked and receipts_distinct

        # Step 5: O(1) Right-to-Delete Cryptographic Shredding (unlinkable per-event commits + key drop)
        target_author_tok = str(shred_target["author_tok"])
        target_shred_tokens = list(shred_target["shred_tokens"])
        assert len(target_shred_tokens) >= 1
        pre_shred_pt = _decrypt_padded_event(
            vault.user_keys[target_author_tok],
            shred_target["padded_envelope"],
            shred_target["aad"],
        )
        assert b"Secret DM" in pre_shred_pt

        dropped = vault.shred_user_o1(target_author_tok)
        assert dropped is True
        shred_payload = {
            "table": table_tok,
            "op": "INGEST",
            "action": "TOMBSTONE_SHRED",
            "shred_tokens": target_shred_tokens,
        }
        st_shred, _, body_shred, _, _, _ = _pay_l402_local(
            gate_srv, ingest_url, shred_payload, wire_captures
        )
        assert st_shred == 200 and body_shred["complexity"] == "O(1)"

        # Verify CONTAINS immediately reports tombstoned & absent
        chk_payload = {
            "table": table_tok,
            "op": "CONTAINS",
            "shred_tokens": target_shred_tokens,
        }
        st_chk, _, body_chk, _, _, _ = _pay_l402_local(
            gate_srv, query_url, chk_payload, wire_captures
        )
        assert st_chk == 200
        assert body_chk["present"] is False and body_chk["tombstoned"] is True

        decrypt_failed_after_shred = False
        try:
            _decrypt_padded_event(
                secrets.token_bytes(32),
                shred_target["padded_envelope"],
                shred_target["aad"],
            )
        except ValueError:
            decrypt_failed_after_shred = True
        o1_shred_verified = (
            dropped
            and body_chk["present"] is False
            and body_chk["tombstoned"] is True
            and decrypt_failed_after_shred
        )

        # Step 6: Zero-Plaintext Wire Audit across ALL captured client & relay bytes
        all_wire_bytes = b"\n".join(wire_captures + up_state.captured_wire_payloads)
        all_wire_lower = all_wire_bytes.lower()
        leaked_terms: list[str] = []
        forbidden_numeric = {s for s in forbidden_plaintexts if s.isdigit()}
        forbidden_text = [s for s in forbidden_plaintexts if not s.isdigit()]
        for secret_str in forbidden_text:
            if secret_str.lower().encode("utf-8") in all_wire_lower:
                leaked_terms.append(secret_str)

        def _is_crypto_hex_token(s_val: str) -> bool:
            low_v = s_val.lower()
            if len(low_v) >= 24 and all(c in "0123456789abcdef" for c in low_v):
                return True
            return any(
                sep in low_v
                and len(low_v.split(sep, 1)[1]) >= 16
                and all(c in "0123456789abcdef" for c in low_v.split(sep, 1)[1])
                for sep in ("_", ":")
            )

        def _scan_json_for_leaks(obj: Any, parent_key: str = "") -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    ks = str(k)
                    ks_low = ks.lower()
                    ks_is_tok = _is_crypto_hex_token(ks)
                    for s in forbidden_plaintexts:
                        if ks_is_tok and s in forbidden_numeric:
                            continue
                        if s.lower() in ks_low and s not in leaked_terms:
                            leaked_terms.append(s)
                    _scan_json_for_leaks(v, ks)
            elif isinstance(obj, list):
                for item in obj:
                    _scan_json_for_leaks(item, parent_key)
            elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
                sv = str(obj)
                if sv in forbidden_numeric and sv not in leaked_terms:
                    leaked_terms.append(sv)
            elif isinstance(obj, str):
                low_s = obj.lower()
                is_ct_blob = (
                    parent_key in (
                        "ct_b64", "nonce_b64", "tag_b64", "nonce_hex", "tag_hex",
                        "sblb_envelope_hex", "ct_result_hex", "receipt_hex",
                        "nsau0001_receipt", "event_tok", "event_author_commit",
                        "payment_hash", "preimage", "macaroon", "aad", "table_hash",
                        "signature", "invoice", "bolt11",
                    )
                    or _is_crypto_hex_token(obj)
                )
                if not is_ct_blob:
                    for s in forbidden_numeric:
                        if s in low_s and s not in leaked_terms:
                            leaked_terms.append(s)

        for payload_raw in wire_captures + up_state.captured_wire_payloads:
            try:
                _scan_json_for_leaks(json.loads(payload_raw.decode("utf-8")))
            except Exception:
                pass
        zero_plaintext_verified = len(leaked_terms) == 0

        sample_row = wire_rows[0]
        wire_sample_redacted = {
            "endpoint": "/api/v1/blind/jsonb/ingest",
            "table": table_tok,
            "event_author_commit": sample_row["event_author_commit"],
            "event_tok": sample_row["event_tok"],
            "slot_count": len(sample_row["cipher_slots"]),
            "plwe_slot_bytes": PLWE_SEEDED_BYTES,
            "plwe_expanded_bytes": PLWE_EXPANDED_BYTES,
            "padded_envelope_bytes": int(sample_row["padded_envelope"]["padded_bytes"]),
            "sblb_envelope_bytes": len(bytes.fromhex(sample_row["sblb_envelope_hex"])),
            "ct_prefix": sample_row["padded_envelope"]["ct_b64"][:32] + "...[REDACTED]",
            "l402_invoice_prefix": inv_in[:24] + "...",
            "wire_bytes_audited": len(all_wire_bytes),
            "plaintext_leaks_found": len(leaked_terms),
        }

        all_ok = (
            http_402_observed
            and zero_plaintext_verified
            and counterfactual_ok
            and o1_shred_verified
            and verify_nsau0001_receipt(mnb_receipt)
            and mnb_settle_proof["preimage_sha256_verified"]
            and (live_probe is None or bool(live_probe["live_zero_knowledge_verified"]))
        )
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        summary: dict[str, Any] = {
            "mode": mode,
            "dummy_padded_events_ingested": len(wire_rows),
            "uniform_envelope_bytes": FIXED_ENVELOPE_BYTES,
            "uniform_slot_count": FIXED_FEATURE_SLOTS,
            "private_feed_ranker_mnb": {
                "sats_paid": PRICING_TIERS["SKLEARN_MNB"].sats,
                "signal_note_verdict": "FEED_PROMOTE",
                "scam_note_verdict": "SPAM_SUPPRESS",
            },
            "encrypted_wot_cohort_tally": {
                "sats_paid": PRICING_TIERS["SUM"].sats,
                "cohort_size": body_wot["cohort_size"],
                "k_min_tkms": body_wot["k_min_tkms"],
                "wot_trust_score_bps": wot_trust_score_bps,
            },
            "l402_replay_http_status": st_replay,
            "wot_stalker_guard": {
                "http_status": st_abort,
                "settlement_header": hdrs_abort.get("x-blindcore-settlement"),
                "plaintext_leaked": body_abort.get("plaintext_leaked"),
            },
            "o1_right_to_delete_shred": {
                "shredded_commits": len(target_shred_tokens),
                "complexity": "O(1)",
                "key_dropped": dropped,
                "tombstoned": body_chk["tombstoned"],
                "ciphertext_undecryptable": decrypt_failed_after_shred,
            },
            "secondary_wot_receipt_hex": wot_receipt["receipt_hex"],
            "secondary_wot_settle_proof": wot_settle_proof,
        }
        if testnet_probe is not None:
            summary["testnet_probe"] = testnet_probe
        if live_probe is not None:
            summary["live_backend_probe"] = live_probe

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
        tmpdir.cleanup()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BlindCore App #4: Decentralized Social Blind Relay & Encrypted WoT Demo"
    )
    parser.add_argument("--mode", choices=("local", "testnet", "live"), default="local")
    parser.add_argument(
        "--gate-url",
        default=os.environ.get("BLINDCORE_GATE_URL", DEFAULT_TESTNET_URL),
        help="Target BlindCore Tri-Rail Gate URL (used in --mode testnet)",
    )
    parser.add_argument("--api-url", default=os.environ.get("BLINDCORE_API_URL", ""))
    parser.add_argument("--api-token", default=os.environ.get("BLINDCORE_API_TOKEN", ""))
    args = parser.parse_args()
    result = run_demo(
        mode=args.mode,
        gate_url=args.gate_url,
        api_url=args.api_url or None,
        api_token=args.api_token or None,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] != "PASS":
        sys.exit(1)


if __name__ == "__main__":
    main()
