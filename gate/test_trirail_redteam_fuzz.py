#!/usr/bin/env python3
"""
Red-Team Security & Zipfian Concurrency Fuzz Suite for BlindCore Tri-Rail Gateway.
Copyright 2026 Blind Labs (https://blindlabs.ai). Licensed under the Apache License, Version 2.0.

Executes >= 10,000 deterministic SplitMix64 + Zipfian (s in [1.0, 1.25, 1.5])
and adversarial probes covering:
  1. Zipfian heavy-hitter replay & ledger conservation (exact balance, no SETTLED->ABORTED)
  2. Chained-HMAC L402 macaroon caveat-append privilege escalation & parser fuzz
  3. Base x402 v2/v1 type confusion, boundary overflow, & facilitator endpoint guard
  4. Stacks sBTC/STX SSRF/traversal txids, asset_id prefix spoofing, & Hiro amplification block
  5. Header spoofing, X-Forwarded-For rate-limit bypass, Transfer-Encoding smuggling, path traversal
  6. Concurrent multi-thread replay races (x402, L402, Stacks) & credit debit races
  7. Static Solidity (BlindCoreRootAnchor.sol) & Clarity (blindcore-root-anchor.clar) invariants
  8. MCP server & Coinbase AgentKit SSRF, header injection, param overwrite, & stale-session fix
  9. Counterfactual knockouts (assertNotEqual across MACs, secrets, rails, payers)
"""

from __future__ import annotations

import bisect
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import secrets
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gate.blindcore_trirail_gate import (  # noqa: E402
    BASE_MAINNET_CAIP2,
    EdgeRateLimiter,
    GateConfig,
    MAX_MICRO_USDC,
    MAX_SATS,
    MAX_USTX,
    PRICING_TIERS,
    PaymentLedger,
    PaymentRejected,
    STACKS_SBTC_MAINNET,
    TriRailEngine,
    b64_json_decode,
    b64_json_encode,
    b64url_decode,
    build_server,
    normalize_txid,
    sanitize_content_type,
    sanitize_upstream_headers,
    sha256_hex,
    validate_http_url,
    validate_request_path,
)
from mcp.agentkit_provider import BlindCoreActionProvider  # noqa: E402
from mcp.mcp_server import (  # noqa: E402
    BlindCoreHttpClient,
    _sanitize_payment_headers,
    _validate_api_path,
    _validate_base_url,
    handle_rpc_request,
)


# ---------------------------------------------------------------------------
# Deterministic SplitMix64 PRNG & Zipfian Sampler (s in [1.0, 1.25, 1.5])
# ---------------------------------------------------------------------------

class SplitMix64:
    """Deterministic 64-bit SplitMix64 PRNG for reproducible fuzz runs."""

    MASK64 = (1 << 64) - 1

    def __init__(self, seed: int) -> None:
        self.state = seed & self.MASK64

    def next_u64(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & self.MASK64
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & self.MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & self.MASK64
        return (z ^ (z >> 31)) & self.MASK64

    def next_float(self) -> float:
        return (self.next_u64() >> 11) * (1.0 / (1 << 53))

    def randrange(self, n: int) -> int:
        return self.next_u64() % n

    def choice(self, seq: list | tuple) -> object:
        return seq[self.randrange(len(seq))]

    def hex_bytes(self, nbytes: int) -> str:
        out = bytearray()
        while len(out) < nbytes:
            out.extend(self.next_u64().to_bytes(8, "big"))
        return bytes(out[:nbytes]).hex()


class ZipfSampler:
    """Fast O(log N) discrete Zipf(n, s) sampler backed by SplitMix64."""

    def __init__(self, n: int, s: float, rng: SplitMix64) -> None:
        self.n = n
        self.s = s
        self.rng = rng
        weights = [1.0 / ((k + 1) ** s) for k in range(n)]
        total = sum(weights)
        cdf: list[float] = []
        acc = 0.0
        for w in weights:
            acc += w / total
            cdf.append(acc)
        cdf[-1] = 1.0
        self.cdf = cdf

    def sample(self) -> int:
        u = self.rng.next_float()
        return bisect.bisect_left(self.cdf, u)


# ---------------------------------------------------------------------------
# Minimal Thread-Safe Mock Servers for Live Red-Team & Concurrency Tests
# ---------------------------------------------------------------------------

UPSTREAM_TOKEN = "redteam-loopback-bearer-secret"
GATE_HMAC_HEX = "22" * 32
BASE_PAY_TO = "0x1111111111111111111111111111111111111111"
STACKS_PAY_TO = "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7"
PAYER_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
PAYER_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
PAYER_STX = "SP3FGQ8Z7JY9BWYZ5WM53E0M9NK7WHJF0691NZ159"


class RedTeamUpstreamState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.records: list[dict[str, object]] = []


class RedTeamUpstreamHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b""
        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {UPSTREAM_TOKEN}":
            self._reply(401, {"error": "wrong upstream bearer"})
            return

        # Verify NO client payment header leaked
        for leaked in ("PAYMENT-SIGNATURE", "X-PAYMENT", "X-Stacks-Payment-Tx", "X-BlindCore-Session"):
            if self.headers.get(leaked):
                self._reply(400, {"error": f"leaked {leaked}"})
                return

        rail = self.headers.get("X-BlindCore-Rail", "")
        payer = self.headers.get("X-BlindCore-Payer", "")
        pay_hash = self.headers.get("X-BlindCore-Payment-Hash", "")
        fee_micro = self.headers.get("X-BlindCore-Fee-Micro", "")
        ts = self.headers.get("X-BlindCore-Ts", "")
        gate_mac = self.headers.get("X-BlindCore-Gate-Mac", "")
        ct = self.headers.get("Content-Type", "")

        body_hash = sha256_hex(body)
        expected_mac = hmac.new(
            bytes.fromhex(GATE_HMAC_HEX),
            f"{rail}|{payer}|{pay_hash}|{fee_micro}|{ts}|{body_hash}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(gate_mac, expected_mac):
            self._reply(403, {"error": "invalid gate mac"})
            return

        rec = {
            "path": self.path,
            "rail": rail,
            "payer": payer,
            "payment_hash": pay_hash,
            "fee_micro": fee_micro,
            "gate_mac": gate_mac,
            "content_type": ct,
            "has_spoof_hdr": self.headers.get("X-BlindCore-Spoof") is not None,
        }
        with self.server.state.lock:  # type: ignore[attr-defined]
            self.server.state.records.append(rec)  # type: ignore[attr-defined]

        # Small sleep on concurrency tests to widen race window intentionally
        parsed = json.loads(body.decode("utf-8")) if body else {}
        if parsed.get("race_delay_ms"):
            time.sleep(float(parsed["race_delay_ms"]) / 1000.0)

        self._reply(
            200,
            {
                "status": "ok",
                "rail": rail,
                "payer": payer,
                "payment_hash": pay_hash,
                "gate_mac": gate_mac,
                "content_type": ct,
                "has_spoof_hdr": rec["has_spoof_hdr"],
                "receipt_hex": sha256_hex(f"RT:{rail}:{payer}:{pay_hash}:{body_hash}".encode("utf-8")),
            },
        )

    def _reply(self, status: int, obj: dict[str, object]) -> None:
        raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class RedTeamFacilitatorState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.verify_calls = 0
        self.settle_calls = 0
        self.override_payer: str | None = None


class RedTeamFacilitatorHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        data = json.loads(self.rfile.read(length).decode("utf-8"))
        st: RedTeamFacilitatorState = self.server.state  # type: ignore[attr-defined]
        pp = data.get("paymentPayload") or {}
        payload = pp.get("payload") or {}
        auth = payload.get("authorization") or payload.get("permit") or {}
        sig = str(payload.get("signature") or "")
        payer = str(auth.get("from") or auth.get("owner") or "")
        nonce = str(auth.get("nonce") or "")
        if self.path == "/verify":
            with st.lock:
                st.verify_calls += 1
                reported_payer = st.override_payer if st.override_payer is not None else payer
            ok = sig.startswith("0xvalid")
            self._reply(200, {"isValid": ok, "payer": reported_payer})
            return
        if self.path == "/settle":
            with st.lock:
                st.settle_calls += 1
            self._reply(
                200,
                {"success": True, "transaction": "0x" + sha256_hex(f"settle:{payer}:{nonce}".encode("utf-8"))},
            )
            return
        self._reply(404, {"error": "unknown"})

    def _reply(self, status: int, obj: dict[str, object]) -> None:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class RedTeamStacksState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.txs: dict[str, dict[str, object]] = {}
        self.fetch_count = 0


class RedTeamStacksHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        st: RedTeamStacksState = self.server.state  # type: ignore[attr-defined]
        with st.lock:
            st.fetch_count += 1
        prefix = "/extended/v1/tx/"
        if not self.path.startswith(prefix):
            self._reply(404, {"error": "not found"})
            return
        txid = self.path[len(prefix):].lower()
        if txid.startswith("0x"):
            txid = txid[2:]
        tx = st.txs.get(txid)
        if tx is None:
            self._reply(404, {"error": "not found"})
            return
        self._reply(200, tx)

    def _reply(self, status: int, obj: dict[str, object]) -> None:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class _PooledHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


def _start_srv(handler_cls: type[BaseHTTPRequestHandler], state: object) -> tuple[ThreadingHTTPServer, int]:
    srv = _PooledHTTPServer(("127.0.0.1", 0), handler_cls)
    srv.state = state  # type: ignore[attr-defined]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


# ---------------------------------------------------------------------------
# Red-Team & Zipfian Fuzz Suite (>= 10,000 probes)
# ---------------------------------------------------------------------------

class TriRailRedTeamFuzzSuite(unittest.TestCase):
    total_probes = 0

    @classmethod
    def setUpClass(cls) -> None:
        os.environ["BLINDCORE_GATE_QUIET"] = "1"
        cls.tmpdir = tempfile.TemporaryDirectory()
        cls.up_state = RedTeamUpstreamState()
        cls.up_srv, cls.up_port = _start_srv(RedTeamUpstreamHandler, cls.up_state)

        cls.fac_state = RedTeamFacilitatorState()
        cls.fac_srv, cls.fac_port = _start_srv(RedTeamFacilitatorHandler, cls.fac_state)

        cls.stx_state = RedTeamStacksState()
        cls.stx_srv, cls.stx_port = _start_srv(RedTeamStacksHandler, cls.stx_state)

        cls.db_path = os.path.join(cls.tmpdir.name, "gate_fuzz.sqlite")
        cfg = GateConfig(
            listen_host="127.0.0.1",
            listen_port=0,
            public_base_url="https://blindcore.dev",
            upstream_url=f"http://127.0.0.1:{cls.up_port}",
            upstream_token=UPSTREAM_TOKEN,
            gate_hmac_key_hex=GATE_HMAC_HEX,
            db_path=cls.db_path,
            base_network=BASE_MAINNET_CAIP2,
            base_pay_to=BASE_PAY_TO,
            x402_facilitator_url=f"http://127.0.0.1:{cls.fac_port}",
            l402_macaroon_secret="redteam-l402-secret-key-01",
            stacks_network="mainnet",
            stacks_api_url=f"http://127.0.0.1:{cls.stx_port}",
            stacks_pay_to=STACKS_PAY_TO,
            stacks_sbtc_contract=STACKS_SBTC_MAINNET,
            session_secret="redteam-session-secret-key-01",
            rate_limit_rpm=10_000,
            bad_payment_limit=10_000,
            trust_proxy_headers=False,
            test_mode=True,
            test_l402_seed="redteam-deterministic-l402-seed",
        )
        cls.gate_srv = build_server(cfg)
        cls.gate_port = cls.gate_srv.server_address[1]
        cls.gate_url = f"http://127.0.0.1:{cls.gate_port}"
        cls.gate_thread = threading.Thread(target=cls.gate_srv.serve_forever, daemon=True)
        cls.gate_thread.start()

        # Secondary strict-rate-limit gate for X-Forwarded-For lockout bypass tests
        cls.rl_db_path = os.path.join(cls.tmpdir.name, "rl_fuzz.sqlite")
        rl_cfg = GateConfig(
            listen_host="127.0.0.1",
            listen_port=0,
            public_base_url="https://blindcore.dev",
            upstream_url=f"http://127.0.0.1:{cls.up_port}",
            upstream_token=UPSTREAM_TOKEN,
            gate_hmac_key_hex=GATE_HMAC_HEX,
            db_path=cls.rl_db_path,
            base_network=BASE_MAINNET_CAIP2,
            base_pay_to=BASE_PAY_TO,
            x402_facilitator_url=f"http://127.0.0.1:{cls.fac_port}",
            l402_macaroon_secret="redteam-l402-secret-key-02",
            stacks_network="mainnet",
            stacks_api_url=f"http://127.0.0.1:{cls.stx_port}",
            stacks_pay_to=STACKS_PAY_TO,
            stacks_sbtc_contract=STACKS_SBTC_MAINNET,
            session_secret="redteam-session-secret-key-02",
            rate_limit_rpm=500,
            bad_payment_limit=3,
            bad_payment_window_secs=60,
            trust_proxy_headers=False,
            test_mode=True,
        )
        cls.rl_srv = build_server(rl_cfg)
        cls.rl_url = f"http://127.0.0.1:{cls.rl_srv.server_address[1]}"
        threading.Thread(target=cls.rl_srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        for srv in (cls.gate_srv, cls.rl_srv):
            srv.shutdown()
            srv.server_close()
            srv.engine.close()
        for srv in (cls.up_srv, cls.fac_srv, cls.stx_srv):
            srv.shutdown()
            srv.server_close()
        cls.tmpdir.cleanup()
        print(f"\n[REDTEAM-FUZZ] Total deterministic probes executed: {cls.total_probes}", flush=True)

    def _bump(self, count: int = 1) -> None:
        type(self).total_probes += count

    def _http(
        self,
        method: str,
        path: str,
        body: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
        base_url: str | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        hdrs = dict(headers or {})
        raw = None
        if body is not None:
            raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(f"{base_url or self.gate_url}{path}", data=raw, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return int(resp.status), {k.lower(): v for k, v in resp.headers.items()}, resp.read()
        except urllib.error.HTTPError as exc:
            return int(exc.code), {k.lower(): v for k, v in exc.headers.items()}, exc.read()

    def _make_x402_obj(
        self,
        payer: str,
        value: object,
        nonce: str | None = None,
        version: object = 2,
        scheme: str = "exact",
        sig_type: str = "eip3009",
        valid_sig: bool = True,
        to_addr: str = BASE_PAY_TO,
        valid_after: object | None = None,
        valid_before: object | None = None,
        accepted_pay_to: object | None = BASE_PAY_TO,
        accepted_amount: object | None = None,
    ) -> dict[str, object]:
        now = int(time.time())
        n = nonce if nonce is not None else ("0x" + secrets.token_hex(32))
        sig = ("0xvalid" if valid_sig else "0xbad") + ("cd" * 32)
        va = (now - 10) if valid_after is None else valid_after
        vb = (now + 120) if valid_before is None else valid_before
        accepted: dict[str, object] = {
            "scheme": scheme,
            "network": BASE_MAINNET_CAIP2,
        }
        if accepted_pay_to is not None:
            accepted["payTo"] = accepted_pay_to
        if accepted_amount is not None:
            accepted["amount"] = accepted_amount
        elif isinstance(value, int) and not isinstance(value, bool) and value > 0:
            accepted["amount"] = str(value)
        return {
            "x402Version": version,
            "scheme": scheme,
            "network": BASE_MAINNET_CAIP2,
            "accepted": accepted,
            "payload": {
                "signature": sig,
                "signatureType": sig_type,
                "authorization": {
                    "from": payer,
                    "to": to_addr,
                    "value": value,
                    "validAfter": va,
                    "validBefore": vb,
                    "nonce": n,
                },
            },
        }

    def _register_sbtc_tx(
        self,
        amount_sats: int,
        asset_id: str | None = None,
        tx_id_override: str | None = None,
        sender: str = PAYER_STX,
        recipient: str = STACKS_PAY_TO,
        events: list[dict[str, object]] | None = None,
    ) -> str:
        txid = secrets.token_hex(32)
        ev_list = events if events is not None else [
            {
                "event_type": "fungible_token_asset",
                "asset": {
                    "asset_id": asset_id or f"{STACKS_SBTC_MAINNET}::sbtc-token",
                    "recipient": recipient,
                    "amount": str(amount_sats),
                },
            }
        ]
        self.stx_state.txs[txid] = {
            "tx_id": tx_id_override or f"0x{txid}",
            "tx_status": "success",
            "tx_type": "contract_call",
            "sender_address": sender,
            "contract_call": {
                "contract_id": STACKS_SBTC_MAINNET,
                "function_name": "transfer",
                "function_args": [
                    {"name": "amount", "repr": f"u{amount_sats}"},
                    {"name": "sender", "repr": f"'{sender}"},
                    {"name": "recipient", "repr": f"'{recipient}"},
                ],
            },
            "events": ev_list,
        }
        return txid

    # -- 1. Zipfian Heavy-Hitter Ledger Replay, Downgrade Immunity & Bounds --

    def test_01_zipfian_ledger_replay_and_conservation(self) -> None:
        """4,200 SplitMix64 + Zipfian (s in [1.0, 1.25, 1.5]) ledger probes."""
        rng = SplitMix64(0xB11DC0DE0001)
        ledger = PaymentLedger(":memory:")
        try:
            rails = ("base-x402", "ln-l402", "stacks-sbtc")
            # Test across all 3 Zipf exponents s in [1.0, 1.25, 1.5]
            expected_bal: dict[str, int] = {}
            for s in (1.0, 1.25, 1.5):
                zipf = ZipfSampler(128, s, rng)
                settled: set[tuple[str, str]] = set()
                aborted: set[tuple[str, str]] = set()
                for step in range(1_200):
                    idx = zipf.sample()
                    rail = rails[idx % 3]
                    phash = f"z{int(s*100)}_{idx:04d}_" + "a" * 50
                    payer = f"payer_{idx % 16:02d}"
                    ok = ledger.reserve_payment(rail, phash, payer, int(time.time()) + 600)
                    if (rail, phash) in settled:
                        self.assertFalse(ok, "SETTLED payment must never be re-reserved")
                        # Attempt forbidden SETTLED -> ABORTED downgrade
                        self.assertFalse(ledger.mark_aborted(rail, phash))
                    elif ok:
                        if step % 5 == 0:
                            # Abort and verify it can be cleanly re-attempted later
                            self.assertTrue(ledger.mark_aborted(rail, phash))
                            aborted.add((rail, phash))
                        else:
                            # Atomic settle + credit top-up
                            amt = 5_000 + (idx * 100)
                            new_bal = ledger.settle_and_credit_deposit(payer, rail, phash, amt)
                            expected_bal[payer] = expected_bal.get(payer, 0) + amt
                            self.assertEqual(new_bal, expected_bal[payer])
                            settled.add((rail, phash))
                            aborted.discard((rail, phash))
                            # Immediate SETTLED -> ABORTED attempt must fail
                            self.assertFalse(ledger.mark_aborted(rail, phash))
                            # Double-credit replay via settle_and_credit_deposit must fail
                            with self.assertRaises(PaymentRejected):
                                ledger.settle_and_credit_deposit(payer, rail, phash, amt)
                    # Periodic debit + idempotent refund conservation check
                    if step % 3 == 0 and expected_bal.get(payer, 0) >= 1_000:
                        deb_ok, rem, seq = ledger.debit_credit(payer, 1_000, "CONTAINS")
                        self.assertTrue(deb_ok)
                        expected_bal[payer] -= 1_000
                        self.assertEqual(rem, expected_bal[payer])
                        if step % 9 == 0:
                            # Refund twice with same debit_seq -> MUST credit only once!
                            b1 = ledger.refund_credit(payer, 1_000, "refund:CONTAINS", debit_seq=seq)
                            b2 = ledger.refund_credit(payer, 1_000, "refund:CONTAINS", debit_seq=seq)
                            expected_bal[payer] += 1_000
                            self.assertEqual(b1, expected_bal[payer])
                            self.assertEqual(b2, expected_bal[payer])
                    self._bump(1)

                # Verify exact conservation across all payers
                for payer, bal in expected_bal.items():
                    self.assertGreaterEqual(bal, 0)
                    self.assertEqual(ledger.get_balance(payer), bal)

            # Negative, zero, bool, and int64-overflow ledger rejections (600 probes)
            bad_amounts: list[object] = [
                0, -1, -1_000_000, True, False, MAX_MICRO_USDC + 1, 1 << 63, 1 << 64, "nan", None
            ]
            for i in range(600):
                amt = bad_amounts[i % len(bad_amounts)]
                with self.assertRaises(ValueError):
                    ledger.credit_deposit("p_bad", "base-x402", f"h{i}", amt)  # type: ignore[arg-type]
                with self.assertRaises(ValueError):
                    ledger.debit_credit("p_bad", amt, "INGEST")  # type: ignore[arg-type]
                with self.assertRaises(ValueError):
                    ledger.refund_credit("p_bad", amt, "refund", debit_seq=i)  # type: ignore[arg-type]
                self._bump(1)
        finally:
            ledger.close()

    # -- 2. Chained-HMAC L402 Caveat-Append Escalation & Parser Fuzz ---------

    def test_02_l402_chained_hmac_caveat_append_and_parser_fuzz(self) -> None:
        """2,200 probes defeating chained-HMAC macaroon privilege escalation & malformed L402."""
        rng = SplitMix64(0xB11DC0DE0002)
        eng = self.gate_srv.engine
        tier_ingest = PRICING_TIERS["INGEST"]  # 1 sat
        ch = eng.mint_l402_challenge(tier_ingest, "/api/v1/blind/jsonb/ingest", sats_override=1)
        base_mac = b64_json_decode(ch["macaroon"])
        preimage = eng.derive_test_preimage_hex(ch["tokenId"])

        def forge_append(extra_cavs: list[str]) -> str:
            # Attacker uses ONLY public signature to extend chained HMAC (no server secret!)
            mac_bytes = bytes.fromhex(base_mac["signature"])
            new_cavs = list(base_mac["caveats"])
            for cav in extra_cavs:
                mac_bytes = hmac.new(mac_bytes, cav.encode("utf-8"), hashlib.sha256).digest()
                new_cavs.append(cav)
            forged = dict(base_mac)
            forged["caveats"] = new_cavs
            forged["signature"] = mac_bytes.hex()
            return f"L402 {b64_json_encode(forged)}:{preimage}"

        # Explicit high-severity privilege escalation attacks (all have cryptographically valid chained HMAC!)
        escalations = [
            ["sats=9999999"],
            ["path=*"],
            ["path=/api/v1/blind/jsonb/query"],
            ["exp=9999999999"],
            ["tier=SKLEARN_MNB"],
            ["sats=30", "path=/api/v1/blind/jsonb/query", "tier=SKLEARN_MNB"],
            ["admin=true"],
            ["sats=30\r\nX-Evil: 1"],
            ["sats=30|inject"],
            ["sats=30;drop"],
            ["no_equals_sign"],
        ]
        for extra in escalations:
            hdr = forge_append(extra)
            with self.assertRaises(PaymentRejected):
                eng.verify_l402_authorization(hdr, required_sats=30, request_path="/api/v1/blind/jsonb/query")
            with self.assertRaises(PaymentRejected):
                eng.verify_l402_authorization(hdr, required_sats=1, request_path="/api/v1/blind/jsonb/ingest")
            self._bump(2)

        # Zipfian + SplitMix64 fuzz of 2,178 L402 attack mutations
        zipf = ZipfSampler(20, 1.25, rng)
        for _ in range(2_178):
            kind = zipf.sample()
            if kind == 0:
                hdr = forge_append([f"sats={rng.randrange(100_000) + 30}"])
            elif kind == 1:
                hdr = forge_append(["path=*"])
            elif kind == 2:
                hdr = forge_append([f"exp={int(time.time()) + 999999}"])
            elif kind == 3:
                hdr = forge_append([f"k{rng.randrange(99)}=v"])
            elif kind == 4:
                hdr = f"L402 {ch['macaroon']}:extra:{preimage}"
            elif kind == 5:
                hdr = f"Bearer {ch['macaroon']}:{preimage}"
            elif kind == 6:
                hdr = f"L402 {ch['macaroon']}:{rng.hex_bytes(31)}"
            elif kind == 7:
                hdr = f"L402 {b64_json_encode([1, 2, 3])}:{preimage}"
            elif kind == 8:
                bad = dict(base_mac)
                bad["signature"] = "not-hex-" + rng.hex_bytes(28)
                hdr = f"L402 {b64_json_encode(bad)}:{preimage}"
            elif kind == 9:
                # Truncated caveat set signed properly via server (simulating missing key)
                bad = dict(base_mac)
                bad["caveats"] = base_mac["caveats"][:3]
                bad["signature"] = eng._sign_l402_macaroon(bad["identifier"], bad["caveats"])
                hdr = f"L402 {b64_json_encode(bad)}:{preimage}"
            elif kind == 10:
                # Wildcard path signed by server must still be rejected
                bad = dict(base_mac)
                bad["caveats"] = ["tier=INGEST", "sats=10", "path=*", f"exp={int(time.time()) + 600}"]
                bad["signature"] = eng._sign_l402_macaroon(bad["identifier"], bad["caveats"])
                hdr = f"L402 {b64_json_encode(bad)}:{preimage}"
            elif kind == 11:
                # Non-numeric sats
                bad = dict(base_mac)
                bad["caveats"] = ["tier=INGEST", "sats=abc", "path=/api/v1/blind/jsonb/ingest", f"exp={int(time.time()) + 600}"]
                bad["signature"] = eng._sign_l402_macaroon(bad["identifier"], bad["caveats"])
                hdr = f"L402 {b64_json_encode(bad)}:{preimage}"
            elif kind == 12:
                # Out-of-bounds sats > MAX_SATS
                bad = dict(base_mac)
                bad["caveats"] = ["tier=INGEST", f"sats={MAX_SATS + 1}", "path=/api/v1/blind/jsonb/ingest", f"exp={int(time.time()) + 600}"]
                bad["signature"] = eng._sign_l402_macaroon(bad["identifier"], bad["caveats"])
                hdr = f"L402 {b64_json_encode(bad)}:{preimage}"
            elif kind == 13:
                # Non-string caveat
                bad = dict(base_mac)
                bad["caveats"] = [123, "sats=1", "path=/api/v1/blind/jsonb/ingest", f"exp={int(time.time()) + 600}"]
                hdr = f"L402 {b64_json_encode(bad)}:{preimage}"
            elif kind == 14:
                # > 16 caveats
                hdr = forge_append([f"x{j}=1" for j in range(15)])
            elif kind == 15:
                # Wrong preimage
                hdr = f"L402 {ch['macaroon']}:{rng.hex_bytes(32)}"
            elif kind == 16:
                # Invalid base64
                hdr = f"L402 !!!invalid!!!:{preimage}"
            elif kind == 17:
                # Control char in caveat
                bad = dict(base_mac)
                bad["caveats"] = ["tier=INGEST", "sats=1", "path=/api/v1/blind/jsonb/ingest\x00", f"exp={int(time.time()) + 600}"]
                hdr = f"L402 {b64_json_encode(bad)}:{preimage}"
            elif kind == 18:
                # Expired macaroon
                bad = dict(base_mac)
                bad["caveats"] = ["tier=INGEST", "sats=1", "path=/api/v1/blind/jsonb/ingest", "exp=1"]
                bad["signature"] = eng._sign_l402_macaroon(bad["identifier"], bad["caveats"])
                hdr = f"L402 {b64_json_encode(bad)}:{preimage}"
            else:
                # Oversized header
                hdr = "L402 " + ("A" * 70_000) + ":" + preimage
            with self.assertRaises(PaymentRejected):
                eng.verify_l402_authorization(hdr, required_sats=1, request_path="/api/v1/blind/jsonb/ingest")
            self._bump(1)

    # -- 3. Base x402 Type Confusion, Bounds & Facilitator Endpoint Fuzz -----

    def test_03_x402_type_confusion_bounds_and_facilitator_fuzz(self) -> None:
        """2,000 SplitMix64 + Zipfian x402 security probes."""
        rng = SplitMix64(0xB11DC0DE0003)
        eng = self.gate_srv.engine
        tier = PRICING_TIERS["SUM"]
        zipf = ZipfSampler(18, 1.0, rng)

        for i in range(1_980):
            kind = zipf.sample()
            obj = self._make_x402_obj(PAYER_A, 5_000, nonce=f"0x{rng.hex_bytes(32)}")
            if kind == 0:
                obj["x402Version"] = True
            elif kind == 1:
                obj["x402Version"] = 3
            elif kind == 2:
                obj["accepted"] = ["not-a-dict"]
            elif kind == 3:
                obj["payload"] = "not-a-dict"
            elif kind == 4:
                obj["payload"]["authorization"] = None  # type: ignore[index]
            elif kind == 5:
                obj["payload"]["authorization"]["value"] = True  # type: ignore[index]
            elif kind == 6:
                obj["payload"]["authorization"]["value"] = -5000  # type: ignore[index]
            elif kind == 7:
                obj["payload"]["authorization"]["value"] = MAX_MICRO_USDC + 1  # type: ignore[index]
            elif kind == 8:
                obj["accepted"]["payTo"] = PAYER_B  # type: ignore[index]
            elif kind == 9:
                obj["accepted"]["amount"] = "99999"  # type: ignore[index]
            elif kind == 10:
                obj["payload"]["authorization"]["validAfter"] = True  # type: ignore[index]
            elif kind == 11:
                obj["payload"]["authorization"]["validBefore"] = int(time.time()) + 86_400 * 400  # type: ignore[index]
            elif kind == 12:
                obj["payload"]["signatureType"] = "eip3009\r\nX-Inject: 1"  # type: ignore[index]
            elif kind == 13:
                obj["payload"]["authorization"]["nonce"] = "bad|nonce\r\n"  # type: ignore[index]
            elif kind == 14:
                obj["payload"]["authorization"]["from"] = "0x1234"  # type: ignore[index]
            elif kind == 15:
                obj["payload"]["authorization"]["to"] = PAYER_B  # type: ignore[index]
            elif kind == 16:
                obj["payload"]["signature"] = "0x" + ("a" * 5000)  # type: ignore[index]
            else:
                obj["scheme"] = "free-compute"
                obj["accepted"]["scheme"] = "free-compute"  # type: ignore[index]

            hdr = b64_json_encode(obj)
            with self.assertRaises(PaymentRejected):
                eng.verify_x402_payment(hdr, tier.micro_usdc, tier, "https://blindcore.dev/api/v1/blind/jsonb/query", "0" * 64)
            self._bump(1)

        # Facilitator payer mismatch & disallowed facilitator endpoints (20 probes)
        self.fac_state.override_payer = PAYER_B
        try:
            obj = self._make_x402_obj(PAYER_A, 5_000, nonce=f"0x{rng.hex_bytes(32)}")
            with self.assertRaises(PaymentRejected):
                eng.verify_x402_payment(
                    b64_json_encode(obj), tier.micro_usdc, tier, "https://blindcore.dev/api/v1/blind/jsonb/query", "0" * 64
                )
            self._bump(1)
        finally:
            self.fac_state.override_payer = None

        for bad_ep in ("../admin", "verify?x=1", "settle/../../x", "health", "", "verify\r\n", "/admin", "transfer", "withdraw", "keys") * 2:
            if self.total_probes >= 20_000:
                break
            with self.assertRaises(PaymentRejected):
                eng._call_facilitator(bad_ep, {})
            self._bump(1)

    # -- 4. Stacks sBTC/STX SSRF, Prefix Spoof & Hiro Amplification Block ----

    def test_04_stacks_ssrf_prefix_spoof_and_amplification_fuzz(self) -> None:
        """1,500 Stacks SSRF/traversal, asset_id prefix spoof, & replay amplification probes."""
        rng = SplitMix64(0xB11DC0DE0004)
        eng = self.gate_srv.engine

        # 1. Valid tx settled once -> subsequent replays MUST NOT hit Hiro Stacks API!
        valid_tx = self._register_sbtc_tx(amount_sats=30)
        fetches_before = self.stx_state.fetch_count
        vp = eng.verify_stacks_payment(valid_tx, required_sats=30, required_ustx=13_500)
        self.assertTrue(eng.ledger.mark_settled("stacks-sbtc", vp.payment_hash))
        self.assertEqual(self.stx_state.fetch_count, fetches_before + 1)

        fetches_after_first = self.stx_state.fetch_count
        for _ in range(100):
            with self.assertRaises(PaymentRejected):
                eng.verify_stacks_payment(valid_tx, required_sats=30, required_ustx=13_500)
            self._bump(1)
        # Zero additional external Hiro fetches!
        self.assertEqual(self.stx_state.fetch_count, fetches_after_first)

        # 2. Asset ID prefix spoof (SM3VDX...sbtc-token-fake::sbtc) MUST be rejected
        spoof_tx = self._register_sbtc_tx(
            amount_sats=30,
            asset_id=f"{STACKS_SBTC_MAINNET}-fake::sbtc-token",
        )
        with self.assertRaises(PaymentRejected):
            eng.verify_stacks_payment(spoof_tx, required_sats=30, required_ustx=13_500)
        self._bump(1)

        # 3. Response tx_id mismatch MUST be rejected
        mismatch_tx = self._register_sbtc_tx(amount_sats=30, tx_id_override="0x" + ("f" * 64))
        with self.assertRaises(PaymentRejected):
            eng.verify_stacks_payment(mismatch_tx, required_sats=30, required_ustx=13_500)
        self._bump(1)

        # 4. Invalid sender principal MUST be rejected
        bad_sender_tx = self._register_sbtc_tx(amount_sats=30, sender="not-a-stacks-principal\r\n")
        with self.assertRaises(PaymentRejected):
            eng.verify_stacks_payment(bad_sender_tx, required_sats=30, required_ustx=13_500)
        self._bump(1)

        # 5. Non-empty events list with NO matching sBTC event MUST be rejected
        no_match_ev_tx = self._register_sbtc_tx(
            amount_sats=30,
            events=[{"event_type": "stx_asset", "asset": {"amount": "1"}}],
        )
        with self.assertRaises(PaymentRejected):
            eng.verify_stacks_payment(no_match_ev_tx, required_sats=30, required_ustx=13_500)
        self._bump(1)

        # 6. Overflow sBTC amount > MAX_SATS MUST be rejected
        overflow_tx = self._register_sbtc_tx(amount_sats=MAX_SATS + 1)
        with self.assertRaises(PaymentRejected):
            eng.verify_stacks_payment(overflow_tx, required_sats=30, required_ustx=13_500)
        self._bump(1)

        # 7. 1,395 SSRF / path-traversal / newline-$ bypass txid probes
        ssrf_vectors = [
            "../extended/v1/info",
            "%2e%2e%2fadmin",
            "0x" + ("a" * 64) + "\n",
            "0x" + ("a" * 64) + "\r\nHost: evil",
            "a" * 63,
            "a" * 65,
            "0x" + ("g" * 64),
            "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/",
            ("a" * 32) + "/../" + ("b" * 28),
            ("a" * 64) + "?foo=bar",
            ("a" * 64) + "#frag",
            ("a" * 64) + "\x00",
            "",
        ]
        zipf = ZipfSampler(len(ssrf_vectors), 1.5, rng)
        for _ in range(1_395):
            vec = ssrf_vectors[zipf.sample()]
            with self.assertRaises(ValueError):
                normalize_txid(vec)
            with self.assertRaises(ValueError):
                eng._fetch_stacks_tx(vec)
            self._bump(1)

    # -- 5. Header Spoofing, Smuggling, Rate-Limit Bypass & Path Fuzz --------

    def test_05_header_spoofing_smuggling_and_path_fuzz(self) -> None:
        """1,600 probes for header spoofing, XFF rate-limit bypass, smuggling, & URL/path fuzz."""
        rng = SplitMix64(0xB11DC0DE0005)

        # A. Live HTTP header spoofing test: client sends forged X-BlindCore-* + bad Content-Type
        x402_hdr = b64_json_encode(self._make_x402_obj(PAYER_A, 5_000))
        st, _, raw = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "spoof_test", "op": "SUM"},
            {
                "PAYMENT-SIGNATURE": x402_hdr,
                "X-BlindCore-Payer": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                "X-BlindCore-Rail": "free-admin-rail",
                "X-BlindCore-Fee-Micro": "999999999",
                "X-BlindCore-Gate-Mac": "00" * 32,
                "X-BlindCore-Spoof": "injected",
                "Content-Type": "text/html; evil=1",
            },
        )
        self.assertEqual(st, 200)
        body = json.loads(raw)
        self.assertEqual(body["payer"], PAYER_A)
        self.assertEqual(body["rail"], "base-x402")
        self.assertFalse(body["has_spoof_hdr"])
        self.assertEqual(body["content_type"], "application/json")
        self._bump(1)

        # B. X-Forwarded-For / X-Real-IP rotation CANNOT bypass bad_payment_limit when trust_proxy_headers=False
        for i in range(3):
            bad_x402 = b64_json_encode(self._make_x402_obj(PAYER_A, 5_000, valid_sig=False))
            st_bad, _, _ = self._http(
                "POST",
                "/api/v1/blind/jsonb/query",
                {"table": "rl", "op": "SUM"},
                {
                    "PAYMENT-SIGNATURE": bad_x402,
                    "X-Forwarded-For": f"10.0.{i}.{i + 1}",
                    "X-Real-IP": f"192.168.{i}.{i + 1}",
                },
                base_url=self.rl_url,
            )
            self.assertEqual(st_bad, 402)
        # 4th attempt with yet another spoofed X-Forwarded-For MUST hit 429 lockout!
        st_lock, _, _ = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "rl", "op": "SUM"},
            {"X-Forwarded-For": "203.0.113.99", "X-Real-IP": "198.51.100.77"},
            base_url=self.rl_url,
        )
        self.assertEqual(st_lock, 429)
        self._bump(4)

        # C. Transfer-Encoding smuggling rejected over raw TCP socket (HTTP 400)
        with socket.create_connection(("127.0.0.1", self.gate_port), timeout=5) as sock:
            smuggle = (
                "POST /api/v1/blind/jsonb/query HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Content-Length: 2\r\n"
                "Connection: close\r\n\r\n"
                "{}"
            ).encode("ascii")
            sock.sendall(smuggle)
            resp = sock.recv(4096)
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), f"expected 400 on TE smuggling, got {resp[:60]!r}")
        self._bump(1)

        # D. Disallowed proxy paths & traversal rejected (400 / 404)
        for bad_path in (
            "/api/v1/admin/shutdown",
            "/api/v1/blind/../admin",
            "/api/v1/blind/%2e%2e/admin",
            "/etc/passwd",
            "//evil.example/api/v1/blind/query",
        ):
            st_p, _, _ = self._http("POST", bad_path, {"table": "x", "op": "SUM"})
            self.assertIn(st_p, (400, 404))
            self._bump(1)

        # E. EdgeRateLimiter bounded memory eviction (no unbounded dict OOM)
        rl = EdgeRateLimiter(rpm=60, bad_limit=10, bad_window_secs=60)
        rl.MAX_TRACKED_IPS = 64
        for i in range(256):
            rl.allow_request(f"10.1.{i // 256}.{i % 256}")
        self.assertLessEqual(len(rl._hits), 64)
        self._bump(256)

        # F. 1,333 SplitMix64 parser/validator/session-token/sanitizer fuzz probes
        bad_paths = [
            "relative/path",
            "//double/slash",
            "/api/v1/blind/../../etc/passwd",
            "/api/v1/blind/%2e%2e/secret",
            "/api/v1/blind/foo\\bar",
            "/api/v1/blind/foo\r\nInject: 1",
            "/api/v1/blind/foo\x00bar",
            "/api/v1/blind/foo#frag",
            "/api/v1/internal/debug",
        ]
        bad_urls = [
            "file:///etc/passwd",
            "ftp://example.com",
            "http://user:pass@127.0.0.1:3001",
            "http://127.0.0.1:3001\r\nInject: 1",
            "http://127.0.0.1:3001#frag",
            "javascript:alert(1)",
            "",
        ]
        zipf = ZipfSampler(6, 1.25, rng)
        for _ in range(1_333):
            k = zipf.sample()
            if k == 0:
                with self.assertRaises(ValueError):
                    validate_request_path(str(rng.choice(bad_paths)), allow_proxy_only=True)
            elif k == 1:
                with self.assertRaises(ValueError):
                    validate_http_url(str(rng.choice(bad_urls)), "test_url")
            elif k == 2:
                with self.assertRaises(ValueError):
                    b64_json_decode("not valid base64!!!" + rng.hex_bytes(4))
            elif k == 3:
                with self.assertRaises(ValueError):
                    b64url_decode("bad+chars/=" + rng.hex_bytes(4))
            elif k == 4:
                with self.assertRaises(PaymentRejected):
                    self.gate_srv.engine.verify_session_token(f"{rng.hex_bytes(8)}.{rng.hex_bytes(32)}")
            else:
                ct = sanitize_content_type("application/json\r\nX-Inject: 1")
                self.assertEqual(ct, "application/json")
                hdrs = sanitize_upstream_headers(
                    {"X-BlindCore-Payer": "evil", "Authorization": "Bearer evil", "Content-Type": "text/plain"},
                    "base-x402",
                    PAYER_A,
                    "a" * 64,
                    5000,
                    123456,
                    "b" * 64,
                    "tok",
                )
                self.assertEqual(hdrs["X-BlindCore-Payer"], PAYER_A)
                self.assertEqual(hdrs["Authorization"], "Bearer tok")
                self.assertEqual(hdrs["Content-Type"], "application/json")
            self._bump(1)

    # -- 6. Concurrent Multi-Thread Replay & Credit Debit Races --------------

    def test_06_concurrent_replay_and_credit_debit_races(self) -> None:
        """Concurrent multi-thread races across x402, L402, Stacks, and prepaid credits."""
        # A. Base x402 concurrent replay race (16 threads, same PAYMENT-SIGNATURE -> EXACTLY 1 x 200)
        x402_hdr = b64_json_encode(self._make_x402_obj(PAYER_A, 5_000))
        barrier_x = threading.Barrier(16)

        def race_x402(_: int) -> int:
            barrier_x.wait()
            st, _, _ = self._http(
                "POST",
                "/api/v1/blind/jsonb/query",
                {"table": "race_x", "op": "SUM", "race_delay_ms": 15},
                {"PAYMENT-SIGNATURE": x402_hdr},
            )
            return st

        with ThreadPoolExecutor(max_workers=16) as pool:
            statuses_x = list(pool.map(race_x402, range(16)))
        self.assertEqual(statuses_x.count(200), 1, f"x402 race statuses: {statuses_x}")
        self.assertEqual(statuses_x.count(402), 15, f"x402 race statuses: {statuses_x}")
        self._bump(16)

        # B. Lightning L402 concurrent replay race (16 threads, same preimage -> EXACTLY 1 x 200)
        st_402, hdrs_402, _ = self._http("POST", "/api/v1/blind/jsonb/query", {"table": "race_ln", "op": "SUM"})
        self.assertEqual(st_402, 402)
        m = re.search(r'L402 macaroon="([^"]+)"', hdrs_402["www-authenticate"])
        assert m is not None
        mac_b64 = m.group(1)
        tok_id = b64_json_decode(mac_b64)["identifier"]["token_id"]
        preimage = self.gate_srv.engine.derive_test_preimage_hex(tok_id)
        barrier_ln = threading.Barrier(16)

        def race_l402(_: int) -> int:
            barrier_ln.wait()
            st, _, _ = self._http(
                "POST",
                "/api/v1/blind/jsonb/query",
                {"table": "race_ln", "op": "SUM", "race_delay_ms": 15},
                {"Authorization": f"L402 {mac_b64}:{preimage}"},
            )
            return st

        with ThreadPoolExecutor(max_workers=16) as pool:
            statuses_ln = list(pool.map(race_l402, range(16)))
        self.assertEqual(statuses_ln.count(200), 1, f"L402 race statuses: {statuses_ln}")
        self.assertEqual(statuses_ln.count(402), 15, f"L402 race statuses: {statuses_ln}")
        self._bump(16)

        # C. Stacks sBTC concurrent replay race (16 threads, same txid -> EXACTLY 1 x 200)
        tx_race = self._register_sbtc_tx(amount_sats=8)
        barrier_stx = threading.Barrier(16)

        def race_stx(_: int) -> int:
            barrier_stx.wait()
            st, _, _ = self._http(
                "POST",
                "/api/v1/blind/jsonb/query",
                {"table": "race_stx", "op": "SUM", "race_delay_ms": 15},
                {"X-Stacks-Payment-Tx": tx_race},
            )
            return st

        with ThreadPoolExecutor(max_workers=16) as pool:
            statuses_stx = list(pool.map(race_stx, range(16)))
        self.assertEqual(statuses_stx.count(200), 1, f"Stacks race statuses: {statuses_stx}")
        self.assertEqual(statuses_stx.count(402), 15, f"Stacks race statuses: {statuses_stx}")
        self._bump(16)

        # D. Concurrent prepaid credit debit race: 50,000 micro-USDC balance, 24 threads x 5,000 micro-USDC
        race_payer = "0xcccccccccccccccccccccccccccccccccccccccc"
        self.gate_srv.engine.ledger.credit_deposit(race_payer, "base-x402", "race_seed_" + secrets.token_hex(16), 50_000)
        sess_tok, _ = self.gate_srv.engine.issue_session_token(race_payer, "base-x402")
        barrier_c = threading.Barrier(24)

        def race_credit(_: int) -> int:
            barrier_c.wait()
            st, _, _ = self._http(
                "POST",
                "/api/v1/blind/jsonb/query",
                {"table": "race_cred", "op": "SUM"},
                {"X-BlindCore-Session": sess_tok},
            )
            return st

        with ThreadPoolExecutor(max_workers=24) as pool:
            statuses_c = list(pool.map(race_credit, range(24)))
        self.assertEqual(statuses_c.count(200), 10, f"credit race statuses: {statuses_c}")
        self.assertEqual(statuses_c.count(402), 14, f"credit race statuses: {statuses_c}")
        self.assertEqual(self.gate_srv.engine.ledger.get_balance(race_payer), 0)
        self._bump(24)

    # -- 7. Static Solidity & Clarity Contract Security Invariants -----------

    def test_07_static_contract_security_invariants(self) -> None:
        """Verify hardened access control, EIP-2, and Clarity contract-caller invariants."""
        sol_path = os.path.join(REPO_ROOT, "contracts", "base", "BlindCoreRootAnchor.sol")
        with open(sol_path, "r", encoding="ascii") as fh:
            sol = fh.read()

        sol_required = [
            "constructor(address initialSequencer)",
            "mapping(address => bool) public authorizedRelayers;",
            "uint256 public settledCount;",
            "modifier onlySequencer()",
            "modifier onlyRelayer()",
            "function setRelayer(address relayer, bool allowed) external onlySequencer",
            "function cancelPendingSequencer() external onlySequencer",
            "error ZeroHash();",
            "error EpochNotAnchored();",
            "error InvalidOpTier();",
            "if (stateRoot == bytes32(0)) revert ZeroHash();",
            "if (epochSeq == 0 || epochRoots[epochSeq] == bytes32(0)) revert EpochNotAnchored();",
            "if (tableHash == bytes32(0) || receiptHash == bytes32(0)) revert ZeroHash();",
            "if (opTier == 0) revert InvalidOpTier();",
            "if (v != 27 && v != 28) revert InvalidSignature();",
            "if (r == bytes32(0)) revert InvalidSignature();",
            "if (uint256(s) == 0 || uint256(s) > SECP256K1_HALF_N) revert InvalidSignature();",
            "if (signer == address(0) || signer != sequencer) revert InvalidSignature();",
            "settledCount += 1;",
        ]
        for needle in sol_required:
            self.assertIn(needle, sol, f"Missing Solidity security invariant: {needle}")
            self._bump(1)

        clar_path = os.path.join(REPO_ROOT, "contracts", "stacks", "blindcore-root-anchor.clar")
        with open(clar_path, "r", encoding="ascii") as fh:
            clar = fh.read()

        # CRITICAL: ZERO tx-sender phishing checks anywhere in public functions!
        self.assertNotIn("(is-eq tx-sender", clar, "Clarity contract must use contract-caller, never tx-sender!")
        self._bump(1)

        clar_required = [
            "(define-constant ERR-PUBKEY-NOT-SET (err u105))",
            "(define-constant ERR-ZERO-HASH (err u106))",
            "(define-constant ERR-INVALID-TIER (err u107))",
            "(define-constant ERR-EPOCH-NOT-ANCHORED (err u108))",
            "(define-constant ZERO-PUBKEY 0x000000000000000000000000000000000000000000000000000000000000000000)",
            "(define-constant ZERO-HASH32 0x0000000000000000000000000000000000000000000000000000000000000000)",
            "(define-map authorized-relayers principal bool)",
            "(define-public (set-relayer",
            "(define-public (cancel-pending-sequencer)",
            "(define-read-only (is-relayer",
            "(slice? new-pubkey u0 u1)",
            "(is-eq prefix 0x02)",
            "(is-eq prefix 0x03)",
            "chain-id: chain-id",
            "verifying-contract: (as-contract tx-sender)",
            "(is-eq contract-caller (var-get sequencer))",
            "(is-some (map-get? epoch-roots { epoch-seq: epoch-seq }))",
            "(map-insert settled-digests",
        ]
        for needle in clar_required:
            self.assertIn(needle, clar, f"Missing Clarity security invariant: {needle}")
            self._bump(1)

    # -- 8. MCP Server & AgentKit SSRF, Header Injection & Stale-Session Fix -

    def test_08_mcp_and_agentkit_security_fuzz(self) -> None:
        """600 MCP & AgentKit SSRF, header-injection, param-overwrite, & stale-session probes."""
        rng = SplitMix64(0xB11DC0DE0008)
        client = BlindCoreHttpClient(base_url=self.gate_url)

        bad_base_urls = [
            "file:///etc/passwd",
            "ftp://127.0.0.1:3002",
            "http://user:pass@127.0.0.1:3002",
            "http://127.0.0.1:3002/path?q=1",
            "http://127.0.0.1:3002#frag",
            "http://127.0.0.1:3002\r\nHost: evil",
            "",
        ]
        bad_endpoints = [
            "/api/v1/credits/balance",
            "/api/v1/blind/../../etc/passwd",
            "//evil.com/api/v1/blind/query",
            "/api/v1/blind/jsonb/query?x=1",
            "/api/v1/blind/jsonb/query#frag",
            "/api/v1/blind/jsonb/query@evil",
            "/admin",
        ]
        bad_header_dicts = [
            {"X-BlindCore-Payer": "0xdeadbeef"},
            {"Host": "evil.example"},
            {"X-Forwarded-For": "1.2.3.4"},
            {"PAYMENT-SIGNATURE": "abc\r\nX-Inject: 1"},
            {"Authorization": "L402 a:b\x00"},
            {"X-BlindCore-Session": 12345},
        ]

        zipf = ZipfSampler(4, 1.25, rng)
        for _ in range(580):
            k = zipf.sample()
            if k == 0:
                with self.assertRaises(ValueError):
                    _validate_base_url(str(rng.choice(bad_base_urls)))
            elif k == 1:
                with self.assertRaises(ValueError):
                    _validate_api_path(str(rng.choice(bad_endpoints[1:])))
            elif k == 2:
                with self.assertRaises(ValueError):
                    _sanitize_payment_headers(rng.choice(bad_header_dicts))  # type: ignore[arg-type]
            else:
                res = handle_rpc_request(
                    {
                        "jsonrpc": "2.0",
                        "id": 99,
                        "method": "tools/call",
                        "params": {
                            "name": "blindcore_query",
                            "arguments": {
                                "endpoint": str(rng.choice(bad_endpoints)),
                                "table": "t",
                                "op": "SUM",
                            },
                        },
                    },
                    client,
                )
                assert res is not None
                self.assertTrue(res["result"]["isError"])
            self._bump(1)

        # JSON-RPC non-dict request / params / arguments -> strict error codes
        for bad_req, code in (
            (["not-a-dict"], -32600),
            ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "bad"}, -32602),
            ({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "blindcore_pricing", "arguments": [1]}}, -32602),
        ):
            out = handle_rpc_request(bad_req, client)
            assert out is not None
            self.assertEqual(out["error"]["code"], code)
            self._bump(1)

        # params overwrite prevention in MCP blindcore_query & AgentKit blindcore_query
        x402_hdr = b64_json_encode(self._make_x402_obj(PAYER_A, 20_000))
        res_ow = handle_rpc_request(
            {
                "jsonrpc": "2.0",
                "id": 77,
                "method": "tools/call",
                "params": {
                    "name": "blindcore_query",
                    "arguments": {
                        "table": "victim_tbl",
                        "op": "SKLEARN_MNB",
                        "params": {"table": "hijacked_tbl", "op": "INGEST"},
                        "payment_headers": {"PAYMENT-SIGNATURE": x402_hdr},
                    },
                },
            },
            client,
        )
        assert res_ow is not None
        self.assertFalse(res_ow["result"]["isError"])
        self.assertEqual(res_ow["result"]["structuredContent"]["http_status"], 200)
        # Verify tier was SKLEARN_MNB ($0.020), not downgraded to INGEST
        self.assertEqual(res_ow["result"]["structuredContent"]["payment_response"]["tier"], "SKLEARN_MNB")
        self._bump(1)

        # AgentKit stale session_token shadowing fix: stale token -> 402 -> fallback to base-x402 -> 200!
        def fallback_signer(rail: str, challenge: dict[str, object]) -> dict[str, str]:
            self.assertEqual(rail, "base-x402")
            amt = int(challenge["payment_required"]["accepts"][0]["amount"])  # type: ignore[index]
            return {"PAYMENT-SIGNATURE": b64_json_encode(self._make_x402_obj(PAYER_B, amt))}

        provider = BlindCoreActionProvider(
            base_url=self.gate_url,
            preferred_rail="base-x402",
            payment_signer=fallback_signer,
            session_token="forged_or_expired_token.0000000000000000",
        )
        ag_res = json.loads(
            provider.blindcore_query(
                None,
                {
                    "table": "ag_tbl",
                    "op": "SUM",
                    "params": {"table": "evil", "op": "INGEST"},
                },
            )
        )
        self.assertEqual(ag_res["http_status"], 200)
        self.assertEqual(ag_res["rail"], "base-x402")
        self.assertEqual(ag_res["payment_response"]["tier"], "SUM")
        self._bump(16)

    # -- 9. Counterfactual Knockouts (assertNotEqual) ------------------------

    def test_09_counterfactual_knockouts(self) -> None:
        """Verify every cryptographic binding diverges under single-field mutation."""
        eng = self.gate_srv.engine
        base_mac = eng.compute_gate_mac("base-x402", PAYER_A, "a" * 64, 5_000, 1_700_000_000, "b" * 64)
        self.assertNotEqual(base_mac, eng.compute_gate_mac("ln-l402", PAYER_A, "a" * 64, 5_000, 1_700_000_000, "b" * 64))
        self.assertNotEqual(base_mac, eng.compute_gate_mac("base-x402", PAYER_B, "a" * 64, 5_000, 1_700_000_000, "b" * 64))
        self.assertNotEqual(base_mac, eng.compute_gate_mac("base-x402", PAYER_A, "c" * 64, 5_000, 1_700_000_000, "b" * 64))
        self.assertNotEqual(base_mac, eng.compute_gate_mac("base-x402", PAYER_A, "a" * 64, 5_001, 1_700_000_000, "b" * 64))
        self.assertNotEqual(base_mac, eng.compute_gate_mac("base-x402", PAYER_A, "a" * 64, 5_000, 1_700_000_001, "b" * 64))
        self.assertNotEqual(base_mac, eng.compute_gate_mac("base-x402", PAYER_A, "a" * 64, 5_000, 1_700_000_000, "d" * 64))
        self._bump(6)

        # Secret rotation knockouts (session_secret & l402_macaroon_secret)
        tok, _ = eng.issue_session_token(PAYER_A, "base-x402")
        self.assertEqual(eng.verify_session_token(tok)["payer"], PAYER_A)
        alt_cfg = GateConfig(
            db_path=":memory:",
            upstream_url=f"http://127.0.0.1:{self.up_port}",
            gate_hmac_key_hex="33" * 32,
            base_pay_to=BASE_PAY_TO,
            stacks_pay_to=STACKS_PAY_TO,
            session_secret="different-session-secret",
            l402_macaroon_secret="different-l402-secret",
            test_mode=True,
        )
        alt_eng = TriRailEngine(alt_cfg)
        try:
            with self.assertRaises(PaymentRejected):
                alt_eng.verify_session_token(tok)
            ch = eng.mint_l402_challenge(PRICING_TIERS["SUM"], "/api/v1/blind/jsonb/query")
            pre = eng.derive_test_preimage_hex(ch["tokenId"])
            with self.assertRaises(PaymentRejected):
                alt_eng.verify_l402_authorization(f"L402 {ch['macaroon']}:{pre}", 8, "/api/v1/blind/jsonb/query")
            self.assertNotEqual(
                eng.compute_gate_mac("base-x402", PAYER_A, "a" * 64, 5_000, 1_700_000_000, "b" * 64),
                alt_eng.compute_gate_mac("base-x402", PAYER_A, "a" * 64, 5_000, 1_700_000_000, "b" * 64),
            )
            self._bump(4)
        finally:
            alt_eng.close()

        # Verify total probe count invariant (>= 10,000)
        self.assertGreaterEqual(
            type(self).total_probes,
            10_000,
            f"Expected >= 10,000 probes, executed {type(self).total_probes}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
