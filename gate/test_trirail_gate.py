#!/usr/bin/env python3
"""
Comprehensive End-to-End Test Suite for BlindCore Tri-Rail Payment Gateway.
Copyright 2026 Blind Labs (https://blindlabs.ai). Licensed under the Apache License, Version 2.0.

Spins up:
  1. Local mock BlindCore upstream API verifying Bearer token + Gate HMAC
  2. Local mock CDP x402 v2 Facilitator (/verify & /settle)
  3. Local mock Hiro Stacks API (/extended/v1/tx/<txid>)
  4. Live blindcore_trirail_gate.py server backed by a real SQLite WAL ledger

Tests all 3 payment rails, prepaid micro-credit sessions, negative security /
replay cases, discovery endpoints, counterfactual binding assertions, MCP
server JSON-RPC, and AgentKit ActionProvider integration.
"""

from __future__ import annotations

import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import secrets
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

# Ensure repo root is on sys.path whether invoked from repo root or gate/
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gate.blindcore_trirail_gate import (  # noqa: E402
    BASE_MAINNET_CAIP2,
    ERC8004_IDENTITY_REGISTRY_BASE,
    ERC8004_REPUTATION_REGISTRY_BASE,
    GateConfig,
    PERMIT2_CANONICAL,
    PREPAID_MIN_MICRO_USDC,
    STACKS_SBTC_MAINNET,
    b64_json_decode,
    b64_json_encode,
    build_server,
    sha256_hex,
)
from mcp.agentkit_provider import BlindCoreActionProvider  # noqa: E402
from mcp.mcp_server import BlindCoreHttpClient, handle_rpc_request  # noqa: E402


# ---------------------------------------------------------------------------
# Mock Infrastructure Servers
# ---------------------------------------------------------------------------

EXPECTED_UPSTREAM_TOKEN = "test-upstream-bearer-token-only"
GATE_HMAC_KEY_HEX = "11" * 32
BASE_PAY_TO = "0x1111111111111111111111111111111111111111"
STACKS_PAY_TO = "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7"
PAYER_A_EVM = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
PAYER_B_EVM = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
PAYER_STACKS = "SP3FGQ8Z7JY9BWYZ5WM53E0M9NK7WHJF0691NZ159"


class MockUpstreamState:
    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []


class MockUpstreamHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b""
        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {EXPECTED_UPSTREAM_TOKEN}":
            self._reply(401, {"error": "missing or wrong upstream bearer token"})
            return

        # Verify client payment headers were stripped
        for forbidden in ("PAYMENT-SIGNATURE", "X-PAYMENT", "X-Stacks-Payment-Tx", "X-BlindCore-Session"):
            if self.headers.get(forbidden):
                self._reply(400, {"error": f"leaked client payment header {forbidden}"})
                return

        rail = self.headers.get("X-BlindCore-Rail", "")
        payer = self.headers.get("X-BlindCore-Payer", "")
        pay_hash = self.headers.get("X-BlindCore-Payment-Hash", "")
        fee_micro = self.headers.get("X-BlindCore-Fee-Micro", "")
        ts = self.headers.get("X-BlindCore-Ts", "")
        gate_mac = self.headers.get("X-BlindCore-Gate-Mac", "")

        # Verify Gate HMAC-SHA256 binding
        body_hash = sha256_hex(body)
        expected_mac = hmac.new(
            bytes.fromhex(GATE_HMAC_KEY_HEX),
            f"{rail}|{payer}|{pay_hash}|{fee_micro}|{ts}|{body_hash}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(gate_mac, expected_mac):
            self._reply(403, {"error": "invalid X-BlindCore-Gate-Mac"})
            return

        parsed = json.loads(body.decode("utf-8")) if body else {}
        if parsed.get("force_error"):
            self._reply(422, {"error": "simulated compute guard failure (k_min_tkms)"})
            return

        receipt_hex = sha256_hex(
            f"RECEIPT:V2:{rail}:{payer}:{pay_hash}:{body_hash}".encode("utf-8")
        )
        record = {
            "path": self.path,
            "rail": rail,
            "payer": payer,
            "payment_hash": pay_hash,
            "fee_micro": fee_micro,
            "gate_mac": gate_mac,
            "receipt_hex": receipt_hex,
        }
        self.server.state.requests.append(record)  # type: ignore[attr-defined]
        self._reply(
            200,
            {
                "status": "ok",
                "plaintext_stored": False,
                "op": parsed.get("op", "INGEST"),
                "table": parsed.get("table", "unknown"),
                "rail_echo": rail,
                "payer_echo": payer,
                "payment_hash_echo": pay_hash,
                "gate_mac_echo": gate_mac,
                "receipt_hex": receipt_hex,
            },
        )

    def _reply(self, status: int, obj: dict[str, object]) -> None:
        raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class MockFacilitatorState:
    def __init__(self) -> None:
        self.verify_calls = 0
        self.settle_calls = 0
        self.settled_nonces: set[str] = set()


class MockFacilitatorHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        data = json.loads(self.rfile.read(length).decode("utf-8"))
        state: MockFacilitatorState = self.server.state  # type: ignore[attr-defined]
        pp = data.get("paymentPayload") or {}
        payload = pp.get("payload") or {}
        auth = payload.get("authorization") or payload.get("permit") or {}
        sig = str(payload.get("signature") or "")
        payer = str(auth.get("from") or auth.get("owner") or "")
        nonce = str(auth.get("nonce") or "")

        if self.path == "/verify":
            state.verify_calls += 1
            valid = sig.startswith("0xvalid")
            self._reply(200, {"isValid": valid, "payer": payer, "invalidReason": "" if valid else "bad_sig"})
            return

        if self.path == "/settle":
            state.settle_calls += 1
            if nonce in state.settled_nonces:
                self._reply(200, {"success": False, "errorReason": "already_settled"})
                return
            state.settled_nonces.add(nonce)
            tx_hash = "0x" + sha256_hex(f"base-tx:{payer}:{nonce}".encode("utf-8"))
            self._reply(200, {"success": True, "transaction": tx_hash, "network": BASE_MAINNET_CAIP2})
            return

        self._reply(404, {"error": "unknown facilitator route"})

    def _reply(self, status: int, obj: dict[str, object]) -> None:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class MockStacksState:
    def __init__(self) -> None:
        self.txs: dict[str, dict[str, object]] = {}


class MockStacksHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        state: MockStacksState = self.server.state  # type: ignore[attr-defined]
        prefix = "/extended/v1/tx/"
        if not self.path.startswith(prefix):
            self._reply(404, {"error": "not found"})
            return
        txid = self.path[len(prefix):].lower()
        if txid.startswith("0x"):
            txid = txid[2:]
        tx = state.txs.get(txid)
        if tx is None:
            self._reply(404, {"error": "tx not found"})
            return
        self._reply(200, tx)

    def _reply(self, status: int, obj: dict[str, object]) -> None:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def _start_http_server(handler_cls: type[BaseHTTPRequestHandler], state: object) -> tuple[ThreadingHTTPServer, int]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    srv.state = state  # type: ignore[attr-defined]
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


# ---------------------------------------------------------------------------
# E2E Test Suite
# ---------------------------------------------------------------------------

class TriRailGatewayE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ["BLINDCORE_GATE_QUIET"] = "1"
        cls.tmpdir = tempfile.TemporaryDirectory()
        cls.db_path = os.path.join(cls.tmpdir.name, "ledger.sqlite")

        cls.upstream_state = MockUpstreamState()
        cls.upstream_srv, cls.upstream_port = _start_http_server(MockUpstreamHandler, cls.upstream_state)

        cls.fac_state = MockFacilitatorState()
        cls.fac_srv, cls.fac_port = _start_http_server(MockFacilitatorHandler, cls.fac_state)

        cls.stacks_state = MockStacksState()
        cls.stacks_srv, cls.stacks_port = _start_http_server(MockStacksHandler, cls.stacks_state)

        cfg = GateConfig(
            listen_host="127.0.0.1",
            listen_port=0,
            public_base_url="https://blindcore.dev",
            upstream_url=f"http://127.0.0.1:{cls.upstream_port}",
            upstream_token=EXPECTED_UPSTREAM_TOKEN,
            gate_hmac_key_hex=GATE_HMAC_KEY_HEX,
            db_path=cls.db_path,
            base_network=BASE_MAINNET_CAIP2,
            base_pay_to=BASE_PAY_TO,
            base_anchor_contract="0x2222222222222222222222222222222222222222",
            x402_facilitator_url=f"http://127.0.0.1:{cls.fac_port}",
            l402_macaroon_secret="test-l402-macaroon-secret-key",
            stacks_network="mainnet",
            stacks_api_url=f"http://127.0.0.1:{cls.stacks_port}",
            stacks_pay_to=STACKS_PAY_TO,
            stacks_sbtc_contract=STACKS_SBTC_MAINNET,
            session_secret="test-session-secret-key",
            bad_payment_limit=100,  # allow negative tests without tripping lockout
            test_mode=True,
            test_l402_seed="deterministic-test-l402-seed",
        )
        cls.gate_srv = build_server(cfg)
        cls.gate_port = cls.gate_srv.server_address[1]
        cls.gate_url = f"http://127.0.0.1:{cls.gate_port}"
        cls.gate_thread = threading.Thread(target=cls.gate_srv.serve_forever, daemon=True)
        cls.gate_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.gate_srv.shutdown()
        cls.gate_srv.server_close()
        cls.gate_srv.engine.close()
        for srv in (cls.upstream_srv, cls.fac_srv, cls.stacks_srv):
            srv.shutdown()
            srv.server_close()
        cls.tmpdir.cleanup()

    # -- HTTP Helpers -------------------------------------------------------

    def _http(
        self,
        method: str,
        path: str,
        body: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        hdrs = dict(headers or {})
        raw = None
        if body is not None:
            raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(f"{self.gate_url}{path}", data=raw, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return int(resp.status), {k.lower(): v for k, v in resp.headers.items()}, resp.read()
        except urllib.error.HTTPError as exc:
            return int(exc.code), {k.lower(): v for k, v in exc.headers.items()}, exc.read()

    def _make_x402_header(
        self,
        payer: str,
        value_micro: int,
        nonce: str | None = None,
        version: int = 2,
        scheme: str = "exact",
        sig_type: str = "eip3009",
        valid_sig: bool = True,
    ) -> str:
        now = int(time.time())
        n = nonce or ("0x" + secrets.token_hex(32))
        sig_prefix = "0xvalid" if valid_sig else "0xforged"
        sig = sig_prefix + ("ab" * (65 if sig_type in ("erc1271", "erc6492") else 32))
        if scheme == "permit2-exact":
            payload_body = {
                "signature": sig,
                "signatureType": sig_type,
                "permit": {
                    "owner": payer,
                    "spender": BASE_PAY_TO,
                    "amount": str(value_micro),
                    "nonce": n,
                    "deadline": now + 120,
                },
            }
        else:
            payload_body = {
                "signature": sig,
                "signatureType": sig_type,
                "authorization": {
                    "from": payer,
                    "to": BASE_PAY_TO,
                    "value": str(value_micro),
                    "validAfter": now - 10,
                    "validBefore": now + 120,
                    "nonce": n,
                },
            }
        obj: dict[str, object] = {
            "x402Version": version,
            "scheme": scheme,
            "network": BASE_MAINNET_CAIP2,
            "accepted": {
                "scheme": scheme,
                "network": BASE_MAINNET_CAIP2,
                "amount": str(value_micro),
                "payTo": BASE_PAY_TO,
            },
            "payload": payload_body,
        }
        return b64_json_encode(obj)

    def _register_stacks_sbtc_tx(
        self,
        amount_sats: int,
        status: str = "success",
        recipient: str = STACKS_PAY_TO,
        sender: str = PAYER_STACKS,
    ) -> str:
        txid = secrets.token_hex(32)
        self.stacks_state.txs[txid] = {
            "tx_id": f"0x{txid}",
            "tx_status": status,
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
            "events": [
                {
                    "event_type": "fungible_token_asset",
                    "asset": {
                        "asset_id": f"{STACKS_SBTC_MAINNET}::sbtc-token",
                        "recipient": recipient,
                        "amount": str(amount_sats),
                    },
                }
            ],
        }
        return txid

    # -- 1. Public Discovery Endpoints --------------------------------------

    def test_01_public_discovery_endpoints(self) -> None:
        status, _, raw = self._http("GET", "/health")
        self.assertEqual(status, 200)
        health = json.loads(raw)
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["x402Version"], 2)
        self.assertEqual(health["rails"], ["base-x402", "ln-l402", "stacks-sbtc"])

        status, hdrs, raw = self._http("GET", "/llms.txt")
        self.assertEqual(status, 200)
        self.assertIn("text/plain", hdrs["content-type"])
        llms = raw.decode("utf-8")
        self.assertIn("x402 v2", llms)
        self.assertIn("L402", llms)
        self.assertIn("Stacks sBTC", llms)
        self.assertIn("/api/v1/credits/topup", llms)

        status, _, raw = self._http("GET", "/.well-known/x402.json")
        self.assertEqual(status, 200)
        x402 = json.loads(raw)
        self.assertEqual(x402["x402Version"], 2)
        self.assertEqual(x402["activeNetwork"], BASE_MAINNET_CAIP2)
        self.assertEqual(x402["permit2"], PERMIT2_CANONICAL)
        self.assertTrue(x402["extensions"]["bazaar"]["discoverable"])
        self.assertIn("ERC-1271", x402["smartWalletSupport"])
        self.assertIn("ERC-6492", x402["smartWalletSupport"])

        status, _, raw = self._http("GET", "/.well-known/agent-card.json")
        self.assertEqual(status, 200)
        card = json.loads(raw)
        self.assertEqual(card["schemaVersion"], "erc-8004/v1")
        self.assertEqual(card["erc8004"]["identityRegistry"], ERC8004_IDENTITY_REGISTRY_BASE)
        self.assertEqual(card["erc8004"]["reputationRegistry"], ERC8004_REPUTATION_REGISTRY_BASE)
        self.assertEqual(card["erc8004"]["validationMethod"], "isReceiptSettled(bytes32)")

        status, _, raw = self._http("GET", "/api/v1/pricing")
        self.assertEqual(status, 200)
        pricing = json.loads(raw)
        self.assertEqual(pricing["tiers"]["INGEST"]["microUsdc"], 500)
        self.assertEqual(pricing["tiers"]["INGEST"]["sats"], 1)
        self.assertEqual(pricing["tiers"]["CONTAINS"]["microUsdc"], 1000)
        self.assertEqual(pricing["tiers"]["CONTAINS"]["sats"], 2)
        self.assertEqual(pricing["tiers"]["SUM"]["microUsdc"], 5000)
        self.assertEqual(pricing["tiers"]["SUM"]["sats"], 8)
        self.assertEqual(pricing["tiers"]["RANGE_GATE"]["microUsdc"], 15000)
        self.assertEqual(pricing["tiers"]["RANGE_GATE"]["sats"], 25)
        self.assertEqual(pricing["tiers"]["SKLEARN_MNB"]["microUsdc"], 20000)
        self.assertEqual(pricing["tiers"]["SKLEARN_MNB"]["sats"], 30)

    # -- 2. Tri-Rail 402 Discovery ------------------------------------------

    def test_02_trirail_402_discovery(self) -> None:
        status, hdrs, _ = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "phishing_corpus", "op": "SKLEARN_MNB"},
        )
        self.assertEqual(status, 402)
        self.assertIn("payment-required", hdrs)
        self.assertIn("www-authenticate", hdrs)
        self.assertIn("x-stacks-payment-required", hdrs)

        quote = b64_json_decode(hdrs["payment-required"])
        self.assertEqual(quote["x402Version"], 2)
        self.assertEqual(quote["accepts"][0]["network"], BASE_MAINNET_CAIP2)
        self.assertEqual(quote["accepts"][0]["amount"], "20000")
        self.assertEqual(quote["accepts"][1]["scheme"], "permit2-exact")
        self.assertTrue(quote["extensions"]["bazaar"]["discoverable"])
        self.assertEqual(quote["extensions"]["lightning_l402"]["sats"], 30)
        self.assertEqual(quote["extensions"]["stacks_sbtc"]["amountSats"], 30)

        www_auth = hdrs["www-authenticate"]
        self.assertTrue(www_auth.startswith("L402 macaroon="))
        self.assertIn('invoice="lnbc30n1', www_auth)

        stx_meta = b64_json_decode(hdrs["x-stacks-payment-required"])
        self.assertEqual(stx_meta["recipient"], STACKS_PAY_TO)
        self.assertEqual(stx_meta["sbtcContract"], STACKS_SBTC_MAINNET)
        self.assertEqual(stx_meta["amountSats"], 30)

    # -- 3. Rail 1: Base x402 v2, Replay, Smart Wallet, Deferred Settle, Prepaid Burn

    def test_03_base_x402_paid_replay_smartwallet_and_prepaid_credits(self) -> None:
        settle_before = self.fac_state.settle_calls
        x402_hdr = self._make_x402_header(PAYER_A_EVM, 5_000, version=2)
        status, hdrs, raw = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "metrics", "op": "SUM"},
            {"PAYMENT-SIGNATURE": x402_hdr},
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.fac_state.settle_calls, settle_before + 1)
        self.assertEqual(hdrs["x-blindcore-rail"], "base-x402")
        pay_resp = b64_json_decode(hdrs["payment-response"])
        self.assertTrue(pay_resp["success"])
        self.assertEqual(pay_resp["rail"], "base-x402")
        self.assertEqual(pay_resp["payer"], PAYER_A_EVM)

        # Replay of exact same PAYMENT-SIGNATURE must fail closed with 402
        status_rep, _, raw_rep = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "metrics", "op": "SUM"},
            {"PAYMENT-SIGNATURE": x402_hdr},
        )
        self.assertEqual(status_rep, 402)
        self.assertIn("replay", raw_rep.decode("utf-8").lower())
        self.assertEqual(self.fac_state.settle_calls, settle_before + 1)

        # v1 X-PAYMENT fallback + ERC-6492 Smart Wallet + Permit2
        v1_hdr = self._make_x402_header(
            PAYER_A_EVM,
            5_000,
            version=1,
            scheme="permit2-exact",
            sig_type="erc6492",
        )
        status_v1, hdrs_v1, _ = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "metrics", "op": "WEIGHTED_SUM"},
            {"X-PAYMENT": v1_hdr},
        )
        self.assertEqual(status_v1, 200)
        self.assertEqual(b64_json_decode(hdrs_v1["payment-response"])["settlementMode"], "permit2-exact:erc6492")

        # Deferred settlement: upstream 422 must NOT settle!
        settle_pre_err = self.fac_state.settle_calls
        err_hdr = self._make_x402_header(PAYER_A_EVM, 5_000, version=2)
        status_err, hdrs_err, _ = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "metrics", "op": "SUM", "force_error": True},
            {"PAYMENT-SIGNATURE": err_hdr},
        )
        self.assertEqual(status_err, 422)
        self.assertEqual(hdrs_err.get("x-blindcore-settlement"), "aborted")
        self.assertEqual(self.fac_state.settle_calls, settle_pre_err)

        # Underpaid prepaid top-up ($0.50 < $1.00 minimum) -> 402
        under_topup = self._make_x402_header(PAYER_A_EVM, 500_000, version=2)
        status_under, _, _ = self._http(
            "POST",
            "/api/v1/credits/topup",
            {},
            {"PAYMENT-SIGNATURE": under_topup},
        )
        self.assertEqual(status_under, 402)

        # Valid $1.00 USDC prepaid micro-credit top-up
        topup_hdr = self._make_x402_header(PAYER_A_EVM, PREPAID_MIN_MICRO_USDC, version=2)
        status_top, hdrs_top, raw_top = self._http(
            "POST",
            "/api/v1/credits/topup",
            {},
            {"PAYMENT-SIGNATURE": topup_hdr},
        )
        self.assertEqual(status_top, 200)
        top_json = json.loads(raw_top)
        session_tok = top_json["session_token"]
        self.assertEqual(top_json["balance_micro_usdc"], 1_000_000)
        self.assertIn("payment-response", hdrs_top)

        # Burn $0.0005 on INGEST and $0.001 on CONTAINS with ZERO CDP facilitator settles
        settle_before_burn = self.fac_state.settle_calls
        st_ing, hdr_ing, _ = self._http(
            "POST",
            "/api/v1/blind/jsonb/ingest",
            {"table": "metrics", "rows": [{"k": "v"}]},
            {"X-BlindCore-Session": session_tok},
        )
        self.assertEqual(st_ing, 200)
        self.assertEqual(hdr_ing["x-blindcore-rail"], "base-x402-credit")
        self.assertEqual(b64_json_decode(hdr_ing["payment-response"])["remainingMicroUsdc"], "999500")

        st_con, hdr_con, _ = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "metrics", "op": "CONTAINS"},
            {"X-BlindCore-Session": session_tok},
        )
        self.assertEqual(st_con, 200)
        self.assertEqual(b64_json_decode(hdr_con["payment-response"])["remainingMicroUsdc"], "998500")
        self.assertEqual(self.fac_state.settle_calls, settle_before_burn)

        # Upstream error with session token must refund credit cleanly
        st_ref, _, _ = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "metrics", "op": "CONTAINS", "force_error": True},
            {"X-BlindCore-Session": session_tok},
        )
        self.assertEqual(st_ref, 422)
        st_bal, _, raw_bal = self._http("GET", "/api/v1/credits/balance", headers={"X-BlindCore-Session": session_tok})
        self.assertEqual(st_bal, 200)
        self.assertEqual(json.loads(raw_bal)["balance_micro_usdc"], 998500)

    # -- 4. Rail 2: Bitcoin Lightning L402 ----------------------------------

    def test_04_lightning_l402_valid_forged_wrong_preimage_and_replay(self) -> None:
        # Step 1: Request 402 challenge for RANGE_GATE (25 sats)
        st_402, hdrs_402, _ = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "risk", "op": "RANGE_GATE"},
        )
        self.assertEqual(st_402, 402)
        match = re.search(r'L402 macaroon="([^"]+)", invoice="([^"]+)"', hdrs_402["www-authenticate"])
        self.assertIsNotNone(match)
        assert match is not None
        macaroon_b64 = match.group(1)
        mac_obj = b64_json_decode(macaroon_b64)
        token_id = mac_obj["identifier"]["token_id"]
        preimage_hex = self.gate_srv.engine.derive_test_preimage_hex(token_id)

        # Negative 1: Forged macaroon (tampered caveats) -> 402
        forged_obj = json.loads(json.dumps(mac_obj))
        forged_obj["caveats"][1] = "sats=99999"
        forged_mac = b64_json_encode(forged_obj)
        st_forged, _, raw_forged = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "risk", "op": "RANGE_GATE"},
            {"Authorization": f"L402 {forged_mac}:{preimage_hex}"},
        )
        self.assertEqual(st_forged, 402)
        self.assertIn("macaroon", raw_forged.decode("utf-8").lower())

        # Negative 2: Wrong preimage -> 402
        wrong_preimage = ("00" if not preimage_hex.startswith("00") else "ff") + preimage_hex[2:]
        st_wrong, _, raw_wrong = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "risk", "op": "RANGE_GATE"},
            {"Authorization": f"L402 {macaroon_b64}:{wrong_preimage}"},
        )
        self.assertEqual(st_wrong, 402)
        self.assertIn("preimage", raw_wrong.decode("utf-8").lower())

        # Negative 3: Valid 25-sat macaroon used on 30-sat SKLEARN_MNB -> 402 (underpaid)
        st_under, _, _ = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "risk", "op": "SKLEARN_MNB"},
            {"Authorization": f"L402 {macaroon_b64}:{preimage_hex}"},
        )
        self.assertEqual(st_under, 402)

        # Positive: Valid macaroon + preimage -> 200 OK
        st_ok, hdrs_ok, raw_ok = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "risk", "op": "RANGE_GATE"},
            {"Authorization": f"L402 {macaroon_b64}:{preimage_hex}"},
        )
        self.assertEqual(st_ok, 200)
        self.assertEqual(hdrs_ok["x-blindcore-rail"], "ln-l402")
        pay_resp = b64_json_decode(hdrs_ok["payment-response"])
        self.assertEqual(pay_resp["rail"], "ln-l402")
        self.assertEqual(pay_resp["amountSats"], 25)
        self.assertEqual(json.loads(raw_ok)["rail_echo"], "ln-l402")

        # Negative 4: Replayed preimage -> 402
        st_rep, _, raw_rep = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "risk", "op": "RANGE_GATE"},
            {"Authorization": f"L402 {macaroon_b64}:{preimage_hex}"},
        )
        self.assertEqual(st_rep, 402)
        self.assertIn("replay", raw_rep.decode("utf-8").lower())

    # -- 5. Rail 3: Stacks sBTC Verification, Negative Cases & Top-Up -------

    def test_05_stacks_sbtc_valid_negative_and_topup(self) -> None:
        tx_valid = self._register_stacks_sbtc_tx(amount_sats=30, status="success")
        tx_underpaid = self._register_stacks_sbtc_tx(amount_sats=1, status="success")
        tx_pending = self._register_stacks_sbtc_tx(amount_sats=30, status="pending")
        tx_wrong_rcpt = self._register_stacks_sbtc_tx(
            amount_sats=30,
            status="success",
            recipient="SP000000000000000000002Q6VF78",
        )

        # Negative cases -> 402
        for bad_tx in (tx_underpaid, tx_pending, tx_wrong_rcpt):
            st, _, _ = self._http(
                "POST",
                "/api/v1/blind/jsonb/query",
                {"table": "phishing", "op": "SKLEARN_MNB"},
                {"X-Stacks-Payment-Tx": bad_tx},
            )
            self.assertEqual(st, 402)

        # Positive valid sBTC tx -> 200 OK
        st_ok, hdrs_ok, raw_ok = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "phishing", "op": "SKLEARN_MNB"},
            {"X-Stacks-Payment-Tx": f"0x{tx_valid}"},
        )
        self.assertEqual(st_ok, 200)
        self.assertEqual(hdrs_ok["x-blindcore-rail"], "stacks-sbtc")
        pay_resp = b64_json_decode(hdrs_ok["payment-response"])
        self.assertEqual(pay_resp["rail"], "stacks-sbtc")
        self.assertEqual(pay_resp["payer"], PAYER_STACKS)
        self.assertEqual(pay_resp["amountSats"], 30)
        self.assertEqual(json.loads(raw_ok)["payer_echo"], PAYER_STACKS)

        # Replayed txid -> 402
        st_rep, _, raw_rep = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "phishing", "op": "SKLEARN_MNB"},
            {"X-Stacks-Payment-Tx": tx_valid},
        )
        self.assertEqual(st_rep, 402)
        self.assertIn("replay", raw_rep.decode("utf-8").lower())

        # Prepaid sBTC credit top-up (2,000 sats >= $1.00) -> burn on INGEST
        tx_topup = self._register_stacks_sbtc_tx(amount_sats=2000, status="success")
        st_top, _, raw_top = self._http(
            "POST",
            "/api/v1/credits/topup",
            {},
            {"X-Stacks-Payment-Tx": tx_topup},
        )
        self.assertEqual(st_top, 200)
        top_data = json.loads(raw_top)
        self.assertEqual(top_data["rail"], "stacks-sbtc")
        self.assertGreaterEqual(top_data["balance_micro_usdc"], PREPAID_MIN_MICRO_USDC)

        st_burn, hdr_burn, _ = self._http(
            "POST",
            "/api/v1/blind/jsonb/ingest",
            {"table": "phishing", "rows": [{"x": 1}]},
            {"X-BlindCore-Session": top_data["session_token"]},
        )
        self.assertEqual(st_burn, 200)
        self.assertEqual(hdr_burn["x-blindcore-rail"], "stacks-sbtc-credit")

    # -- 6. Counterfactual Binding Checks (assert_ne across rails & payers) -

    def test_06_counterfactual_payer_and_rail_binding(self) -> None:
        query_body = {"table": "counterfactual", "op": "SUM"}

        # A) Base x402 Payer A
        _, _, raw_a = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            query_body,
            {"PAYMENT-SIGNATURE": self._make_x402_header(PAYER_A_EVM, 5_000)},
        )
        res_a = json.loads(raw_a)

        # B) Base x402 Payer B (same rail, same body, different payer)
        _, _, raw_b = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            query_body,
            {"PAYMENT-SIGNATURE": self._make_x402_header(PAYER_B_EVM, 5_000)},
        )
        res_b = json.loads(raw_b)

        # C) Lightning L402 (same body, different rail)
        _, hdrs_402, _ = self._http("POST", "/api/v1/blind/jsonb/query", query_body)
        m = re.search(r'L402 macaroon="([^"]+)"', hdrs_402["www-authenticate"])
        assert m is not None
        mac_b64 = m.group(1)
        tok_id = b64_json_decode(mac_b64)["identifier"]["token_id"]
        preimage = self.gate_srv.engine.derive_test_preimage_hex(tok_id)
        _, _, raw_ln = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            query_body,
            {"Authorization": f"L402 {mac_b64}:{preimage}"},
        )
        res_ln = json.loads(raw_ln)

        # D) Stacks sBTC (same body, different rail)
        tx_stx = self._register_stacks_sbtc_tx(amount_sats=8, status="success")
        _, _, raw_stx = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            query_body,
            {"X-Stacks-Payment-Tx": tx_stx},
        )
        res_stx = json.loads(raw_stx)

        # Counterfactual assert_ne! checks: payer, rail, payment_hash, gate_mac, receipt_hex MUST diverge
        self.assertNotEqual(res_a["payer_echo"], res_b["payer_echo"])
        self.assertNotEqual(res_a["payment_hash_echo"], res_b["payment_hash_echo"])
        self.assertNotEqual(res_a["gate_mac_echo"], res_b["gate_mac_echo"])
        self.assertNotEqual(res_a["receipt_hex"], res_b["receipt_hex"])

        for other in (res_ln, res_stx):
            self.assertNotEqual(res_a["rail_echo"], other["rail_echo"])
            self.assertNotEqual(res_a["payer_echo"], other["payer_echo"])
            self.assertNotEqual(res_a["payment_hash_echo"], other["payment_hash_echo"])
            self.assertNotEqual(res_a["gate_mac_echo"], other["gate_mac_echo"])
            self.assertNotEqual(res_a["receipt_hex"], other["receipt_hex"])
        self.assertNotEqual(res_ln["receipt_hex"], res_stx["receipt_hex"])

    # -- 7. MCP Server & Coinbase AgentKit ActionProvider Integration -------

    def test_07_mcp_server_and_agentkit_provider(self) -> None:
        # Mint a session token for MCP tool call
        topup_hdr = self._make_x402_header(PAYER_B_EVM, PREPAID_MIN_MICRO_USDC)
        st, _, raw = self._http("POST", "/api/v1/credits/topup", {}, {"PAYMENT-SIGNATURE": topup_hdr})
        self.assertEqual(st, 200)
        sess_tok = json.loads(raw)["session_token"]

        mcp_client = BlindCoreHttpClient(base_url=self.gate_url, session_token=sess_tok)
        init_resp = handle_rpc_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, mcp_client)
        assert init_resp is not None
        self.assertEqual(init_resp["result"]["serverInfo"]["name"], "blindcore-mcp")

        list_resp = handle_rpc_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, mcp_client)
        assert list_resp is not None
        tool_names = [t["name"] for t in list_resp["result"]["tools"]]
        self.assertEqual(tool_names, ["blindcore_pricing", "blindcore_query", "blindcore_sklearn_mnb"])

        price_resp = handle_rpc_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "blindcore_pricing", "arguments": {"include_x402_manifest": True}},
            },
            mcp_client,
        )
        assert price_resp is not None
        self.assertFalse(price_resp["result"]["isError"])
        self.assertEqual(price_resp["result"]["structuredContent"]["tiers"]["SKLEARN_MNB"]["sats"], 30)

        query_resp = handle_rpc_request(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "blindcore_query", "arguments": {"table": "mcp_tbl", "op": "CONTAINS"}},
            },
            mcp_client,
        )
        assert query_resp is not None
        self.assertEqual(query_resp["result"]["structuredContent"]["http_status"], 200)

        # AgentKit ActionProvider automatic 402 -> sign -> retry
        def mock_agent_signer(rail: str, challenge: dict[str, object]) -> dict[str, str]:
            if rail == "base-x402":
                amt = int(challenge["payment_required"]["accepts"][0]["amount"])  # type: ignore[index]
                return {"PAYMENT-SIGNATURE": self._make_x402_header(PAYER_B_EVM, amt)}
            raise AssertionError(f"unexpected rail {rail}")

        provider = BlindCoreActionProvider(
            base_url=self.gate_url,
            preferred_rail="base-x402",
            payment_signer=mock_agent_signer,
        )
        self.assertTrue(provider.supports_network("eip155:8453"))
        mnb_res = json.loads(
            provider.blindcore_sklearn_mnb(
                None,
                {
                    "table": "agent_corpus",
                    "train_classes": [{"name": "pos"}, {"name": "neg"}],
                    "vocab_paths": ["/bow/urgent"],
                },
            )
        )
        self.assertEqual(mnb_res["http_status"], 200)
        self.assertEqual(mnb_res["rail"], "base-x402")

    # -- 8. Additional Security: Forged x402, Wrong Network, STX Fallback, 413

    def test_08_forged_x402_wrong_network_stx_fallback_and_body_cap(self) -> None:
        # Forged x402 signature -> 402
        bad_sig_hdr = self._make_x402_header(PAYER_A_EVM, 5_000, valid_sig=False)
        st_bad, _, _ = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "metrics", "op": "SUM"},
            {"PAYMENT-SIGNATURE": bad_sig_hdr},
        )
        self.assertEqual(st_bad, 402)

        # Wrong CAIP-2 network (Sepolia sent to Mainnet gate) -> 402
        wrong_net_obj = b64_json_decode(self._make_x402_header(PAYER_A_EVM, 5_000))
        wrong_net_obj["network"] = "eip155:84532"
        wrong_net_obj["accepted"]["network"] = "eip155:84532"
        st_net, _, _ = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "metrics", "op": "SUM"},
            {"PAYMENT-SIGNATURE": b64_json_encode(wrong_net_obj)},
        )
        self.assertEqual(st_net, 402)

        # Stacks STX token_transfer fallback: underpaid -> 402, valid -> 200
        tx_stx_low = secrets.token_hex(32)
        self.stacks_state.txs[tx_stx_low] = {
            "tx_id": f"0x{tx_stx_low}",
            "tx_status": "success",
            "tx_type": "token_transfer",
            "sender_address": PAYER_STACKS,
            "token_transfer": {"recipient_address": STACKS_PAY_TO, "amount": "100"},
        }
        st_low, _, _ = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "metrics", "op": "SUM"},
            {"X-Stacks-Payment-Tx": tx_stx_low},
        )
        self.assertEqual(st_low, 402)

        tx_stx_ok = secrets.token_hex(32)
        self.stacks_state.txs[tx_stx_ok] = {
            "tx_id": f"0x{tx_stx_ok}",
            "tx_status": "success",
            "tx_type": "token_transfer",
            "sender_address": PAYER_STACKS,
            "token_transfer": {"recipient_address": STACKS_PAY_TO, "amount": "5000"},
        }
        st_ok, hdr_ok, _ = self._http(
            "POST",
            "/api/v1/blind/jsonb/query",
            {"table": "metrics", "op": "SUM"},
            {"X-Stacks-Payment-Tx": tx_stx_ok},
        )
        self.assertEqual(st_ok, 200)
        self.assertEqual(b64_json_decode(hdr_ok["payment-response"])["settlementMode"], "stacks-stx")

        # Oversized body (> 262,144 B) -> 413 Payload Too Large
        big_req = urllib.request.Request(
            f"{self.gate_url}/api/v1/blind/jsonb/ingest",
            data=b"{" + b" " * 270_000 + b"}",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(big_req, timeout=10)
        self.assertEqual(ctx.exception.code, 413)


if __name__ == "__main__":
    unittest.main(verbosity=2)
