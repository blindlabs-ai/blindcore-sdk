#!/usr/bin/env python3
"""
BlindCore Tri-Rail Payment Gateway (SPDX-License-Identifier: Apache-2.0).

Production-grade Python 3 stdlib-only HTTP reverse proxy enforcing metered
tri-rail payments in front of the BlindCore confidential compute API:
  - Rail 1 (base-x402): x402 v2 (Base L2 USDC EIP-3009, Permit2, ERC-1271 /
    ERC-6492 smart wallets, v1 X-PAYMENT fallback) + prepaid micro-credit ledger.
  - Rail 2 (ln-l402): Bitcoin Lightning L402 (LSAT) with HMAC-SHA256 macaroons,
    LND REST / LNbits / deterministic test backends, SHA-256 preimage check.
  - Rail 3 (stacks-sbtc): Stacks sBTC (SIP-010) and STX payment verification
    via Hiro Stacks API + prepaid sBTC session credit top-up.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import secrets
import sqlite3
import ssl
import threading
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


# ---------------------------------------------------------------------------
# Protocol Constants & Canonical Base / Stacks Addresses
# ---------------------------------------------------------------------------

MAX_BODY_BYTES = 262_144
MAX_HEADER_BYTES = 65_536
PREPAID_MIN_MICRO_USDC = 1_000_000        # $1.00 USDC minimum top-up
MAX_MICRO_USDC = 10_000_000_000_000       # $10M cap (safely below signed int64 max)
MAX_SATS = 10_000_000_000                 # 100 BTC per single op/top-up cap
MAX_USTX = 10_000_000_000_000             # 10M STX per single op/top-up cap
DEFAULT_BTC_USD_PRICE = 66_667            # Used to convert sBTC/L402 top-ups to micro-USDC
DEFAULT_STX_MICRO_USD = 1_500_000         # $1.50 per STX fallback quote (1 STX = 1e6 uSTX)

BASE_MAINNET_CAIP2 = "eip155:8453"
BASE_SEPOLIA_CAIP2 = "eip155:84532"

USDC_BY_NETWORK = {
    BASE_MAINNET_CAIP2: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    BASE_SEPOLIA_CAIP2: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
}
PERMIT2_CANONICAL = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

ERC8004_IDENTITY_REGISTRY_BASE = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432"
ERC8004_REPUTATION_REGISTRY_BASE = "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63"

STACKS_SBTC_MAINNET = "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token"
STACKS_SBTC_TESTNET = "ST1F7QA2MDF17S807EPA36TSS8AMEFY4KA9TVGWXT.sbtc-token"

HEX64_RE = re.compile(r"\A[0-9a-fA-F]{64}\Z")
STACKS_TXID_RE = re.compile(r"\A(?:0x)?[0-9a-fA-F]{64}\Z")
EVM_ADDR_RE = re.compile(r"\A0x[0-9a-fA-F]{40}\Z")
STACKS_PRINCIPAL_RE = re.compile(
    r"\A[SM][PT][0-9A-Z]{28,41}(?:\.[a-zA-Z][a-zA-Z0-9_-]{0,127})?\Z"
)
SAFE_PAYER_RE = re.compile(r"\A[a-zA-Z0-9:._-]{3,128}\Z")
SAFE_SIG_TYPE_RE = re.compile(r"\A[a-z0-9_-]{1,32}\Z")
CAVEAT_KEY_RE = re.compile(r"\A[a-z_]{1,32}\Z")
B64URL_RE = re.compile(r"\A[A-Za-z0-9_-]+\Z")
SAFE_CONTENT_TYPE_RE = re.compile(
    r"\Aapplication/json(?:\s*;\s*charset=(?:utf-8|UTF-8))?\Z"
)
ALLOWED_ORIGIN_RAILS = frozenset(("base-x402", "ln-l402", "stacks-sbtc"))
ALLOWED_L402_CAVEAT_KEYS = frozenset(("tier", "sats", "path", "exp"))
ALLOWED_PROXY_PREFIXES = ("/api/v1/blind/", "/api/auction/")
STRIPPED_CLIENT_HEADERS = frozenset((
    "authorization",
    "payment-signature",
    "x-payment",
    "x-stacks-payment-tx",
    "proxy-authorization",
    "cookie",
))


@dataclass(frozen=True)
class PriceTier:
    name: str
    op_tier_id: int
    micro_usdc: int
    sats: int
    ustx: int
    description: str


PRICING_TIERS: dict[str, PriceTier] = {
    "INGEST": PriceTier(
        name="INGEST",
        op_tier_id=1,
        micro_usdc=500,
        sats=1,
        ustx=350,
        description="Encrypted batch ingest (<= 256 KiB); use prepaid session credits to bypass CDP tx fee",
    ),
    "CONTAINS": PriceTier(
        name="CONTAINS",
        op_tier_id=2,
        micro_usdc=1_000,
        sats=2,
        ustx=700,
        description="Constant-time encrypted CONTAINS / LATEST query",
    ),
    "SUM": PriceTier(
        name="SUM",
        op_tier_id=3,
        micro_usdc=5_000,
        sats=8,
        ustx=3_500,
        description="Homomorphic SUM / WEIGHTED_SUM aggregation",
    ),
    "RANGE_GATE": PriceTier(
        name="RANGE_GATE",
        op_tier_id=4,
        micro_usdc=15_000,
        sats=25,
        ustx=10_000,
        description="Homomorphic RANGE_GATE policy check or sealed-bid AUCTION clearing",
    ),
    "SKLEARN_MNB": PriceTier(
        name="SKLEARN_MNB",
        op_tier_id=5,
        micro_usdc=20_000,
        sats=30,
        ustx=13_500,
        description="Single-pass encrypted MultinomialNB training and cohort scoring",
    ),
}


def _parse_bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    val = raw.strip().lower()
    if val in ("1", "true", "yes", "on"):
        return True
    if val in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"invalid boolean value for {name}: {raw!r}")


def _validate_positive_int(val: Any, name: str, max_val: int) -> int:
    if isinstance(val, bool):
        raise ValueError(f"{name} must be an integer, not bool")
    try:
        num = int(val)
    except Exception as exc:
        raise ValueError(f"invalid integer for {name}: {exc}") from exc
    if num <= 0 or num > max_val:
        raise ValueError(f"{name} out of bounds (1..{max_val}): {num}")
    return num


def validate_http_url(url: str, field_name: str, allow_empty: bool = False) -> str:
    cleaned = url.strip().rstrip("/")
    if not cleaned:
        if allow_empty:
            return ""
        raise ValueError(f"{field_name} must not be empty")
    if any(ch in cleaned for ch in ("\r", "\n", "\x00", " ", "\t")):
        raise ValueError(f"{field_name} contains illegal whitespace or control chars")
    parsed = urllib.parse.urlsplit(cleaned)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"{field_name} must use http or https scheme")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"{field_name} must specify a valid host without embedded credentials")
    if parsed.fragment:
        raise ValueError(f"{field_name} must not include a URL fragment")
    return cleaned


def validate_request_path(raw_path: str, allow_proxy_only: bool = False) -> str:
    if not isinstance(raw_path, str) or not raw_path.startswith("/") or raw_path.startswith("//"):
        raise ValueError("invalid request path")
    if any(ch in raw_path for ch in ("\r", "\n", "\x00", "\\", "#")):
        raise ValueError("illegal characters in request path")
    path_only = raw_path.split("?", 1)[0]
    decoded = urllib.parse.unquote(path_only)
    if any(ch in decoded for ch in ("\r", "\n", "\x00", "\\", "#")):
        raise ValueError("illegal encoded characters in request path")
    if "//" in decoded or ".." in decoded.split("/"):
        raise ValueError("path traversal segment rejected")
    if allow_proxy_only and not any(decoded.startswith(p) for p in ALLOWED_PROXY_PREFIXES):
        raise ValueError(f"endpoint not allowed on paid proxy: {decoded}")
    return decoded


def sanitize_content_type(raw_ct: str | None) -> str:
    if not raw_ct:
        return "application/json"
    cleaned = raw_ct.strip()
    if SAFE_CONTENT_TYPE_RE.fullmatch(cleaned):
        return cleaned
    return "application/json"


def sanitize_upstream_headers(
    incoming_headers: Any,
    rail: str,
    payer: str,
    payment_hash: str,
    fee_micro_usdc: int,
    now_ts: int,
    gate_mac: str,
    upstream_token: str,
) -> dict[str, str]:
    """
    Build loopback upstream headers from scratch after explicitly stripping all
    untrusted client X-BlindCore-* and Authorization / payment headers.
    """
    raw_ct = None
    if incoming_headers is not None:
        for k, v in incoming_headers.items():
            kl = str(k).lower()
            if kl.startswith("x-blindcore-") or kl in STRIPPED_CLIENT_HEADERS:
                continue
            if kl == "content-type" and raw_ct is None:
                raw_ct = str(v)

    for label, val in (
        ("rail", rail),
        ("payer", payer),
        ("payment_hash", payment_hash),
        ("gate_mac", gate_mac),
    ):
        if any(ch in val for ch in ("\r", "\n", "\x00", "|")):
            raise ValueError(f"unsafe character in upstream header field {label}")

    out: dict[str, str] = {
        "Content-Type": sanitize_content_type(raw_ct),
        "X-BlindCore-Rail": rail,
        "X-BlindCore-Payer": payer,
        "X-BlindCore-Payment-Hash": payment_hash,
        "X-BlindCore-Fee-Micro": str(fee_micro_usdc),
        "X-BlindCore-Ts": str(now_ts),
        "X-BlindCore-Gate-Mac": gate_mac,
    }
    if upstream_token:
        if any(ch in upstream_token for ch in ("\r", "\n", "\x00")):
            raise ValueError("unsafe upstream_token")
        out["Authorization"] = f"Bearer {upstream_token}"
    return out


def b64_json_encode(obj: Any) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def b64_json_decode(encoded: str) -> Any:
    if not isinstance(encoded, str):
        raise ValueError("base64 input must be a string")
    raw = encoded.strip()
    if not raw or len(raw) > MAX_HEADER_BYTES:
        raise ValueError("base64 payload empty or exceeds size limit")
    if any(ch in raw for ch in ("\r", "\n", "\x00", " ", "\t")):
        raise ValueError("base64 payload contains whitespace or control chars")
    pad = (-len(raw)) % 4
    if pad == 3:
        raise ValueError("invalid base64 length")
    if pad:
        raw += "=" * pad
    try:
        decoded = base64.b64decode(raw.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError(f"invalid base64 encoding: {exc}") from exc
    return json.loads(decoded.decode("utf-8"))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(encoded: str) -> bytes:
    if not isinstance(encoded, str):
        raise ValueError("base64url input must be a string")
    raw = encoded.strip()
    if not raw or len(raw) > MAX_HEADER_BYTES or not B64URL_RE.fullmatch(raw):
        raise ValueError("invalid base64url encoding")
    pad = (-len(raw)) % 4
    if pad == 3:
        raise ValueError("invalid base64url length")
    if pad:
        raw += "=" * pad
    return base64.urlsafe_b64decode(raw.encode("ascii"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_txid(txid: str) -> str:
    if not isinstance(txid, str):
        raise ValueError("transaction id must be a string")
    if any(ch in txid for ch in ("\r", "\n", "\x00", "/", "\\", "?", "#", "..")):
        raise ValueError("illegal characters in transaction id")
    cleaned = txid.strip()
    if not STACKS_TXID_RE.fullmatch(cleaned):
        raise ValueError("invalid 32-byte hex transaction id")
    cleaned = cleaned.lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    return cleaned


def resolve_price_tier(path: str, body_json: dict[str, Any] | None) -> PriceTier:
    clean_path = path.split("?", 1)[0].rstrip("/") or "/"
    if clean_path in ("/api/v1/blind/ingest", "/api/v1/blind/jsonb/ingest"):
        return PRICING_TIERS["INGEST"]
    if clean_path.startswith("/api/auction/"):
        return PRICING_TIERS["RANGE_GATE"]

    op = ""
    if isinstance(body_json, dict):
        op = str(body_json.get("op", "")).strip().upper()
        if op == "BLIND_PIPELINE":
            stages = body_json.get("stages")
            if isinstance(stages, dict):
                score = stages.get("score")
                agg = stages.get("aggregate")
                score_kind = str(score.get("kind", "")).upper() if isinstance(score, dict) else ""
                agg_kind = str(agg.get("kind", "")).upper() if isinstance(agg, dict) else ""
                if score_kind == "SKLEARN_MNB":
                    return PRICING_TIERS["SKLEARN_MNB"]
                if score_kind in ("RANGE_GATE", "AUCTION"):
                    return PRICING_TIERS["RANGE_GATE"]
                if agg_kind in ("SUM", "WEIGHTED_SUM"):
                    return PRICING_TIERS["SUM"]
            return PRICING_TIERS["CONTAINS"]

    if op == "INGEST":
        return PRICING_TIERS["INGEST"]
    if op in ("CONTAINS", "LATEST"):
        return PRICING_TIERS["CONTAINS"]
    if op in ("SUM", "WEIGHTED_SUM"):
        return PRICING_TIERS["SUM"]
    if op in ("RANGE_GATE", "AUCTION", "AUCTION_CLEAR", "AUCTION_COMMIT"):
        return PRICING_TIERS["RANGE_GATE"]
    if op == "SKLEARN_MNB":
        return PRICING_TIERS["SKLEARN_MNB"]
    return PRICING_TIERS["CONTAINS"]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class GateConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 3002
    public_base_url: str = "https://blindcore.dev"
    upstream_url: str = "http://127.0.0.1:3001"
    upstream_token: str = ""
    gate_hmac_key_hex: str = ""
    db_path: str = ":memory:"

    # Rail 1: Base L2 x402 v2
    base_network: str = BASE_MAINNET_CAIP2
    base_pay_to: str = "0x000000000000000000000000000000000000dEaD"
    base_anchor_contract: str = "0x0000000000000000000000000000000000000000"
    x402_facilitator_url: str = ""
    cdp_api_key: str = ""

    # Rail 2: Bitcoin Lightning L402
    l402_macaroon_secret: str = ""
    lnd_rest_url: str = ""
    lnd_macaroon_hex: str = ""
    lnd_tls_cert_path: str = ""
    lnbits_url: str = ""
    lnbits_api_key: str = ""

    # Rail 3: Stacks sBTC / STX
    stacks_network: str = "mainnet"
    stacks_api_url: str = "https://api.mainnet.hiro.so"
    stacks_pay_to: str = "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7"
    stacks_sbtc_contract: str = STACKS_SBTC_MAINNET
    stacks_anchor_contract: str = "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7.blindcore-root-anchor"
    btc_usd_price: int = DEFAULT_BTC_USD_PRICE

    # Session credits & rate limits
    session_secret: str = ""
    session_ttl_secs: int = 86_400
    rate_limit_rpm: int = 240
    bad_payment_limit: int = 12
    bad_payment_window_secs: int = 300
    trust_proxy_headers: bool = False

    # Deterministic local test mode (enables local L402 invoice minting & optional local x402 verification)
    test_mode: bool = False
    test_x402_secret: str = ""
    test_l402_seed: str = ""
    http_timeout_secs: float = 15.0

    def validate(self) -> None:
        self.public_base_url = validate_http_url(self.public_base_url, "public_base_url")
        self.upstream_url = validate_http_url(self.upstream_url, "upstream_url")
        self.x402_facilitator_url = validate_http_url(
            self.x402_facilitator_url, "x402_facilitator_url", allow_empty=True
        )
        self.lnd_rest_url = validate_http_url(self.lnd_rest_url, "lnd_rest_url", allow_empty=True)
        self.lnbits_url = validate_http_url(self.lnbits_url, "lnbits_url", allow_empty=True)
        self.stacks_api_url = validate_http_url(self.stacks_api_url, "stacks_api_url")
        if self.base_network not in USDC_BY_NETWORK:
            raise ValueError(f"unsupported base_network: {self.base_network}")
        if not EVM_ADDR_RE.fullmatch(self.base_pay_to):
            raise ValueError(f"invalid base_pay_to EVM address: {self.base_pay_to}")
        if self.stacks_network not in ("mainnet", "testnet"):
            raise ValueError(f"unsupported stacks_network: {self.stacks_network}")
        if not STACKS_PRINCIPAL_RE.fullmatch(self.stacks_pay_to):
            raise ValueError(f"invalid stacks_pay_to principal: {self.stacks_pay_to}")
        if self.btc_usd_price <= 0:
            raise ValueError("btc_usd_price must be positive")
        if self.session_ttl_secs <= 0:
            raise ValueError("session_ttl_secs must be positive")
        if self.http_timeout_secs <= 0:
            raise ValueError("http_timeout_secs must be positive")
        if self.gate_hmac_key_hex:
            try:
                key_bytes = bytes.fromhex(self.gate_hmac_key_hex)
            except ValueError as exc:
                raise ValueError(f"invalid gate_hmac_key_hex: {exc}") from exc
            if len(key_bytes) < 32:
                raise ValueError("gate_hmac_key_hex must be at least 32 bytes (64 hex chars)")

    @property
    def base_usdc_asset(self) -> str:
        return USDC_BY_NETWORK.get(self.base_network, USDC_BY_NETWORK[BASE_MAINNET_CAIP2])

    @classmethod
    def from_env(cls) -> "GateConfig":
        test_mode = _parse_bool_env("BLINDCORE_TEST_MODE", default=False)
        trust_proxy = _parse_bool_env("BLINDCORE_TRUST_PROXY_HEADERS", default=False)
        base_net = os.environ.get("BLINDCORE_BASE_NETWORK", BASE_MAINNET_CAIP2).strip()
        if base_net not in USDC_BY_NETWORK:
            raise ValueError(f"unsupported BLINDCORE_BASE_NETWORK: {base_net}")
        stacks_net = os.environ.get("BLINDCORE_STACKS_NETWORK", "mainnet").strip().lower()
        if stacks_net not in ("mainnet", "testnet"):
            raise ValueError(f"unsupported BLINDCORE_STACKS_NETWORK: {stacks_net}")
        default_sbtc = STACKS_SBTC_MAINNET if stacks_net == "mainnet" else STACKS_SBTC_TESTNET
        default_stacks_api = (
            "https://api.mainnet.hiro.so" if stacks_net == "mainnet" else "https://api.testnet.hiro.so"
        )
        upstream_tok = (
            os.environ.get("BLINDCORE_UPSTREAM_TOKEN")
            or os.environ.get("UPSTREAM_API_TOKEN")
            or ""
        )
        cfg = cls(
            listen_host=os.environ.get("BLINDCORE_LISTEN_HOST", "127.0.0.1"),
            listen_port=int(os.environ.get("BLINDCORE_LISTEN_PORT", "3002")),
            public_base_url=os.environ.get("BLINDCORE_PUBLIC_URL", "https://blindcore.dev").rstrip("/"),
            upstream_url=os.environ.get("BLINDCORE_UPSTREAM_URL", "http://127.0.0.1:3001").rstrip("/"),
            upstream_token=upstream_tok,
            gate_hmac_key_hex=os.environ.get("BLINDCORE_GATE_HMAC_KEY_HEX", ""),
            db_path=os.environ.get("BLINDCORE_GATE_DB", "/var/lib/blindcore-gate/ledger.sqlite"),
            base_network=base_net,
            base_pay_to=os.environ.get("BLINDCORE_BASE_PAY_TO", "0x000000000000000000000000000000000000dEaD"),
            base_anchor_contract=os.environ.get(
                "BLINDCORE_BASE_ANCHOR_CONTRACT",
                "0x0000000000000000000000000000000000000000",
            ),
            x402_facilitator_url=os.environ.get("BLINDCORE_X402_FACILITATOR_URL", "").rstrip("/"),
            cdp_api_key=os.environ.get("BLINDCORE_CDP_API_KEY", ""),
            l402_macaroon_secret=os.environ.get("L402_MACAROON_SECRET", ""),
            lnd_rest_url=os.environ.get("LND_REST_URL", "").rstrip("/"),
            lnd_macaroon_hex=os.environ.get("LND_MACAROON_HEX", ""),
            lnd_tls_cert_path=os.environ.get("LND_TLS_CERT_PATH", ""),
            lnbits_url=os.environ.get("LNBITS_URL", "").rstrip("/"),
            lnbits_api_key=os.environ.get("LNBITS_API_KEY", ""),
            stacks_network=stacks_net,
            stacks_api_url=os.environ.get("STACKS_API_URL", default_stacks_api).rstrip("/"),
            stacks_pay_to=os.environ.get(
                "BLINDCORE_STACKS_PAY_TO",
                "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7",
            ),
            stacks_sbtc_contract=os.environ.get("BLINDCORE_STACKS_SBTC_CONTRACT", default_sbtc),
            stacks_anchor_contract=os.environ.get(
                "BLINDCORE_STACKS_ANCHOR_CONTRACT",
                "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7.blindcore-root-anchor",
            ),
            btc_usd_price=int(os.environ.get("BLINDCORE_BTC_USD_PRICE", str(DEFAULT_BTC_USD_PRICE))),
            session_secret=os.environ.get("BLINDCORE_SESSION_SECRET", ""),
            session_ttl_secs=int(os.environ.get("BLINDCORE_SESSION_TTL_SECS", "86400")),
            rate_limit_rpm=int(os.environ.get("BLINDCORE_RATE_LIMIT_RPM", "240")),
            bad_payment_limit=int(os.environ.get("BLINDCORE_BAD_PAYMENT_LIMIT", "12")),
            bad_payment_window_secs=int(os.environ.get("BLINDCORE_BAD_PAYMENT_WINDOW_SECS", "300")),
            trust_proxy_headers=trust_proxy,
            test_mode=test_mode,
            test_x402_secret=os.environ.get("BLINDCORE_TEST_X402_SECRET", ""),
            test_l402_seed=os.environ.get("BLINDCORE_TEST_L402_SEED", ""),
            http_timeout_secs=float(os.environ.get("BLINDCORE_HTTP_TIMEOUT_SECS", "15.0")),
        )
        cfg.validate()
        return cfg


# ---------------------------------------------------------------------------
# Thread-Safe SQLite Replay & Prepaid Micro-Credit Ledger
# ---------------------------------------------------------------------------

class PaymentLedger:
    def __init__(self, db_path: str) -> None:
        self._lock = threading.RLock()
        if db_path != ":memory:":
            parent = os.path.dirname(os.path.abspath(db_path))
            if parent:
                os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(
            db_path,
            timeout=10.0,
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS payment_replays (
                rail TEXT NOT NULL,
                payment_hash TEXT NOT NULL,
                payer TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('PENDING', 'SETTLED', 'ABORTED')),
                valid_until INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (rail, payment_hash)
            )
            """
        )
        self._conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_replays_unique
            ON payment_replays (rail, payment_hash)
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS credit_balances (
                payer TEXT PRIMARY KEY,
                balance_micro_usdc INTEGER NOT NULL CHECK (balance_micro_usdc >= 0),
                total_deposited_micro_usdc INTEGER NOT NULL CHECK (total_deposited_micro_usdc >= 0),
                debit_seq INTEGER NOT NULL DEFAULT 0 CHECK (debit_seq >= 0),
                updated_at INTEGER NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS credit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payer TEXT NOT NULL,
                rail TEXT NOT NULL,
                payment_hash TEXT NOT NULL,
                delta_micro_usdc INTEGER NOT NULL,
                reason TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_credit_events_topup_unique
            ON credit_events (rail, payment_hash)
            WHERE reason = 'TOPUP'
            """
        )
        self._conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_credit_events_refund_unique
            ON credit_events (payer, payment_hash)
            WHERE rail = 'prepaid-credit' AND payment_hash LIKE 'refund-%'
            """
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def is_payment_locked_or_settled(self, rail: str, payment_hash: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT state FROM payment_replays WHERE rail = ? AND payment_hash = ?",
                (rail, payment_hash),
            ).fetchone()
            return row is not None and row[0] in ("PENDING", "SETTLED")

    def reserve_payment(self, rail: str, payment_hash: str, payer: str, valid_until: int) -> bool:
        """Atomically lock a payment hash. Returns False if already PENDING or SETTLED."""
        if not rail or not payment_hash or not payer:
            raise ValueError("rail, payment_hash, and payer must be non-empty")
        now = int(time.time())
        bounded_until = min(int(valid_until), now + 86_400 * 365 * 5)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT state FROM payment_replays WHERE rail = ? AND payment_hash = ?",
                    (rail, payment_hash),
                ).fetchone()
                if row is not None:
                    if row[0] in ("PENDING", "SETTLED"):
                        self._conn.execute("ROLLBACK")
                        return False
                    cur = self._conn.execute(
                        """
                        UPDATE payment_replays
                        SET payer = ?, state = 'PENDING', valid_until = ?, created_at = ?
                        WHERE rail = ? AND payment_hash = ? AND state = 'ABORTED'
                        """,
                        (payer, bounded_until, now, rail, payment_hash),
                    )
                    if cur.rowcount != 1:
                        self._conn.execute("ROLLBACK")
                        return False
                else:
                    self._conn.execute(
                        """
                        INSERT INTO payment_replays
                            (rail, payment_hash, payer, state, valid_until, created_at)
                        VALUES (?, ?, ?, 'PENDING', ?, ?)
                        """,
                        (rail, payment_hash, payer, bounded_until, now),
                    )
                self._conn.execute("COMMIT")
                return True
            except Exception:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                raise

    def mark_settled(self, rail: str, payment_hash: str) -> bool:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                cur = self._conn.execute(
                    """
                    UPDATE payment_replays
                    SET state = 'SETTLED'
                    WHERE rail = ? AND payment_hash = ? AND state = 'PENDING'
                    """,
                    (rail, payment_hash),
                )
                self._conn.execute("COMMIT")
                return cur.rowcount == 1
            except Exception:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                raise

    def mark_aborted(self, rail: str, payment_hash: str) -> bool:
        """Transition ONLY PENDING -> ABORTED; never downgrade SETTLED payments."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                cur = self._conn.execute(
                    """
                    UPDATE payment_replays
                    SET state = 'ABORTED'
                    WHERE rail = ? AND payment_hash = ? AND state = 'PENDING'
                    """,
                    (rail, payment_hash),
                )
                self._conn.execute("COMMIT")
                return cur.rowcount == 1
            except Exception:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                raise

    def settle_and_credit_deposit(
        self,
        payer: str,
        rail: str,
        payment_hash: str,
        amount_micro_usdc: int,
    ) -> int:
        """Atomically transition PENDING -> SETTLED and credit prepaid balance."""
        amount = _validate_positive_int(amount_micro_usdc, "deposit amount", MAX_MICRO_USDC)
        now = int(time.time())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                cur = self._conn.execute(
                    """
                    UPDATE payment_replays
                    SET state = 'SETTLED'
                    WHERE rail = ? AND payment_hash = ? AND state = 'PENDING'
                    """,
                    (rail, payment_hash),
                )
                if cur.rowcount != 1:
                    raise PaymentRejected("payment already settled or not reserved")
                row = self._conn.execute(
                    "SELECT balance_micro_usdc, total_deposited_micro_usdc FROM credit_balances WHERE payer = ?",
                    (payer,),
                ).fetchone()
                if row is None:
                    new_bal = amount
                    self._conn.execute(
                        """
                        INSERT INTO credit_balances
                            (payer, balance_micro_usdc, total_deposited_micro_usdc, debit_seq, updated_at)
                        VALUES (?, ?, ?, 0, ?)
                        """,
                        (payer, new_bal, amount, now),
                    )
                else:
                    new_bal = int(row[0]) + amount
                    new_tot = int(row[1]) + amount
                    if new_bal > MAX_MICRO_USDC or new_tot > MAX_MICRO_USDC:
                        raise ValueError("credit balance overflow")
                    self._conn.execute(
                        """
                        UPDATE credit_balances
                        SET balance_micro_usdc = ?, total_deposited_micro_usdc = ?, updated_at = ?
                        WHERE payer = ?
                        """,
                        (new_bal, new_tot, now, payer),
                    )
                self._conn.execute(
                    """
                    INSERT INTO credit_events (payer, rail, payment_hash, delta_micro_usdc, reason, created_at)
                    VALUES (?, ?, ?, ?, 'TOPUP', ?)
                    """,
                    (payer, rail, payment_hash, amount, now),
                )
                self._conn.execute("COMMIT")
                return new_bal
            except Exception:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                raise

    def credit_deposit(
        self,
        payer: str,
        rail: str,
        payment_hash: str,
        amount_micro_usdc: int,
    ) -> int:
        amount = _validate_positive_int(amount_micro_usdc, "deposit amount", MAX_MICRO_USDC)
        now = int(time.time())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT balance_micro_usdc, total_deposited_micro_usdc FROM credit_balances WHERE payer = ?",
                    (payer,),
                ).fetchone()
                if row is None:
                    new_bal = amount
                    self._conn.execute(
                        """
                        INSERT INTO credit_balances
                            (payer, balance_micro_usdc, total_deposited_micro_usdc, debit_seq, updated_at)
                        VALUES (?, ?, ?, 0, ?)
                        """,
                        (payer, new_bal, amount, now),
                    )
                else:
                    new_bal = int(row[0]) + amount
                    new_tot = int(row[1]) + amount
                    if new_bal > MAX_MICRO_USDC or new_tot > MAX_MICRO_USDC:
                        raise ValueError("credit balance overflow")
                    self._conn.execute(
                        """
                        UPDATE credit_balances
                        SET balance_micro_usdc = ?, total_deposited_micro_usdc = ?, updated_at = ?
                        WHERE payer = ?
                        """,
                        (new_bal, new_tot, now, payer),
                    )
                self._conn.execute(
                    """
                    INSERT INTO credit_events (payer, rail, payment_hash, delta_micro_usdc, reason, created_at)
                    VALUES (?, ?, ?, ?, 'TOPUP', ?)
                    """,
                    (payer, rail, payment_hash, amount, now),
                )
                self._conn.execute("COMMIT")
                return new_bal
            except Exception:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                raise

    def debit_credit(self, payer: str, amount_micro_usdc: int, reason: str) -> tuple[bool, int, int]:
        """Atomically debit prepaid balance. Returns (ok, remaining_micro_usdc, debit_seq)."""
        amount = _validate_positive_int(amount_micro_usdc, "debit amount", MAX_MICRO_USDC)
        now = int(time.time())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT balance_micro_usdc, debit_seq FROM credit_balances WHERE payer = ?",
                    (payer,),
                ).fetchone()
                if row is None or int(row[0]) < amount:
                    bal = int(row[0]) if row is not None else 0
                    seq = int(row[1]) if row is not None else 0
                    self._conn.execute("ROLLBACK")
                    return (False, bal, seq)
                new_bal = int(row[0]) - amount
                new_seq = int(row[1]) + 1
                self._conn.execute(
                    """
                    UPDATE credit_balances
                    SET balance_micro_usdc = ?, debit_seq = ?, updated_at = ?
                    WHERE payer = ? AND balance_micro_usdc >= ?
                    """,
                    (new_bal, new_seq, now, payer, amount),
                )
                self._conn.execute(
                    """
                    INSERT INTO credit_events (payer, rail, payment_hash, delta_micro_usdc, reason, created_at)
                    VALUES (?, 'prepaid-credit', ?, ?, ?, ?)
                    """,
                    (payer, f"debit-{new_seq}", -amount, reason, now),
                )
                self._conn.execute("COMMIT")
                return (True, new_bal, new_seq)
            except Exception:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                raise

    def refund_credit(
        self,
        payer: str,
        amount_micro_usdc: int,
        reason: str,
        debit_seq: int | None = None,
    ) -> int:
        amount = _validate_positive_int(amount_micro_usdc, "refund amount", MAX_MICRO_USDC)
        now = int(time.time())
        refund_key = f"refund-{debit_seq}" if debit_seq is not None else f"refund-ad-hoc-{secrets.token_hex(8)}"
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT balance_micro_usdc FROM credit_balances WHERE payer = ?",
                    (payer,),
                ).fetchone()
                if row is None:
                    raise ValueError(f"cannot refund unknown payer: {payer}")
                new_bal = int(row[0]) + amount
                if new_bal > MAX_MICRO_USDC:
                    raise ValueError("refund credit balance overflow")
                self._conn.execute(
                    """
                    INSERT INTO credit_events (payer, rail, payment_hash, delta_micro_usdc, reason, created_at)
                    VALUES (?, 'prepaid-credit', ?, ?, ?, ?)
                    """,
                    (payer, refund_key, amount, reason, now),
                )
                self._conn.execute(
                    "UPDATE credit_balances SET balance_micro_usdc = ?, updated_at = ? WHERE payer = ?",
                    (new_bal, now, payer),
                )
                self._conn.execute("COMMIT")
                return new_bal
            except sqlite3.IntegrityError:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                return self.get_balance(payer)
            except Exception:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                raise

    def get_balance(self, payer: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT balance_micro_usdc FROM credit_balances WHERE payer = ?",
                (payer,),
            ).fetchone()
            return int(row[0]) if row is not None else 0


# ---------------------------------------------------------------------------
# Sliding-Window Rate Limiter (AC-7 Loopback Separation)
# ---------------------------------------------------------------------------

class EdgeRateLimiter:
    MAX_TRACKED_IPS = 16_384

    def __init__(self, rpm: int, bad_limit: int, bad_window_secs: int) -> None:
        self._lock = threading.Lock()
        self._rpm = max(1, rpm)
        self._bad_limit = max(1, bad_limit)
        self._bad_window = max(10, bad_window_secs)
        self._hits: dict[str, list[float]] = {}
        self._bad_hits: dict[str, list[float]] = {}

    def _evict_stale_locked(self, now: float) -> None:
        if len(self._hits) >= self.MAX_TRACKED_IPS:
            stale = [ip for ip, ts_list in self._hits.items() if not ts_list or now - ts_list[-1] >= 60.0]
            for ip in stale:
                del self._hits[ip]
            if len(self._hits) >= self.MAX_TRACKED_IPS:
                self._hits.clear()
        if len(self._bad_hits) >= self.MAX_TRACKED_IPS:
            stale_bad = [
                ip for ip, ts_list in self._bad_hits.items() if not ts_list or now - ts_list[-1] >= self._bad_window
            ]
            for ip in stale_bad:
                del self._bad_hits[ip]
            if len(self._bad_hits) >= self.MAX_TRACKED_IPS:
                self._bad_hits.clear()

    def allow_request(self, client_ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._evict_stale_locked(now)
            bad = [t for t in self._bad_hits.get(client_ip, []) if now - t < self._bad_window]
            if bad:
                self._bad_hits[client_ip] = bad
                if len(bad) >= self._bad_limit:
                    return False
            elif client_ip in self._bad_hits:
                del self._bad_hits[client_ip]
            hits = [t for t in self._hits.get(client_ip, []) if now - t < 60.0]
            if len(hits) >= self._rpm:
                self._hits[client_ip] = hits
                return False
            hits.append(now)
            self._hits[client_ip] = hits
            return True

    def record_bad_payment(self, client_ip: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._evict_stale_locked(now)
            bad = [t for t in self._bad_hits.get(client_ip, []) if now - t < self._bad_window]
            bad.append(now)
            self._bad_hits[client_ip] = bad


# ---------------------------------------------------------------------------
# Payment Verification Context & Result
# ---------------------------------------------------------------------------

@dataclass
class VerifiedPayment:
    rail: str
    payer: str
    payment_hash: str
    fee_micro_usdc: int
    amount_sats: int
    transaction_ref: str
    network: str
    settlement_mode: str
    # Optional x402 deferred settlement payload
    x402_payload: dict[str, Any] | None = None
    x402_requirements: dict[str, Any] | None = None
    remaining_credit_micro_usdc: int | None = None
    debit_seq: int | None = None


class PaymentRejected(Exception):
    def __init__(self, reason: str, record_abuse: bool = True) -> None:
        super().__init__(reason)
        self.reason = reason
        self.record_abuse = record_abuse


# ---------------------------------------------------------------------------
# Tri-Rail Gateway Engine
# ---------------------------------------------------------------------------

class TriRailEngine:
    def __init__(self, config: GateConfig) -> None:
        config.validate()
        self.config = config
        self.ledger = PaymentLedger(config.db_path)
        self.rate_limiter = EdgeRateLimiter(
            config.rate_limit_rpm,
            config.bad_payment_limit,
            config.bad_payment_window_secs,
        )

        # Derive secrets (explicitly configured or ephemeral per-process)
        self._l402_secret = (
            config.l402_macaroon_secret.encode("utf-8")
            if config.l402_macaroon_secret
            else secrets.token_bytes(32)
        )
        self._session_secret = (
            config.session_secret.encode("utf-8")
            if config.session_secret
            else secrets.token_bytes(32)
        )
        if config.gate_hmac_key_hex:
            self._gate_hmac_key = bytes.fromhex(config.gate_hmac_key_hex)
        else:
            self._gate_hmac_key = secrets.token_bytes(32)

        self._test_x402_secret = (
            config.test_x402_secret.encode("utf-8")
            if config.test_x402_secret
            else b"blindcore-local-x402-test-secret"
        )
        self._test_l402_seed = (
            config.test_l402_seed.encode("utf-8")
            if config.test_l402_seed
            else b"blindcore-local-l402-test-seed"
        )

    def close(self) -> None:
        self.ledger.close()

    # -- Loopback Claim HMAC ------------------------------------------------

    def compute_gate_mac(
        self,
        rail: str,
        payer: str,
        payment_hash: str,
        fee_micro_usdc: int,
        ts: int,
        body_sha256: str,
    ) -> str:
        msg = f"{rail}|{payer}|{payment_hash}|{fee_micro_usdc}|{ts}|{body_sha256}".encode("utf-8")
        return hmac.new(self._gate_hmac_key, msg, hashlib.sha256).hexdigest()

    # -- Session Credit Tokens ----------------------------------------------

    def issue_session_token(self, payer: str, origin_rail: str) -> tuple[str, int]:
        if origin_rail not in ALLOWED_ORIGIN_RAILS:
            raise ValueError(f"unsupported origin_rail: {origin_rail}")
        if not SAFE_PAYER_RE.fullmatch(payer):
            raise ValueError("unsafe payer identifier")
        expires_at = int(time.time()) + self.config.session_ttl_secs
        payload = {"payer": payer, "origin_rail": origin_rail, "exp": expires_at}
        raw_b64 = b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        sig = hmac.new(self._session_secret, raw_b64.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{raw_b64}.{sig}", expires_at

    def verify_session_token(self, token: str) -> dict[str, Any]:
        if not isinstance(token, str) or len(token) > MAX_HEADER_BYTES:
            raise PaymentRejected("malformed session token")
        parts = token.strip().split(".")
        if len(parts) != 2:
            raise PaymentRejected("malformed session token")
        raw_b64, sig = parts
        if not B64URL_RE.fullmatch(raw_b64) or not HEX64_RE.fullmatch(sig):
            raise PaymentRejected("malformed session token encoding")
        expected = hmac.new(self._session_secret, raw_b64.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig.lower(), expected):
            raise PaymentRejected("invalid session token signature")
        try:
            payload = json.loads(b64url_decode(raw_b64).decode("utf-8"))
        except Exception as exc:
            raise PaymentRejected(f"corrupt session token payload: {exc}") from exc
        if not isinstance(payload, dict):
            raise PaymentRejected("session token payload must be a JSON object")
        raw_exp = payload.get("exp")
        if isinstance(raw_exp, bool):
            raise PaymentRejected("invalid session token expiration")
        try:
            exp = int(raw_exp)
        except Exception as exc:
            raise PaymentRejected(f"invalid session token expiration: {exc}") from exc
        if exp < int(time.time()):
            raise PaymentRejected("session token expired", record_abuse=False)
        payer = payload.get("payer")
        origin_rail = payload.get("origin_rail")
        if not isinstance(payer, str) or not SAFE_PAYER_RE.fullmatch(payer):
            raise PaymentRejected("invalid payer in session token")
        if not isinstance(origin_rail, str) or origin_rail not in ALLOWED_ORIGIN_RAILS:
            raise PaymentRejected("invalid origin_rail in session token")
        return payload

    # -- Rail 2: Lightning L402 Invoice & Macaroon Minting ------------------

    def derive_test_preimage_hex(self, token_id: str) -> str:
        """Deterministic preimage helper for test mode ONLY (never embedded in macaroon)."""
        return hmac.new(self._test_l402_seed, f"preimage:{token_id}".encode("utf-8"), hashlib.sha256).hexdigest()

    def _mint_lnd_invoice(self, sats: int, memo: str) -> tuple[str, str]:
        url = f"{self.config.lnd_rest_url}/v1/invoices"
        body = json.dumps({"value": str(sats), "memo": memo, "expiry": "600"}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Grpc-Metadata-macaroon": self.config.lnd_macaroon_hex,
                "Content-Type": "application/json",
            },
        )
        ctx = None
        if self.config.lnd_tls_cert_path:
            ctx = ssl.create_default_context(cafile=self.config.lnd_tls_cert_path)
        with urllib.request.urlopen(req, timeout=self.config.http_timeout_secs, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        r_hash_hex = base64.b64decode(data["r_hash"]).hex()
        bolt11 = data["payment_request"]
        return r_hash_hex, bolt11

    def _mint_lnbits_invoice(self, sats: int, memo: str) -> tuple[str, str]:
        url = f"{self.config.lnbits_url}/api/v1/payments"
        body = json.dumps({"out": False, "amount": sats, "memo": memo, "expiry": 600}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "X-Api-Key": self.config.lnbits_api_key,
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=self.config.http_timeout_secs) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return str(data["payment_hash"]).lower(), str(data["payment_request"])

    def mint_l402_challenge(self, tier: PriceTier, path: str, sats_override: int | None = None) -> dict[str, Any]:
        sats = sats_override if sats_override is not None else tier.sats
        token_id = secrets.token_hex(16)
        memo = f"BlindCore {tier.name} {sats} sats"

        if self.config.lnd_rest_url and self.config.lnd_macaroon_hex:
            payment_hash, bolt11 = self._mint_lnd_invoice(sats, memo)
        elif self.config.lnbits_url and self.config.lnbits_api_key:
            payment_hash, bolt11 = self._mint_lnbits_invoice(sats, memo)
        elif self.config.test_mode:
            preimage_hex = self.derive_test_preimage_hex(token_id)
            payment_hash = hashlib.sha256(bytes.fromhex(preimage_hex)).hexdigest()
            bolt11 = f"lnbc{sats}n1blindcoretest{payment_hash[:28]}"
        else:
            # No live Lightning node configured: still emit valid x402/Stacks 402 with clear L402 placeholder
            return {
                "enabled": False,
                "sats": sats,
                "macaroon": "",
                "invoice": "",
                "paymentHash": "",
            }

        exp = int(time.time()) + 600
        caveats = [
            f"tier={tier.name}",
            f"sats={sats}",
            f"path={path.split('?', 1)[0]}",
            f"exp={exp}",
        ]
        identifier = {"payment_hash": payment_hash, "token_id": token_id}
        sig = self._sign_l402_macaroon(identifier, caveats)
        mac_obj = {
            "version": 1,
            "location": self.config.public_base_url,
            "identifier": identifier,
            "caveats": caveats,
            "signature": sig,
        }
        macaroon_b64 = b64_json_encode(mac_obj)
        return {
            "enabled": True,
            "sats": sats,
            "paymentHash": payment_hash,
            "tokenId": token_id,
            "macaroon": macaroon_b64,
            "invoice": bolt11,
            "expiresAt": exp,
        }

    def _sign_l402_macaroon(self, identifier: dict[str, Any], caveats: list[str]) -> str:
        # Chained HMAC-SHA256 over identifier then each caveat (standard macaroon construction)
        id_bytes = json.dumps(identifier, separators=(",", ":"), sort_keys=True).encode("utf-8")
        mac = hmac.new(self._l402_secret, id_bytes, hashlib.sha256).digest()
        for cav in caveats:
            mac = hmac.new(mac, cav.encode("utf-8"), hashlib.sha256).digest()
        return mac.hex()

    def verify_l402_authorization(
        self,
        auth_header: str,
        required_sats: int,
        request_path: str,
    ) -> VerifiedPayment:
        if not isinstance(auth_header, str) or len(auth_header) > MAX_HEADER_BYTES:
            raise PaymentRejected("invalid or oversized L402 Authorization header")
        parts = auth_header.strip().split(" ", 1)
        if len(parts) != 2 or parts[0].upper() not in ("L402", "LSAT"):
            raise PaymentRejected("invalid L402 Authorization scheme")
        creds = parts[1].strip()
        if ":" not in creds:
            raise PaymentRejected("L402 credential must be <macaroon>:<preimage_hex>")
        mac_b64, preimage_hex = creds.rsplit(":", 1)
        if ":" in mac_b64:
            raise PaymentRejected("malformed L402 credential structure")
        preimage_hex = preimage_hex.strip().lower()
        if not HEX64_RE.fullmatch(preimage_hex):
            raise PaymentRejected("L402 preimage must be 64-char hex (32 bytes)")

        try:
            mac_obj = b64_json_decode(mac_b64)
        except Exception as exc:
            raise PaymentRejected(f"invalid L402 macaroon encoding: {exc}") from exc

        if not isinstance(mac_obj, dict):
            raise PaymentRejected("L402 macaroon payload must be a JSON object")

        identifier = mac_obj.get("identifier")
        caveats = mac_obj.get("caveats")
        sig = mac_obj.get("signature")
        if (
            not isinstance(identifier, dict)
            or not isinstance(caveats, list)
            or not isinstance(sig, str)
            or not HEX64_RE.fullmatch(sig)
        ):
            raise PaymentRejected("malformed L402 macaroon structure")

        if not caveats or len(caveats) > 16:
            raise PaymentRejected("L402 macaroon caveat count out of bounds")

        clean_caveats: list[str] = []
        for cav in caveats:
            if not isinstance(cav, str) or any(ch in cav for ch in ("\r", "\n", "\x00", "|", ";")):
                raise PaymentRejected("illegal character or non-string in L402 caveat")
            clean_caveats.append(cav)

        expected_sig = self._sign_l402_macaroon(identifier, clean_caveats)
        if not hmac.compare_digest(sig.lower(), expected_sig):
            raise PaymentRejected("forged or tampered L402 macaroon signature")

        # Parse and strictly enforce caveats (reject unknown, duplicate, or missing keys
        # to block chained-HMAC caveat-append privilege escalation)
        parsed_cav: dict[str, str] = {}
        for cav in clean_caveats:
            if "=" not in cav:
                raise PaymentRejected("malformed L402 caveat syntax")
            k, v = cav.split("=", 1)
            k = k.strip()
            v = v.strip()
            if not CAVEAT_KEY_RE.fullmatch(k) or k not in ALLOWED_L402_CAVEAT_KEYS:
                raise PaymentRejected(f"disallowed L402 caveat key: {k}")
            if k in parsed_cav:
                raise PaymentRejected(f"duplicate L402 caveat key rejected: {k}")
            parsed_cav[k] = v

        if set(parsed_cav.keys()) != ALLOWED_L402_CAVEAT_KEYS:
            raise PaymentRejected("incomplete L402 caveat set")

        try:
            exp = int(parsed_cav["exp"])
            paid_sats = int(parsed_cav["sats"])
        except ValueError as exc:
            raise PaymentRejected(f"invalid numeric L402 caveat: {exc}") from exc

        if exp < int(time.time()):
            raise PaymentRejected("L402 macaroon expired", record_abuse=False)

        if paid_sats <= 0 or paid_sats > MAX_SATS:
            raise PaymentRejected(f"L402 sats out of bounds: {paid_sats}")
        if paid_sats < required_sats:
            raise PaymentRejected(f"L402 invoice underpaid: {paid_sats} < {required_sats} sats")

        cav_path = parsed_cav["path"]
        clean_req_path = request_path.split("?", 1)[0]
        if not cav_path or cav_path == "*" or cav_path != clean_req_path:
            raise PaymentRejected(f"L402 macaroon path mismatch: {cav_path} != {clean_req_path}")

        raw_pay_hash = identifier.get("payment_hash")
        if not isinstance(raw_pay_hash, str) or not HEX64_RE.fullmatch(raw_pay_hash.strip()):
            raise PaymentRejected("invalid payment_hash in L402 macaroon")
        payment_hash = raw_pay_hash.strip().lower()

        computed_hash = hashlib.sha256(bytes.fromhex(preimage_hex)).hexdigest()
        if not hmac.compare_digest(computed_hash, payment_hash):
            raise PaymentRejected("L402 preimage does not match invoice payment_hash")

        fee_micro_usdc = int(round(paid_sats * self.config.btc_usd_price / 100.0))
        if fee_micro_usdc <= 0 or fee_micro_usdc > MAX_MICRO_USDC:
            raise PaymentRejected(f"L402 fee out of bounds: {fee_micro_usdc}")

        raw_token_id = identifier.get("token_id", payment_hash[:16])
        if not isinstance(raw_token_id, str) or not raw_token_id.strip():
            raise PaymentRejected("invalid token_id in L402 macaroon")
        token_id = raw_token_id.strip()
        payer = f"ln:{sha256_hex(f'{token_id}:{payment_hash}'.encode('utf-8'))[:24]}"
        if not self.ledger.reserve_payment("ln-l402", payment_hash, payer, exp + 300):
            raise PaymentRejected("L402 payment replay detected")

        return VerifiedPayment(
            rail="ln-l402",
            payer=payer,
            payment_hash=payment_hash,
            fee_micro_usdc=fee_micro_usdc,
            amount_sats=paid_sats,
            transaction_ref=payment_hash,
            network="bitcoin:lightning",
            settlement_mode="lightning-preimage",
        )

    # -- Rail 1: Base L2 x402 v2 (+ v1 fallback, Smart Wallets, Permit2) ----

    def build_x402_requirements(
        self,
        tier: PriceTier,
        request_url: str,
        body_sha256: str,
        micro_usdc_override: int | None = None,
    ) -> list[dict[str, Any]]:
        amount = micro_usdc_override if micro_usdc_override is not None else tier.micro_usdc
        common_extra = {
            "name": "USD Coin",
            "version": "2",
            "tier": tier.name,
            "opTierId": tier.op_tier_id,
            "bodySha256": body_sha256,
            "smartWalletSupport": ["ERC-1271", "ERC-6492"],
            "permit2": PERMIT2_CANONICAL,
            "prepaidTopupUrl": f"{self.config.public_base_url}/api/v1/credits/topup",
            "prepaidMinMicroUsdc": str(PREPAID_MIN_MICRO_USDC),
            "recommendPrepaid": amount < 5_000,
        }
        return [
            {
                "scheme": "exact",
                "network": self.config.base_network,
                "amount": str(amount),
                "maxAmountRequired": str(amount),
                "resource": request_url,
                "description": tier.description,
                "mimeType": "application/json",
                "asset": self.config.base_usdc_asset,
                "payTo": self.config.base_pay_to,
                "maxTimeoutSeconds": 60,
                "extra": common_extra,
            },
            {
                "scheme": "permit2-exact",
                "network": self.config.base_network,
                "amount": str(amount),
                "maxAmountRequired": str(amount),
                "resource": request_url,
                "description": f"{tier.description} (Permit2 / Smart Wallet)",
                "mimeType": "application/json",
                "asset": self.config.base_usdc_asset,
                "payTo": self.config.base_pay_to,
                "maxTimeoutSeconds": 60,
                "extra": common_extra,
            },
        ]

    def _call_facilitator(self, endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(endpoint, str) or endpoint not in ("verify", "settle"):
            raise PaymentRejected(f"disallowed facilitator endpoint: {endpoint!r}")
        ep = endpoint
        url = f"{self.config.x402_facilitator_url}/{ep}"
        headers = {"Content-Type": "application/json"}
        if self.config.cdp_api_key:
            headers["Authorization"] = f"Bearer {self.config.cdp_api_key}"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.config.http_timeout_secs) as resp:
                raw = resp.read(MAX_BODY_BYTES + 1)
                if len(raw) > MAX_BODY_BYTES:
                    raise PaymentRejected("facilitator response exceeds size limit", record_abuse=False)
                parsed = json.loads(raw.decode("utf-8"))
                if not isinstance(parsed, dict):
                    raise PaymentRejected("facilitator response must be a JSON object", record_abuse=False)
                return parsed
        except PaymentRejected:
            raise
        except urllib.error.HTTPError as exc:
            err_body = exc.read(4096).decode("utf-8", errors="replace")
            raise PaymentRejected(f"facilitator /{ep} rejected ({exc.code}): {err_body}") from exc
        except Exception as exc:
            raise PaymentRejected(f"facilitator /{ep} error: {exc}", record_abuse=False) from exc

    def sign_test_x402(self, payer: str, to_addr: str, value: int, nonce: str, network: str) -> str:
        msg = f"{payer.lower()}|{to_addr.lower()}|{value}|{nonce.lower()}|{network}".encode("utf-8")
        return "0x" + hmac.new(self._test_x402_secret, msg, hashlib.sha256).hexdigest()

    def verify_x402_payment(
        self,
        header_val: str,
        required_micro_usdc: int,
        tier: PriceTier,
        request_url: str,
        body_sha256: str,
    ) -> VerifiedPayment:
        try:
            decoded = b64_json_decode(header_val)
        except Exception as exc:
            raise PaymentRejected(f"invalid x402 payment header: {exc}") from exc
        if not isinstance(decoded, dict):
            raise PaymentRejected("x402 payment payload must be a JSON object")

        raw_ver = decoded.get("x402Version", 2)
        if isinstance(raw_ver, bool) or not isinstance(raw_ver, int) or raw_ver not in (1, 2):
            raise PaymentRejected(f"unsupported x402Version: {raw_ver!r}")
        version = raw_ver

        accepted = decoded.get("accepted")
        if accepted is None:
            accepted = {}
        elif not isinstance(accepted, dict):
            raise PaymentRejected("x402 accepted field must be a JSON object")

        scheme = str(accepted.get("scheme") or decoded.get("scheme") or "exact")
        network = str(accepted.get("network") or decoded.get("network") or self.config.base_network)
        if network != self.config.base_network:
            raise PaymentRejected(f"x402 network mismatch: {network} != {self.config.base_network}")
        if scheme not in ("exact", "permit2-exact"):
            raise PaymentRejected(f"unsupported x402 scheme: {scheme}")

        payload = decoded.get("payload")
        if not isinstance(payload, dict):
            raise PaymentRejected("x402 payload must be a JSON object")
        raw_sig = payload.get("signature")
        if not isinstance(raw_sig, str) or not raw_sig.strip() or len(raw_sig) > 4096:
            raise PaymentRejected("missing or invalid x402 signature")
        signature = raw_sig.strip()

        # Extract authorization fields from EIP-3009 or Permit2
        auth = payload.get("authorization") if "authorization" in payload else payload.get("permit")
        if not isinstance(auth, dict):
            raise PaymentRejected("x402 authorization/permit must be a JSON object")
        payer = str(auth.get("from") or auth.get("owner") or "").strip()
        to_addr = str(auth.get("to") or auth.get("spender") or "").strip()
        nonce = str(auth.get("nonce") or "").strip()

        raw_val = auth.get("value") if "value" in auth else auth.get("amount")
        try:
            value = _validate_positive_int(raw_val, "x402 amount", MAX_MICRO_USDC)
        except ValueError as exc:
            raise PaymentRejected(str(exc)) from exc

        if not EVM_ADDR_RE.fullmatch(payer):
            raise PaymentRejected("invalid payer EVM address")
        if not EVM_ADDR_RE.fullmatch(to_addr) or to_addr.lower() != self.config.base_pay_to.lower():
            raise PaymentRejected("x402 recipient does not match payTo")

        acc_pay_to = accepted.get("payTo")
        if acc_pay_to is not None:
            if not isinstance(acc_pay_to, str) or acc_pay_to.strip().lower() != self.config.base_pay_to.lower():
                raise PaymentRejected("x402 accepted.payTo mismatch")
        acc_amount = accepted.get("amount")
        if acc_amount is not None:
            try:
                acc_amt_int = _validate_positive_int(acc_amount, "accepted.amount", MAX_MICRO_USDC)
            except ValueError as exc:
                raise PaymentRejected(str(exc)) from exc
            if acc_amt_int != value:
                raise PaymentRejected("x402 accepted.amount does not match authorization value")

        if value < required_micro_usdc:
            raise PaymentRejected(f"x402 payment underpaid: {value} < {required_micro_usdc} micro-USDC")
        if not nonce or len(nonce) > 128 or any(ch in nonce for ch in ("\r", "\n", "\x00", "|", " ", "\t")):
            raise PaymentRejected("missing or invalid x402 authorization nonce")

        raw_sig_type = payload.get("signatureType", "eip3009")
        sig_type = str(raw_sig_type).strip().lower()
        if not SAFE_SIG_TYPE_RE.fullmatch(sig_type):
            raise PaymentRejected("invalid x402 signatureType")

        now = int(time.time())
        raw_va = auth.get("validAfter", 0)
        raw_vb = auth.get("validBefore", auth.get("deadline", now + 60))
        if isinstance(raw_va, bool) or isinstance(raw_vb, bool):
            raise PaymentRejected("x402 validity timestamps must be integers, not bool")
        try:
            valid_after = int(raw_va)
            valid_before = int(raw_vb)
        except (TypeError, ValueError) as exc:
            raise PaymentRejected(f"invalid x402 validity timestamps: {exc}") from exc
        if valid_after < 0 or valid_before > now + 86_400 * 365:
            raise PaymentRejected("x402 validity window out of bounds")
        if valid_after > now + 5:
            raise PaymentRejected("x402 authorization not yet valid")
        if valid_before <= now:
            raise PaymentRejected("x402 authorization expired", record_abuse=False)

        payment_hash = sha256_hex(
            f"base-x402:{network}:{payer.lower()}:{nonce.lower()}".encode("utf-8")
        )
        if not self.ledger.reserve_payment("base-x402", payment_hash, payer.lower(), valid_before + 300):
            raise PaymentRejected("x402 payment replay detected")

        reqs_list = self.build_x402_requirements(tier, request_url, body_sha256, required_micro_usdc)
        matched_req = next((r for r in reqs_list if r["scheme"] == scheme), reqs_list[0])

        try:
            if self.config.x402_facilitator_url:
                res = self._call_facilitator(
                    "verify",
                    {
                        "x402Version": version,
                        "paymentPayload": decoded,
                        "paymentRequirements": matched_req,
                    },
                )
                if not res.get("isValid"):
                    reason = res.get("invalidReason") or "facilitator rejected signature"
                    raise PaymentRejected(f"x402 verify failed: {reason}")
                fac_payer = res.get("payer")
                if fac_payer is not None and str(fac_payer).strip():
                    if str(fac_payer).strip().lower() != payer.lower():
                        raise PaymentRejected("x402 facilitator payer mismatch")
                tx_ref = payer.lower()
            elif self.config.test_mode:
                expected_sig = self.sign_test_x402(payer, to_addr, value, nonce, network)
                if not hmac.compare_digest(signature.lower(), expected_sig.lower()):
                    raise PaymentRejected("invalid x402 test signature")
                tx_ref = f"0x{payment_hash}"
            else:
                raise PaymentRejected("x402 facilitator URL not configured", record_abuse=False)
        except Exception:
            self.ledger.mark_aborted("base-x402", payment_hash)
            raise

        return VerifiedPayment(
            rail="base-x402",
            payer=payer.lower(),
            payment_hash=payment_hash,
            fee_micro_usdc=value,
            amount_sats=0,
            transaction_ref=tx_ref,
            network=network,
            settlement_mode=f"{scheme}:{sig_type}",
            x402_payload=decoded,
            x402_requirements=matched_req,
        )

    def settle_x402_if_needed(self, payment: VerifiedPayment) -> str:
        if payment.rail != "base-x402":
            return payment.transaction_ref
        if self.config.x402_facilitator_url and payment.x402_payload and payment.x402_requirements:
            res = self._call_facilitator(
                "settle",
                {
                    "x402Version": int(payment.x402_payload.get("x402Version", 2)),
                    "paymentPayload": payment.x402_payload,
                    "paymentRequirements": payment.x402_requirements,
                },
            )
            if not res.get("success", False):
                raise PaymentRejected(f"x402 settle failed: {res.get('errorReason', 'unknown')}")
            tx_hash = str(res.get("transaction") or res.get("txHash") or payment.transaction_ref)
            payment.transaction_ref = tx_hash
            return tx_hash
        return payment.transaction_ref

    # -- Rail 3: Stacks sBTC (SIP-010) & STX Verification -------------------

    def _fetch_stacks_tx(self, txid: str) -> dict[str, Any]:
        clean_txid = normalize_txid(txid)
        url = f"{self.config.stacks_api_url}/extended/v1/tx/0x{clean_txid}"
        req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.config.http_timeout_secs) as resp:
                raw = resp.read(MAX_BODY_BYTES + 1)
                if len(raw) > MAX_BODY_BYTES:
                    raise PaymentRejected("Stacks API response exceeds size limit", record_abuse=False)
                parsed = json.loads(raw.decode("utf-8"))
                if not isinstance(parsed, dict):
                    raise PaymentRejected("Stacks API response must be a JSON object", record_abuse=False)
                return parsed
        except PaymentRejected:
            raise
        except urllib.error.HTTPError as exc:
            raise PaymentRejected(f"Stacks tx lookup failed ({exc.code})") from exc
        except Exception as exc:
            raise PaymentRejected(f"Stacks API unreachable: {exc}", record_abuse=False) from exc

    @staticmethod
    def _parse_clarity_uint(repr_str: str) -> int:
        if not isinstance(repr_str, str):
            raise ValueError("clarity uint must be a string")
        cleaned = repr_str.strip()
        if cleaned.startswith("u"):
            cleaned = cleaned[1:]
        if not cleaned or not cleaned.isdigit():
            raise ValueError(f"invalid clarity uint: {repr_str!r}")
        return int(cleaned)

    @staticmethod
    def _parse_clarity_principal(repr_str: str) -> str:
        cleaned = repr_str.strip()
        if cleaned.startswith("'"):
            cleaned = cleaned[1:]
        return cleaned

    def verify_stacks_payment(
        self,
        raw_txid: str,
        required_sats: int,
        required_ustx: int,
    ) -> VerifiedPayment:
        try:
            txid = normalize_txid(raw_txid)
        except ValueError as exc:
            raise PaymentRejected(str(exc)) from exc

        # Block replay amplification BEFORE querying external Hiro Stacks API
        if self.ledger.is_payment_locked_or_settled("stacks-sbtc", txid):
            raise PaymentRejected("Stacks payment txid replay detected")

        tx = self._fetch_stacks_tx(txid)
        raw_resp_txid = tx.get("tx_id")
        if not isinstance(raw_resp_txid, str):
            raise PaymentRejected("Stacks tx response missing tx_id")
        try:
            resp_txid = normalize_txid(raw_resp_txid)
        except ValueError as exc:
            raise PaymentRejected(f"invalid Stacks response tx_id: {exc}") from exc
        if not hmac.compare_digest(resp_txid, txid):
            raise PaymentRejected("Stacks tx_id mismatch")

        if tx.get("tx_status") != "success":
            raise PaymentRejected(f"Stacks tx not confirmed success (status={tx.get('tx_status')})")

        payer = str(tx.get("sender_address") or "").strip()
        if not STACKS_PRINCIPAL_RE.fullmatch(payer):
            raise PaymentRejected("invalid or missing Stacks sender_address")

        tx_type = str(tx.get("tx_type") or "")
        paid_sats = 0
        paid_micro_usdc = 0
        settlement_mode = "stacks-sbtc"

        if tx_type == "contract_call":
            cc = tx.get("contract_call")
            if not isinstance(cc, dict):
                raise PaymentRejected("malformed Stacks contract_call object")
            contract_id = str(cc.get("contract_id") or "")
            fn_name = str(cc.get("function_name") or "")
            if contract_id != self.config.stacks_sbtc_contract or fn_name != "transfer":
                raise PaymentRejected("Stacks contract_call is not an sBTC SIP-010 transfer")

            args = cc.get("function_args") or []
            if not isinstance(args, list):
                raise PaymentRejected("malformed Stacks function_args")
            arg_map = {str(a.get("name")): str(a.get("repr", "")) for a in args if isinstance(a, dict)}
            recipient = self._parse_clarity_principal(arg_map.get("recipient", ""))
            try:
                amount_sats = self._parse_clarity_uint(arg_map.get("amount", "u0"))
            except ValueError as exc:
                raise PaymentRejected(f"invalid Stacks sBTC amount: {exc}") from exc

            # Cross-check fungible token events when present; prevent asset_id prefix spoofing
            events = tx.get("events") or []
            if not isinstance(events, list):
                raise PaymentRejected("malformed Stacks events list")
            if events:
                matched_event = False
                for ev in events:
                    if not isinstance(ev, dict) or ev.get("event_type") != "fungible_token_asset":
                        continue
                    asset = ev.get("asset")
                    if not isinstance(asset, dict):
                        continue
                    ev_rcpt = str(asset.get("recipient") or "").strip()
                    ev_asset_id = str(asset.get("asset_id") or "").strip()
                    if ev_rcpt == self.config.stacks_pay_to and (
                        ev_asset_id == self.config.stacks_sbtc_contract
                        or ev_asset_id.startswith(self.config.stacks_sbtc_contract + "::")
                    ):
                        recipient = ev_rcpt
                        try:
                            amount_sats = _validate_positive_int(
                                asset.get("amount"), "Stacks sBTC event amount", MAX_SATS
                            )
                        except ValueError as exc:
                            raise PaymentRejected(str(exc)) from exc
                        matched_event = True
                        break
                if not matched_event:
                    raise PaymentRejected("Stacks sBTC transfer missing matching fungible_token_asset event")
            else:
                try:
                    amount_sats = _validate_positive_int(amount_sats, "Stacks sBTC amount", MAX_SATS)
                except ValueError as exc:
                    raise PaymentRejected(str(exc)) from exc

            if recipient != self.config.stacks_pay_to:
                raise PaymentRejected("Stacks sBTC transfer recipient mismatch")
            if amount_sats < required_sats:
                raise PaymentRejected(f"Stacks sBTC underpaid: {amount_sats} < {required_sats} sats")
            paid_sats = amount_sats
            paid_micro_usdc = int(round(paid_sats * self.config.btc_usd_price / 100.0))
            if paid_micro_usdc <= 0 or paid_micro_usdc > MAX_MICRO_USDC:
                raise PaymentRejected(f"Stacks sBTC fee out of bounds: {paid_micro_usdc}")
        elif tx_type == "token_transfer":
            tt = tx.get("token_transfer")
            if not isinstance(tt, dict):
                raise PaymentRejected("malformed Stacks token_transfer object")
            recipient = str(tt.get("recipient_address") or "").strip()
            try:
                amount_ustx = _validate_positive_int(tt.get("amount"), "Stacks STX amount", MAX_USTX)
            except ValueError as exc:
                raise PaymentRejected(str(exc)) from exc
            if recipient != self.config.stacks_pay_to:
                raise PaymentRejected("Stacks STX transfer recipient mismatch")
            if amount_ustx < required_ustx:
                raise PaymentRejected(f"Stacks STX underpaid: {amount_ustx} < {required_ustx} uSTX")
            settlement_mode = "stacks-stx"
            paid_micro_usdc = int(round(amount_ustx * DEFAULT_STX_MICRO_USD / 1_000_000.0))
            if paid_micro_usdc <= 0 or paid_micro_usdc > MAX_MICRO_USDC:
                raise PaymentRejected(f"Stacks STX fee out of bounds: {paid_micro_usdc}")
            paid_sats = max(required_sats, int(round(paid_micro_usdc * 100.0 / self.config.btc_usd_price)))
            if paid_sats > MAX_SATS:
                raise PaymentRejected(f"Stacks STX sats equivalent out of bounds: {paid_sats}")
        else:
            raise PaymentRejected(f"unsupported Stacks tx_type: {tx_type}")

        if not self.ledger.reserve_payment("stacks-sbtc", txid, payer, int(time.time()) + 86_400 * 365):
            raise PaymentRejected("Stacks payment txid replay detected")

        return VerifiedPayment(
            rail="stacks-sbtc",
            payer=payer,
            payment_hash=txid,
            fee_micro_usdc=paid_micro_usdc,
            amount_sats=paid_sats,
            transaction_ref=f"0x{txid}",
            network=f"stacks:{self.config.stacks_network}",
            settlement_mode=settlement_mode,
        )

    # -- Prepaid Micro-Credit Session Verification --------------------------

    def verify_session_credit(
        self,
        session_token: str,
        tier: PriceTier,
        body_sha256: str,
    ) -> VerifiedPayment:
        claims = self.verify_session_token(session_token)
        payer = str(claims["payer"])
        origin_rail = str(claims.get("origin_rail", "base-x402"))
        ok, remaining, seq = self.ledger.debit_credit(payer, tier.micro_usdc, tier.name)
        if not ok:
            raise PaymentRejected(
                f"insufficient prepaid credit balance ({remaining} < {tier.micro_usdc} micro-USDC)",
                record_abuse=False,
            )
        credit_rail = f"{origin_rail}-credit"
        payment_hash = sha256_hex(f"{credit_rail}:{payer}:{seq}:{body_sha256}".encode("utf-8"))
        return VerifiedPayment(
            rail=credit_rail,
            payer=payer,
            payment_hash=payment_hash,
            fee_micro_usdc=tier.micro_usdc,
            amount_sats=0,
            transaction_ref=f"credit-seq-{seq}",
            network="blindcore:prepaid-ledger",
            settlement_mode="prepaid-session",
            remaining_credit_micro_usdc=remaining,
            debit_seq=seq,
        )

    # -- Unified Discovery Payloads -----------------------------------------

    def build_bazaar_extension(self, tier: PriceTier, path: str) -> dict[str, Any]:
        return {
            "discoverable": True,
            "category": "confidential-compute",
            "provider": "BlindCore",
            "latencySlaMs": 25,
            "info": {
                "input": {
                    "type": "http",
                    "method": "POST",
                    "path": path,
                    "contentType": "application/json",
                    "bodyExample": {"table": "corpus", "op": tier.name},
                },
                "output": {
                    "contentType": "application/json",
                    "example": {"status": "ok", "plaintext_stored": False, "receipt_hex": "0x..."},
                },
            },
            "schema": {
                "type": "object",
                "required": ["table"],
                "properties": {
                    "table": {"type": "string"},
                    "op": {"type": "string", "enum": list(PRICING_TIERS.keys()) + ["LATEST", "WEIGHTED_SUM", "BLIND_PIPELINE"]},
                },
            },
        }

    def build_402_response(
        self,
        tier: PriceTier,
        path: str,
        body_sha256: str,
        error_msg: str = "Payment required",
        micro_usdc_override: int | None = None,
        sats_override: int | None = None,
        ustx_override: int | None = None,
    ) -> tuple[dict[str, str], dict[str, Any]]:
        req_url = f"{self.config.public_base_url}{path}"
        accepts = self.build_x402_requirements(tier, req_url, body_sha256, micro_usdc_override)
        l402 = self.mint_l402_challenge(tier, path, sats_override=sats_override)
        sats = sats_override if sats_override is not None else tier.sats
        ustx = ustx_override if ustx_override is not None else tier.ustx

        stacks_meta = {
            "network": f"stacks:{self.config.stacks_network}",
            "apiUrl": self.config.stacks_api_url,
            "recipient": self.config.stacks_pay_to,
            "sbtcContract": self.config.stacks_sbtc_contract,
            "amountSats": sats,
            "amountUstx": ustx,
            "header": "X-Stacks-Payment-Tx",
            "tier": tier.name,
            "bodySha256": body_sha256,
            "prepaidTopupUrl": f"{self.config.public_base_url}/api/v1/credits/topup",
        }

        x402_quote = {
            "x402Version": 2,
            "error": error_msg,
            "resource": {
                "url": req_url,
                "description": tier.description,
                "mimeType": "application/json",
            },
            "accepts": accepts,
            "extensions": {
                "bazaar": self.build_bazaar_extension(tier, path),
                "lightning_l402": {
                    "enabled": l402["enabled"],
                    "sats": sats,
                    "paymentHash": l402["paymentHash"],
                    "invoice": l402["invoice"],
                    "macaroon": l402["macaroon"],
                },
                "stacks_sbtc": stacks_meta,
            },
        }

        headers = {
            "Content-Type": "application/json",
            "PAYMENT-REQUIRED": b64_json_encode(x402_quote),
            "X-Stacks-Payment-Required": b64_json_encode(stacks_meta),
        }
        if l402["enabled"]:
            headers["WWW-Authenticate"] = f'L402 macaroon="{l402["macaroon"]}", invoice="{l402["invoice"]}"'

        return headers, x402_quote

    def build_llms_txt(self) -> str:
        lines = [
            "# BlindCore Confidential Compute Tri-Rail API",
            "",
            "Zero-plaintext homomorphic JSONB analytics, MultinomialNB ML scoring, and sealed-bid clearing.",
            f"Base URL: {self.config.public_base_url}",
            "",
            "## Payment Rails (HTTP 402 Negotiation)",
            f"1. Base L2 USDC (x402 v2): Network {self.config.base_network}, Asset {self.config.base_usdc_asset}, PayTo {self.config.base_pay_to}",
            "   - Headers: PAYMENT-REQUIRED (402), PAYMENT-SIGNATURE (retry), PAYMENT-RESPONSE (200). Supports EIP-3009, Permit2, ERC-1271, ERC-6492, and v1 X-PAYMENT.",
            "   - Prepaid Micro-Credit Sessions: POST /api/v1/credits/topup (min $1.00 USDC) -> X-BlindCore-Session header for sub-$0.005 ops.",
            "2. Bitcoin Lightning (L402 / LSAT): Pay BOLT11 invoice in WWW-Authenticate header and retry with Authorization: L402 <macaroon>:<preimage_hex>.",
            f"3. Stacks sBTC / STX: Transfer sBTC ({self.config.stacks_sbtc_contract}) or STX to {self.config.stacks_pay_to} and retry with X-Stacks-Payment-Tx: <txid>.",
            "",
            "## Pricing Tiers",
            "- INGEST (/api/v1/blind/jsonb/ingest): $0.0005 USDC (500 micro-USDC) | 1 sat",
            "- CONTAINS / LATEST (/api/v1/blind/jsonb/query): $0.001 USDC (1000 micro-USDC) | 2 sats",
            "- SUM / WEIGHTED_SUM (/api/v1/blind/jsonb/query): $0.005 USDC (5000 micro-USDC) | 8 sats",
            "- RANGE_GATE / AUCTION (/api/auction/clear): $0.015 USDC (15000 micro-USDC) | 25 sats",
            "- SKLEARN_MNB (/api/v1/blind/jsonb/query): $0.020 USDC (20000 micro-USDC) | 30 sats",
            "",
            "## Discovery & Verification",
            "- GET /.well-known/x402.json (x402 v2 + Bazaar metadata)",
            "- GET /.well-known/agent-card.json (ERC-8004 Trustless Agent Card)",
            "- GET /api/v1/pricing (machine-readable pricing table)",
            "- GET /health (liveness & rail status)",
        ]
        return "\n".join(lines) + "\n"

    def build_well_known_x402(self) -> dict[str, Any]:
        resources = []
        route_map = [
            ("/api/v1/blind/jsonb/ingest", PRICING_TIERS["INGEST"]),
            ("/api/v1/blind/jsonb/query", PRICING_TIERS["CONTAINS"]),
            ("/api/v1/blind/query", PRICING_TIERS["SUM"]),
            ("/api/auction/clear", PRICING_TIERS["RANGE_GATE"]),
        ]
        for path, tier in route_map:
            resources.append(
                {
                    "resource": f"{self.config.public_base_url}{path}",
                    "method": "POST",
                    "tier": tier.name,
                    "amountMicroUsdc": str(tier.micro_usdc),
                    "amountSats": tier.sats,
                    "accepts": self.build_x402_requirements(tier, f"{self.config.public_base_url}{path}", "0" * 64),
                    "extensions": {"bazaar": self.build_bazaar_extension(tier, path)},
                }
            )
        return {
            "x402Version": 2,
            "service": "BlindCore Confidential Compute Coprocessor",
            "homepage": self.config.public_base_url,
            "networks": [BASE_MAINNET_CAIP2, BASE_SEPOLIA_CAIP2],
            "activeNetwork": self.config.base_network,
            "asset": self.config.base_usdc_asset,
            "payTo": self.config.base_pay_to,
            "permit2": PERMIT2_CANONICAL,
            "smartWalletSupport": ["ERC-1271", "ERC-6492"],
            "prepaidTopup": {
                "endpoint": f"{self.config.public_base_url}/api/v1/credits/topup",
                "minMicroUsdc": PREPAID_MIN_MICRO_USDC,
                "supportedRails": ["base-x402", "stacks-sbtc", "ln-l402"],
            },
            "triRail": {
                "baseX402": {"network": self.config.base_network, "usdc": self.config.base_usdc_asset},
                "lightningL402": {"scheme": "L402", "header": "WWW-Authenticate"},
                "stacksSbtc": {
                    "network": f"stacks:{self.config.stacks_network}",
                    "recipient": self.config.stacks_pay_to,
                    "sbtcContract": self.config.stacks_sbtc_contract,
                    "header": "X-Stacks-Payment-Tx",
                },
            },
            "extensions": {
                "bazaar": {
                    "discoverable": True,
                    "category": "confidential-compute",
                    "tags": ["blind-jsonb", "homomorphic-ml", "x402-v2", "l402", "sbtc"],
                }
            },
            "resources": resources,
        }

    def build_agent_card(self) -> dict[str, Any]:
        return {
            "schemaVersion": "erc-8004/v1",
            "name": "BlindCore Confidential Compute Oracle",
            "description": "Zero-plaintext homomorphic JSONB search, MultinomialNB scoring, and sealed-bid clearing with verifiable Base L2 and Stacks receipts.",
            "url": self.config.public_base_url,
            "erc8004": {
                "network": BASE_MAINNET_CAIP2,
                "identityRegistry": ERC8004_IDENTITY_REGISTRY_BASE,
                "reputationRegistry": ERC8004_REPUTATION_REGISTRY_BASE,
                "validationContract": self.config.base_anchor_contract,
                "validationMethod": "isReceiptSettled(bytes32)",
            },
            "stacksAnchor": {
                "network": f"stacks:{self.config.stacks_network}",
                "contract": self.config.stacks_anchor_contract,
                "validationMethod": "is-receipt-settled",
            },
            "protocols": {
                "x402": {"version": 2, "manifest": f"{self.config.public_base_url}/.well-known/x402.json"},
                "l402": {"scheme": "L402", "network": "bitcoin:lightning"},
                "stacksSbtc": {"header": "X-Stacks-Payment-Tx", "sbtcContract": self.config.stacks_sbtc_contract},
                "mcp": {"transport": "stdio", "tools": ["blindcore_pricing", "blindcore_query", "blindcore_sklearn_mnb"]},
            },
            "capabilities": ["CONTAINS", "LATEST", "SUM", "WEIGHTED_SUM", "RANGE_GATE", "SKLEARN_MNB", "AUCTION_CLEAR"],
        }

    def build_pricing_payload(self) -> dict[str, Any]:
        return {
            "currency": {"base": "USDC", "lightning": "sats", "stacks": "sBTC/STX"},
            "prepaidMinMicroUsdc": PREPAID_MIN_MICRO_USDC,
            "prepaidMinSats": max(1, int(round(PREPAID_MIN_MICRO_USDC * 100.0 / self.config.btc_usd_price))),
            "tiers": {
                k: {
                    "opTierId": t.op_tier_id,
                    "usd": f"{t.micro_usdc / 1_000_000:.4f}",
                    "microUsdc": t.micro_usdc,
                    "sats": t.sats,
                    "ustx": t.ustx,
                    "description": t.description,
                }
                for k, t in PRICING_TIERS.items()
            },
        }


# ---------------------------------------------------------------------------
# HTTP Reverse Proxy Handler
# ---------------------------------------------------------------------------

class TriRailHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, server_address: tuple[str, int], engine: TriRailEngine) -> None:
        self.engine = engine
        super().__init__(server_address, TriRailRequestHandler)


class TriRailRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        if os.environ.get("BLINDCORE_GATE_QUIET", "0") == "1":
            return
        super().log_message(format, *args)

    @property
    def engine(self) -> TriRailEngine:
        return self.server.engine  # type: ignore[attr-defined]

    def _client_ip(self) -> str:
        if self.engine.config.trust_proxy_headers:
            xff = self.headers.get("X-Real-IP") or self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            if xff:
                return xff[:64]
        return self.client_address[0] if self.client_address else "unknown"

    def _send_bytes(self, status: int, body: bytes, headers: dict[str, str]) -> None:
        self.send_response(status)
        out_headers = dict(headers)
        out_headers["Content-Length"] = str(len(body))
        out_headers.setdefault("Connection", "close")
        for k, v in out_headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, obj: Any, extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        self._send_bytes(status, body, headers)

    def _read_body(self) -> bytes | None:
        if self.headers.get("Transfer-Encoding"):
            self._send_json(400, {"error": "Transfer-Encoding not supported; provide explicit Content-Length"})
            return None
        raw_len = self.headers.get("Content-Length", "0").strip()
        try:
            length = int(raw_len)
        except ValueError:
            self._send_json(400, {"error": "invalid Content-Length"})
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            self._send_json(413, {"error": f"payload exceeds {MAX_BODY_BYTES} bytes"})
            return None
        data = self.rfile.read(length) if length > 0 else b""
        if len(data) != length:
            self._send_json(400, {"error": "truncated request body"})
            return None
        return data

    # -- GET Routes (Discovery & Prepaid Balance) ---------------------------

    def do_GET(self) -> None:
        client_ip = self._client_ip()
        if not self.engine.rate_limiter.allow_request(client_ip):
            self._send_json(429, {"error": "rate limit or payment failure lockout"})
            return
        try:
            clean_path = validate_request_path(self.path, allow_proxy_only=False)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return

        if clean_path in ("/health", "/healthz"):
            self._send_json(
                200,
                {
                    "status": "ok",
                    "service": "blindcore-trirail-gate",
                    "x402Version": 2,
                    "rails": ["base-x402", "ln-l402", "stacks-sbtc"],
                    "baseNetwork": self.engine.config.base_network,
                    "stacksNetwork": self.engine.config.stacks_network,
                    "upstreamConfigured": bool(self.engine.config.upstream_url),
                },
            )
            return
        if clean_path == "/llms.txt":
            body = self.engine.build_llms_txt().encode("utf-8")
            self._send_bytes(200, body, {"Content-Type": "text/plain; charset=utf-8"})
            return
        if clean_path == "/.well-known/x402.json":
            self._send_json(200, self.engine.build_well_known_x402())
            return
        if clean_path == "/.well-known/agent-card.json":
            self._send_json(200, self.engine.build_agent_card())
            return
        if clean_path == "/api/v1/pricing":
            self._send_json(200, self.engine.build_pricing_payload())
            return
        if clean_path == "/api/v1/credits/balance":
            sess = self.headers.get("X-BlindCore-Session", "").strip()
            if not sess:
                self._send_json(401, {"error": "missing X-BlindCore-Session header"})
                return
            try:
                claims = self.engine.verify_session_token(sess)
            except PaymentRejected as exc:
                if exc.record_abuse:
                    self.engine.rate_limiter.record_bad_payment(client_ip)
                self._send_json(401, {"error": exc.reason})
                return
            bal = self.engine.ledger.get_balance(str(claims["payer"]))
            self._send_json(
                200,
                {
                    "payer": claims["payer"],
                    "balance_micro_usdc": bal,
                    "balance_usd": f"{bal / 1_000_000:.6f}",
                },
            )
            return
        self._send_json(404, {"error": "not found"})

    # -- POST Routes (Top-Up & Tri-Rail Paid Proxy) -------------------------

    def do_POST(self) -> None:
        client_ip = self._client_ip()
        if not self.engine.rate_limiter.allow_request(client_ip):
            self._send_json(429, {"error": "rate limit or payment failure lockout"})
            return

        try:
            clean_path = validate_request_path(self.path, allow_proxy_only=False)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return

        body = self._read_body()
        if body is None:
            return
        body_sha256 = sha256_hex(body)

        if clean_path == "/api/v1/credits/topup":
            self._handle_credit_topup(client_ip, body_sha256)
            return

        try:
            clean_path = validate_request_path(self.path, allow_proxy_only=True)
        except ValueError as exc:
            self._send_json(404, {"error": str(exc)})
            return

        body_json: dict[str, Any] | None = None
        if body:
            try:
                parsed = json.loads(body.decode("utf-8"))
                if isinstance(parsed, dict):
                    body_json = parsed
            except Exception:
                self._send_json(400, {"error": "invalid JSON request body"})
                return

        tier = resolve_price_tier(clean_path, body_json)
        self._handle_paid_proxy(client_ip, clean_path, tier, body, body_sha256)

    def _authenticate_payment(
        self,
        tier: PriceTier,
        clean_path: str,
        body_sha256: str,
        required_micro_usdc: int,
        required_sats: int,
        required_ustx: int,
        allow_session_credit: bool,
    ) -> VerifiedPayment | None:
        req_url = f"{self.engine.config.public_base_url}{clean_path}"

        # 1. Prepaid micro-credit session (bypasses per-tx CDP facilitator fee)
        session_hdr = self.headers.get("X-BlindCore-Session", "").strip()
        if allow_session_credit and session_hdr:
            return self.engine.verify_session_credit(session_hdr, tier, body_sha256)

        # 2. Rail 1: Base x402 v2 (PAYMENT-SIGNATURE) or v1 fallback (X-PAYMENT)
        x402_hdr = (
            self.headers.get("PAYMENT-SIGNATURE")
            or self.headers.get("X-PAYMENT")
            or ""
        ).strip()
        if x402_hdr:
            return self.engine.verify_x402_payment(
                x402_hdr,
                required_micro_usdc,
                tier,
                req_url,
                body_sha256,
            )

        # 3. Rail 2: Bitcoin Lightning L402 (Authorization: L402 <mac>:<preimage>)
        auth_hdr = self.headers.get("Authorization", "").strip()
        if auth_hdr.upper().startswith("L402 ") or auth_hdr.upper().startswith("LSAT "):
            return self.engine.verify_l402_authorization(auth_hdr, required_sats, clean_path)

        # 4. Rail 3: Stacks sBTC / STX (X-Stacks-Payment-Tx: <txid>)
        stacks_tx = self.headers.get("X-Stacks-Payment-Tx", "").strip()
        if stacks_tx:
            return self.engine.verify_stacks_payment(stacks_tx, required_sats, required_ustx)

        return None

    def _build_payment_response_header(self, payment: VerifiedPayment, tier: PriceTier) -> str:
        payload: dict[str, Any] = {
            "x402Version": 2,
            "success": True,
            "rail": payment.rail,
            "payer": payment.payer,
            "paymentHash": payment.payment_hash,
            "tier": tier.name,
            "amountMicroUsdc": str(payment.fee_micro_usdc),
            "amountSats": payment.amount_sats,
            "transaction": payment.transaction_ref,
            "network": payment.network,
            "settlementMode": payment.settlement_mode,
            "settledAt": int(time.time()),
        }
        if payment.remaining_credit_micro_usdc is not None:
            payload["remainingMicroUsdc"] = str(payment.remaining_credit_micro_usdc)
        return b64_json_encode(payload)

    def _handle_credit_topup(self, client_ip: str, body_sha256: str) -> None:
        min_sats = max(1, int(round(PREPAID_MIN_MICRO_USDC * 100.0 / self.engine.config.btc_usd_price)))
        min_ustx = max(1, int(round(PREPAID_MIN_MICRO_USDC * 1_000_000.0 / DEFAULT_STX_MICRO_USD)))
        topup_tier = PriceTier(
            name="CREDIT_TOPUP",
            op_tier_id=0,
            micro_usdc=PREPAID_MIN_MICRO_USDC,
            sats=min_sats,
            ustx=min_ustx,
            description="Prepaid micro-credit session top-up ($1.00 USDC minimum)",
        )
        try:
            payment = self._authenticate_payment(
                topup_tier,
                "/api/v1/credits/topup",
                body_sha256,
                PREPAID_MIN_MICRO_USDC,
                min_sats,
                min_ustx,
                allow_session_credit=False,
            )
        except PaymentRejected as exc:
            if exc.record_abuse:
                self.engine.rate_limiter.record_bad_payment(client_ip)
            hdrs, quote = self.engine.build_402_response(
                topup_tier,
                "/api/v1/credits/topup",
                body_sha256,
                error_msg=exc.reason,
                micro_usdc_override=PREPAID_MIN_MICRO_USDC,
                sats_override=min_sats,
                ustx_override=min_ustx,
            )
            self._send_json(402, quote, hdrs)
            return

        if payment is None:
            hdrs, quote = self.engine.build_402_response(
                topup_tier,
                "/api/v1/credits/topup",
                body_sha256,
                error_msg="Prepaid credit top-up requires >= $1.00 USDC (or equivalent sBTC/L402)",
                micro_usdc_override=PREPAID_MIN_MICRO_USDC,
                sats_override=min_sats,
                ustx_override=min_ustx,
            )
            self._send_json(402, quote, hdrs)
            return

        if payment.fee_micro_usdc < PREPAID_MIN_MICRO_USDC:
            self.engine.ledger.mark_aborted(payment.rail, payment.payment_hash)
            hdrs, quote = self.engine.build_402_response(
                topup_tier,
                "/api/v1/credits/topup",
                body_sha256,
                error_msg=f"top-up below $1.00 minimum ({payment.fee_micro_usdc} micro-USDC)",
                micro_usdc_override=PREPAID_MIN_MICRO_USDC,
                sats_override=min_sats,
                ustx_override=min_ustx,
            )
            self._send_json(402, quote, hdrs)
            return

        try:
            self.engine.settle_x402_if_needed(payment)
            new_bal = self.engine.ledger.settle_and_credit_deposit(
                payment.payer,
                payment.rail,
                payment.payment_hash,
                payment.fee_micro_usdc,
            )
        except PaymentRejected as exc:
            self.engine.ledger.mark_aborted(payment.rail, payment.payment_hash)
            self._send_json(402, {"error": exc.reason})
            return
        except Exception:
            self.engine.ledger.mark_aborted(payment.rail, payment.payment_hash)
            self._send_json(500, {"error": "credit settlement failed"})
            return

        session_token, expires_at = self.engine.issue_session_token(payment.payer, payment.rail)
        payment.remaining_credit_micro_usdc = new_bal
        pay_resp_b64 = self._build_payment_response_header(payment, topup_tier)
        self._send_json(
            200,
            {
                "status": "ok",
                "rail": payment.rail,
                "payer": payment.payer,
                "payment_hash": payment.payment_hash,
                "credited_micro_usdc": payment.fee_micro_usdc,
                "balance_micro_usdc": new_bal,
                "balance_usd": f"{new_bal / 1_000_000:.6f}",
                "session_token": session_token,
                "expires_at": expires_at,
            },
            {
                "PAYMENT-RESPONSE": pay_resp_b64,
                "X-PAYMENT-RESPONSE": pay_resp_b64,
                "X-BlindCore-Rail": payment.rail,
                "X-BlindCore-Payment-Hash": payment.payment_hash,
            },
        )

    def _handle_paid_proxy(
        self,
        client_ip: str,
        clean_path: str,
        tier: PriceTier,
        body: bytes,
        body_sha256: str,
    ) -> None:
        try:
            payment = self._authenticate_payment(
                tier,
                clean_path,
                body_sha256,
                tier.micro_usdc,
                tier.sats,
                tier.ustx,
                allow_session_credit=True,
            )
        except PaymentRejected as exc:
            if exc.record_abuse:
                self.engine.rate_limiter.record_bad_payment(client_ip)
            hdrs, quote = self.engine.build_402_response(
                tier,
                clean_path,
                body_sha256,
                error_msg=exc.reason,
            )
            self._send_json(402, quote, hdrs)
            return

        if payment is None:
            hdrs, quote = self.engine.build_402_response(tier, clean_path, body_sha256)
            self._send_json(402, quote, hdrs)
            return

        # Build sanitized loopback upstream request (strip ALL client X-BlindCore-* & payment headers)
        now_ts = int(time.time())
        gate_mac = self.engine.compute_gate_mac(
            payment.rail,
            payment.payer,
            payment.payment_hash,
            payment.fee_micro_usdc,
            now_ts,
            body_sha256,
        )
        upstream_headers = sanitize_upstream_headers(
            self.headers,
            payment.rail,
            payment.payer,
            payment.payment_hash,
            payment.fee_micro_usdc,
            now_ts,
            gate_mac,
            self.engine.config.upstream_token,
        )

        upstream_url = f"{self.engine.config.upstream_url}{clean_path}"
        req = urllib.request.Request(upstream_url, data=body, method="POST", headers=upstream_headers)

        upstream_status = 502
        upstream_body = b""
        upstream_ct = "application/json"
        try:
            with urllib.request.urlopen(req, timeout=self.engine.config.http_timeout_secs) as resp:
                upstream_status = int(resp.status)
                upstream_body = resp.read(MAX_BODY_BYTES * 4)
                upstream_ct = sanitize_content_type(resp.headers.get("Content-Type"))
        except urllib.error.HTTPError as exc:
            upstream_status = int(exc.code)
            upstream_body = exc.read(MAX_BODY_BYTES * 4)
            upstream_ct = sanitize_content_type(exc.headers.get("Content-Type"))
        except Exception as exc:
            upstream_status = 502
            upstream_body = json.dumps({"error": f"upstream compute unavailable: {exc}"}).encode("utf-8")

        # Deferred settlement: abort or refund if upstream failed
        if not (200 <= upstream_status < 300):
            if payment.settlement_mode == "prepaid-session":
                self.engine.ledger.refund_credit(
                    payment.payer,
                    tier.micro_usdc,
                    f"refund:{tier.name}",
                    debit_seq=payment.debit_seq,
                )
            else:
                self.engine.ledger.mark_aborted(payment.rail, payment.payment_hash)
            self._send_bytes(
                upstream_status,
                upstream_body,
                {
                    "Content-Type": upstream_ct,
                    "X-BlindCore-Rail": payment.rail,
                    "X-BlindCore-Settlement": "aborted",
                },
            )
            return

        # Upstream succeeded -> finalize settlement and emit PAYMENT-RESPONSE
        if payment.settlement_mode != "prepaid-session":
            try:
                self.engine.settle_x402_if_needed(payment)
                if not self.engine.ledger.mark_settled(payment.rail, payment.payment_hash):
                    raise PaymentRejected("payment settlement state conflict")
            except PaymentRejected as exc:
                self.engine.ledger.mark_aborted(payment.rail, payment.payment_hash)
                self._send_json(402, {"error": exc.reason})
                return
            except Exception:
                self.engine.ledger.mark_aborted(payment.rail, payment.payment_hash)
                self._send_json(502, {"error": "payment settlement error"})
                return

        pay_resp_b64 = self._build_payment_response_header(payment, tier)
        self._send_bytes(
            upstream_status,
            upstream_body,
            {
                "Content-Type": upstream_ct,
                "PAYMENT-RESPONSE": pay_resp_b64,
                "X-PAYMENT-RESPONSE": pay_resp_b64,
                "X-BlindCore-Rail": payment.rail,
                "X-BlindCore-Payment-Hash": payment.payment_hash,
            },
        )


def build_server(config: GateConfig) -> TriRailHTTPServer:
    engine = TriRailEngine(config)
    return TriRailHTTPServer((config.listen_host, config.listen_port), engine)


def main() -> None:
    parser = argparse.ArgumentParser(description="BlindCore Tri-Rail Payment Gateway")
    parser.add_argument("--host", default=None, help="Bind host (overrides BLINDCORE_LISTEN_HOST)")
    parser.add_argument("--port", type=int, default=None, help="Bind port (overrides BLINDCORE_LISTEN_PORT)")
    parser.add_argument("--upstream", default=None, help="Upstream BlindCore API URL")
    args = parser.parse_args()

    cfg = GateConfig.from_env()
    if args.host:
        cfg.listen_host = args.host
    if args.port is not None:
        cfg.listen_port = args.port
    if args.upstream:
        cfg.upstream_url = args.upstream.rstrip("/")

    server = build_server(cfg)
    print(
        f"blindcore-trirail-gate listening on http://{cfg.listen_host}:{cfg.listen_port} "
        f"-> upstream {cfg.upstream_url} (base={cfg.base_network}, stacks={cfg.stacks_network})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.engine.close()


if __name__ == "__main__":
    main()
