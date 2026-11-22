#!/usr/bin/env python3
"""Zero-dependency BlindCore (by Blind Labs) Live Evaluation Harness.

Verifies:
  (a) GET /auction reachability, CSP/security headers, and browser seal primitives
  (b) GET /api/auction/state + local SHA-256 NSAU0001 receipt verification
  (c) 10x live SQL query latency probe (SELECT 1 & pg_catalog.pg_class, p50/p95 ms)
  (d) Optional --reserve smoke test submitting a browser-equivalent sealed SHA-256
      commitment with zero plaintext price transmitted on the wire
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import hmac
import json
import math
import os
import secrets
import ssl
import sys
import time
from pathlib import Path
from typing import Any

# Import local stdlib-only BlindCore client.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE / "python"))
from blindcore_sdk import BlindCoreClient  # noqa: E402

EXPECTED_BID_KEYS = frozenset({"bidder_hash", "commit_sha256", "tier_or_qty", "timestamp_ms"})


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, math.ceil((pct / 100.0) * len(ordered)) - 1))
    return ordered[idx]


def compute_nsau0001_receipt(state: dict[str, Any]) -> str:
    magic = str(state.get("receipt_magic", ""))
    mode = str(state.get("mode", ""))
    seq = int(state.get("state_seq", 0))
    cp_raw = state.get("clearing_price")
    cp = 0 if cp_raw is None else int(cp_raw)
    tranches = state.get("tranches") or []
    filled_csv = ":".join(str(int(t.get("filled_units", 0))) for t in tranches)
    dutch = state.get("dutch") or {}
    dutch_filled = int(dutch.get("filled_slots", 0))
    bids = state.get("sealed_bids") or []
    commits_csv = ",".join(str(b.get("commit_sha256", "")) for b in bids)
    preimage = f"{magic}|AUCTION|{mode}|{seq}|{cp}|{filled_csv}|{dutch_filled}|{commits_csv}"
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def check_auction_portal(client: BlindCoreClient) -> tuple[bool, str]:
    auth_mode = "public"
    status, headers, body = client.request_raw("GET", "/auction", auth=False)
    if status == 401:
        auth_mode = "bearer-strict"
        status, headers, body = client.request_raw("GET", "/auction", auth=True)
    if status != 200:
        return False, f"HTTP {status} (expected 200)"

    ctype = headers.get("content-type", "")
    nosniff = headers.get("x-content-type-options", "").lower()
    csp = headers.get("content-security-policy", "")
    html = body.decode("utf-8", errors="replace")
    html_low = html.lower()

    issues: list[str] = []
    if "text/html" not in ctype.lower():
        issues.append(f"bad Content-Type '{ctype}'")
    if nosniff != "nosniff":
        issues.append(f"missing nosniff (got '{nosniff or 'none'}')")
    if "default-src 'self'" not in csp:
        issues.append(f"weak/missing CSP ('{csp or 'none'}')")
    if "<script src=\"http" in html_low or "<script src='http" in html_low:
        issues.append("external script tag detected")
    for required in ("crypto.subtle", "sha-256", "aes-gcm"):
        if required not in html_low:
            issues.append(f"missing browser seal primitive '{required}'")

    if issues:
        return False, "; ".join(issues)
    return True, f"HTTP 200 ({auth_mode}, {len(body)} B), CSP+nosniff OK"


def check_state_and_receipt(client: BlindCoreClient) -> tuple[bool, str, dict[str, Any] | None]:
    state = client.get_json("/api/auction/state", auth=True)
    if not isinstance(state, dict):
        return False, "response is not a JSON object", None

    issues: list[str] = []
    magic = state.get("receipt_magic")
    srv_hex = str(state.get("receipt_hex", ""))
    if magic != "NSAU0001":
        issues.append(f"unexpected receipt_magic '{magic}'")
    if len(srv_hex) != 64 or not all(c in "0123456789abcdef" for c in srv_hex):
        issues.append("malformed 64-hex receipt_hex")

    bids = state.get("sealed_bids")
    if not isinstance(bids, list):
        issues.append("sealed_bids missing or not a list")
        bids = []
    for idx, bid in enumerate(bids):
        if not isinstance(bid, dict):
            issues.append(f"sealed_bids[{idx}] not an object")
            continue
        keys = frozenset(bid.keys())
        if keys != EXPECTED_BID_KEYS:
            issues.append(f"sealed_bids[{idx}] unexpected keys {sorted(keys)}")
        for k in keys:
            if "price" in k.lower():
                issues.append(f"plaintext price key '{k}' leaked in sealed_bids[{idx}]")

    local_hex = compute_nsau0001_receipt(state)
    if not hmac.compare_digest(local_hex, srv_hex):
        issues.append(f"SHA-256 mismatch (local={local_hex[:12]}.. srv={srv_hex[:12]}..)")

    if issues:
        return False, "; ".join(issues), state
    seq = state.get("state_seq", 0)
    return (
        True,
        f"NSAU0001 SHA-256 MATCH (seq={seq}, bids={len(bids)}, digest={local_hex[:12]}..)",
        state,
    )


def check_sql_latency_probe(client: BlindCoreClient, count: int) -> tuple[bool, str]:
    queries = (
        ("SELECT 1", "scalar"),
        ("SELECT COUNT(*) FROM pg_catalog.pg_class", "catalog"),
    )
    lat_ms: list[float] = []
    srv_us: list[int] = []

    for i in range(count):
        sql, label = queries[i % len(queries)]
        t0 = time.perf_counter()
        res = client.query_json(sql)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        if not isinstance(res, dict) or int(res.get("row_count", 0)) < 1:
            return False, f"query #{i + 1} ({label}) returned invalid result"
        rows = res.get("rows") or []
        if not rows or not rows[0]:
            return False, f"query #{i + 1} ({label}) returned empty row"
        val = rows[0][0]
        if label == "scalar" and val != 1:
            return False, f"SELECT 1 returned {val!r} instead of 1"
        if label == "catalog" and (not isinstance(val, int) or val < 1):
            return False, f"pg_class count returned unexpected value {val!r}"
        lat_ms.append(dt_ms)
        srv_us.append(int(res.get("elapsed_us", 0)))

    p50 = _percentile(lat_ms, 50.0)
    p95 = _percentile(lat_ms, 95.0)
    srv_p50_ms = _percentile([float(x) / 1000.0 for x in srv_us], 50.0)
    return (
        True,
        f"{count}/{count} OK | RTT p50={p50:.2f}ms p95={p95:.2f}ms (engine p50={srv_p50_ms:.3f}ms)",
    )


def check_sealed_reserve(
    client: BlindCoreClient,
    state_before: dict[str, Any] | None,
    mode: str,
    bidder_id: str,
    qty: int,
    rail: str,
) -> tuple[bool, str]:
    if state_before is None:
        return False, "cannot reserve without valid initial state"
    before_seq = int(state_before.get("state_seq", 0))
    nonce = "n-" + secrets.token_hex(8)

    if mode == "tranches":
        tranches = state_before.get("tranches") or []
        open_tier = next((t for t in tranches if t.get("status") == "OPEN"), None)
        if open_tier is None:
            return False, "no OPEN tranche available for reservation"
        collateral_tier = int(open_tier["tier"])
        limit_price_cents = int(open_tier["price_cents"])
    else:
        dutch = state_before.get("dutch") or {}
        if dutch.get("cleared"):
            return False, "dutch auction is already cleared"
        collateral_tier = 50
        p_min = int(dutch.get("p_min_cents", 10000))
        p_max = int(dutch.get("p_max_cents", 100000))
        limit_price_cents = p_min + ((p_max - p_min) * (collateral_tier - 1)) // 99

    preimage = (
        f"AUCTION-COMMIT-V1|{mode}|{bidder_id}|{nonce}|"
        f"{qty}|{collateral_tier}|{limit_price_cents}|{rail}"
    )
    commit_sha256 = hashlib.sha256(preimage.encode("utf-8")).hexdigest()

    # Plaintext price is intentionally omitted from the wire payload.
    payload = {
        "mode": mode,
        "bidder_id": bidder_id,
        "nonce": nonce,
        "commit_sha256": commit_sha256,
        "qty": qty,
        "collateral_tier": collateral_tier,
        "rail": rail,
    }
    wire_json = json.dumps(payload, separators=(",", ":"))
    if "price" in wire_json.lower():
        return False, "internal guard tripped: plaintext price field in commit payload"

    ack = client.post_json("/api/auction/commit", payload)
    if ack.get("status") != "accepted" or ack.get("commit_sha256") != commit_sha256:
        return False, f"unexpected commit ack: {ack}"

    ok_after, msg_after, state_after = check_state_and_receipt(client)
    if not ok_after or state_after is None:
        return False, f"post-commit receipt verify failed: {msg_after}"
    after_seq = int(state_after.get("state_seq", 0))
    if after_seq <= before_seq:
        return False, f"state_seq did not advance ({before_seq} -> {after_seq})"

    return (
        True,
        f"ACCEPTED (mode={mode}, qty={qty}, seq {before_seq}->{after_seq}, 0 plaintext price, receipt OK)",
    )


def render_scorecard(
    target_url: str,
    rows: list[tuple[str, str, str]],
    overall_ok: bool,
) -> str:
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    c1 = max(len("Check"), *(len(r[0]) for r in rows))
    c2 = max(len("Status"), *(len(r[1]) for r in rows))
    c3 = max(len("Measured Evidence"), *(len(r[2]) for r in rows))
    sep = f"+-{'-' * c1}-+-{'-' * c2}-+-{'-' * c3}-+"
    verdict = "PASS" if overall_ok else "FAIL"

    lines = [
        "",
        "BlindCore (by Blind Labs) -- Live Evaluation Scorecard",
        f"Target: {target_url}  |  Timestamp: {now_utc}  |  Verdict: {verdict}",
        sep,
        f"| {'Check'.ljust(c1)} | {'Status'.ljust(c2)} | {'Measured Evidence'.ljust(c3)} |",
        sep,
    ]
    for name, status, detail in rows:
        lines.append(f"| {name.ljust(c1)} | {status.ljust(c2)} | {detail.ljust(c3)} |")
    lines.append(sep)
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Zero-dependency BlindCore live evaluation & CISO/investor scorecard."
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("BLINDCORE_URL", ""),
        help="Target base URL (default: env BLINDCORE_URL, e.g. https://demo.example.com)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("BLINDCORE_TOKEN", ""),
        help="Bearer API token (default: env BLINDCORE_TOKEN)",
    )
    parser.add_argument(
        "--queries",
        type=int,
        default=10,
        help="Number of live SQL queries for latency probe (default: 10)",
    )
    parser.add_argument(
        "--reserve",
        action="store_true",
        help="Submit a live browser-equivalent sealed SHA-256 reservation (mutates state)",
    )
    parser.add_argument(
        "--reserve-mode",
        choices=("tranches", "dutch"),
        default="tranches",
        help="Auction mode when --reserve is enabled (default: tranches)",
    )
    parser.add_argument(
        "--reserve-bidder",
        default="",
        help="Bidder handle for --reserve (default: random eval-smoke-<hex>)",
    )
    parser.add_argument(
        "--reserve-qty",
        type=int,
        default=1,
        help="Share quantity for --reserve (default: 1)",
    )
    parser.add_argument(
        "--reserve-rail",
        choices=("stripe", "wire", "usdc"),
        default="usdc",
        help="Settlement rail for --reserve (default: usdc)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request socket timeout in seconds (default: 10.0)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS certificate validation (staging/self-signed only)",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    url = args.url.strip()
    token = args.token.strip()
    if not url:
        print("ERROR: set BLINDCORE_URL or pass --url (e.g. https://demo.example.com)", file=sys.stderr)
        return 2
    if not token:
        print("ERROR: set BLINDCORE_TOKEN or pass --token", file=sys.stderr)
        return 2
    if args.queries < 1:
        print("ERROR: --queries must be >= 1", file=sys.stderr)
        return 2
    if args.reserve_qty < 1:
        print("ERROR: --reserve-qty must be >= 1", file=sys.stderr)
        return 2

    ssl_ctx: ssl.SSLContext | None = None
    if args.insecure:
        ssl_ctx = ssl._create_unverified_context()  # noqa: SLF001

    client = BlindCoreClient(url, token, timeout=args.timeout, ssl_context=ssl_ctx)
    rows: list[tuple[str, str, str]] = []
    all_ok = True

    # (a) GET /auction reachability + CSP/security headers
    try:
        ok_a, msg_a = check_auction_portal(client)
    except Exception as exc:
        ok_a, msg_a = False, f"exception: {exc}"
    rows.append(("1. Portal /auction + CSP", "PASS" if ok_a else "FAIL", msg_a))
    all_ok = all_ok and ok_a

    # (b) GET /api/auction/state + local SHA-256 NSAU0001 receipt verification
    state_obj: dict[str, Any] | None = None
    try:
        ok_b, msg_b, state_obj = check_state_and_receipt(client)
    except Exception as exc:
        ok_b, msg_b = False, f"exception: {exc}"
    rows.append(("2. State + NSAU0001 Receipt", "PASS" if ok_b else "FAIL", msg_b))
    all_ok = all_ok and ok_b

    # (c) 10x live SQL query latency probe (p50 / p95 ms)
    try:
        ok_c, msg_c = check_sql_latency_probe(client, args.queries)
    except Exception as exc:
        ok_c, msg_c = False, f"exception: {exc}"
    rows.append((f"3. Live SQL Probe ({args.queries}x)", "PASS" if ok_c else "FAIL", msg_c))
    all_ok = all_ok and ok_c

    # (d) Optional --reserve sealed SHA-256 commitment smoke test
    if args.reserve:
        bidder = args.reserve_bidder.strip() or f"eval-smoke-{secrets.token_hex(4)}"
        try:
            ok_d, msg_d = check_sealed_reserve(
                client,
                state_obj,
                args.reserve_mode,
                bidder,
                args.reserve_qty,
                args.reserve_rail,
            )
        except Exception as exc:
            ok_d, msg_d = False, f"exception: {exc}"
        rows.append(("4. Sealed Commit (--reserve)", "PASS" if ok_d else "FAIL", msg_d))
        all_ok = all_ok and ok_d
    else:
        rows.append(
            (
                "4. Sealed Commit (--reserve)",
                "SKIP",
                "read-only mode (pass --reserve to submit a sealed SHA-256 commit)",
            )
        )

    print(render_scorecard(url, rows, all_ok))
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
