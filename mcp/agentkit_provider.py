#!/usr/bin/env python3
"""
Coinbase AgentKit BlindCoreActionProvider (SPDX-License-Identifier: Apache-2.0).

Drop-in ActionProvider supporting BlindCore's tri-rail HTTP 402 payment
negotiation across:
  - Base L2 USDC (x402 v2 PAYMENT-SIGNATURE + EIP-3009 / Permit2 / Smart Wallets)
  - Bitcoin Lightning (L402 macaroon + preimage)
  - Stacks sBTC / STX (X-Stacks-Payment-Tx)
  - Prepaid Micro-Credit Sessions (X-BlindCore-Session)

Works both inside `coinbase_agentkit` (when installed) and standalone with
zero third-party dependencies for stdlib testing and lightweight agents.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable

try:
    from coinbase_agentkit import ActionProvider as _BaseActionProvider  # type: ignore
    from coinbase_agentkit import create_action as _create_action  # type: ignore
    AGENTKIT_AVAILABLE = True
except ImportError:
    AGENTKIT_AVAILABLE = False

    class _BaseActionProvider:  # type: ignore[no-redef]
        def __init__(self, name: str, action_providers: list[Any] | None = None) -> None:
            self.name = name
            self.action_providers = action_providers or []

        def supports_network(self, network: Any) -> bool:
            return True

    def _create_action(name: str, description: str, schema: Any = None) -> Callable[..., Any]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            fn._agentkit_action = {"name": name, "description": description, "schema": schema}  # type: ignore[attr-defined]
            return fn
        return decorator


try:
    from mcp.mcp_server import (
        ALLOWED_QUERY_ENDPOINTS,
        BlindCoreHttpClient,
        _sanitize_payment_headers,
    )
except ImportError:
    from mcp_server import (  # type: ignore[no-redef]
        ALLOWED_QUERY_ENDPOINTS,
        BlindCoreHttpClient,
        _sanitize_payment_headers,
    )


SUPPORTED_RAILS = frozenset(("base-x402", "ln-l402", "stacks-sbtc", "prepaid-session"))

# Payment signer callback signature:
#   signer(rail: str, challenge_402: dict[str, Any]) -> dict[str, str]
# Returns HTTP headers to attach on retry (e.g. {"PAYMENT-SIGNATURE": ...}).
PaymentSigner = Callable[[str, dict[str, Any]], dict[str, str]]


class BlindCoreActionProvider(_BaseActionProvider):
    """AgentKit ActionProvider for BlindCore Tri-Rail confidential compute."""

    SUPPORTED_NETWORKS = ("base-mainnet", "base-sepolia", "eip155:8453", "eip155:84532")

    def __init__(
        self,
        base_url: str | None = None,
        preferred_rail: str = "base-x402",
        payment_signer: PaymentSigner | None = None,
        session_token: str | None = None,
    ) -> None:
        super().__init__("blindcore-tri-rail", [])
        if preferred_rail not in SUPPORTED_RAILS:
            raise ValueError(f"unsupported preferred_rail: {preferred_rail}")
        self.preferred_rail = preferred_rail
        self.payment_signer = payment_signer
        self.client = BlindCoreHttpClient(
            base_url=base_url or os.environ.get("BLINDCORE_GATE_URL", "http://127.0.0.1:3002"),
            session_token=session_token,
        )

    def supports_network(self, network: Any) -> bool:
        net_id = getattr(network, "network_id", str(network))
        return str(net_id) in self.SUPPORTED_NETWORKS

    def _execute_with_402_retry(
        self,
        path: str,
        payload: dict[str, Any],
        rail: str | None = None,
    ) -> dict[str, Any]:
        active_rail = rail or self.preferred_rail
        if active_rail not in SUPPORTED_RAILS:
            raise ValueError(f"unsupported payment rail: {active_rail}")

        # 1. If a prepaid session token is already loaded (and not topping up), try it first.
        if self.client.session_token and path != "/api/v1/credits/topup":
            first = self.client.post_paid(path, payload)
            if first["http_status"] != 402:
                return first

        # 2. Probe endpoint cleanly (suppressing any stale session_token) for HTTP 402 quote.
        challenge = self.client.post_paid(path, payload, suppress_default_payment=True)
        if challenge["http_status"] != 402:
            return challenge

        if self.payment_signer is None:
            return challenge

        # 3. Delegate signing/payment to the agent's wallet signer for the chosen rail.
        raw_pay_headers = self.payment_signer(active_rail, challenge)
        if not raw_pay_headers:
            return challenge
        pay_headers = _sanitize_payment_headers(raw_pay_headers)
        if not pay_headers:
            return challenge

        # 4. Retry paid request with proof header ONLY (never leak stale session_token).
        return self.client.post_paid(
            path,
            payload,
            payment_headers=pay_headers,
            suppress_default_payment=True,
        )

    @_create_action(
        name="blindcore_get_pricing",
        description="Fetch BlindCore Tri-Rail pricing tiers (Base USDC, Lightning sats, Stacks sBTC) and x402 v2 discovery.",
    )
    def blindcore_get_pricing(self, _wallet_provider: Any = None, _args: dict[str, Any] | None = None) -> str:
        return json.dumps(self.client.get_json("/api/v1/pricing"), sort_keys=True)

    @_create_action(
        name="blindcore_topup_credits",
        description="Top up a prepaid BlindCore micro-credit session ($1.00 USDC min or sBTC/L402 equivalent) to bypass per-tx facilitator fees on sub-$0.005 queries.",
    )
    def blindcore_topup_credits(self, _wallet_provider: Any = None, args: dict[str, Any] | None = None) -> str:
        params = args or {}
        if not isinstance(params, dict):
            raise ValueError("args must be a dict")
        rail = str(params.get("rail") or self.preferred_rail)
        if rail not in SUPPORTED_RAILS or rail == "prepaid-session":
            raise ValueError(f"unsupported topup rail: {rail}")
        res = self._execute_with_402_retry("/api/v1/credits/topup", {}, rail=rail)
        if res.get("http_status") == 200 and isinstance(res.get("body"), dict):
            tok = res["body"].get("session_token")
            if tok:
                self.client.session_token = str(tok)
        return json.dumps(res, sort_keys=True)

    @_create_action(
        name="blindcore_query",
        description="Run a zero-plaintext BlindCore query (CONTAINS, LATEST, SUM, WEIGHTED_SUM, RANGE_GATE, BLIND_PIPELINE) with automatic 402 negotiation.",
    )
    def blindcore_query(self, _wallet_provider: Any = None, args: dict[str, Any] | None = None) -> str:
        params = args or {}
        if not isinstance(params, dict):
            raise ValueError("args must be a dict")
        endpoint = str(params.get("endpoint") or "/api/v1/blind/jsonb/query")
        if endpoint not in ALLOWED_QUERY_ENDPOINTS:
            raise ValueError(f"disallowed BlindCore query endpoint: {endpoint}")
        rail = params.get("rail")
        rail_str = str(rail) if rail is not None else None
        if rail_str is not None and rail_str not in SUPPORTED_RAILS:
            raise ValueError(f"unsupported payment rail: {rail_str}")
        payload: dict[str, Any] = {}
        extra = params.get("params")
        if isinstance(extra, dict):
            payload.update(extra)
        # Set table and op AFTER extra so params cannot overwrite them
        payload["table"] = str(params["table"])
        payload["op"] = str(params.get("op", "CONTAINS"))
        res = self._execute_with_402_retry(endpoint, payload, rail=rail_str)
        return json.dumps(res, sort_keys=True)

    @_create_action(
        name="blindcore_sklearn_mnb",
        description="Run encrypted single-pass MultinomialNB training and cohort scoring (op=SKLEARN_MNB) with automatic tri-rail payment.",
    )
    def blindcore_sklearn_mnb(self, _wallet_provider: Any = None, args: dict[str, Any] | None = None) -> str:
        params = args or {}
        if not isinstance(params, dict):
            raise ValueError("args must be a dict")
        rail = params.get("rail")
        rail_str = str(rail) if rail is not None else None
        if rail_str is not None and rail_str not in SUPPORTED_RAILS:
            raise ValueError(f"unsupported payment rail: {rail_str}")
        payload = {
            "table": str(params["table"]),
            "op": "SKLEARN_MNB",
            "train_classes": params["train_classes"],
            "vocab_paths": params["vocab_paths"],
            "score_cohorts": params.get("score_cohorts", []),
            "alpha": float(params.get("alpha", 1.0)),
            "weight_scale": int(params.get("weight_scale", 10000)),
        }
        res = self._execute_with_402_retry(
            "/api/v1/blind/jsonb/query",
            payload,
            rail=rail_str,
        )
        return json.dumps(res, sort_keys=True)


def blindcore_action_provider(
    base_url: str | None = None,
    preferred_rail: str = "base-x402",
    payment_signer: PaymentSigner | None = None,
    session_token: str | None = None,
) -> BlindCoreActionProvider:
    return BlindCoreActionProvider(
        base_url=base_url,
        preferred_rail=preferred_rail,
        payment_signer=payment_signer,
        session_token=session_token,
    )
