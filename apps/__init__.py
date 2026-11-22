"""
BlindCore Tri-Rail Killer Applications & Interactive Showcase Hub.
Copyright 2026 Blind Labs (https://blindlabs.ai). Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

from typing import Any

REQUIRED_RESULT_KEYS: tuple[str, ...] = (
    "app_id",
    "title",
    "rail",
    "status",
    "elapsed_ms",
    "http_402_observed",
    "zero_plaintext_verified",
    "counterfactual_knockout_verified",
    "settle_proof",
    "nsau0001_receipt_hex",
    "wire_sample_redacted",
    "summary",
)

APP_CATALOG: tuple[dict[str, Any], ...] = (
    {
        "app_id": "app01",
        "module": "apps.app01_agent_private_brain",
        "title": "Private Brain for Autonomous AI Agents",
        "rail": "base-x402",
        "rail_label": "Base x402 v2 USDC + MCP / AgentKit",
        "description": (
            "Encrypted BlindJSONB agent memory with prepaid micro-credits, "
            "constant-time CONTAINS retrieval, and single-pass SKLEARN_MNB threat scoring."
        ),
    },
    {
        "app_id": "app02",
        "module": "apps.app02_sealed_bid_darkpool",
        "title": "Non-Custodial Sealed-Bid OTC Dark Pool & MEV-Free Batch Clearing",
        "rail": "base-x402+stacks-sbtc",
        "rail_label": "Base x402 v2 + Stacks sBTC",
        "description": (
            "4 institutional market makers clear encrypted limit orders over ciphertexts "
            "via RANGE_GATE / WEIGHTED_SUM with dual Base and Stacks settlement proofs."
        ),
    },
    {
        "app_id": "app03",
        "module": "apps.app03_consortium_fraud_credit",
        "title": "Cross-Institution Consortium Fraud Exchange & Confidential Credit Underwriting",
        "rail": "base-x402",
        "rail_label": "Base x402 v2 USDC",
        "description": (
            "3 competing institutions pool encrypted borrower and fraud records for joint "
            "SKLEARN_MNB scoring, RANGE_GATE <= 3x leverage covenants, k_min_tkms privacy, "
            "and O(1) cryptographic shredding."
        ),
    },
    {
        "app_id": "app04",
        "module": "apps.app04_nostr_blind_relay",
        "title": "Decentralized Social Blind Relay, Private Feed & Encrypted Web-of-Trust",
        "rail": "ln-l402",
        "rail_label": "Bitcoin Lightning L402 sats",
        "description": (
            "Dummy-padded encrypted Nostr events with private SKLEARN_MNB anti-spam feed "
            "ranking, k_min_tkms encrypted WoT cohort tallies, replay blocks, and O(1) shredding."
        ),
    },
)

__all__ = ["APP_CATALOG", "REQUIRED_RESULT_KEYS"]
