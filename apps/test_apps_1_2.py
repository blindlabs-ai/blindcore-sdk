#!/usr/bin/env python3
"""
Automated Verification Suite for BlindCore Killer Apps #1 & #2
Copyright 2026 Blind Labs (https://blindlabs.ai). Licensed under the Apache License, Version 2.0.

Verifies:
  - Exact 12-key JSON return contract for both apps
  - status == "PASS", http_402_observed == True,
    zero_plaintext_verified == True, counterfactual_knockout_verified == True
  - Base BlindCoreRootAnchor.sol EIP-712 v2 + ABI calldata summary (App 1 & 2)
  - Stacks blindcore-root-anchor.clar settle-receipt Clarity payload (App 2)
  - 96-byte NSAU0001 receipt verification & single-byte tamper rejection
  - Counterfactual receipt knockouts (assertNotEqual across runs, apps, and vaults)
  - CLI execution (`--mode local`) for both apps
  - 100% 7-bit ASCII hygiene across all owned files
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from apps import app01_agent_private_brain as app01  # noqa: E402
from apps import app02_sealed_bid_darkpool as app02  # noqa: E402


EXPECTED_CONTRACT_KEYS = frozenset((
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
))


class TestKillerApps1And2(unittest.TestCase):
    def _assert_contract(self, res: dict, expected_app_id: str) -> None:
        self.assertEqual(set(res.keys()), EXPECTED_CONTRACT_KEYS)
        # Must be cleanly JSON-serializable
        roundtrip = json.loads(json.dumps(res, sort_keys=True))
        self.assertEqual(set(roundtrip.keys()), EXPECTED_CONTRACT_KEYS)
        self.assertEqual(res["app_id"], expected_app_id)
        self.assertIsInstance(res["title"], str)
        self.assertTrue(len(res["title"]) > 10)
        self.assertIsInstance(res["rail"], str)
        self.assertEqual(res["status"], "PASS")
        self.assertIsInstance(res["elapsed_ms"], (int, float))
        self.assertGreater(res["elapsed_ms"], 0.0)
        self.assertTrue(res["http_402_observed"])
        self.assertTrue(res["zero_plaintext_verified"])
        self.assertTrue(res["counterfactual_knockout_verified"])
        rec_hex = res["nsau0001_receipt_hex"]
        self.assertIsInstance(rec_hex, str)
        self.assertEqual(len(rec_hex), 192)
        self.assertTrue(rec_hex.startswith("4e53415530303031"))
        self.assertIsInstance(res["settle_proof"], dict)
        self.assertIsInstance(res["wire_sample_redacted"], dict)
        self.assertIsInstance(res["summary"], dict)

    def test_app01_local_contract_and_invariants(self) -> None:
        res = app01.run_demo(mode="local")
        self._assert_contract(res, "app01_agent_private_brain")
        self.assertEqual(res["rail"], "base-x402")

        sp = res["settle_proof"]
        self.assertEqual(sp["scheme"], "EIP-712-v2")
        self.assertEqual(sp["contract"], "BlindCoreRootAnchor.sol")
        self.assertTrue(sp["eip2_low_s_verified"])
        self.assertEqual(sp["calldata_summary"]["abi_arg_count"], 9)
        self.assertEqual(sp["calldata_summary"]["abi_args_byte_len"], 288)

        exec_sum = res["summary"]["execution"]
        self.assertTrue(exec_sum["bazaar_discoverable"])
        cc = exec_sum["prepaid_credit_conservation"]
        self.assertEqual(cc["deposited_micro_usdc"], 1_000_000)
        self.assertEqual(cc["spent_micro_usdc"], 21_500)
        self.assertEqual(cc["remaining_micro_usdc"], 978_500)
        self.assertTrue(exec_sum["mcp_contains_retrieval"]["local_decrypt_verified"])
        self.assertEqual(exec_sum["mcp_contains_retrieval"]["matched_count"], 1)
        self.assertTrue(exec_sum["sklearn_mnb_scoring"]["phishing_candidate_blocked"])
        self.assertTrue(exec_sum["sklearn_mnb_scoring"]["benign_candidate_allowed"])

        ko = exec_sum["security_knockouts"]
        self.assertTrue(ko["x402_replay_rejected_402"])
        self.assertTrue(ko["tampered_session_rejected_402"])
        self.assertTrue(ko["tampered_gate_mac_rejected_403"])
        self.assertTrue(ko["tampered_nsau0001_rejected"])
        self.assertTrue(ko["counterfactual_receipt_distinct"])

        audit = res["wire_sample_redacted"]["wire_audit"]
        self.assertTrue(audit["zero_plaintext_verified"])
        self.assertEqual(audit["leaks_found"], 0)
        self.assertGreater(audit["blobs_inspected"], 0)

    def test_app02_local_contract_and_dual_anchors(self) -> None:
        res = app02.run_demo(mode="local")
        self._assert_contract(res, "app02_sealed_bid_darkpool")
        self.assertEqual(res["rail"], "base-x402+stacks-sbtc")

        sp = res["settle_proof"]
        self.assertTrue(sp["dual_rail_verified"])

        base_anchor = sp["base_anchor"]
        self.assertEqual(base_anchor["contract"], "BlindCoreRootAnchor.sol")
        self.assertEqual(base_anchor["scheme"], "EIP-712-v2")
        self.assertTrue(base_anchor["eip2_low_s_verified"])
        self.assertEqual(base_anchor["calldata_summary"]["abi_arg_count"], 9)

        stacks_anchor = sp["stacks_anchor"]
        self.assertEqual(stacks_anchor["contract"], "blindcore-root-anchor.clar")
        self.assertEqual(stacks_anchor["function_name"], "settle-receipt")
        self.assertEqual(stacks_anchor["signature_bytes_len"], 65)
        self.assertIn("settle-receipt", stacks_anchor["clarity_snippet"])
        self.assertIn("blindcore-root-anchor", stacks_anchor["clarity_snippet"])

        exec_sum = res["summary"]["execution"]
        self.assertEqual(exec_sum["custody_model"], "NON_CUSTODIAL_ZERO_ESCROW")
        self.assertEqual(exec_sum["market_makers_submitted"], 4)
        self.assertTrue(exec_sum["mev_frontrun_protected"])
        self.assertTrue(exec_sum["stage1_base_x402_weighted_sum"]["unblinded_weighted_bid_matches_oracle"])
        self.assertTrue(exec_sum["stage1_base_x402_weighted_sum"]["unblinded_weighted_ask_matches_oracle"])
        self.assertTrue(exec_sum["stage2_stacks_sbtc_range_gate_clear"]["unblinded_clearing_verified_locally"])

        ko = exec_sum["security_knockouts"]
        self.assertTrue(ko["base_x402_replay_rejected_402"])
        self.assertTrue(ko["stacks_sbtc_replay_rejected_402"])
        self.assertTrue(ko["unauthorized_recipient_rejected_402"])
        self.assertTrue(ko["tampered_gate_mac_rejected_403"])
        self.assertTrue(ko["tampered_nsau0001_rejected"])
        self.assertTrue(ko["counterfactual_receipt_and_digests_distinct"])

        audit = res["wire_sample_redacted"]["wire_audit"]
        self.assertTrue(audit["zero_plaintext_verified"])
        self.assertEqual(audit["leaks_found"], 0)
        self.assertGreater(audit["blobs_inspected"], 0)

    def test_counterfactual_receipt_knockouts_assert_not_equal(self) -> None:
        r1_a = app01.run_demo(mode="local")
        r1_b = app01.run_demo(mode="local")
        self.assertNotEqual(r1_a["nsau0001_receipt_hex"], r1_b["nsau0001_receipt_hex"])
        self.assertNotEqual(r1_a["settle_proof"]["digest"], r1_b["settle_proof"]["digest"])

        r2_a = app02.run_demo(mode="local")
        r2_b = app02.run_demo(mode="local")
        self.assertNotEqual(r2_a["nsau0001_receipt_hex"], r2_b["nsau0001_receipt_hex"])
        self.assertNotEqual(
            r2_a["settle_proof"]["base_anchor"]["digest"],
            r2_b["settle_proof"]["base_anchor"]["digest"],
        )
        self.assertNotEqual(
            r2_a["settle_proof"]["stacks_anchor"]["digest"],
            r2_b["settle_proof"]["stacks_anchor"]["digest"],
        )
        self.assertNotEqual(r1_a["nsau0001_receipt_hex"], r2_a["nsau0001_receipt_hex"])

    def test_crypto_tamper_and_wire_canary_knockouts(self) -> None:
        # Vault authentication tag tamper knockout
        vault = app01.AgentPrivateVault(secrets.token_bytes(32))
        env = vault.encrypt_record({"note": "secret_alpha_signal"}, aad="tbl:rec1")
        dec = vault.decrypt_record(env, aad="tbl:rec1")
        self.assertEqual(dec["note"], "secret_alpha_signal")

        bad_env = dict(env)
        ct_hex = env["ciphertext_hex"]
        bad_env["ciphertext_hex"] = ("ff" if ct_hex[:2] != "ff" else "00") + ct_hex[2:]
        with self.assertRaises(ValueError):
            vault.decrypt_record(bad_env, aad="tbl:rec1")

        # Wire plaintext canary detector knockout (must detect injected leak)
        clean_audit = app01.audit_zero_plaintext([b'{"tok":"bt_0123456789abcdef"}'], ["secret_alpha"])
        leaky_audit = app01.audit_zero_plaintext([b'{"note":"secret_alpha_leak"}'], ["secret_alpha"])
        self.assertTrue(clean_audit["zero_plaintext_verified"])
        self.assertFalse(leaky_audit["zero_plaintext_verified"])
        self.assertNotEqual(clean_audit["leaks_found"], leaky_audit["leaks_found"])

        # DarkPoolOrderCipher blinding roundtrip + distinct ciphertexts under distinct keys
        c1 = app02.DarkPoolOrderCipher(secrets.token_bytes(32))
        c2 = app02.DarkPoolOrderCipher(secrets.token_bytes(32))
        self.assertNotEqual(c1.blind_price_hex(67300), c2.blind_price_hex(67300))
        self.assertEqual(c1.unblind_price(c1.blind_price_hex(67300)), 67300)
        self.assertEqual(c1.unblind_size(c1.blind_size_hex(1100)), 1100)

    def test_cli_local_mode_both_apps(self) -> None:
        for script_rel, app_id in (
            ("apps/app01_agent_private_brain.py", "app01_agent_private_brain"),
            ("apps/app02_sealed_bid_darkpool.py", "app02_sealed_bid_darkpool"),
        ):
            proc = subprocess.run(
                [sys.executable, os.path.join(REPO_ROOT, script_rel), "--mode", "local"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            parsed = json.loads(proc.stdout)
            self._assert_contract(parsed, app_id)

    def test_owned_files_strict_7bit_ascii(self) -> None:
        owned = (
            "apps/app01_agent_private_brain.py",
            "apps/app02_sealed_bid_darkpool.py",
            "apps/test_apps_1_2.py",
        )
        for rel in owned:
            path = os.path.join(REPO_ROOT, rel)
            raw = open(path, "rb").read()
            non_ascii = [b for b in raw if b >= 128]
            self.assertEqual(non_ascii, [], f"non-ASCII bytes found in {rel}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
