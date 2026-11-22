"""Unit tests for tools/ui_self_test.py contract logic and OPSEC hygiene."""

from __future__ import annotations

import importlib.util
import os
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL_PATH = os.path.join(REPO_ROOT, "tools", "ui_self_test.py")

_spec = importlib.util.spec_from_file_location("ui_self_test", TOOL_PATH)
assert _spec is not None and _spec.loader is not None
ui_self_test = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ui_self_test)


def _clean_surface_report() -> dict:
    return {
        "surface": "/mail/",
        "http_status": 200,
        "all_pageerrors": [],
        "all_console_errors": [],
        "all_failed_requests": [],
        "duplicate_js_functions": [],
        "dead_buttons": [],
        "error_buttons": [],
        "layout_issues_desktop": [],
        "layout_issues_mobile": [],
        "visible_jargon": [],
        "js_dialog_jargon": [],
        "account_counterfactual": {"ran": True, "passed": True, "detail": "OK", "errors": []},
    }


class TestUiSelfTestHarness(unittest.TestCase):
    def test_parse_surfaces_aliases_and_paths(self) -> None:
        self.assertEqual(
            ui_self_test.parse_surfaces(["social,sign,mail,finance"]),
            ["/social/", "/sign/", "/mail/", "/finance/"],
        )
        self.assertEqual(ui_self_test.parse_surfaces(["/"]), ["/"])
        self.assertEqual(ui_self_test.parse_surfaces(["mail", "finance"]), ["/mail/", "/finance/"])

    def test_find_duplicate_js_functions_detects_shadowing(self) -> None:
        html = """
        <script>
          function bytesToB64(a) { return a; }
          function okFn() {}
          function bytesToB64(b) { return b; }
        </script>
        """
        dupes = ui_self_test.find_duplicate_js_functions(html)
        self.assertEqual(len(dupes), 1)
        self.assertEqual(dupes[0]["function"], "bytesToB64")

    def test_evaluate_failures_counterfactual_gates(self) -> None:
        clean = _clean_surface_report()
        self.assertEqual(ui_self_test.evaluate_failures(clean), [])

        cases = [
            ("all_pageerrors", ["DataError: AES key data must be 128 or 256 bits"]),
            ("all_console_errors", ["Failed to load resource: 404"]),
            ("all_failed_requests", [{"status": 400, "url": "/api/v1/auth/magic-link"}]),
            ("dead_buttons", [{"id": "btn-dead", "text": "Dead"}]),
            ("error_buttons", [{"id": "btn-err", "text": "Err"}]),
            ("layout_issues_mobile", [{"type": "horizontal_overflow", "detail": "459 > 390"}]),
            ("duplicate_js_functions", [{"function": "bytesToB64", "script_lines": [10, 90]}]),
        ]
        for field, bad_val in cases:
            broken = _clean_surface_report()
            broken[field] = bad_val
            fails = ui_self_test.evaluate_failures(broken)
            self.assertTrue(len(fails) >= 1, f"Expected failure for {field}")

        cf_broken = _clean_surface_report()
        cf_broken["account_counterfactual"] = {
            "ran": True,
            "passed": False,
            "detail": "localStorage identity did not change",
            "errors": ["counterfactual_failed"],
        }
        self.assertTrue(len(ui_self_test.evaluate_failures(cf_broken)) >= 1)

    def test_tool_opsec_ascii_and_zero_unsafe_dom_sink(self) -> None:
        with open(TOOL_PATH, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertTrue(src.isascii())
        self.assertNotIn("inner" + "HTML", src)
        self.assertNotIn("sqlite" + "3", src.lower())


if __name__ == "__main__":
    unittest.main()
