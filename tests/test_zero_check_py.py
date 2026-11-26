"""Counterfactual and dogfood tests for blindcore.zero_check_py."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

SDK_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SDK_ROOT / "python"))

from blindcore.zero_check_py import Finding, check_ast_module, check_ast_path  # noqa: E402
import zero_check_py as top_zero_check_py  # noqa: E402


class TestZeroCheckPy(unittest.TestCase):
    def _cf(self, rule_id: str, vuln_src: str, fixed_src: str, domain: str = "all") -> None:
        vuln = check_ast_module(vuln_src, domain=domain, filename="vuln.py")
        fixed = check_ast_module(fixed_src, domain=domain, filename="fixed.py")
        self.assertGreaterEqual(len(vuln), 1, f"expected {rule_id} on vulnerable snippet")
        self.assertIn(rule_id, [f.rule_id for f in vuln])
        self.assertEqual(len(fixed), 0, f"expected 0 findings on fixed snippet, got {fixed}")
        self.assertNotEqual(len(vuln), len(fixed))

    def test_imports_and_validation(self) -> None:
        self.assertIs(top_zero_check_py.Finding, Finding)
        self.assertIs(top_zero_check_py.check_ast_module, check_ast_module)
        self.assertIs(top_zero_check_py.check_ast_path, check_ast_path)
        with self.assertRaises(ValueError):
            check_ast_module("x = 1", domain="invalid")

    def test_py_width_01(self) -> None:
        self._cf(
            "PY-WIDTH-01",
            "import struct\ndef enc(port: int, count: int) -> bytes:\n"
            "    return struct.pack('!H', port) + count.to_bytes(4, 'big')\n",
            "import struct\ndef enc(port: int, count: int) -> bytes:\n"
            "    if not (0 <= port <= 65535):\n        raise ValueError('p')\n"
            "    if count < 0 or count > 0xFFFFFFFF:\n        raise ValueError('c')\n"
            "    return struct.pack('!H', port) + count.to_bytes(4, 'big')\n",
            domain="bitcoin",
        )
        self._cf(
            "PY-WIDTH-01",
            "def f(a: int, b: int) -> bytes:\n    if 0 <= a <= 200 and 0 <= b <= 200:\n"
            "        x = (a + b) << 1\n        return x.to_bytes(1, 'big')\n    return b''\n",
            "def f(a: int, b: int) -> bytes:\n    if 0 <= a <= 60 and 0 <= b <= 60:\n"
            "        x: int = (a + b) | 1\n        return x.to_bytes(1, 'big')\n    return b''\n",
            domain="bitcoin",
        )

    def test_py_msat_02(self) -> None:
        vuln = "def calc_fee(amount_msat: int) -> int:\n    return amount_msat * 1000\n"
        fixed = (
            "def calc_fee(amount_msat: int) -> int:\n"
            "    if not (0 <= amount_msat <= 10_000_000_000_000):\n        raise ValueError('m')\n"
            "    return amount_msat * 1000\n"
        )
        self._cf("PY-MSAT-02", vuln, fixed, domain="bitcoin")
        self.assertEqual(check_ast_module(vuln, domain="defi"), [])

    def test_py_plwe_03(self) -> None:
        vuln = "def submit(slot: int) -> bytes:\n    # PLWE0001\n    return encode_plwe_slot(slot)\n"
        fixed = (
            "Q0 = (1 << 127) - 1\ndef submit(slot: int) -> bytes:\n    # PLWE0001\n"
            "    if slot < 0 or slot >= Q0:\n        raise ValueError('s')\n"
            "    return encode_plwe_slot(slot)\n"
        )
        self._cf("PY-PLWE-03", vuln, fixed, domain="defi")
        self.assertEqual(check_ast_module(vuln, domain="bitcoin"), [])

    def test_py_float_04(self) -> None:
        self._cf(
            "PY-FLOAT-04",
            "def bps_fee(amount_wei: int) -> float:\n    return float(amount_wei) * 0.0025\n",
            "def bps_fee(amount_wei: int) -> int:\n    return (amount_wei * 25) // 10_000\n",
            domain="defi",
        )

    def test_py_uri_05(self) -> None:
        self._cf(
            "PY-URI-05",
            "def parse_ipv4(host: str) -> list[int]:\n    return [int(o) for o in host.split('.')]\n",
            "import re\ndef parse_ipv4(host: str) -> list[int]:\n    out = []\n"
            "    for o in host.split('.'):\n        if not re.fullmatch(r'0|[1-9][0-9]*', o):\n"
            "            raise ValueError('o')\n        out.append(int(o))\n    return out\n",
        )
        self._cf(
            "PY-URI-05",
            "from urllib.parse import urljoin\ndef join_route(base_url: str, segment: str) -> str:\n"
            "    return urljoin(base_url, segment)\n",
            "from urllib.parse import urlsplit\ndef join_route(base_url: str, segment: str) -> str:\n"
            "    p = urlsplit(base_url)\n    c = segment.split('?', 1)[0].split('#', 1)[0].lstrip('/')\n"
            "    return f'{p.scheme}://{p.netloc}/{c}'\n",
        )

    def test_py_crypto_06(self) -> None:
        self._cf(
            "PY-CRYPTO-06",
            "import hashlib\ndef build_receipt(key: bytes, body: bytes) -> bytes:\n"
            "    receipt = hashlib.sha256(key + body).digest()\n    return receipt\n",
            "import hashlib, hmac\ndef build_receipt(key: bytes, body: bytes) -> bytes:\n"
            "    receipt = hmac.new(key, body, hashlib.sha256).digest()\n    return receipt\n",
        )

    def test_py_timing_07(self) -> None:
        self._cf(
            "PY-TIMING-07",
            "def verify(api_token: str, expected_token: str) -> bool:\n    return api_token == expected_token\n",
            "import hmac\ndef verify(api_token: str, expected_token: str) -> bool:\n"
            "    return hmac.compare_digest(api_token, expected_token)\n",
        )

    def test_py_csrf_08(self) -> None:
        self._cf(
            "PY-CSRF-08",
            "from http.server import BaseHTTPRequestHandler\nclass H(BaseHTTPRequestHandler):\n"
            "    def do_POST(self) -> None:\n        self.send_response(200)\n",
            "from http.server import BaseHTTPRequestHandler\nclass H(BaseHTTPRequestHandler):\n"
            "    def do_POST(self) -> None:\n"
            "        if self.headers.get('Host') != '127.0.0.1:8332' or self.headers.get('Origin'):\n"
            "            self.send_response(403)\n            return\n        self.send_response(200)\n",
        )

    def test_py_merkle_09(self) -> None:
        self._cf(
            "PY-MERKLE-09",
            "import hashlib\ndef merkle_root(level: list[bytes]) -> bytes:\n    while len(level) > 1:\n"
            "        if len(level) & 1:\n            level.append(level[-1])\n"
            "        level = [hashlib.sha256(level[i] + level[i+1]).digest() for i in range(0, len(level), 2)]\n"
            "    return level[0]\n",
            "import hashlib\ndef merkle_root(level: list[bytes]) -> bytes:\n    while len(level) > 1:\n"
            "        nxt = [hashlib.sha256(b'\\x01' + level[i] + level[i+1]).digest() for i in range(0, len(level) - 1, 2)]\n"
            "        if len(level) & 1:\n            nxt.append(level[-1])\n        level = nxt\n"
            "    return level[0]\n",
        )
        self._cf(
            "PY-MERKLE-09",
            "def modinv64(d: int) -> int:\n    x = 3 * d\n"
            "    for _ in range(4):\n        x = (x * (2 - d * x)) & 0xFFFFFFFFFFFFFFFF\n    return x\n",
            "def modinv64(d: int) -> int:\n    x = (3 * d) ^ 2\n"
            "    for _ in range(4):\n        x = (x * (2 - d * x)) & 0xFFFFFFFFFFFFFFFF\n    return x\n",
        )

    def test_dogfood_sdk_and_cli_json(self) -> None:
        self.assertEqual(check_ast_path(SDK_ROOT / "python" / "blindcore", domain="all"), [])
        self.assertEqual(check_ast_path(SDK_ROOT / "sklearn_blind", domain="all"), [])
        py_findings = check_ast_path(SDK_ROOT / "python", domain="all")
        self.assertTrue(all(isinstance(f, Finding) for f in py_findings))
        self.assertEqual([f for f in py_findings if f.rule_id != "PY-WIDTH-01"], [])

        env = {**os.environ, "PYTHONPATH": str(SDK_ROOT / "python"), "PYTHONDONTWRITEBYTECODE": "1"}
        proc = subprocess.run(
            [sys.executable, "-m", "blindcore.zero_check_py", "--domain", "all", "--json", str(SDK_ROOT / "sklearn_blind")],
            capture_output=True, text=True, env=env, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stderr, "")
        self.assertEqual(json.loads(proc.stdout), [])


if __name__ == "__main__":
    unittest.main()
