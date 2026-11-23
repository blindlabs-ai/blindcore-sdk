import http.server
import json
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "python")))

from blindcore_sdk import (  # noqa: E402
    BlindCoreClient,
    BlindFeedClient,
    BlindMailClient,
    BlindSignClient,
    PaymentRequiredError,
    from_base64url,
    pad2,
    sha256_hex,
    to_base64url,
    unpad2,
)


class _MockBlindCoreHandler(http.server.BaseHTTPRequestHandler):
    recorded = []

    def log_message(self, format, *args):
        return

    def _read_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return None
        raw = self.rfile.read(length).decode("utf-8")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    def _reply(self, status, payload, extra_headers=None):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _handle(self, method):
        body = self._read_body()
        self.__class__.recorded.append(
            {
                "method": method,
                "path": self.path,
                "auth": self.headers.get("Authorization"),
                "x_payment": self.headers.get("X-PAYMENT"),
                "payment_signature": self.headers.get("PAYMENT-SIGNATURE"),
                "stacks_payment_tx": self.headers.get("X-Stacks-Payment-Tx"),
                "body": body,
            }
        )
        if self.path == "/v1/ml/sklearn-mnb" and not self.headers.get("X-PAYMENT"):
            self._reply(
                402,
                {"x402Version": 2, "sbtcAddress": "SP2MOCK"},
                {
                    "WWW-Authenticate": 'L402 macaroon="m1", invoice="lnbc1"',
                    "X-Payment-Required": "x402-v2",
                },
            )
            return
        if self.path == "/api/v1/blind/jsonb/query" and not (
            self.headers.get("PAYMENT-SIGNATURE") or self.headers.get("X-Stacks-Payment-Tx")
        ):
            self._reply(
                402,
                {
                    "x402Version": 2,
                    "error": "Payment required",
                    "extensions": {
                        "lightning_l402": {
                            "enabled": False,
                            "invoice": "",
                            "macaroon": "",
                            "paymentHash": "",
                            "sats": 2,
                        },
                        "stacks_sbtc": {
                            "network": "stacks:mainnet",
                            "recipient": "SP3NM1CKTY7NA47G37BKMN3Z739PEB0GGVJCDA15M",
                            "amountSats": 2,
                        },
                    },
                },
                {
                    "PAYMENT-REQUIRED": "eyJ4NDAyVmVyc2lvbiI6Mn0=",
                    "X-Stacks-Payment-Required": "eyJuZXR3b3JrIjoic3RhY2tzOm1haW5uZXQifQ==",
                },
            )
            return
        if self.path.startswith("/api/v1/query") and not self.headers.get("PAYMENT-SIGNATURE"):
            self._reply(
                402,
                {
                    "x402Version": 2,
                    "extensions": {
                        "lightning_l402": {
                            "enabled": True,
                            "invoice": "lnbc2n1live",
                            "macaroon": "mac_live",
                            "sats": 2,
                        },
                    },
                },
                {
                    "PAYMENT-REQUIRED": "eyJ4NDAyVmVyc2lvbiI6Mn0=",
                },
            )
            return
        if self.path == "/v1/sign/envelopes":
            self._reply(201, {"envelope_id": "env_py_1"})
            return
        if self.path == "/v1/vault/shares":
            self._reply(201, {"share_id": "sh_py_1"})
            return
        self._reply(200, {"ok": True, "path": self.path})

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_DELETE(self):
        self._handle("DELETE")


class TestBlindCorePythonSdk(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MockBlindCoreHandler)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _MockBlindCoreHandler.recorded.clear()

    def test_pad2_and_encoding_helpers(self):
        raw = b"blindcore-python-test"
        padded = pad2(raw, min_block=256)
        self.assertEqual(len(padded), 256)
        self.assertEqual(unpad2(padded), raw)
        self.assertEqual(from_base64url(to_base64url(raw)), raw)
        self.assertEqual(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_http_402_negotiation_and_error(self):
        core_no_hook = BlindCoreClient(base_url=self.base_url)
        with self.assertRaises(PaymentRequiredError) as ctx:
            core_no_hook.sklearn_mnb({"x": [[1, 0]]})
        self.assertEqual(ctx.exception.status, 402)
        self.assertEqual(ctx.exception.challenge["protocols"], ["x402", "L402", "sBTC"])

        seen = {}

        def pay_hook(challenge, context):
            seen["protocols"] = challenge["protocols"]
            seen["method"] = context["method"]
            return {"X-PAYMENT": "x402-proof-ok"}

        core = BlindCoreClient(base_url=self.base_url, token="tok_py", on_payment_required=pay_hook)
        res = core.sklearn_mnb({"x": [[1, 0]]})
        self.assertTrue(res["ok"])
        self.assertEqual(seen["protocols"], ["x402", "L402", "sBTC"])
        self.assertEqual(seen["method"], "POST")

    def test_blind_jsonb_and_query_json_402_headers_and_defaults(self):
        default_core = BlindCoreClient()
        self.assertEqual(default_core.base_url, "https://api.blindlabs.ai")

        core_no_hook = BlindCoreClient(base_url=self.base_url)
        with self.assertRaises(PaymentRequiredError) as ctx:
            core_no_hook.query_blind_jsonb(table="t", op="CONTAINS")
        ch = ctx.exception.challenge
        self.assertEqual(ch["protocols"], ["x402", "sBTC"])
        self.assertNotIn("L402", ch["protocols"])
        self.assertEqual(ch["payment_required"], "eyJ4NDAyVmVyc2lvbiI6Mn0=")
        self.assertEqual(ch["x_payment_required"], "eyJ4NDAyVmVyc2lvbiI6Mn0=")
        self.assertEqual(ch["stacks_payment_required"], "eyJuZXR3b3JrIjoic3RhY2tzOm1haW5uZXQifQ==")

        # Retry hook on query_blind_jsonb with X-Stacks-Payment-Tx
        seen_jb = {}

        def pay_stacks(challenge, context):
            seen_jb["protocols"] = challenge["protocols"]
            seen_jb["url"] = context["url"]
            return {"X-Stacks-Payment-Tx": "0x" + "ab" * 32}

        core_stacks = BlindCoreClient(base_url=self.base_url, on_payment_required=pay_stacks)
        res = core_stacks.query_blind_jsonb(table="t", op="CONTAINS")
        self.assertTrue(res["ok"])
        self.assertEqual(seen_jb["protocols"], ["x402", "sBTC"])
        self.assertTrue(seen_jb["url"].endswith("/api/v1/blind/jsonb/query"))

        # query_json also routes through 402 handler (and enabled lightning_l402 triggers L402)
        with self.assertRaises(PaymentRequiredError) as ctx_sql:
            core_no_hook.query_json("SELECT 1")
        self.assertEqual(ctx_sql.exception.challenge["protocols"], ["x402", "L402"])

        core_sql_hook = BlindCoreClient(
            base_url=self.base_url,
            on_payment_required=lambda ch, ctx: {"PAYMENT-SIGNATURE": "sig-ok"},
        )
        self.assertTrue(core_sql_hook.query_json("SELECT 1")["ok"])

    def test_all_clients_end_to_end(self):
        core = BlindCoreClient(base_url=self.base_url, token="tok_py")
        sign = BlindSignClient(core)
        feed = BlindFeedClient(core)
        mail = BlindMailClient(core)

        self.assertTrue(core.query_jsonb("docs", {"a": 1})["ok"])
        self.assertTrue(core.ingest_jsonb("docs", [{"a": 1}])["ok"])

        env = sign.create_envelope(
            title="NDA",
            digest_sha256=sha256_hex("nda"),
            encrypted_blob={"alg": "AES-256-GCM", "pad": "PAD2", "iv": "aa", "ciphertext": "bb"},
            key_base64url="secretkey123",
        )
        self.assertEqual(env["envelope_id"], "env_py_1")
        self.assertEqual(env["invite_link"], "https://blindlabs.ai/sign/#env=env_py_1&k=secretkey123")
        self.assertTrue(
            sign.countersign_envelope(
                envelope_id="env_py_1",
                digest_sha256=sha256_hex("nda"),
                signature="sig1",
                signer_id="alice",
            )["ok"]
        )
        self.assertTrue(sign.shred_envelope("env_py_1")["ok"])
        self.assertTrue(sign.store_vault_item(label="k1", encrypted_blob={"iv": "a"})["ok"])
        share = sign.create_temp_share(item_id="i1", key_base64url="k123")
        self.assertEqual(share["share_id"], "sh_py_1")
        self.assertTrue(share["share_link"].startswith("https://blindlabs.ai/sign/#share=sh_py_1&k=k123"))

        self.assertTrue(
            feed.register_profile(
                handle="alice",
                display_name="Alice",
                signing_public_jwk={"kty": "EC"},
                ecdh_public_jwk={"kty": "EC"},
            )["ok"]
        )
        self.assertTrue(
            feed.create_signed_post(
                author_id="alice",
                body="hello",
                signature="sig",
                created_at="2026-01-01T00:00:00Z",
            )["ok"]
        )
        self.assertTrue(feed.send_encrypted_dm(sender_id="alice", recipient_id="bob", encrypted_dm={"iv": "x"})["ok"])
        self.assertTrue(feed.create_group(name="Core", creator_id="alice")["ok"])
        self.assertTrue(feed.add_group_member(group_id="g1", member_id="bob", wrapped_group_key={"iv": "x"})["ok"])
        self.assertTrue(
            feed.remove_group_member_and_rotate(
                group_id="g1", remove_member_id="bob", rotated_wrapped_keys={"alice": {"iv": "y"}}
            )["ok"]
        )
        self.assertTrue(
            feed.grant_temp_group_access(group_id="g1", guest_id="carol", wrapped_group_key={"iv": "z"})["ok"]
        )
        self.assertTrue(feed.submit_dating_swipe(actor_id="alice", target_id="bob", direction="right")["ok"])

        self.assertTrue(mail.send_mail(sender="a@example.com", to="b@example.com", subject="Hi", body="Hello")["ok"])
        self.assertTrue(mail.request_magic_link(email="a@example.com", redirect_url="https://app.example.com")["ok"])
        self.assertTrue(mail.verify_magic_link(token="magic1")["ok"])
        self.assertTrue(mail.get_dns_records("example.com")["ok"])


if __name__ == "__main__":
    unittest.main()
