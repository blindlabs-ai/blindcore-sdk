#!/usr/bin/env python3
"""Live unit, parity, speedup & hostile MITM audit suite for sklearn_blind."""

from __future__ import annotations

import collections
import http.server
import math
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

import numpy as np
from sklearn.cluster import KMeans
from sklearn.covariance import EmpiricalCovariance
from sklearn.discriminant_analysis import (
    LinearDiscriminantAnalysis,
    QuadraticDiscriminantAnalysis,
)
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import (
    Lasso,
    LinearRegression,
    LogisticRegression,
    Ridge,
    RidgeClassifier,
    SGDClassifier,
)
from sklearn.naive_bayes import BernoulliNB, ComplementNB, GaussianNB, MultinomialNB
from sklearn.neighbors import NearestCentroid
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import python.blindcore_sdk as sdk  # noqa: E402
from python.blindcore_sdk import (  # noqa: E402
    LWE_PLAIN_MOD,
    PLWE_EXPANDED_BYTES,
    BlindClientPlweKey,
    BlindCoreClient,
    crc32c,
    verify_blind_receipt,
)
from sklearn_blind import (  # noqa: E402
    BlindBernoulliNB,
    BlindComplementNB,
    BlindCountVectorizer,
    BlindDecisionTreeClassifier,
    BlindEllipticEnvelope,
    BlindGaussianNB,
    BlindGradientBoostingClassifier,
    BlindHashingVectorizer,
    BlindKMeans,
    BlindLasso,
    BlindLinearDiscriminantAnalysis,
    BlindLinearRegression,
    BlindLinearSVC,
    BlindLogisticRegression,
    BlindMinMaxScaler,
    BlindMultinomialNB,
    BlindNearestCentroid,
    BlindOlapSession,
    BlindQuadraticDiscriminantAnalysis,
    BlindRandomForestClassifier,
    BlindRBFSampler,
    BlindRidge,
    BlindRidgeClassifier,
    BlindSGDClassifier,
    BlindSklearnConnector,
    BlindStandardScaler,
    BlindZScoreDetector,
    RadixSlotPacker,
    check_weighted_sum_noise,
)


def _shannon_entropy(data: bytes) -> float:
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values()) if n else 0.0


class _WireSniffProxy:
    """Hostile MITM localhost HTTP proxy recording raw request & response bytes."""

    def __init__(self, upstream_url: str) -> None:
        self.upstream_url = upstream_url.rstrip("/")
        self.requests: list[bytes] = []
        self.responses: list[bytes] = []
        self._lock = threading.Lock()
        parent = self

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                return

            def _fwd(self, method: str) -> None:
                n = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(n) if n > 0 else b""
                with parent._lock:
                    parent.requests.append(body)
                hdrs = {k: self.headers[k] for k in ("Authorization", "Content-Type", "Accept") if k in self.headers}
                req = urllib.request.Request(
                    f"{parent.upstream_url}{self.path}",
                    data=body if method != "GET" else None,
                    headers=hdrs,
                    method=method,
                )
                try:
                    with urllib.request.urlopen(req, timeout=20.0) as r:
                        raw, status, ctype = r.read(), r.status, r.headers.get("Content-Type", "application/json")
                except urllib.error.HTTPError as e:
                    raw, status, ctype = e.read(), int(e.code), e.headers.get("Content-Type", "application/json")
                with parent._lock:
                    parent.responses.append(raw)
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                self._fwd("GET")

            def do_POST(self) -> None:
                self._fwd("POST")

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class TestCryptoAndPackingUnit(unittest.TestCase):
    def test_crc32c_and_decrypt_numpy_vs_pure_parity(self) -> None:
        rng = np.random.default_rng(7)
        for length in (0, 1, 15, 16, 255, 256, 257, 1024, 16460, 32768, 40000):
            buf = rng.integers(0, 256, size=length, dtype=np.uint8).tobytes()
            self.assertEqual(crc32c(buf), sdk._crc32c_pure(buf) ^ 0xFFFFFFFF, f"len={length}")

        pk = BlindClientPlweKey.generate()
        vals = [-1234567890123, -1, 0, 1, 42, 999999999999]
        cts = pk.encrypt_batch(vals, workers=2)
        self.assertEqual(len(set(cts)), len(cts))
        exp_ct = BlindClientPlweKey.homomorphic_weighted_sum(cts, [1, -2, 3, -4, 5, -1])
        fast_val = pk.decrypt_int(exp_ct)
        saved_np = sdk._np
        try:
            sdk._np = None
            pure_val = pk.decrypt_int(exp_ct)
        finally:
            sdk._np = saved_np
        expected = sum(v * w for v, w in zip(vals, [1, -2, 3, -4, 5, -1]))
        self.assertEqual(fast_val, expected)
        self.assertEqual(pure_val, expected)

    def test_radix_packer_unsigned_and_signed_carry_boundaries(self) -> None:
        up = RadixSlotPacker(n_slots=4, base_bits=14, signed=False)
        for vec in ([0, 0, 0, 0], [16383, 0, 16383, 1], [16383, 16383, 16383, 16383]):
            self.assertEqual(up.unpack(up.pack(vec)), vec)
        with self.assertRaises(ValueError):
            up.pack([-1, 0, 0, 0])
        with self.assertRaises(ValueError):
            up.pack([16384, 0, 0, 0])
        with self.assertRaises(ValueError):
            up.unpack(up.capacity)

        sp = RadixSlotPacker(n_slots=3, base_bits=19, signed=True)
        lim = sp.max_abs  # 2**18 - 1 = 262143
        for vec in (
            [-1, 1, -1],
            [1, -1, 1],
            [-lim, lim, -lim],
            [lim, -lim, lim],
            [0, -lim, 1],
            [-1, 0, lim],
        ):
            self.assertEqual(sp.unpack(sp.pack(vec)), vec)
        # Verify signed sum with borrow across lanes preserves exact values
        v_a = sp.pack([100, -500, lim - 10])
        v_b = sp.pack([-200, 600, -lim + 5])
        self.assertEqual(sp.unpack(v_a + v_b), [-100, 100, -5])
        with self.assertRaises(ValueError):
            sp.pack([lim + 1, 0, 0])
        with self.assertRaises(ValueError):
            sp.pack([-(lim + 1), 0, 0])
        with self.assertRaises(ValueError):
            sp.unpack(sp.half)  # slot 0 == -half violates |s_k| <= half - 1
        with self.assertRaises(ValueError):
            RadixSlotPacker(n_slots=4, base_bits=15, signed=False)  # 2**60 > LWE_PLAIN_MOD // 2
        with self.assertRaises(ValueError):
            check_weighted_sum_noise(10, [(1 << 63) - 1])
        with self.assertRaises(ValueError):
            check_weighted_sum_noise(1000, [1 << 60])


class TestSklearnBlindLiveSuite(unittest.TestCase):
    _proc: subprocess.Popen[bytes] | None = None
    _td: tempfile.TemporaryDirectory[str] | None = None
    api_url: str = ""
    api_token: str = ""

    @classmethod
    def setUpClass(cls) -> None:
        bin_path = os.environ.get("BLINDCORE_API_BIN", "/tmp/blindcore-api")
        if not os.path.isfile(bin_path):
            raise unittest.SkipTest(f"missing {bin_path}")
        with socket.socket() as s1:
            s1.bind(("127.0.0.1", 0))
            p1 = s1.getsockname()[1]
        with socket.socket() as s2:
            s2.bind(("127.0.0.1", 0))
            p2 = s2.getsockname()[1]
        cls.api_token = secrets.token_hex(16)
        cls._td = tempfile.TemporaryDirectory(prefix="bc_sk_suite_")
        env = os.environ.copy()
        env[bytes.fromhex("4155544f44425f4150495f544f4b454e").decode("ascii")] = cls.api_token
        cls._proc = subprocess.Popen(
            [bin_path, "--api-bind", f"127.0.0.1:{p1}", "--pg-bind", f"127.0.0.1:{p2}", "--data-dir", cls._td.name, "--disk-gb", "1"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        cls.api_url = f"http://127.0.0.1:{p1}"
        c = BlindCoreClient(cls.api_url, token=cls.api_token)
        for _ in range(60):
            try:
                c.get_json("/api/v1/catalog")
                c.close()
                return
            except Exception:
                time.sleep(0.05)
        raise RuntimeError("live /tmp/blindcore-api failed to become healthy")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._proc is not None:
            cls._proc.terminate()
            cls._proc.wait(timeout=3)
        if cls._td is not None:
            cls._td.cleanup()

    def _new_session(self, url: str | None = None) -> tuple[BlindCoreClient, BlindOlapSession]:
        cli = BlindCoreClient(url or self.api_url, token=self.api_token, timeout=20.0)
        return cli, BlindOlapSession(cli, BlindClientPlweKey.generate())

    def test_01_live_mnb_speedup_over_10x_and_exact_parity(self) -> None:
        rng = np.random.default_rng(11)
        n_tr, n_te, v = 400, 120, 12
        y_tr = rng.integers(0, 2, size=n_tr)
        y_te = rng.integers(0, 2, size=n_te)
        lam0 = np.array([2.5, 2.2, 2.0, 1.8, 1.5, 1.3, 0.3, 0.2, 0.2, 0.2, 0.1, 0.1])
        lam1 = np.array([0.2, 0.2, 0.3, 0.2, 0.2, 0.1, 2.2, 2.5, 2.1, 1.9, 1.6, 1.4])
        X_tr = np.vstack([rng.poisson(lam1 if yi else lam0) for yi in y_tr]).astype(np.int64)
        X_te = np.vstack([rng.poisson(lam1 if yi else lam0) for yi in y_te]).astype(np.int64)

        # Warm up forkserver pool once before timing
        pk_warm = BlindClientPlweKey.generate()
        pk_warm.encrypt_batch_hex([1] * 128)

        # Unpacked pure-single-thread baseline (26 train cols + 120 test rows, no keep-alive)
        base_cli = BlindCoreClient(self.api_url, token=self.api_token, keep_alive=False)
        base_pk = BlindClientPlweKey.generate()
        t_b0 = time.perf_counter()
        tr_tbl = f"mnb_base_tr_{secrets.token_hex(3)}"
        tr_cols = [f"c{c}_n" for c in range(2)] + [f"c{c}_f{j}" for c in range(2) for j in range(v)]
        base_cli.create_blind_table(tr_tbl, [{"name": cn, "kind": "blind_add"} for cn in tr_cols] + [{"name": "rid", "kind": "blind_token"}])
        tr_rows = []
        for i in range(n_tr):
            ci = int(y_tr[i])
            ct_map = {f"c{c}_n": base_pk.encrypt_int_hex(1 if c == ci else 0) for c in range(2)}
            for c in range(2):
                for j in range(v):
                    ct_map[f"c{c}_f{j}"] = base_pk.encrypt_int_hex(int(X_tr[i, j]) if c == ci else 0)
            ct_map["rid"] = secrets.token_hex(32)
            tr_rows.append({"ciphertexts_hex": ct_map})
        for i in range(0, len(tr_rows), 50):
            base_cli.ingest_blind(tr_tbl, tr_rows[i : i + 50])
        base_sums = [base_pk.decrypt_int(base_cli.query_blind(tr_tbl, "SUM", column=cn)["ct_result_hex"]) for cn in tr_cols]
        te_tbl = f"mnb_base_te_{secrets.token_hex(3)}"
        f_cols = [f"f{j}" for j in range(v)]
        base_cli.create_blind_table(te_tbl, [{"name": cn, "kind": "blind_add"} for cn in f_cols] + [{"name": "rid", "kind": "blind_token"}])
        rids = [secrets.token_hex(32) for _ in range(n_te)]
        te_rows = [
            {"ciphertexts_hex": {**{f"f{j}": base_pk.encrypt_int_hex(int(X_te[i, j])) for j in range(v)}, "rid": rids[i]}}
            for i in range(n_te)
        ]
        for i in range(0, len(te_rows), 50):
            base_cli.ingest_blind(te_tbl, te_rows[i : i + 50])
        w_dummy = [100] * v
        for i in range(n_te):
            q = base_cli.query_blind(te_tbl, "WEIGHTED_SUM", columns=f_cols, weights=w_dummy, where={"column": "rid", "eq_token_hex": rids[i]})
            _ = base_pk.decrypt_int(q["ct_result_hex"])
        base_ms = (time.perf_counter() - t_b0) * 1000.0
        base_cli.close()
        self.assertEqual(base_sums[0] + base_sums[1], n_tr)

        # Accelerated radix-packed BlindMultinomialNB
        cli, sess = self._new_session()
        t_f0 = time.perf_counter()
        bmnb = BlindMultinomialNB(sess, alpha=1.0).fit(X_tr, y_tr)
        p_blind = bmnb.predict_proba(X_te)
        y_blind = bmnb.predict(X_te)
        fast_ms = (time.perf_counter() - t_f0) * 1000.0
        cohort_ll = bmnb.predict_cohort(X_te)
        cli.close()

        ref = MultinomialNB(alpha=1.0).fit(X_tr, y_tr)
        p_ref = ref.predict_proba(X_te)
        y_ref = ref.predict(X_te)
        speedup = base_ms / fast_ms
        self.assertGreaterEqual(speedup, 10.0, f"MNB speedup {speedup:.2f}x < 10x (base={base_ms:.1f}ms, fast={fast_ms:.1f}ms)")
        self.assertLess(float(np.max(np.abs(p_blind - p_ref))), 2e-3)
        self.assertTrue(np.array_equal(y_blind, y_ref))
        ref_cohort = float(np.sum(ref.predict_log_proba(X_te)[:, 1] - ref.predict_log_proba(X_te)[:, 0]))
        self.assertAlmostEqual(float(cohort_ll[0]) / n_te, ref_cohort / n_te, delta=2e-3)

    def test_02_all_8_sklearn_families_live_parity(self) -> None:
        cli, sess = self._new_session()
        conn = BlindSklearnConnector(cli)
        rng = np.random.default_rng(42)

        # Mode 1 SQL -> NumPy + ML_*_SCORE pushdown
        X_m1 = rng.normal(0.0, 1.0, size=(40, 3))
        y_m1 = (X_m1[:, 0] * 1.5 - X_m1[:, 1] * 0.8 + 0.2 > 0).astype(np.float64)
        t_m1 = f"m1_tbl_{secrets.token_hex(3)}"
        conn.ingest_table(t_m1, X_m1, y_m1, ["f0", "f1", "f2"])
        Xf, yf = conn.fetch_numpy(f"SELECT f0, f1, f2, target FROM {t_m1}", target_col="target")
        self.assertLess(float(np.max(np.abs(Xf - X_m1))), 1e-9)
        self.assertLess(float(np.max(np.abs(yf - y_m1))), 1e-9)
        lin_sql = conn.pushdown_linear_score(t_m1, ["f0", "f1", "f2"], [1.5, -0.8, 0.0], 0.2)
        self.assertLess(float(np.max(np.abs(lin_sql - (0.2 + 1.5 * X_m1[:, 0] - 0.8 * X_m1[:, 1])))), 1e-9)
        z_sql = conn.pushdown_anomaly_z(t_m1, "f0", 0.0, 1.0)
        self.assertLess(float(np.max(np.abs(z_sql - np.abs(X_m1[:, 0])))), 1e-9)

        # Family 1: BernoulliNB & ComplementNB
        Xc = rng.integers(0, 4, size=(90, 6))
        yc = (Xc[:, 3] + Xc[:, 4] + Xc[:, 5] > Xc[:, 0] + Xc[:, 1] + Xc[:, 2]).astype(np.int64)
        for BlindCls, RefCls in ((BlindBernoulliNB, BernoulliNB), (BlindComplementNB, ComplementNB)):
            bm = BlindCls(sess).fit(Xc[:70], yc[:70])
            rm = RefCls().fit(Xc[:70], yc[:70])
            self.assertTrue(np.array_equal(bm.predict(Xc[70:]), rm.predict(Xc[70:])))

        # Family 2 & 3: Linear Classification & Regression
        Xl = rng.normal(0.0, 1.0, size=(80, 4))
        w_true = np.array([1.8, -1.2, 0.7, -0.4])
        y_reg = Xl @ w_true + 0.5 + rng.normal(0.0, 0.05, size=80)
        y_cls = (Xl @ w_true + 0.2 > 0.0).astype(np.int64)
        for BlindR, RefR in (
            (BlindLinearRegression(sess), LinearRegression()),
            (BlindRidge(sess, alpha=1.0), Ridge(alpha=1.0)),
            (BlindLasso(sess, alpha=0.05), Lasso(alpha=0.05)),
        ):
            BlindR.fit(Xl[:60], y_reg[:60])
            RefR.fit(Xl[:60], y_reg[:60])
            self.assertLess(float(np.max(np.abs(BlindR.predict(Xl[60:]) - RefR.predict(Xl[60:])))), 2e-2)

        b_rc = BlindRidgeClassifier(sess, alpha=1.0).fit(Xl[:60], y_cls[:60])
        r_rc = RidgeClassifier(alpha=1.0).fit(Xl[:60], y_cls[:60])
        self.assertTrue(np.array_equal(b_rc.predict(Xl[60:]), r_rc.predict(Xl[60:])))

        b_lr = BlindLogisticRegression(sess, C=1.0).fit(Xl[:60], y_cls[:60])
        r_lr = LogisticRegression(C=1.0).fit(Xl[:60], y_cls[:60])
        self.assertGreaterEqual(float(np.mean(b_lr.predict(Xl[60:]) == r_lr.predict(Xl[60:]))), 0.95)

        b_sgd = BlindSGDClassifier(sess, alpha=0.01, lr=0.8, max_iter=10).fit(Xl[:60], y_cls[:60])
        r_sgd = SGDClassifier(loss="log_loss", alpha=0.01, random_state=42).fit(Xl[:60], y_cls[:60])
        self.assertGreaterEqual(float(np.mean(b_sgd.predict(Xl[60:]) == y_cls[60:])), 0.85)
        self.assertEqual(b_sgd.predict(Xl[60:]).shape, r_sgd.predict(Xl[60:]).shape)

        b_svc = BlindLinearSVC(sess, C=1.0).fit(Xl[:60], y_cls[:60])
        r_svc = LinearSVC(C=1.0, random_state=42).fit(Xl[:60], y_cls[:60])
        self.assertGreaterEqual(float(np.mean(b_svc.predict(Xl[60:]) == r_svc.predict(Xl[60:]))), 0.95)

        # Family 4: GaussianNB, LDA, QDA
        Xg = np.vstack([rng.normal(-1.5, 0.7, size=(40, 3)), rng.normal(1.5, 0.9, size=(40, 3))])
        yg = np.array([0] * 40 + [1] * 40)
        perm = rng.permutation(80)
        Xg, yg = Xg[perm], yg[perm]
        for BlindG, RefG in (
            (BlindGaussianNB(sess), GaussianNB()),
            (BlindLinearDiscriminantAnalysis(sess), LinearDiscriminantAnalysis()),
            (BlindQuadraticDiscriminantAnalysis(sess), QuadraticDiscriminantAnalysis()),
        ):
            BlindG.fit(Xg[:60], yg[:60])
            RefG.fit(Xg[:60], yg[:60])
            self.assertLess(float(np.max(np.abs(BlindG.predict_proba(Xg[60:]) - RefG.predict_proba(Xg[60:])))), 2e-2)
            self.assertTrue(np.array_equal(BlindG.predict(Xg[60:]), RefG.predict(Xg[60:])))

        # Family 5: DecisionTree, RandomForest, GradientBoosting + Mode 1 SQL stump pushdown
        for BlindT, RefT in (
            (BlindDecisionTreeClassifier(sess, max_depth=3, random_state=42), DecisionTreeClassifier(max_depth=3, random_state=42)),
            (BlindRandomForestClassifier(sess, n_estimators=5, max_depth=3, random_state=42), RandomForestClassifier(n_estimators=5, max_depth=3, random_state=42)),
            (BlindGradientBoostingClassifier(sess, n_estimators=6, max_depth=2, random_state=42), GradientBoostingClassifier(n_estimators=6, max_depth=2, random_state=42)),
        ):
            BlindT.fit(Xg[:60], yg[:60])
            RefT.fit(Xg[:60], yg[:60])
            self.assertLess(float(np.max(np.abs(BlindT.predict_proba(Xg[60:]) - RefT.predict_proba(Xg[60:])))), 2e-3)
            self.assertTrue(np.array_equal(BlindT.predict(Xg[60:]), RefT.predict(Xg[60:])))
        stump = DecisionTreeClassifier(max_depth=1, random_state=42).fit(X_m1, y_m1.astype(int))
        stump_sql = BlindDecisionTreeClassifier.pushdown_sql_stump(conn, t_m1, ["f0", "f1", "f2"], stump)
        self.assertLess(float(np.max(np.abs(stump_sql - stump.predict_proba(X_m1)[:, 1]))), 1e-9)

        # Family 6: NearestCentroid & KMeans
        b_nc = BlindNearestCentroid(sess).fit(Xg[:60], yg[:60])
        r_nc = NearestCentroid().fit(Xg[:60], yg[:60])
        self.assertTrue(np.array_equal(b_nc.predict(Xg[60:]), r_nc.predict(Xg[60:])))

        init_c = np.array([[-1.2, -1.2, -1.2], [1.2, 1.2, 1.2]])
        b_km = BlindKMeans(sess, n_clusters=2, max_iter=8).fit(Xg[:60], init_centers=init_c)
        r_km = KMeans(n_clusters=2, init=init_c, n_init=1, max_iter=8).fit(Xg[:60])
        self.assertLess(float(np.max(np.abs(b_km.cluster_centers_ - r_km.cluster_centers_))), 1e-2)
        self.assertTrue(np.array_equal(b_km.predict(Xg[60:]), r_km.predict(Xg[60:])))

        # Family 7: Preprocessing & Text Vectorizers
        b_ss = BlindStandardScaler(sess).fit(Xg[:60])
        r_ss = StandardScaler().fit(Xg[:60])
        self.assertLess(float(np.max(np.abs(b_ss.transform(Xg[60:]) - r_ss.transform(Xg[60:])))), 2e-2)
        b_mm = BlindMinMaxScaler(sess).fit(Xg[:60])
        r_mm = MinMaxScaler().fit(Xg[:60])
        self.assertLess(float(np.max(np.abs(b_mm.transform_encrypted(Xg[60:]) - r_mm.transform(Xg[60:])))), 2e-2)
        b_mm_sql = BlindMinMaxScaler(sess).fit_sql(conn, t_m1, ["f0", "f1", "f2"])
        self.assertLess(float(np.max(np.abs(b_mm_sql.data_min_ - X_m1.min(axis=0)))), 1e-9)
        docs = ["urgent wire transfer invoice", "quarterly board meeting notes", "wire invoice overdue"]
        cv = BlindCountVectorizer(max_features=4).fit_transform(docs)
        hv = BlindHashingVectorizer(n_features=6).fit_transform(docs)
        self.assertEqual(cv.shape, (3, 4))
        self.assertEqual(hv.shape, (3, 6))

        # Family 8: RBFSampler, ZScoreDetector, EllipticEnvelope
        X_xor = np.vstack([
            rng.normal([1.5, 1.5], 0.35, size=(20, 2)),
            rng.normal([-1.5, -1.5], 0.35, size=(20, 2)),
            rng.normal([1.5, -1.5], 0.35, size=(20, 2)),
            rng.normal([-1.5, 1.5], 0.35, size=(20, 2)),
        ])
        y_xor = np.array([1] * 40 + [0] * 40)
        b_rbf = BlindRBFSampler(sess, gamma=0.5, n_components=12, alpha=0.5, random_state=42).fit(X_xor, y_xor)
        self.assertGreaterEqual(float(np.mean(b_rbf.predict(X_xor) == y_xor)), 0.90)

        X_anom = np.vstack([rng.normal(0.0, 1.0, size=(50, 2)), np.array([[7.5, -6.5], [-8.0, 7.0]])])
        b_zs = BlindZScoreDetector(sess, threshold=3.5).fit(X_anom[:50])
        self.assertEqual(list(b_zs.predict(X_anom[50:])), [-1, -1])
        self.assertEqual(int(np.sum(b_zs.predict(X_anom[:50]) == 1)), 50)

        b_ee = BlindEllipticEnvelope(sess, contamination=0.05).fit(X_anom[:50])
        r_ec = EmpiricalCovariance().fit(X_anom[:50])
        self.assertLess(float(np.max(np.abs(b_ee.mahalanobis(X_anom[:10]) - r_ec.mahalanobis(X_anom[:10])))), 5e-2)
        self.assertEqual(list(b_ee.predict(X_anom[50:])), [-1, -1])
        cli.close()

    def test_03_hostile_mitm_zero_knowledge_wire_audit(self) -> None:
        proxy = _WireSniffProxy(self.api_url)
        try:
            cli, sess = self._new_session(proxy.url)
            rng = np.random.default_rng(99)
            X_tr = rng.integers(0, 6, size=(40, 6))
            y_tr = (X_tr[:, 0] + X_tr[:, 1] > 4).astype(np.int64)
            X_te = np.array([[7391821, 8419263, 6192847, 5281937, 4918273, 3829147], [11, 23, 37, 41, 53, 67]], dtype=np.int64)
            mnb = BlindMultinomialNB(sess, alpha=1.0).fit(X_tr, y_tr)
            _ = mnb.predict_proba(X_te)

            # Verify IND-CPA randomness, entropy, wrong-key knockout & 1-bit receipt tamper
            c1 = sess.key.encrypt_int(42)
            c2 = sess.key.encrypt_int(42)
            self.assertNotEqual(c1, c2)
            blob = b"".join((lambda c: c[40:56] + c[60:80])(sess.key.encrypt_int(42)) for _ in range(256))
            self.assertGreater(_shannon_entropy(blob), 7.95)

            tbl = f"zk_tamper_{secrets.token_hex(3)}"
            cli.create_blind_table(tbl, [{"name": "x", "kind": "blind_add"}])
            cli.ingest_blind(tbl, [{"ciphertexts_hex": {"x": sess.key.encrypt_int_hex(91827364)}}])
            q = cli.query_blind(tbl, "SUM", column="x")
            raw_ct = bytes.fromhex(str(q["ct_result_hex"]))
            self.assertEqual(len(raw_ct), PLWE_EXPANDED_BYTES)
            self.assertTrue(verify_blind_receipt(q, "SUM", tbl, 1, raw_ct))
            bad_q = dict(q)
            hx = str(q["receipt_hex"])
            bad_q["receipt_hex"] = hx[:-1] + ("0" if hx[-1] != "0" else "1")
            self.assertFalse(verify_blind_receipt(bad_q, "SUM", tbl, 1, raw_ct))
            wrong_pk = BlindClientPlweKey.generate()
            self.assertNotEqual(wrong_pk.decrypt_int(raw_ct), 91827364)
            cli.close()

            all_wire = b"".join(proxy.requests) + b"".join(proxy.responses)
            for forbidden in (b"seal_values", b"seal_doc", b"threshold_decrypt", b"decrypted_aggregate"):
                self.assertNotIn(forbidden, all_wire)
            for sentinel in (b"7391821", b"8419263", b"6192847", b"5281937", b"4918273", b"3829147", b"91827364"):
                self.assertNotIn(sentinel, b"".join(proxy.requests))
            self.assertGreater(sess.stats["n_receipts_verified"], 0)
        finally:
            proxy.close()


if __name__ == "__main__":
    unittest.main()
