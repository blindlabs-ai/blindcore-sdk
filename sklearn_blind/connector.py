"""Mode 1 SQL <-> NumPy connector and Mode 2 Zero-Key Blind OLAP session."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import secrets
import time
from typing import Any, Sequence

import numpy as np

from python.blindcore_sdk import (
    BlindClientPlweKey,
    BlindCoreClient,
    PLWE_EXPANDED_BYTES,
    verify_blind_receipt,
)
from .packing import (
    RadixSlotPacker,
    check_weighted_sum_noise,
    choose_signed_packer,
)


def _safe_ident(name: str) -> str:
    clean = str(name).strip()
    if not clean or not all(ch.isascii() and (ch.isalnum() or ch == "_") for ch in clean):
        raise ValueError(f"invalid SQL identifier: {name!r}")
    return clean


class BlindSklearnConnector:
    """Mode 1 bridge: fetch SQL tables as NumPy arrays and run in-DB ML_*_SCORE pushdown.

    In Mode 1, data is encrypted at rest and in transit (TLS) while SQL queries
    execute on server memory. This unlocks 100% of stock scikit-learn estimators
    plus native Rust SQL scoring pushdown (ML_LINEAR_SCORE, ML_TREE_SCORE, ML_ANOMALY_Z).
    """

    def __init__(self, client: BlindCoreClient) -> None:
        self.client = client

    def ingest_table(
        self,
        table: str,
        X: np.ndarray,
        y: np.ndarray | None = None,
        feature_names: Sequence[str] | None = None,
        batch_size: int = 128,
    ) -> int:
        tbl = _safe_ident(table)
        X_arr = np.asarray(X, dtype=np.float64)
        if X_arr.ndim != 2:
            raise ValueError("X must be 2D")
        n_rows, n_feat = X_arr.shape
        cols = (
            [_safe_ident(c) for c in feature_names]
            if feature_names is not None
            else [f"f{j}" for j in range(n_feat)]
        )
        if len(cols) != n_feat:
            raise ValueError("feature_names length mismatch")
        col_defs = [f"{c} DOUBLE" for c in cols]
        y_arr = None
        if y is not None:
            y_arr = np.asarray(y, dtype=np.float64).reshape(-1)
            if len(y_arr) != n_rows:
                raise ValueError("y length mismatch")
            col_defs.append("target DOUBLE")
        self.client.query_json(f"CREATE TABLE {tbl} ({', '.join(col_defs)})")
        for start in range(0, n_rows, batch_size):
            end = min(start + batch_size, n_rows)
            tuples = []
            for i in range(start, end):
                vals = [f"{float(X_arr[i, j]):.12g}" for j in range(n_feat)]
                if y_arr is not None:
                    vals.append(f"{float(y_arr[i]):.12g}")
                tuples.append(f"({', '.join(vals)})")
            self.client.query_json(f"INSERT INTO {tbl} VALUES {', '.join(tuples)}")
        return n_rows

    def fetch_numpy(
        self, sql: str, target_col: str | None = None
    ) -> np.ndarray | tuple[np.ndarray, np.ndarray]:
        resp = self.client.query_json(sql)
        cols = list(resp.get("columns", []))
        rows = resp.get("rows", [])
        if not rows:
            empty = np.empty((0, len(cols)), dtype=np.float64)
            return (empty, np.empty((0,), dtype=np.float64)) if target_col else empty
        mat = np.asarray(rows, dtype=np.float64)
        if target_col is None:
            return mat
        idx = cols.index(target_col)
        feat_idx = [i for i in range(len(cols)) if i != idx]
        return mat[:, feat_idx], mat[:, idx]

    def pushdown_linear_score(
        self, table: str, feature_cols: Sequence[str], coef: Sequence[float], intercept: float
    ) -> np.ndarray:
        tbl = _safe_ident(table)
        args = [f"{float(intercept):.12g}"]
        for col, w in zip(feature_cols, coef):
            args.append(_safe_ident(col))
            args.append(f"{float(w):.12g}")
        resp = self.client.query_json(f"SELECT ML_LINEAR_SCORE({', '.join(args)}) AS sc FROM {tbl}")
        return np.asarray([r[0] for r in resp["rows"]], dtype=np.float64)

    def pushdown_tree_ensemble_score(
        self, table: str, stumps: Sequence[tuple[str, float, float, float]], bias: float = 0.0
    ) -> np.ndarray:
        tbl = _safe_ident(table)
        terms = [
            f"ML_TREE_SCORE({_safe_ident(col)}, {float(thr):.12g}, {float(lv):.12g}, {float(rv):.12g})"
            for col, thr, lv, rv in stumps
        ]
        expr = " + ".join(terms) if terms else "0.0"
        if bias != 0.0:
            expr = f"({float(bias):.12g} + {expr})"
        resp = self.client.query_json(f"SELECT {expr} AS sc FROM {tbl}")
        return np.asarray([r[0] for r in resp["rows"]], dtype=np.float64)

    def pushdown_anomaly_z(self, table: str, col: str, mean: float, std: float) -> np.ndarray:
        tbl = _safe_ident(table)
        c = _safe_ident(col)
        resp = self.client.query_json(
            f"SELECT ML_ANOMALY_Z({c}, {float(mean):.12g}, {float(std):.12g}) AS z FROM {tbl}"
        )
        return np.asarray([r[0] for r in resp["rows"]], dtype=np.float64)


class BlindOlapSession:
    """Mode 2 zero-key encrypted compute session over /api/v1/blind/*.

    Every integer is encrypted locally under the client's BlindClientPlweKey
    (80 B IND-CPA PLWE0001 frames). The server holds zero keys, evaluates SUM
    and WEIGHTED_SUM strictly on ciphertexts, and signs NSAU0001 receipts.
    """

    def __init__(
        self,
        client: BlindCoreClient,
        key: BlindClientPlweKey | None = None,
        *,
        verify_receipts: bool = True,
        max_query_workers: int = 4,
    ) -> None:
        self.client = client
        self.key = key if key is not None else BlindClientPlweKey.generate()
        self.verify_receipts = bool(verify_receipts)
        self.max_query_workers = max(1, int(max_query_workers))
        self._handle_key = secrets.token_bytes(32)
        self.stats: dict[str, float | int] = {}
        self.reset_stats()

    def reset_stats(self) -> None:
        self.stats = {
            "encrypt_ms": 0.0,
            "ingest_ms": 0.0,
            "query_ms": 0.0,
            "server_ms": 0.0,
            "decrypt_ms": 0.0,
            "n_cts_encrypted": 0,
            "n_queries": 0,
            "n_receipts_verified": 0,
        }

    def _group_token_hex(self, table: str, group_idx: int) -> str:
        return hmac.new(
            self._handle_key, f"gid:{table}:{group_idx}".encode("ascii"), hashlib.sha256
        ).hexdigest()

    def _ingest_chunked(
        self, table: str, rows: list[dict[str, Any]], max_bytes: int = 200_000
    ) -> None:
        chunk: list[dict[str, Any]] = []
        acc = 64 + len(table)
        for row in rows:
            ct_map = row.get("ciphertexts_hex", {})
            est = 32 + sum(len(str(k)) + len(str(v)) + 8 for k, v in ct_map.items())
            if chunk and acc + est > max_bytes:
                self.client.ingest_blind(table, chunk)
                chunk = []
                acc = 64 + len(table)
            chunk.append(row)
            acc += est
        if chunk:
            self.client.ingest_blind(table, chunk)

    def _verify_and_extract_ct(
        self, resp: dict[str, Any], op: str, table: str, expected_rows: int
    ) -> bytes:
        if "decrypted_aggregate" in resp:
            raise RuntimeError("Mode 2 invariant violated: server returned decrypted_aggregate")
        ct_hex = str(resp["ct_result_hex"])
        raw_ct = bytes.fromhex(ct_hex)
        if len(raw_ct) != PLWE_EXPANDED_BYTES:
            raise RuntimeError(f"unexpected expanded ciphertext length: {len(raw_ct)}")
        if self.verify_receipts:
            if not verify_blind_receipt(resp, op, table, expected_rows, raw_ct):
                raise RuntimeError(f"NSAU0001 receipt verification failed for {op} on {table}")
            self.stats["n_receipts_verified"] += 1
        return raw_ct

    def encrypted_packed_sums(
        self,
        rows_slots: Sequence[Sequence[int]],
        packer: RadixSlotPacker,
        prefix: str = "sk_sum",
    ) -> list[int]:
        """Encrypt radix-packed rows, run server SUMs with zero keys, decrypt & unpack."""
        n_rows = len(rows_slots)
        if n_rows == 0:
            return []
        m_slots = len(rows_slots[0])
        k = packer.n_slots
        n_cols = (m_slots + k - 1) // k
        use_rid = (n_rows > 128) or (n_rows * min(n_cols, 31) * 175 > 190_000)
        max_add_cols = 31 if use_rid else 32

        t0 = time.perf_counter()
        flat_packed: list[int] = []
        pad_needed = n_cols * k - m_slots
        pad_tail = [0] * pad_needed
        for row in rows_slots:
            padded = list(row) + pad_tail if pad_needed else list(row)
            for c_idx in range(n_cols):
                flat_packed.append(packer.pack(padded[c_idx * k : (c_idx + 1) * k]))
        cts_hex = self.key.encrypt_batch_hex(flat_packed)
        self.stats["encrypt_ms"] += (time.perf_counter() - t0) * 1000.0
        self.stats["n_cts_encrypted"] += len(cts_hex)

        raw_cts_all: list[bytes] = []
        for c0 in range(0, n_cols, max_add_cols):
            c1 = min(c0 + max_add_cols, n_cols)
            shard_cols = [f"c{j}" for j in range(c1 - c0)]
            table = f"{_safe_ident(prefix)}_{secrets.token_hex(4)}"
            schema = [{"name": cn, "kind": "blind_add"} for cn in shard_cols]
            if use_rid:
                schema.append({"name": "rid", "kind": "blind_token"})

            t1 = time.perf_counter()
            self.client.create_blind_table(table, schema)
            ing_rows: list[dict[str, Any]] = []
            for i in range(n_rows):
                ct_map = {
                    shard_cols[j]: cts_hex[i * n_cols + c0 + j] for j in range(c1 - c0)
                }
                if use_rid:
                    ct_map["rid"] = self._group_token_hex(f"{table}:r", i)
                ing_rows.append({"ciphertexts_hex": ct_map})
            self._ingest_chunked(table, ing_rows)
            self.stats["ingest_ms"] += (time.perf_counter() - t1) * 1000.0

            t2 = time.perf_counter()
            if len(shard_cols) > 1 and self.max_query_workers > 1:
                with ThreadPoolExecutor(max_workers=min(self.max_query_workers, len(shard_cols))) as ex:
                    resps = list(ex.map(lambda cn: self.client.query_blind(table, "SUM", column=cn), shard_cols))
            else:
                resps = [self.client.query_blind(table, "SUM", column=cn) for cn in shard_cols]
            self.stats["query_ms"] += (time.perf_counter() - t2) * 1000.0
            self.stats["n_queries"] += len(resps)
            for resp in resps:
                self.stats["server_ms"] += float(resp.get("elapsed_us", 0.0)) / 1000.0
                raw_cts_all.append(self._verify_and_extract_ct(resp, "SUM", table, n_rows))

        t3 = time.perf_counter()
        dec_vals = self.key.decrypt_batch(raw_cts_all)
        out: list[int] = []
        for dv in dec_vals:
            out.extend(packer.unpack(dv))
        self.stats["decrypt_ms"] += (time.perf_counter() - t3) * 1000.0
        return out[:m_slots]

    def encrypted_packed_linear_score(
        self,
        X_int: np.ndarray,
        W_int: np.ndarray,
        prefix: str = "sk_lin",
        *,
        packer: RadixSlotPacker | None = None,
        cohort_only: bool = False,
    ) -> np.ndarray:
        """Score integer matrix X_int @ W_int.T on untrusted server via packed WEIGHTED_SUM."""
        X_arr = np.asarray(X_int, dtype=np.int64)
        W_arr = np.asarray(W_int, dtype=np.int64)
        if X_arr.ndim == 1:
            X_arr = X_arr.reshape(1, -1)
        if W_arr.ndim == 1:
            W_arr = W_arr.reshape(1, -1)
        n_docs, n_feat = X_arr.shape
        n_out = W_arr.shape[0]
        if W_arr.shape[1] != n_feat:
            raise ValueError("feature dimension mismatch between X_int and W_int")

        if cohort_only:
            for m in range(n_out):
                check_weighted_sum_noise(n_docs, W_arr[m].tolist())
            return self._score_cohort_raw(X_arr, W_arr, prefix)

        for m in range(n_out):
            check_weighted_sum_noise(1, W_arr[m].tolist())

        if packer is None:
            abs_x = np.abs(X_arr).astype(object)
            abs_w = np.abs(W_arr).astype(object)
            max_in = int(abs_x.max()) if abs_x.size else 0
            max_dot = int((abs_x @ abs_w.T).max()) if abs_x.size and abs_w.size else 0
            packer = choose_signed_packer(max(max_in, max_dot, 1), n_docs)

        k = packer.n_slots
        n_groups = (n_docs + k - 1) // k
        use_gid = n_groups > 1
        max_f = 31 if use_gid else 32
        if n_feat > max_f:
            total = np.zeros((n_docs, n_out), dtype=np.int64)
            for f0 in range(0, n_feat, max_f):
                f1 = min(f0 + max_f, n_feat)
                total += self.encrypted_packed_linear_score(
                    X_arr[:, f0:f1], W_arr[:, f0:f1], prefix=prefix, packer=packer
                )
            return total

        col_names = [f"f{j}" for j in range(n_feat)]

        t0 = time.perf_counter()
        flat_packed: list[int] = []
        for g in range(n_groups):
            start = g * k
            end = min(start + k, n_docs)
            pad = k - (end - start)
            for j in range(n_feat):
                slots = [int(X_arr[i, j]) for i in range(start, end)]
                if pad:
                    slots.extend([0] * pad)
                flat_packed.append(packer.pack(slots))
        cts_hex = self.key.encrypt_batch_hex(flat_packed)
        self.stats["encrypt_ms"] += (time.perf_counter() - t0) * 1000.0
        self.stats["n_cts_encrypted"] += len(cts_hex)

        table = f"{_safe_ident(prefix)}_{secrets.token_hex(4)}"
        schema = [{"name": cn, "kind": "blind_add"} for cn in col_names]
        if use_gid:
            schema.append({"name": "gid", "kind": "blind_token"})

        t1 = time.perf_counter()
        self.client.create_blind_table(table, schema)
        gids = [self._group_token_hex(table, g) for g in range(n_groups)] if use_gid else []
        ing_rows: list[dict[str, Any]] = []
        for g in range(n_groups):
            ct_map = {col_names[j]: cts_hex[g * n_feat + j] for j in range(n_feat)}
            if use_gid:
                ct_map["gid"] = gids[g]
            ing_rows.append({"ciphertexts_hex": ct_map})
        self._ingest_chunked(table, ing_rows)
        self.stats["ingest_ms"] += (time.perf_counter() - t1) * 1000.0

        tasks = [(g, m) for m in range(n_out) for g in range(n_groups)]
        weights_lists = [W_arr[m].tolist() for m in range(n_out)]

        def _run_q(item: tuple[int, int]) -> dict[str, Any]:
            g, m = item
            where = {"column": "gid", "eq_token_hex": gids[g]} if use_gid else None
            return self.client.query_blind(
                table, "WEIGHTED_SUM", columns=col_names, weights=weights_lists[m], where=where
            )

        t2 = time.perf_counter()
        if len(tasks) > 1 and self.max_query_workers > 1:
            with ThreadPoolExecutor(max_workers=min(self.max_query_workers, len(tasks))) as ex:
                resps = list(ex.map(_run_q, tasks))
        else:
            resps = [_run_q(t) for t in tasks]
        self.stats["query_ms"] += (time.perf_counter() - t2) * 1000.0
        self.stats["n_queries"] += len(resps)

        raw_cts: list[bytes] = []
        for resp in resps:
            self.stats["server_ms"] += float(resp.get("elapsed_us", 0.0)) / 1000.0
            raw_cts.append(self._verify_and_extract_ct(resp, "WEIGHTED_SUM", table, 1))

        t3 = time.perf_counter()
        dec_vals = self.key.decrypt_batch(raw_cts)
        scores = np.zeros((n_docs, n_out), dtype=np.int64)
        for idx, (g, m) in enumerate(tasks):
            unpacked = packer.unpack(dec_vals[idx])
            start = g * k
            end = min(start + k, n_docs)
            scores[start:end, m] = unpacked[: end - start]
        self.stats["decrypt_ms"] += (time.perf_counter() - t3) * 1000.0
        return scores

    def _score_cohort_raw(
        self, X_arr: np.ndarray, W_arr: np.ndarray, prefix: str
    ) -> np.ndarray:
        n_docs, n_feat = X_arr.shape
        n_out = W_arr.shape[0]
        use_rid = (n_docs > 128) or (n_docs * min(n_feat, 31) * 175 > 190_000)
        max_f = 31 if use_rid else 32
        if n_feat > max_f:
            total = np.zeros(n_out, dtype=np.int64)
            for f0 in range(0, n_feat, max_f):
                f1 = min(f0 + max_f, n_feat)
                total += self._score_cohort_raw(X_arr[:, f0:f1], W_arr[:, f0:f1], prefix)
            return total

        col_names = [f"f{j}" for j in range(n_feat)]
        t0 = time.perf_counter()
        flat = [int(X_arr[i, j]) for i in range(n_docs) for j in range(n_feat)]
        cts_hex = self.key.encrypt_batch_hex(flat)
        self.stats["encrypt_ms"] += (time.perf_counter() - t0) * 1000.0
        self.stats["n_cts_encrypted"] += len(cts_hex)

        table = f"{_safe_ident(prefix)}_{secrets.token_hex(4)}"
        schema = [{"name": cn, "kind": "blind_add"} for cn in col_names]
        if use_rid:
            schema.append({"name": "rid", "kind": "blind_token"})
        t1 = time.perf_counter()
        self.client.create_blind_table(table, schema)
        ing_rows: list[dict[str, Any]] = []
        for i in range(n_docs):
            ct_map = {col_names[j]: cts_hex[i * n_feat + j] for j in range(n_feat)}
            if use_rid:
                ct_map["rid"] = self._group_token_hex(f"{table}:r", i)
            ing_rows.append({"ciphertexts_hex": ct_map})
        self._ingest_chunked(table, ing_rows)
        self.stats["ingest_ms"] += (time.perf_counter() - t1) * 1000.0

        t2 = time.perf_counter()
        resps = [
            self.client.query_blind(
                table, "WEIGHTED_SUM", columns=col_names, weights=W_arr[m].tolist()
            )
            for m in range(n_out)
        ]
        self.stats["query_ms"] += (time.perf_counter() - t2) * 1000.0
        self.stats["n_queries"] += len(resps)
        raw_cts = []
        for resp in resps:
            self.stats["server_ms"] += float(resp.get("elapsed_us", 0.0)) / 1000.0
            raw_cts.append(self._verify_and_extract_ct(resp, "WEIGHTED_SUM", table, n_docs))
        t3 = time.perf_counter()
        dec = self.key.decrypt_batch(raw_cts)
        self.stats["decrypt_ms"] += (time.perf_counter() - t3) * 1000.0
        return np.asarray(dec, dtype=np.int64)
