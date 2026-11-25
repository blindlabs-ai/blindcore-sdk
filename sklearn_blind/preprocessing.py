"""Family 7: Zero-Key Blind Preprocessing & Text Vectorizers."""

from __future__ import annotations

import hashlib
import re
from typing import Sequence

import numpy as np

from .connector import BlindOlapSession, BlindSklearnConnector
from .packing import choose_signed_packer

_TOKEN_RE = re.compile(r"(?u)\b\w\w+\b")


class BlindStandardScaler:
    """Zero-key encrypted StandardScaler via packed (N, sum x, sum x^2) PLWE0001 SUM."""

    def __init__(self, session: BlindOlapSession, *, feat_scale: int = 1000) -> None:
        self.session = session
        self.feat_scale = int(feat_scale)
        self.mean_: np.ndarray | None = None
        self.var_: np.ndarray | None = None
        self.scale_: np.ndarray | None = None
        self.n_samples_seen_: int = 0

    def fit(self, X: np.ndarray) -> "BlindStandardScaler":
        X_arr = np.asarray(X, dtype=np.float64)
        n, d = X_arr.shape
        s = float(self.feat_scale)
        Xq = np.rint(X_arr * s).astype(np.int64)
        rows_slots: list[list[int]] = []
        for i in range(n):
            row = [1]
            row.extend(int(Xq[i, j]) for j in range(d))
            row.extend(int(Xq[i, j]) * int(Xq[i, j]) for j in range(d))
            rows_slots.append(row)
        col_abs = np.sum(np.abs(np.asarray(rows_slots, dtype=object)), axis=0)
        packer = choose_signed_packer(max(int(col_abs.max()), 1), 1 + 2 * d)
        sums = self.session.encrypted_packed_sums(rows_slots, packer, prefix="std_fit")
        n_seen = int(sums[0])
        sx = np.asarray(sums[1 : 1 + d], dtype=np.float64) / s
        sx2 = np.asarray(sums[1 + d : 1 + 2 * d], dtype=np.float64) / (s * s)
        mu = sx / float(n_seen)
        var = np.maximum(sx2 / float(n_seen) - mu * mu, 0.0)
        scale = np.where(var > 0.0, np.sqrt(var), 1.0)
        self.n_samples_seen_ = n_seen
        self.mean_ = mu
        self.var_ = var
        self.scale_ = scale
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        assert self.mean_ is not None and self.scale_ is not None
        return (np.asarray(X, dtype=np.float64) - self.mean_) / self.scale_

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        return self.fit(X).transform(X)


class BlindMinMaxScaler:
    """Two-mode MinMaxScaler: client or Mode 1 SQL MIN/MAX fit + encrypted affine transform.

    Honest cryptographic note: exact MIN/MAX comparisons are non-additive, so fit()
    runs locally on the client (or via Mode 1 SQL MIN/MAX pushdown). Once bounds are
    fitted, transform_encrypted() executes the affine scaling homomorphically via
    server WEIGHTED_SUM with zero server keys.
    """

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        feature_range: tuple[float, float] = (0.0, 1.0),
        feat_scale: int = 1000,
        weight_scale: int = 1000,
    ) -> None:
        self.session = session
        self.feature_range = (float(feature_range[0]), float(feature_range[1]))
        self.feat_scale = int(feat_scale)
        self.weight_scale = int(weight_scale)
        self.data_min_: np.ndarray | None = None
        self.data_max_: np.ndarray | None = None
        self.scale_: np.ndarray | None = None
        self.min_: np.ndarray | None = None

    def fit(self, X: np.ndarray) -> "BlindMinMaxScaler":
        X_arr = np.asarray(X, dtype=np.float64)
        d_min = np.min(X_arr, axis=0)
        d_max = np.max(X_arr, axis=0)
        span = np.where((d_max - d_min) > 0.0, d_max - d_min, 1.0)
        lo, hi = self.feature_range
        self.data_min_ = d_min
        self.data_max_ = d_max
        self.scale_ = (hi - lo) / span
        self.min_ = lo - d_min * self.scale_
        return self

    def fit_sql(
        self, connector: BlindSklearnConnector, table: str, feature_cols: Sequence[str]
    ) -> "BlindMinMaxScaler":
        aggs = ", ".join(f"MIN({c}), MAX({c})" for c in feature_cols)
        row = connector.client.query_json(f"SELECT {aggs} FROM {table}")["rows"][0]
        d_min = np.asarray(row[0::2], dtype=np.float64)
        d_max = np.asarray(row[1::2], dtype=np.float64)
        span = np.where((d_max - d_min) > 0.0, d_max - d_min, 1.0)
        lo, hi = self.feature_range
        self.data_min_ = d_min
        self.data_max_ = d_max
        self.scale_ = (hi - lo) / span
        self.min_ = lo - d_min * self.scale_
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        assert self.scale_ is not None and self.min_ is not None
        return np.asarray(X, dtype=np.float64) * self.scale_ + self.min_

    def transform_encrypted(self, X: np.ndarray) -> np.ndarray:
        """Apply affine scaling homomorphically on server via diagonal WEIGHTED_SUM."""
        assert self.scale_ is not None and self.min_ is not None
        X_arr = np.asarray(X, dtype=np.float64)
        Xq = np.rint(X_arr * self.feat_scale).astype(np.int64)
        Wq = np.diag(np.rint(self.scale_ * self.weight_scale).astype(np.int64))
        raw = self.session.encrypted_packed_linear_score(Xq, Wq, prefix="minmax_tr")
        return (raw.astype(np.float64) / float(self.feat_scale * self.weight_scale)) + self.min_


class BlindCountVectorizer:
    """Client-side deterministic token-count vectorizer aligned with sklearn CountVectorizer."""

    def __init__(
        self,
        *,
        vocabulary: dict[str, int] | Sequence[str] | None = None,
        max_features: int | None = None,
    ) -> None:
        self.max_features = max_features
        self.vocabulary_: dict[str, int] = {}
        if vocabulary is not None:
            if isinstance(vocabulary, dict):
                self.vocabulary_ = {str(k).lower(): int(v) for k, v in vocabulary.items()}
            else:
                self.vocabulary_ = {str(tok).lower(): idx for idx, tok in enumerate(vocabulary)}

    def _tokenize(self, text: str) -> list[str]:
        return _TOKEN_RE.findall(str(text).lower())

    def fit(self, documents: Sequence[str]) -> "BlindCountVectorizer":
        if not self.vocabulary_:
            freq: dict[str, int] = {}
            for doc in documents:
                for tok in self._tokenize(doc):
                    freq[tok] = freq.get(tok, 0) + 1
            ordered = sorted(freq.keys(), key=lambda t: (-freq[t], t))
            if self.max_features is not None:
                ordered = ordered[: self.max_features]
            ordered.sort()
            self.vocabulary_ = {tok: idx for idx, tok in enumerate(ordered)}
        return self

    def transform(self, documents: Sequence[str]) -> np.ndarray:
        vocab = self.vocabulary_
        mat = np.zeros((len(documents), len(vocab)), dtype=np.int64)
        for i, doc in enumerate(documents):
            for tok in self._tokenize(doc):
                idx = vocab.get(tok)
                if idx is not None:
                    mat[i, idx] += 1
        return mat

    def fit_transform(self, documents: Sequence[str]) -> np.ndarray:
        return self.fit(documents).transform(documents)


class BlindHashingVectorizer:
    """Stateless client-side hashing vectorizer producing non-negative count matrices."""

    def __init__(self, *, n_features: int = 16, alternate_sign: bool = False) -> None:
        self.n_features = int(n_features)
        self.alternate_sign = bool(alternate_sign)

    def fit(self, documents: Sequence[str]) -> "BlindHashingVectorizer":
        return self

    def transform(self, documents: Sequence[str]) -> np.ndarray:
        mat = np.zeros((len(documents), self.n_features), dtype=np.int64)
        for i, doc in enumerate(documents):
            for tok in _TOKEN_RE.findall(str(doc).lower()):
                dig = hashlib.sha256(tok.encode("utf-8")).digest()
                bucket = int.from_bytes(dig[:4], "little") % self.n_features
                sign = -1 if (self.alternate_sign and (dig[4] & 1)) else 1
                mat[i, bucket] += sign
        return mat

    def fit_transform(self, documents: Sequence[str]) -> np.ndarray:
        return self.transform(documents)
