"""Family 8: Zero-Key Blind Kernel Approximation (RFF) & Anomaly Detection."""

from __future__ import annotations

import math

import numpy as np

from .connector import BlindOlapSession, BlindSklearnConnector
from .linear import BlindRidge, BlindRidgeClassifier
from .packing import choose_signed_packer


class BlindRBFSampler:
    """Random Fourier Features (RFF) + zero-key encrypted PLWE0001 Ridge / Classifier.

    Computes the client-side Monte Carlo RBF map z(x) = sqrt(2/D) * cos(x @ W + b)
    (identical to sklearn.kernel_approximation.RBFSampler), then executes the entire
    kernel Gram matrix SUM (Z^T Z, Z^T y) and WEIGHTED_SUM inference on the untrusted
    server with zero server keys.
    """

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        gamma: float = 1.0,
        n_components: int = 16,
        alpha: float = 1.0,
        task: str = "classification",
        random_state: int = 42,
        feat_scale: int = 1000,
        weight_scale: int = 1000,
    ) -> None:
        self.session = session
        self.gamma = float(gamma)
        self.n_components = int(n_components)
        self.alpha = float(alpha)
        self.task = str(task)
        self.random_state = int(random_state)
        self.feat_scale = int(feat_scale)
        self.weight_scale = int(weight_scale)
        self.random_weights_: np.ndarray | None = None
        self.random_offset_: np.ndarray | None = None
        self.head_: BlindRidgeClassifier | BlindRidge | None = None

    def fit_sampler(self, n_features: int) -> "BlindRBFSampler":
        rng = np.random.default_rng(self.random_state)
        self.random_weights_ = rng.normal(
            0.0, math.sqrt(2.0 * self.gamma), size=(int(n_features), self.n_components)
        )
        self.random_offset_ = rng.uniform(0.0, 2.0 * math.pi, size=(self.n_components,))
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        assert self.random_weights_ is not None and self.random_offset_ is not None
        proj = np.asarray(X, dtype=np.float64) @ self.random_weights_ + self.random_offset_
        return math.sqrt(2.0 / float(self.n_components)) * np.cos(proj)

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindRBFSampler":
        X_arr = np.asarray(X, dtype=np.float64)
        if self.random_weights_ is None:
            self.fit_sampler(X_arr.shape[1])
        Z = self.transform(X_arr)
        if self.task == "regression":
            head: BlindRidgeClassifier | BlindRidge = BlindRidge(
                self.session,
                alpha=self.alpha,
                feat_scale=self.feat_scale,
                weight_scale=self.weight_scale,
            )
        else:
            head = BlindRidgeClassifier(
                self.session,
                alpha=self.alpha,
                feat_scale=self.feat_scale,
                weight_scale=self.weight_scale,
            )
        head.fit(Z, y)
        self.head_ = head
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        assert self.head_ is not None
        return self.head_.predict(self.transform(X))


class BlindZScoreDetector:
    """Zero-key encrypted Z-score anomaly detector (+ Mode 1 SQL ML_ANOMALY_Z pushdown)."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        threshold: float = 3.0,
        feat_scale: int = 1000,
    ) -> None:
        self.session = session
        self.threshold = float(threshold)
        self.feat_scale = int(feat_scale)
        self.mean_: np.ndarray | None = None
        self.std_: np.ndarray | None = None

    def fit(self, X: np.ndarray) -> "BlindZScoreDetector":
        X_arr = np.asarray(X, dtype=np.float64)
        if X_arr.ndim == 1:
            X_arr = X_arr.reshape(-1, 1)
        n, d = X_arr.shape
        s = float(self.feat_scale)
        Xq = np.rint(X_arr * s).astype(np.int64)
        rows_slots = [
            [1] + [int(Xq[i, j]) for j in range(d)] + [int(Xq[i, j]) ** 2 for j in range(d)]
            for i in range(n)
        ]
        col_abs = np.sum(np.abs(np.asarray(rows_slots, dtype=object)), axis=0)
        packer = choose_signed_packer(max(int(col_abs.max()), 1), 1 + 2 * d)
        sums = self.session.encrypted_packed_sums(rows_slots, packer, prefix="zscore_fit")
        n_seen = float(sums[0])
        sx = np.asarray(sums[1 : 1 + d], dtype=np.float64) / s
        sx2 = np.asarray(sums[1 + d : 1 + 2 * d], dtype=np.float64) / (s * s)
        mu = sx / n_seen
        var = np.maximum(sx2 / n_seen - mu * mu, 1e-12)
        self.mean_ = mu
        self.std_ = np.sqrt(var)
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        assert self.mean_ is not None and self.std_ is not None
        X_arr = np.asarray(X, dtype=np.float64)
        if X_arr.ndim == 1:
            X_arr = X_arr.reshape(-1, 1)
        z = np.abs(X_arr - self.mean_) / self.std_
        return np.max(z, axis=1)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return +1 for inliers and -1 for anomalies (matching sklearn anomaly convention)."""
        return np.where(self.score_samples(X) > self.threshold, -1, 1)

    def pushdown_sql_z(
        self, connector: BlindSklearnConnector, table: str, col: str, feat_idx: int = 0
    ) -> np.ndarray:
        assert self.mean_ is not None and self.std_ is not None
        return connector.pushdown_anomaly_z(
            table, col, float(self.mean_[feat_idx]), float(self.std_[feat_idx])
        )


class BlindEllipticEnvelope:
    """Zero-key encrypted Gaussian Mahalanobis outlier detector via packed covariance SUM."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        contamination: float = 0.1,
        reg: float = 1e-6,
        feat_scale: int = 1000,
    ) -> None:
        self.session = session
        self.contamination = float(contamination)
        self.reg = float(reg)
        self.feat_scale = int(feat_scale)
        self.location_: np.ndarray | None = None
        self.covariance_: np.ndarray | None = None
        self.precision_: np.ndarray | None = None
        self.offset_: float = 0.0

    def fit(self, X: np.ndarray) -> "BlindEllipticEnvelope":
        X_arr = np.asarray(X, dtype=np.float64)
        n, d = X_arr.shape
        pairs = [(j, k) for j in range(d) for k in range(j, d)]
        s = float(self.feat_scale)
        Xq = np.rint(X_arr * s).astype(np.int64)
        rows_slots = [
            [1]
            + [int(Xq[i, j]) for j in range(d)]
            + [int(Xq[i, j]) * int(Xq[i, k]) for j, k in pairs]
            for i in range(n)
        ]
        col_abs = np.sum(np.abs(np.asarray(rows_slots, dtype=object)), axis=0)
        packer = choose_signed_packer(max(int(col_abs.max()), 1), len(rows_slots[0]))
        sums = self.session.encrypted_packed_sums(rows_slots, packer, prefix="elliptic_fit")
        n_seen = float(sums[0])
        mu = (np.asarray(sums[1 : 1 + d], dtype=np.float64) / s) / n_seen
        xtx = np.zeros((d, d), dtype=np.float64)
        off = 1 + d
        for pi, (j, k) in enumerate(pairs):
            val = float(sums[off + pi]) / (s * s)
            xtx[j, k] = val
            xtx[k, j] = val
        cov = (xtx / n_seen) - np.outer(mu, mu) + self.reg * np.eye(d)
        prec = np.linalg.pinv(cov)
        self.location_ = mu
        self.covariance_ = cov
        self.precision_ = prec
        train_scores = self.score_samples(X_arr)
        self.offset_ = float(np.percentile(train_scores, 100.0 * self.contamination))
        return self

    def mahalanobis(self, X: np.ndarray) -> np.ndarray:
        assert self.location_ is not None and self.precision_ is not None
        diff = np.asarray(X, dtype=np.float64) - self.location_
        return np.einsum("ij,jk,ik->i", diff, self.precision_, diff)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return -self.mahalanobis(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return np.where(self.score_samples(X) < self.offset_, -1, 1)
