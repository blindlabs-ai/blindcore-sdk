"""Family 4: Zero-Key Blind Generative & Discriminant Models (GaussianNB, LDA, QDA)."""

from __future__ import annotations

import math

import numpy as np

from .connector import BlindOlapSession
from .packing import choose_signed_packer


def _log_softmax(logits: np.ndarray) -> np.ndarray:
    m = np.max(logits, axis=1, keepdims=True)
    shifted = logits - m
    return shifted - np.log(np.sum(np.exp(shifted), axis=1, keepdims=True))


class BlindGaussianNB:
    """Zero-key encrypted GaussianNB via radix-packed per-class (N_c, sum x, sum x^2) SUM."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        var_smoothing: float = 1e-9,
        feat_scale: int = 1000,
    ) -> None:
        self.session = session
        self.var_smoothing = float(var_smoothing)
        self.feat_scale = int(feat_scale)
        self.classes_: np.ndarray | None = None
        self.class_count_: np.ndarray | None = None
        self.class_prior_: np.ndarray | None = None
        self.theta_: np.ndarray | None = None
        self.var_: np.ndarray | None = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindGaussianNB":
        X_arr = np.asarray(X, dtype=np.float64)
        y_arr = np.asarray(y).reshape(-1)
        classes = np.unique(y_arr)
        n, d = X_arr.shape
        c_cnt = len(classes)
        c_map = {c: idx for idx, c in enumerate(classes)}
        s = float(self.feat_scale)
        Xq = np.rint(X_arr * s).astype(np.int64)
        stride = 1 + 2 * d
        total = c_cnt * stride

        rows_slots: list[list[int]] = []
        for i in range(n):
            row = [0] * total
            base = c_map[y_arr[i]] * stride
            row[base] = 1
            for j in range(d):
                xj = int(Xq[i, j])
                row[base + 1 + j] = xj
                row[base + 1 + d + j] = xj * xj
            rows_slots.append(row)

        col_abs = np.sum(np.abs(np.asarray(rows_slots, dtype=object)), axis=0)
        packer = choose_signed_packer(max(int(col_abs.max()), 1), total)
        sums = self.session.encrypted_packed_sums(rows_slots, packer, prefix="gnb_fit")

        counts = np.zeros(c_cnt, dtype=np.float64)
        theta = np.zeros((c_cnt, d), dtype=np.float64)
        var = np.zeros((c_cnt, d), dtype=np.float64)
        all_sum_x = np.zeros(d, dtype=np.float64)
        all_sum_x2 = np.zeros(d, dtype=np.float64)
        for ci in range(c_cnt):
            base = ci * stride
            nc = float(sums[base])
            counts[ci] = nc
            sx = np.asarray(sums[base + 1 : base + 1 + d], dtype=np.float64) / s
            sx2 = np.asarray(sums[base + 1 + d : base + 1 + 2 * d], dtype=np.float64) / (s * s)
            all_sum_x += sx
            all_sum_x2 += sx2
            mu = sx / nc
            theta[ci] = mu
            var[ci] = np.maximum(sx2 / nc - mu * mu, 0.0)

        global_var = np.maximum(all_sum_x2 / n - (all_sum_x / n) ** 2, 0.0)
        eps = self.var_smoothing * float(np.max(global_var))
        self.classes_ = classes
        self.class_count_ = counts
        self.class_prior_ = counts / float(n)
        self.theta_ = theta
        self.var_ = var + eps
        return self

    def predict_log_proba(self, X: np.ndarray) -> np.ndarray:
        assert self.theta_ is not None and self.var_ is not None and self.class_prior_ is not None
        X_arr = np.asarray(X, dtype=np.float64)
        jll = np.zeros((X_arr.shape[0], len(self.class_prior_)), dtype=np.float64)
        for ci in range(len(self.class_prior_)):
            log_det = -0.5 * np.sum(np.log(2.0 * math.pi * self.var_[ci]))
            quad = -0.5 * np.sum(((X_arr - self.theta_[ci]) ** 2) / self.var_[ci], axis=1)
            jll[:, ci] = math.log(float(self.class_prior_[ci])) + log_det + quad
        return _log_softmax(jll)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return np.exp(self.predict_log_proba(X))

    def predict(self, X: np.ndarray) -> np.ndarray:
        assert self.classes_ is not None
        return self.classes_[np.argmax(self.predict_log_proba(X), axis=1)]


class BlindLinearDiscriminantAnalysis:
    """Zero-key encrypted LDA via encrypted pooled covariance SUM + WEIGHTED_SUM scoring."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        reg_param: float = 0.0,
        feat_scale: int = 1000,
        weight_scale: int = 1000,
    ) -> None:
        self.session = session
        self.reg_param = float(reg_param)
        self.feat_scale = int(feat_scale)
        self.weight_scale = int(weight_scale)
        self.classes_: np.ndarray | None = None
        self.means_: np.ndarray | None = None
        self.priors_: np.ndarray | None = None
        self.coef_: np.ndarray | None = None
        self.intercept_: np.ndarray | None = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindLinearDiscriminantAnalysis":
        X_arr = np.asarray(X, dtype=np.float64)
        y_arr = np.asarray(y).reshape(-1)
        classes = np.unique(y_arr)
        n, d = X_arr.shape
        c_cnt = len(classes)
        c_map = {c: idx for idx, c in enumerate(classes)}
        pairs = [(j, k) for j in range(d) for k in range(j, d)]
        s = float(self.feat_scale)
        Xq = np.rint(X_arr * s).astype(np.int64)
        c_stride = 1 + d
        total = c_cnt * c_stride + len(pairs)

        rows_slots: list[list[int]] = []
        for i in range(n):
            row = [0] * total
            base = c_map[y_arr[i]] * c_stride
            row[base] = 1
            for j in range(d):
                row[base + 1 + j] = int(Xq[i, j])
            off = c_cnt * c_stride
            for pi, (j, k) in enumerate(pairs):
                row[off + pi] = int(Xq[i, j]) * int(Xq[i, k])
            rows_slots.append(row)

        col_abs = np.sum(np.abs(np.asarray(rows_slots, dtype=object)), axis=0)
        packer = choose_signed_packer(max(int(col_abs.max()), 1), total)
        sums = self.session.encrypted_packed_sums(rows_slots, packer, prefix="lda_fit")

        counts = np.zeros(c_cnt, dtype=np.float64)
        means = np.zeros((c_cnt, d), dtype=np.float64)
        for ci in range(c_cnt):
            base = ci * c_stride
            counts[ci] = float(sums[base])
            means[ci] = (np.asarray(sums[base + 1 : base + 1 + d], dtype=np.float64) / s) / counts[ci]

        xtx = np.zeros((d, d), dtype=np.float64)
        off = c_cnt * c_stride
        for pi, (j, k) in enumerate(pairs):
            val = float(sums[off + pi]) / (s * s)
            xtx[j, k] = val
            xtx[k, j] = val

        # Pooled within-class scatter S_W = X^T X - sum_c N_c mu_c mu_c^T
        scatter_w = xtx.copy()
        for ci in range(c_cnt):
            scatter_w -= counts[ci] * np.outer(means[ci], means[ci])
        cov = scatter_w / float(n)
        if self.reg_param > 0.0:
            cov = (1.0 - self.reg_param) * cov + self.reg_param * np.eye(d) * (np.trace(cov) / d)
        cov_inv = np.linalg.pinv(cov + 1e-12 * np.eye(d))
        priors = counts / float(n)
        coef = means @ cov_inv
        intercept = np.array(
            [-0.5 * float(means[ci] @ cov_inv @ means[ci]) + math.log(float(priors[ci])) for ci in range(c_cnt)],
            dtype=np.float64,
        )
        self.classes_ = classes
        self.means_ = means
        self.priors_ = priors
        self.coef_ = coef
        self.intercept_ = intercept
        return self

    def predict_log_proba(self, X: np.ndarray) -> np.ndarray:
        assert self.coef_ is not None and self.intercept_ is not None
        Xq = np.rint(np.asarray(X, dtype=np.float64) * self.feat_scale).astype(np.int64)
        Wq = np.rint(self.coef_ * self.weight_scale).astype(np.int64)
        raw = self.session.encrypted_packed_linear_score(Xq, Wq, prefix="lda_pred")
        logits = (raw.astype(np.float64) / float(self.feat_scale * self.weight_scale)) + self.intercept_.reshape(1, -1)
        return _log_softmax(logits)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return np.exp(self.predict_log_proba(X))

    def predict(self, X: np.ndarray) -> np.ndarray:
        assert self.classes_ is not None
        return self.classes_[np.argmax(self.predict_log_proba(X), axis=1)]


class BlindQuadraticDiscriminantAnalysis:
    """Zero-key encrypted QDA via radix-packed per-class covariance sufficient-stat SUM."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        reg_param: float = 0.0,
        feat_scale: int = 1000,
    ) -> None:
        self.session = session
        self.reg_param = float(reg_param)
        self.feat_scale = int(feat_scale)
        self.classes_: np.ndarray | None = None
        self.means_: np.ndarray | None = None
        self.priors_: np.ndarray | None = None
        self.covariances_: list[np.ndarray] = []

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindQuadraticDiscriminantAnalysis":
        X_arr = np.asarray(X, dtype=np.float64)
        y_arr = np.asarray(y).reshape(-1)
        classes = np.unique(y_arr)
        n, d = X_arr.shape
        c_cnt = len(classes)
        c_map = {c: idx for idx, c in enumerate(classes)}
        pairs = [(j, k) for j in range(d) for k in range(j, d)]
        s = float(self.feat_scale)
        Xq = np.rint(X_arr * s).astype(np.int64)
        stride = 1 + d + len(pairs)
        total = c_cnt * stride

        rows_slots: list[list[int]] = []
        for i in range(n):
            row = [0] * total
            base = c_map[y_arr[i]] * stride
            row[base] = 1
            for j in range(d):
                row[base + 1 + j] = int(Xq[i, j])
            for pi, (j, k) in enumerate(pairs):
                row[base + 1 + d + pi] = int(Xq[i, j]) * int(Xq[i, k])
            rows_slots.append(row)

        col_abs = np.sum(np.abs(np.asarray(rows_slots, dtype=object)), axis=0)
        packer = choose_signed_packer(max(int(col_abs.max()), 1), total)
        sums = self.session.encrypted_packed_sums(rows_slots, packer, prefix="qda_fit")

        counts = np.zeros(c_cnt, dtype=np.float64)
        means = np.zeros((c_cnt, d), dtype=np.float64)
        covs: list[np.ndarray] = []
        for ci in range(c_cnt):
            base = ci * stride
            nc = float(sums[base])
            counts[ci] = nc
            mu = (np.asarray(sums[base + 1 : base + 1 + d], dtype=np.float64) / s) / nc
            means[ci] = mu
            xtx = np.zeros((d, d), dtype=np.float64)
            for pi, (j, k) in enumerate(pairs):
                val = float(sums[base + 1 + d + pi]) / (s * s)
                xtx[j, k] = val
                xtx[k, j] = val
            cov = (xtx - nc * np.outer(mu, mu)) / max(nc - 1.0, 1.0)
            if self.reg_param > 0.0:
                cov = (1.0 - self.reg_param) * cov + self.reg_param * np.eye(d)
            covs.append(cov + 1e-9 * np.eye(d))

        self.classes_ = classes
        self.means_ = means
        self.priors_ = counts / float(n)
        self.covariances_ = covs
        return self

    def predict_log_proba(self, X: np.ndarray) -> np.ndarray:
        assert self.means_ is not None and self.priors_ is not None
        X_arr = np.asarray(X, dtype=np.float64)
        c_cnt = len(self.priors_)
        jll = np.zeros((X_arr.shape[0], c_cnt), dtype=np.float64)
        for ci in range(c_cnt):
            cov = self.covariances_[ci]
            sign, logdet = np.linalg.slogdet(cov)
            inv_cov = np.linalg.pinv(cov)
            diff = X_arr - self.means_[ci]
            quad = np.einsum("ij,jk,ik->i", diff, inv_cov, diff)
            jll[:, ci] = math.log(float(self.priors_[ci])) - 0.5 * (logdet + quad)
        return _log_softmax(jll)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return np.exp(self.predict_log_proba(X))

    def predict(self, X: np.ndarray) -> np.ndarray:
        assert self.classes_ is not None
        return self.classes_[np.argmax(self.predict_log_proba(X), axis=1)]
