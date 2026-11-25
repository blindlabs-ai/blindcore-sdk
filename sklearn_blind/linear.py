"""Families 2 & 3: Zero-Key Blind Linear Classifiers and Regressors."""

from __future__ import annotations

import numpy as np

from .connector import BlindOlapSession
from .packing import choose_signed_packer


def _encrypted_gram_stats(
    session: BlindOlapSession,
    X: np.ndarray,
    Y: np.ndarray,
    feat_scale: int,
    prefix: str,
) -> tuple[int, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Compute (N, sum X, sum Y, X^T X, X^T Y) via zero-key radix-packed PLWE0001 SUM."""
    X_arr = np.asarray(X, dtype=np.float64)
    Y_arr = np.asarray(Y, dtype=np.float64)
    if Y_arr.ndim == 1:
        Y_arr = Y_arr.reshape(-1, 1)
    n_samples, d = X_arr.shape
    m = Y_arr.shape[1]
    s = float(feat_scale)
    Xq = np.rint(X_arr * s).astype(np.int64)
    Yq = np.rint(Y_arr * s).astype(np.int64)

    pairs = [(j, k) for j in range(d) for k in range(j, d)]
    rows_slots: list[list[int]] = []
    max_abs = n_samples
    for i in range(n_samples):
        row = [1]
        row.extend(int(Xq[i, j]) for j in range(d))
        row.extend(int(Yq[i, c]) for c in range(m))
        row.extend(int(Xq[i, j]) * int(Xq[i, k]) for j, k in pairs)
        row.extend(int(Xq[i, j]) * int(Yq[i, c]) for j in range(d) for c in range(m))
        rows_slots.append(row)

    col_abs = np.sum(np.abs(np.asarray(rows_slots, dtype=object)), axis=0)
    max_abs = max(int(col_abs.max()) if col_abs.size else 1, 1)
    packer = choose_signed_packer(max_abs, len(rows_slots[0]))
    sums = session.encrypted_packed_sums(rows_slots, packer, prefix=prefix)

    pos = 0
    n_val = int(sums[pos]); pos += 1
    sum_x = np.asarray(sums[pos : pos + d], dtype=np.float64) / s; pos += d
    sum_y = np.asarray(sums[pos : pos + m], dtype=np.float64) / s; pos += m
    xtx = np.zeros((d, d), dtype=np.float64)
    for j, k in pairs:
        val = float(sums[pos]) / (s * s); pos += 1
        xtx[j, k] = val
        xtx[k, j] = val
    xty = np.zeros((d, m), dtype=np.float64)
    for j in range(d):
        for c in range(m):
            xty[j, c] = float(sums[pos]) / (s * s); pos += 1
    return n_val, sum_x, sum_y, xtx, xty


class _EncryptedLinearPredictorMixin:
    session: BlindOlapSession
    feat_scale: int
    weight_scale: int
    coef_: np.ndarray
    intercept_: np.ndarray

    def _encrypted_decision(self, X: np.ndarray, prefix: str) -> np.ndarray:
        X_arr = np.asarray(X, dtype=np.float64)
        Xq = np.rint(X_arr * self.feat_scale).astype(np.int64)
        coef_2d = np.atleast_2d(self.coef_)
        Wq = np.rint(coef_2d * self.weight_scale).astype(np.int64)
        raw = self.session.encrypted_packed_linear_score(Xq, Wq, prefix=prefix)
        scores = raw.astype(np.float64) / float(self.feat_scale * self.weight_scale)
        return scores + np.asarray(self.intercept_, dtype=np.float64).reshape(1, -1)


class BlindLinearRegression(_EncryptedLinearPredictorMixin):
    """Zero-key encrypted OLS LinearRegression via homomorphic Gram matrix SUM."""

    def __init__(
        self, session: BlindOlapSession, *, feat_scale: int = 1000, weight_scale: int = 1000
    ) -> None:
        self.session = session
        self.feat_scale = int(feat_scale)
        self.weight_scale = int(weight_scale)
        self.coef_ = np.zeros(0)
        self.intercept_ = np.zeros(1)

    def fit(self, X: np.ndarray, y: np.ndarray, alpha: float = 0.0) -> "BlindLinearRegression":
        n, sx, sy, xtx, xty = _encrypted_gram_stats(
            self.session, X, y, self.feat_scale, prefix="linreg_fit"
        )
        mx = sx / n
        my = sy / n
        xc_t_xc = xtx - n * np.outer(mx, mx)
        xc_t_yc = xty - n * np.outer(mx, my)
        d = xc_t_xc.shape[0]
        if alpha > 0.0:
            w = np.linalg.solve(xc_t_xc + alpha * np.eye(d), xc_t_yc)
        else:
            w = np.linalg.lstsq(xc_t_xc, xc_t_yc, rcond=None)[0]
        self.coef_ = w[:, 0]
        self.intercept_ = np.array([float(my[0] - mx @ self.coef_)], dtype=np.float64)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self._encrypted_decision(X, prefix="linreg_pred")[:, 0]

    def score(self, X: np.ndarray, y: np.ndarray) -> float:
        yt = np.asarray(y, dtype=np.float64).reshape(-1)
        yp = self.predict(X)
        ss_res = float(np.sum((yt - yp) ** 2))
        ss_tot = float(np.sum((yt - np.mean(yt)) ** 2))
        return 1.0 - ss_res / max(ss_tot, 1e-15)


class BlindRidge(BlindLinearRegression):
    """Zero-key encrypted Ridge regression matching sklearn.linear_model.Ridge."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        alpha: float = 1.0,
        feat_scale: int = 1000,
        weight_scale: int = 1000,
    ) -> None:
        super().__init__(session, feat_scale=feat_scale, weight_scale=weight_scale)
        self.alpha = float(alpha)

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindRidge":  # type: ignore[override]
        return super().fit(X, y, alpha=self.alpha)


class BlindLasso(BlindLinearRegression):
    """Zero-key encrypted Lasso: server sums (X^T X, X^T y); client solves L1 coordinate descent."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        alpha: float = 0.1,
        max_iter: int = 1000,
        tol: float = 1e-7,
        feat_scale: int = 1000,
        weight_scale: int = 1000,
    ) -> None:
        super().__init__(session, feat_scale=feat_scale, weight_scale=weight_scale)
        self.alpha = float(alpha)
        self.max_iter = int(max_iter)
        self.tol = float(tol)

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindLasso":  # type: ignore[override]
        n, sx, sy, xtx, xty = _encrypted_gram_stats(
            self.session, X, y, self.feat_scale, prefix="lasso_fit"
        )
        mx = sx / n
        my = sy / n
        G = (xtx - n * np.outer(mx, mx)) / float(n)
        r = (xty[:, 0] - n * mx * my[0]) / float(n)
        d = G.shape[0]
        w = np.zeros(d, dtype=np.float64)
        for _ in range(self.max_iter):
            w_old = w.copy()
            for j in range(d):
                gjj = G[j, j]
                if gjj <= 1e-15:
                    w[j] = 0.0
                    continue
                rho = r[j] - (G[j] @ w - gjj * w[j])
                if rho > self.alpha:
                    w[j] = (rho - self.alpha) / gjj
                elif rho < -self.alpha:
                    w[j] = (rho + self.alpha) / gjj
                else:
                    w[j] = 0.0
            if float(np.max(np.abs(w - w_old))) < self.tol:
                break
        self.coef_ = w
        self.intercept_ = np.array([float(my[0] - mx @ w)], dtype=np.float64)
        return self


class BlindRidgeClassifier(_EncryptedLinearPredictorMixin):
    """Zero-key encrypted RidgeClassifier matching sklearn.linear_model.RidgeClassifier."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        alpha: float = 1.0,
        feat_scale: int = 1000,
        weight_scale: int = 1000,
    ) -> None:
        self.session = session
        self.alpha = float(alpha)
        self.feat_scale = int(feat_scale)
        self.weight_scale = int(weight_scale)
        self.classes_: np.ndarray | None = None
        self.coef_ = np.zeros((1, 1))
        self.intercept_ = np.zeros(1)

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindRidgeClassifier":
        y_arr = np.asarray(y).reshape(-1)
        self.classes_ = np.unique(y_arr)
        if len(self.classes_) == 2:
            Y = np.where(y_arr == self.classes_[1], 1.0, -1.0).reshape(-1, 1)
        else:
            Y = np.where(y_arr[:, None] == self.classes_[None, :], 1.0, -1.0)
        n, sx, sy, xtx, xty = _encrypted_gram_stats(
            self.session, X, Y, self.feat_scale, prefix="ridge_clf"
        )
        mx = sx / n
        my = sy / n
        xc_t_xc = xtx - n * np.outer(mx, mx)
        xc_t_yc = xty - n * np.outer(mx, my)
        W = np.linalg.solve(xc_t_xc + self.alpha * np.eye(xc_t_xc.shape[0]), xc_t_yc)
        self.coef_ = W.T
        self.intercept_ = my - mx @ W
        return self

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        sc = self._encrypted_decision(X, prefix="ridge_dec")
        return sc[:, 0] if sc.shape[1] == 1 else sc

    def predict(self, X: np.ndarray) -> np.ndarray:
        assert self.classes_ is not None
        dec = self.decision_function(X)
        if dec.ndim == 1:
            return np.where(dec >= 0.0, self.classes_[1], self.classes_[0])
        return self.classes_[np.argmax(dec, axis=1)]


class BlindLogisticRegression(_EncryptedLinearPredictorMixin):
    """Zero-key encrypted LogisticRegression via encrypted Newton-IRLS SUM + WEIGHTED_SUM."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        C: float = 1.0,
        max_iter: int = 8,
        feat_scale: int = 1000,
        weight_scale: int = 1000,
    ) -> None:
        self.session = session
        self.C = float(C)
        self.max_iter = int(max_iter)
        self.feat_scale = int(feat_scale)
        self.weight_scale = int(weight_scale)
        self.classes_: np.ndarray | None = None
        self.coef_ = np.zeros((1, 1))
        self.intercept_ = np.zeros(1)

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindLogisticRegression":
        X_arr = np.asarray(X, dtype=np.float64)
        y_arr = np.asarray(y).reshape(-1)
        self.classes_ = np.unique(y_arr)
        if len(self.classes_) != 2:
            raise ValueError("BlindLogisticRegression supports binary classification")
        yb = (y_arr == self.classes_[1]).astype(np.float64)
        n, d = X_arr.shape
        Xa = np.hstack([X_arr, np.ones((n, 1), dtype=np.float64)])
        da = d + 1
        pairs = [(j, k) for j in range(da) for k in range(j, da)]
        theta = np.zeros(da, dtype=np.float64)
        lam = 1.0 / self.C
        g_scale = float(self.feat_scale)

        for _ in range(self.max_iter):
            z = np.clip(Xa @ theta, -30.0, 30.0)
            p = 1.0 / (1.0 + np.exp(-z))
            w_diag = np.maximum(p * (1.0 - p), 1e-6)
            rows_slots: list[list[int]] = []
            for i in range(n):
                gi = (p[i] - yb[i]) * Xa[i]
                row = [int(round(gi[j] * g_scale)) for j in range(da)]
                wi = w_diag[i]
                row.extend(int(round(wi * Xa[i, j] * Xa[i, k] * g_scale)) for j, k in pairs)
                rows_slots.append(row)
            col_abs = np.sum(np.abs(np.asarray(rows_slots, dtype=object)), axis=0)
            packer = choose_signed_packer(max(int(col_abs.max()), 1), len(rows_slots[0]))
            sums = self.session.encrypted_packed_sums(rows_slots, packer, prefix="logreg_irls")
            grad = np.asarray(sums[:da], dtype=np.float64) / g_scale
            H = np.zeros((da, da), dtype=np.float64)
            pos = da
            for j, k in pairs:
                val = float(sums[pos]) / g_scale; pos += 1
                H[j, k] = val
                H[k, j] = val
            reg = np.diag([lam] * d + [0.0])
            grad[:d] += lam * theta[:d]
            step = np.linalg.solve(H + reg + 1e-8 * np.eye(da), grad)
            theta -= step
            if float(np.linalg.norm(step)) < 1e-6:
                break
        self.coef_ = theta[:d].reshape(1, -1)
        self.intercept_ = np.array([theta[d]], dtype=np.float64)
        return self

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        return self._encrypted_decision(X, prefix="logreg_dec")[:, 0]

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        z = np.clip(self.decision_function(X), -30.0, 30.0)
        p1 = 1.0 / (1.0 + np.exp(-z))
        return np.column_stack([1.0 - p1, p1])

    def predict(self, X: np.ndarray) -> np.ndarray:
        assert self.classes_ is not None
        return np.where(self.decision_function(X) >= 0.0, self.classes_[1], self.classes_[0])


class BlindSGDClassifier(BlindLogisticRegression):
    """Zero-key encrypted federated-gradient SGDClassifier (L2 log-loss)."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        alpha: float = 0.001,
        lr: float = 0.5,
        max_iter: int = 12,
        feat_scale: int = 1000,
        weight_scale: int = 1000,
    ) -> None:
        super().__init__(
            session, C=1.0 / max(alpha, 1e-9), max_iter=max_iter,
            feat_scale=feat_scale, weight_scale=weight_scale,
        )
        self.alpha = float(alpha)
        self.lr = float(lr)

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindSGDClassifier":
        X_arr = np.asarray(X, dtype=np.float64)
        y_arr = np.asarray(y).reshape(-1)
        self.classes_ = np.unique(y_arr)
        yb = (y_arr == self.classes_[1]).astype(np.float64)
        n, d = X_arr.shape
        Xa = np.hstack([X_arr, np.ones((n, 1), dtype=np.float64)])
        theta = np.zeros(d + 1, dtype=np.float64)
        g_scale = float(self.feat_scale)
        for _ in range(self.max_iter):
            p = 1.0 / (1.0 + np.exp(-np.clip(Xa @ theta, -30.0, 30.0)))
            rows_slots = [
                [int(round((p[i] - yb[i]) * Xa[i, j] * g_scale)) for j in range(d + 1)]
                for i in range(n)
            ]
            col_abs = np.sum(np.abs(np.asarray(rows_slots, dtype=object)), axis=0)
            packer = choose_signed_packer(max(int(col_abs.max()), 1), d + 1)
            g_sum = np.asarray(
                self.session.encrypted_packed_sums(rows_slots, packer, prefix="sgd_grad"),
                dtype=np.float64,
            ) / (g_scale * n)
            g_sum[:d] += self.alpha * theta[:d]
            theta -= self.lr * g_sum
        self.coef_ = theta[:d].reshape(1, -1)
        self.intercept_ = np.array([theta[d]], dtype=np.float64)
        return self


class BlindLinearSVC(BlindLogisticRegression):
    """Zero-key encrypted LinearSVC via encrypted squared-hinge IRLS SUM + WEIGHTED_SUM."""

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindLinearSVC":
        X_arr = np.asarray(X, dtype=np.float64)
        y_arr = np.asarray(y).reshape(-1)
        self.classes_ = np.unique(y_arr)
        ys = np.where(y_arr == self.classes_[1], 1.0, -1.0)
        n, d = X_arr.shape
        Xa = np.hstack([X_arr, np.ones((n, 1), dtype=np.float64)])
        da = d + 1
        pairs = [(j, k) for j in range(da) for k in range(j, da)]
        theta = np.zeros(da, dtype=np.float64)
        g_scale = float(self.feat_scale)
        for _ in range(self.max_iter):
            margins = ys * (Xa @ theta)
            active = (margins < 1.0).astype(np.float64)
            rows_slots = []
            for i in range(n):
                ai = active[i]
                gi = -2.0 * self.C * ai * ys[i] * (1.0 - margins[i]) * Xa[i]
                row = [int(round(gi[j] * g_scale)) for j in range(da)]
                row.extend(
                    int(round(2.0 * self.C * ai * Xa[i, j] * Xa[i, k] * g_scale))
                    for j, k in pairs
                )
                rows_slots.append(row)
            col_abs = np.sum(np.abs(np.asarray(rows_slots, dtype=object)), axis=0)
            packer = choose_signed_packer(max(int(col_abs.max()), 1), len(rows_slots[0]))
            sums = self.session.encrypted_packed_sums(rows_slots, packer, prefix="lsvc_irls")
            grad = np.asarray(sums[:da], dtype=np.float64) / g_scale
            H = np.zeros((da, da), dtype=np.float64)
            pos = da
            for j, k in pairs:
                val = float(sums[pos]) / g_scale; pos += 1
                H[j, k] = val
                H[k, j] = val
            reg = np.diag([1.0] * d + [0.0])
            grad[:d] += theta[:d]
            step = np.linalg.solve(H + reg + 1e-6 * np.eye(da), grad)
            theta -= step
            if float(np.linalg.norm(step)) < 1e-6:
                break
        self.coef_ = theta[:d].reshape(1, -1)
        self.intercept_ = np.array([theta[d]], dtype=np.float64)
        return self
