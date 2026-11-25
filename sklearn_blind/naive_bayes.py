"""Family 1: Zero-Key Blind Naive Bayes (MultinomialNB, BernoulliNB, ComplementNB)."""

from __future__ import annotations

import math
from typing import Any

import numpy as np

from .connector import BlindOlapSession
from .packing import choose_unsigned_packer


def _log_softmax(logits: np.ndarray) -> np.ndarray:
    m = np.max(logits, axis=1, keepdims=True)
    shifted = logits - m
    return shifted - np.log(np.sum(np.exp(shifted), axis=1, keepdims=True))


class _BaseBlindCountNB:
    """Shared radix-packed zero-key sufficient-stat fit and WEIGHTED_SUM scoring."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        alpha: float = 1.0,
        fit_prior: bool = True,
        score_scale: int = 2048,
    ) -> None:
        self.session = session
        self.alpha = float(alpha)
        self.fit_prior = bool(fit_prior)
        self.score_scale = int(score_scale)
        self.classes_: np.ndarray | None = None
        self.class_count_: np.ndarray | None = None
        self.feature_count_: np.ndarray | None = None
        self.class_log_prior_: np.ndarray | None = None
        self.feature_log_prob_: np.ndarray | None = None
        self._coef_delta_: np.ndarray | None = None
        self._intercept_delta_: np.ndarray | None = None

    def _preprocess_x(self, X: np.ndarray) -> np.ndarray:
        arr = np.asarray(X, dtype=np.int64)
        if arr.ndim != 2:
            raise ValueError("X must be 2D")
        if np.any(arr < 0):
            raise ValueError("count Naive Bayes requires non-negative integer inputs")
        return arr

    def _fit_encrypted_counts(self, X_int: np.ndarray, y: np.ndarray, prefix: str) -> None:
        y_arr = np.asarray(y).reshape(-1)
        if len(y_arr) != X_int.shape[0]:
            raise ValueError("X and y length mismatch")
        classes = np.unique(y_arr)
        n_classes = len(classes)
        n_samples, n_feat = X_int.shape
        class_to_idx = {c: idx for idx, c in enumerate(classes)}

        # Encode class membership strictly as IND-CPA {0, 1} / {0, x_j} indicators (0 tokens).
        stride = n_feat + 1
        total_slots = n_classes * stride
        max_col_sum = int(np.max(np.sum(X_int, axis=0))) if X_int.size else 0
        max_slot_sum = max(n_samples, max_col_sum, 1)
        packer = choose_unsigned_packer(max_slot_sum, total_slots)

        rows_slots: list[list[int]] = []
        for i in range(n_samples):
            row = [0] * total_slots
            c_idx = class_to_idx[y_arr[i]]
            base = c_idx * stride
            row[base] = 1
            for j in range(n_feat):
                row[base + 1 + j] = int(X_int[i, j])
            rows_slots.append(row)

        sums = self.session.encrypted_packed_sums(rows_slots, packer, prefix=prefix)
        class_count = np.zeros(n_classes, dtype=np.float64)
        feat_count = np.zeros((n_classes, n_feat), dtype=np.float64)
        for c_idx in range(n_classes):
            base = c_idx * stride
            class_count[c_idx] = float(sums[base])
            for j in range(n_feat):
                feat_count[c_idx, j] = float(sums[base + 1 + j])

        self.classes_ = classes
        self.class_count_ = class_count
        self.feature_count_ = feat_count
        if self.fit_prior:
            self.class_log_prior_ = np.log(class_count) - math.log(float(n_samples))
        else:
            self.class_log_prior_ = np.full(n_classes, -math.log(float(n_classes)), dtype=np.float64)

    def _linear_scoring_params(self) -> tuple[np.ndarray, np.ndarray]:
        assert self.feature_log_prob_ is not None and self.class_log_prior_ is not None
        return self.feature_log_prob_, self.class_log_prior_

    def _compute_delta_weights(self) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        W, b = self._linear_scoring_params()
        # Subtract class 0 so binary needs 1 relative query and C classes need C-1 queries.
        dW = W[1:] - W[0:1]
        db = b[1:] - b[0]
        W_int = np.rint(dW * self.score_scale).astype(np.int64)
        return W_int, db, W

    def predict_log_proba(self, X: np.ndarray) -> np.ndarray:
        X_int = self._preprocess_x(X)
        W_int, db, _ = self._compute_delta_weights()
        raw_scores = self.session.encrypted_packed_linear_score(
            X_int, W_int, prefix="nb_pred"
        )
        n_docs = X_int.shape[0]
        n_classes = W_int.shape[0] + 1
        rel_logits = np.zeros((n_docs, n_classes), dtype=np.float64)
        rel_logits[:, 1:] = (raw_scores.astype(np.float64) / float(self.score_scale)) + db.reshape(1, -1)
        return _log_softmax(rel_logits)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return np.exp(self.predict_log_proba(X))

    def predict(self, X: np.ndarray) -> np.ndarray:
        assert self.classes_ is not None
        log_p = self.predict_log_proba(X)
        return self.classes_[np.argmax(log_p, axis=1)]

    def predict_cohort(self, X: np.ndarray) -> np.ndarray:
        """Compute aggregate cohort log-odds over all documents in one WEIGHTED_SUM pass."""
        X_int = self._preprocess_x(X)
        W_int, db, _ = self._compute_delta_weights()
        agg = self.session.encrypted_packed_linear_score(
            X_int, W_int, prefix="nb_cohort", cohort_only=True
        )
        return (agg.astype(np.float64) / float(self.score_scale)) + float(X_int.shape[0]) * db

    def score(self, X: np.ndarray, y: np.ndarray) -> float:
        return float(np.mean(self.predict(X) == np.asarray(y).reshape(-1)))


class BlindMultinomialNB(_BaseBlindCountNB):
    """Zero-key radix-packed encrypted MultinomialNB matching sklearn.naive_bayes.MultinomialNB."""

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindMultinomialNB":
        X_int = self._preprocess_x(X)
        self._fit_encrypted_counts(X_int, y, prefix="mnb_fit")
        assert self.feature_count_ is not None
        smoothed_fc = self.feature_count_ + self.alpha
        smoothed_cc = np.sum(smoothed_fc, axis=1, keepdims=True)
        self.feature_log_prob_ = np.log(smoothed_fc) - np.log(smoothed_cc)
        return self


class BlindBernoulliNB(_BaseBlindCountNB):
    """Zero-key radix-packed encrypted BernoulliNB matching sklearn.naive_bayes.BernoulliNB."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        alpha: float = 1.0,
        binarize: float | None = 0.0,
        fit_prior: bool = True,
        score_scale: int = 2048,
    ) -> None:
        super().__init__(session, alpha=alpha, fit_prior=fit_prior, score_scale=score_scale)
        self.binarize = binarize

    def _preprocess_x(self, X: np.ndarray) -> np.ndarray:
        arr = np.asarray(X, dtype=np.float64)
        if arr.ndim != 2:
            raise ValueError("X must be 2D")
        if self.binarize is not None:
            return (arr > self.binarize).astype(np.int64)
        return (arr > 0).astype(np.int64)

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindBernoulliNB":
        X_bin = self._preprocess_x(X)
        self._fit_encrypted_counts(X_bin, y, prefix="bnb_fit")
        assert self.feature_count_ is not None and self.class_count_ is not None
        smoothed_fc = self.feature_count_ + self.alpha
        smoothed_cc = self.class_count_.reshape(-1, 1) + 2.0 * self.alpha
        self.feature_log_prob_ = np.log(smoothed_fc) - np.log(smoothed_cc)
        return self

    def _linear_scoring_params(self) -> tuple[np.ndarray, np.ndarray]:
        assert self.feature_log_prob_ is not None and self.class_log_prior_ is not None
        neg_prob = np.log(1.0 - np.exp(self.feature_log_prob_))
        W = self.feature_log_prob_ - neg_prob
        b = self.class_log_prior_ + np.sum(neg_prob, axis=1)
        return W, b


class BlindComplementNB(_BaseBlindCountNB):
    """Zero-key radix-packed encrypted ComplementNB matching sklearn.naive_bayes.ComplementNB."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        alpha: float = 1.0,
        norm: bool = False,
        score_scale: int = 2048,
    ) -> None:
        super().__init__(session, alpha=alpha, fit_prior=False, score_scale=score_scale)
        self.norm = bool(norm)

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindComplementNB":
        X_int = self._preprocess_x(X)
        self._fit_encrypted_counts(X_int, y, prefix="cnb_fit")
        assert self.feature_count_ is not None
        comp_count = np.sum(self.feature_count_, axis=0, keepdims=True) - self.feature_count_
        logged = np.log(comp_count + self.alpha) - np.log(
            np.sum(comp_count + self.alpha, axis=1, keepdims=True)
        )
        if self.norm:
            weights = logged / np.sum(np.abs(logged), axis=1, keepdims=True)
        else:
            weights = -logged
        self.feature_log_prob_ = weights
        self.class_log_prior_ = np.zeros(self.feature_count_.shape[0], dtype=np.float64)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        assert self.classes_ is not None and self.feature_log_prob_ is not None
        X_int = self._preprocess_x(X)
        W_int = np.rint(self.feature_log_prob_ * self.score_scale).astype(np.int64)
        raw = self.session.encrypted_packed_linear_score(X_int, W_int, prefix="cnb_pred")
        if len(self.classes_) == 1:
            return np.full(X_int.shape[0], self.classes_[0])
        return self.classes_[np.argmax(raw, axis=1)]
