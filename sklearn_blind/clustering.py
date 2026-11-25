"""Family 6: Zero-Key Blind Clustering & Nearest Centroid (NearestCentroid, KMeans)."""

from __future__ import annotations

import numpy as np

from .connector import BlindOlapSession
from .packing import choose_signed_packer


def _encrypted_centroid_aggregation(
    session: BlindOlapSession,
    X_arr: np.ndarray,
    labels: np.ndarray,
    n_groups: int,
    feat_scale: int,
    prefix: str,
) -> tuple[np.ndarray, np.ndarray]:
    """Compute per-cluster (count, sum x) via IND-CPA {0, 1} indicators and PLWE0001 SUM."""
    n, d = X_arr.shape
    s = float(feat_scale)
    Xq = np.rint(X_arr * s).astype(np.int64)
    stride = 1 + d
    total = n_groups * stride
    rows_slots: list[list[int]] = []
    for i in range(n):
        row = [0] * total
        base = int(labels[i]) * stride
        row[base] = 1
        for j in range(d):
            row[base + 1 + j] = int(Xq[i, j])
        rows_slots.append(row)
    col_abs = np.sum(np.abs(np.asarray(rows_slots, dtype=object)), axis=0)
    packer = choose_signed_packer(max(int(col_abs.max()), 1), total)
    sums = session.encrypted_packed_sums(rows_slots, packer, prefix=prefix)
    counts = np.zeros(n_groups, dtype=np.float64)
    centers = np.zeros((n_groups, d), dtype=np.float64)
    for g in range(n_groups):
        base = g * stride
        counts[g] = float(sums[base])
        if counts[g] > 0.0:
            centers[g] = (np.asarray(sums[base + 1 : base + 1 + d], dtype=np.float64) / s) / counts[g]
    return counts, centers


class BlindNearestCentroid:
    """Zero-key encrypted NearestCentroid: packed SUM fit + linear WEIGHTED_SUM scoring."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        feat_scale: int = 1000,
        weight_scale: int = 1000,
    ) -> None:
        self.session = session
        self.feat_scale = int(feat_scale)
        self.weight_scale = int(weight_scale)
        self.classes_: np.ndarray | None = None
        self.centroids_: np.ndarray | None = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindNearestCentroid":
        X_arr = np.asarray(X, dtype=np.float64)
        y_arr = np.asarray(y).reshape(-1)
        classes = np.unique(y_arr)
        c_map = {c: idx for idx, c in enumerate(classes)}
        labels = np.asarray([c_map[v] for v in y_arr], dtype=np.int64)
        _, centers = _encrypted_centroid_aggregation(
            self.session, X_arr, labels, len(classes), self.feat_scale, prefix="nc_fit"
        )
        self.classes_ = classes
        self.centroids_ = centers
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        assert self.classes_ is not None and self.centroids_ is not None
        # argmin_c ||x - mu_c||^2 == argmax_c (2 * mu_c . x - ||mu_c||^2)
        X_arr = np.asarray(X, dtype=np.float64)
        Xq = np.rint(X_arr * self.feat_scale).astype(np.int64)
        Wq = np.rint(2.0 * self.centroids_ * self.weight_scale).astype(np.int64)
        raw = self.session.encrypted_packed_linear_score(Xq, Wq, prefix="nc_pred")
        scores = (raw.astype(np.float64) / float(self.feat_scale * self.weight_scale)) - np.sum(
            self.centroids_**2, axis=1
        ).reshape(1, -1)
        return self.classes_[np.argmax(scores, axis=1)]


class BlindKMeans:
    """Zero-key encrypted KMeans: every M-step aggregates cluster means via PLWE0001 SUM."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        n_clusters: int = 3,
        max_iter: int = 10,
        tol: float = 1e-4,
        random_state: int = 42,
        feat_scale: int = 1000,
        weight_scale: int = 1000,
    ) -> None:
        self.session = session
        self.n_clusters = int(n_clusters)
        self.max_iter = int(max_iter)
        self.tol = float(tol)
        self.random_state = int(random_state)
        self.feat_scale = int(feat_scale)
        self.weight_scale = int(weight_scale)
        self.cluster_centers_: np.ndarray | None = None
        self.labels_: np.ndarray | None = None
        self.n_iter_: int = 0

    def _init_centers_kmeans_pp(self, X_arr: np.ndarray) -> np.ndarray:
        rng = np.random.default_rng(self.random_state)
        n = X_arr.shape[0]
        centers = [X_arr[int(rng.integers(0, n))].copy()]
        for _ in range(1, self.n_clusters):
            dists = np.min(
                np.stack([np.sum((X_arr - c) ** 2, axis=1) for c in centers], axis=1), axis=1
            )
            probs = dists / max(float(np.sum(dists)), 1e-15)
            idx = int(rng.choice(n, p=probs))
            centers.append(X_arr[idx].copy())
        return np.vstack(centers)

    def fit(
        self, X: np.ndarray, init_centers: np.ndarray | None = None
    ) -> "BlindKMeans":
        X_arr = np.asarray(X, dtype=np.float64)
        centers = (
            np.asarray(init_centers, dtype=np.float64).copy()
            if init_centers is not None
            else self._init_centers_kmeans_pp(X_arr)
        )
        labels = np.zeros(X_arr.shape[0], dtype=np.int64)
        for it in range(1, self.max_iter + 1):
            sq_dists = np.sum((X_arr[:, None, :] - centers[None, :, :]) ** 2, axis=2)
            labels = np.argmin(sq_dists, axis=1)
            counts, new_centers = _encrypted_centroid_aggregation(
                self.session, X_arr, labels, self.n_clusters, self.feat_scale, prefix="km_mstep"
            )
            for k_idx in range(self.n_clusters):
                if counts[k_idx] == 0.0:
                    new_centers[k_idx] = centers[k_idx]
            shift = float(np.linalg.norm(new_centers - centers))
            centers = new_centers
            self.n_iter_ = it
            if shift <= self.tol:
                break
        self.cluster_centers_ = centers
        self.labels_ = labels
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        assert self.cluster_centers_ is not None
        X_arr = np.asarray(X, dtype=np.float64)
        Xq = np.rint(X_arr * self.feat_scale).astype(np.int64)
        Wq = np.rint(2.0 * self.cluster_centers_ * self.weight_scale).astype(np.int64)
        raw = self.session.encrypted_packed_linear_score(Xq, Wq, prefix="km_pred")
        scores = (raw.astype(np.float64) / float(self.feat_scale * self.weight_scale)) - np.sum(
            self.cluster_centers_**2, axis=1
        ).reshape(1, -1)
        return np.argmax(scores, axis=1)
