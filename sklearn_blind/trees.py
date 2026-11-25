"""Family 5: Honest Two-Mode Trees & Ensembles (Mode 1 SQL Pushdown + Mode 2 Blind Leaf Scoring)."""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np

from .connector import BlindOlapSession, BlindSklearnConnector


def _extract_tree_leaves(tree_obj: Any) -> tuple[list[int], np.ndarray]:
    """Return leaf node IDs and normalized class probability rows for a fitted sklearn tree."""
    t = tree_obj.tree_
    leaf_ids = [int(i) for i in range(t.node_count) if t.children_left[i] == -1]
    vals = t.value[leaf_ids, 0, :].astype(np.float64)
    row_sums = np.sum(vals, axis=1, keepdims=True)
    probs = np.divide(vals, np.where(row_sums > 0.0, row_sums, 1.0))
    return leaf_ids, probs


class _BaseBlindLeafEnsemble:
    """Honest two-mode tree wrapper:
      - Mode 1 (connector): pushes stump/tree scoring to Rust SQL ML_TREE_SCORE.
      - Mode 2 (session): nonlinear threshold comparisons run client-side to form
        a {0, 1} leaf indicator bitvector, encrypted under IND-CPA PLWE0001; the
        untrusted server scores the ensemble leaf weights via WEIGHTED_SUM with 0 keys.
    """

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        weight_scale: int = 10000,
    ) -> None:
        self.session = session
        self.weight_scale = int(weight_scale)
        self.estimator_: Any = None
        self.classes_: np.ndarray | None = None
        self._trees_: list[Any] = []
        self._leaf_id_maps_: list[dict[int, int]] = []
        self._leaf_weights_: np.ndarray | None = None  # shape (n_outputs, total_leaves)
        self._bias_: np.ndarray | None = None
        self._is_gbdt_logits_: bool = False

    def _compile_trees(
        self,
        trees: Sequence[Any],
        leaf_weight_blocks: Sequence[np.ndarray],
        bias: np.ndarray,
        *,
        is_gbdt_logits: bool = False,
    ) -> None:
        self._trees_ = list(trees)
        self._leaf_id_maps_ = []
        for tr, blk in zip(trees, leaf_weight_blocks):
            t = tr.tree_
            leaf_ids = [int(i) for i in range(t.node_count) if t.children_left[i] == -1]
            if len(leaf_ids) != blk.shape[0]:
                raise ValueError("leaf weight block mismatch")
            self._leaf_id_maps_.append({lid: idx for idx, lid in enumerate(leaf_ids)})
        stacked = np.vstack(leaf_weight_blocks)  # (total_leaves, n_out)
        self._leaf_weights_ = stacked.T
        self._bias_ = np.asarray(bias, dtype=np.float64)
        self._is_gbdt_logits_ = bool(is_gbdt_logits)

    def _encode_leaf_indicators(self, X: np.ndarray) -> np.ndarray:
        X_arr = np.asarray(X, dtype=np.float64)
        n = X_arr.shape[0]
        total_leaves = sum(len(m) for m in self._leaf_id_maps_)
        Z = np.zeros((n, total_leaves), dtype=np.int64)
        offset = 0
        for tr, lmap in zip(self._trees_, self._leaf_id_maps_):
            applied = tr.apply(X_arr)
            for i, lid in enumerate(applied):
                Z[i, offset + lmap[int(lid)]] = 1
            offset += len(lmap)
        return Z

    def _encrypted_raw_score(self, X: np.ndarray, prefix: str) -> np.ndarray:
        assert self._leaf_weights_ is not None and self._bias_ is not None
        Z = self._encode_leaf_indicators(X)
        Wq = np.rint(self._leaf_weights_ * self.weight_scale).astype(np.int64)
        raw = self.session.encrypted_packed_linear_score(Z, Wq, prefix=prefix)
        return (raw.astype(np.float64) / float(self.weight_scale)) + self._bias_.reshape(1, -1)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        sc = self._encrypted_raw_score(X, prefix="tree_leaf")
        if self._is_gbdt_logits_:
            if sc.shape[1] == 1:
                p1 = 1.0 / (1.0 + np.exp(-np.clip(sc[:, 0], -30.0, 30.0)))
                return np.column_stack([1.0 - p1, p1])
            m = np.max(sc, axis=1, keepdims=True)
            ex = np.exp(sc - m)
            return ex / np.sum(ex, axis=1, keepdims=True)
        sc = np.clip(sc, 0.0, 1.0)
        denom = np.sum(sc, axis=1, keepdims=True)
        return np.divide(sc, np.where(denom > 0.0, denom, 1.0))

    def predict(self, X: np.ndarray) -> np.ndarray:
        assert self.classes_ is not None
        return self.classes_[np.argmax(self.predict_proba(X), axis=1)]

    @staticmethod
    def pushdown_sql_stump(
        connector: BlindSklearnConnector,
        table: str,
        feature_names: Sequence[str],
        stump_tree: Any,
    ) -> np.ndarray:
        """Mode 1 helper: push a depth-1 decision stump directly to Rust SQL ML_TREE_SCORE."""
        t = stump_tree.tree_
        feat_idx = int(t.feature[0])
        thr = float(t.threshold[0])
        l_id = int(t.children_left[0])
        r_id = int(t.children_right[0])
        l_val = float(t.value[l_id, 0, -1] / max(float(np.sum(t.value[l_id, 0])), 1.0))
        r_val = float(t.value[r_id, 0, -1] / max(float(np.sum(t.value[r_id, 0])), 1.0))
        return connector.pushdown_tree_ensemble_score(
            table, [(feature_names[feat_idx], thr, l_val, r_val)]
        )


class BlindDecisionTreeClassifier(_BaseBlindLeafEnsemble):
    """Two-mode DecisionTreeClassifier (Mode 1 SQL ML_TREE_SCORE / Mode 2 blind leaf scoring)."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        max_depth: int = 3,
        random_state: int = 42,
        weight_scale: int = 10000,
    ) -> None:
        super().__init__(session, weight_scale=weight_scale)
        self.max_depth = int(max_depth)
        self.random_state = int(random_state)

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindDecisionTreeClassifier":
        from sklearn.tree import DecisionTreeClassifier

        est = DecisionTreeClassifier(max_depth=self.max_depth, random_state=self.random_state)
        est.fit(X, y)
        return self.fit_from_sklearn(est)

    def fit_from_sklearn(self, est: Any) -> "BlindDecisionTreeClassifier":
        self.estimator_ = est
        self.classes_ = np.asarray(est.classes_)
        _, probs = _extract_tree_leaves(est)
        self._compile_trees([est], [probs], np.zeros(len(self.classes_), dtype=np.float64))
        return self


class BlindRandomForestClassifier(_BaseBlindLeafEnsemble):
    """Two-mode RandomForestClassifier with encrypted server leaf-ensemble WEIGHTED_SUM."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        n_estimators: int = 5,
        max_depth: int = 3,
        random_state: int = 42,
        weight_scale: int = 10000,
    ) -> None:
        super().__init__(session, weight_scale=weight_scale)
        self.n_estimators = int(n_estimators)
        self.max_depth = int(max_depth)
        self.random_state = int(random_state)

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindRandomForestClassifier":
        from sklearn.ensemble import RandomForestClassifier

        est = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            random_state=self.random_state,
        )
        est.fit(X, y)
        return self.fit_from_sklearn(est)

    def fit_from_sklearn(self, est: Any) -> "BlindRandomForestClassifier":
        self.estimator_ = est
        self.classes_ = np.asarray(est.classes_)
        n_est = float(len(est.estimators_))
        blocks = [_extract_tree_leaves(tr)[1] / n_est for tr in est.estimators_]
        self._compile_trees(est.estimators_, blocks, np.zeros(len(self.classes_), dtype=np.float64))
        return self


class BlindGradientBoostingClassifier(_BaseBlindLeafEnsemble):
    """Two-mode GradientBoostingClassifier with encrypted server additive leaf WEIGHTED_SUM."""

    def __init__(
        self,
        session: BlindOlapSession,
        *,
        n_estimators: int = 8,
        max_depth: int = 2,
        learning_rate: float = 0.1,
        random_state: int = 42,
        weight_scale: int = 10000,
    ) -> None:
        super().__init__(session, weight_scale=weight_scale)
        self.n_estimators = int(n_estimators)
        self.max_depth = int(max_depth)
        self.learning_rate = float(learning_rate)
        self.random_state = int(random_state)

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BlindGradientBoostingClassifier":
        from sklearn.ensemble import GradientBoostingClassifier

        est = GradientBoostingClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            learning_rate=self.learning_rate,
            random_state=self.random_state,
        )
        est.fit(X, y)
        return self.fit_from_sklearn(est)

    def fit_from_sklearn(self, est: Any) -> "BlindGradientBoostingClassifier":
        self.estimator_ = est
        self.classes_ = np.asarray(est.classes_)
        lr = float(est.learning_rate)
        n_stages, k_out = est.estimators_.shape
        trees: list[Any] = []
        blocks: list[np.ndarray] = []
        for s_idx in range(n_stages):
            for c_idx in range(k_out):
                tr = est.estimators_[s_idx, c_idx]
                t = tr.tree_
                leaf_ids = [int(i) for i in range(t.node_count) if t.children_left[i] == -1]
                blk = np.zeros((len(leaf_ids), k_out), dtype=np.float64)
                for row_i, lid in enumerate(leaf_ids):
                    blk[row_i, c_idx] = lr * float(t.value[lid, 0, 0])
                trees.append(tr)
                blocks.append(blk)
        # Initial raw prior logit from sklearn's init_ estimator
        dummy = np.zeros((1, est.n_features_in_), dtype=np.float64)
        init_raw = est._raw_predict_init(dummy)[0]
        self._compile_trees(trees, blocks, init_raw, is_gbdt_logits=True)
        return self
