"""
Multi-Modal Feature Ensemble Model (Random Forest / GBDT) for PhishShift.
Model 3 for FR-02: Pure NumPy non-linear ensemble combining textual & structural cues.
Portable, zero external C++ DLL dependencies.
"""

import json
import math
import re
import numpy as np
from typing import List, Dict, Any, Tuple
from src.models.tfidf_linear import SimpleTfidfVectorizer


class SimpleDecisionNode:
    def __init__(self, feature_idx: int = -1, threshold: float = 0.0, value: float = 0.0, left=None, right=None):
        self.feature_idx = feature_idx
        self.threshold = threshold
        self.value = value
        self.left = left
        self.right = right

    def is_leaf(self) -> bool:
        return self.left is None and self.right is None

    def to_dict(self) -> Dict[str, Any]:
        if self.is_leaf():
            return {"value": round(float(self.value), 5)}
        return {
            "feature_idx": int(self.feature_idx),
            "threshold": round(float(self.threshold), 5),
            "left": self.left.to_dict() if self.left else None,
            "right": self.right.to_dict() if self.right else None
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "SimpleDecisionNode":
        if "value" in d and "left" not in d:
            return SimpleDecisionNode(value=d["value"])
        node = SimpleDecisionNode(feature_idx=d["feature_idx"], threshold=d["threshold"])
        if d.get("left"):
            node.left = SimpleDecisionNode.from_dict(d["left"])
        if d.get("right"):
            node.right = SimpleDecisionNode.from_dict(d["right"])
        return node


class SimpleDecisionTree:
    def __init__(self, max_depth: int = 4, min_samples_split: int = 5, max_features: int = 15):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.max_features = max_features
        self.root: SimpleDecisionNode = None

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.root = self._build_tree(X, y, depth=0)

    def _build_tree(self, X: np.ndarray, y: np.ndarray, depth: int) -> SimpleDecisionNode:
        n_samples, n_features = X.shape
        mean_y = float(np.mean(y)) if len(y) > 0 else 0.5

        if depth >= self.max_depth or n_samples < self.min_samples_split or np.all(y == y[0]):
            return SimpleDecisionNode(value=mean_y)

        # Random feature subset selection
        feature_indices = np.random.choice(n_features, size=min(self.max_features, n_features), replace=False)

        best_feat, best_thresh, best_gain = None, None, -1.0
        best_left_idx, best_right_idx = None, None
        curr_var = np.var(y) * n_samples

        for f_idx in feature_indices:
            values = np.unique(X[:, f_idx])
            if len(values) <= 1:
                continue
            # Check candidate split thresholds
            candidate_thresholds = values[::max(1, len(values)//6)]
            for thresh in candidate_thresholds:
                left_mask = X[:, f_idx] <= thresh
                right_mask = ~left_mask
                if np.sum(left_mask) < 2 or np.sum(right_mask) < 2:
                    continue

                left_var = np.var(y[left_mask]) * np.sum(left_mask)
                right_var = np.var(y[right_mask]) * np.sum(right_mask)
                gain = curr_var - (left_var + right_var)

                if gain > best_gain:
                    best_gain = gain
                    best_feat = f_idx
                    best_thresh = thresh
                    best_left_idx = left_mask
                    best_right_idx = right_mask

        if best_gain <= 0.001 or best_feat is None:
            return SimpleDecisionNode(value=mean_y)

        left_node = self._build_tree(X[best_left_idx], y[best_left_idx], depth + 1)
        right_node = self._build_tree(X[best_right_idx], y[best_right_idx], depth + 1)
        return SimpleDecisionNode(feature_idx=best_feat, threshold=best_thresh, left=left_node, right=right_node)

    def predict_row(self, x: np.ndarray) -> float:
        node = self.root
        while not node.is_leaf():
            if x[node.feature_idx] <= node.threshold:
                node = node.left
            else:
                node = node.right
        return node.value


class MultiModalEnsembleClassifier:
    def __init__(self, n_trees: int = 30, max_depth: int = 4):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.vectorizer = SimpleTfidfVectorizer(min_df=2, max_features=120)
        self.trees: List[SimpleDecisionTree] = []
        self.sender_domain_types = [
            "internal_corporate", "free_webmail", "spoofed_lookalike",
            "suspicious_random", "external_partner"
        ]
        self.is_fitted = False

    def _extract_dense_features(self, records: List[Dict[str, Any]]) -> np.ndarray:
        features = []
        urgency_regex = re.compile(r"\b(urgent|immediately|action required|suspended|critical|expire)\b", re.I)

        for r in records:
            subject = r.get("subject_or_title", "")
            body = r.get("body_text", "")
            combined_text = f"{subject} {body}"
            url_meta = r.get("sanitized_url_features", {})
            sender = r.get("sender_domain_type", "unknown")
            channel = r.get("channel", "email")

            sender_vec = [1.0 if sender == s else 0.0 for s in self.sender_domain_types]
            is_sms = 1.0 if channel == "sms" else 0.0
            has_url = 1.0 if url_meta.get("has_url") else 0.0
            is_ip = 1.0 if url_meta.get("is_ip_based") else 0.0
            has_short = 1.0 if url_meta.get("has_shortener") else 0.0
            susp_tld = 1.0 if url_meta.get("suspicious_tld") else 0.0
            subdomains = float(url_meta.get("subdomain_count", 0))
            url_len = float(url_meta.get("url_length", 0)) / 100.0

            text_len = float(len(combined_text)) / 500.0
            urgency_hits = float(len(urgency_regex.findall(combined_text)))
            exclamations = float(combined_text.count("!"))
            caps_ratio = float(sum(1 for c in combined_text if c.isupper())) / (len(combined_text) + 1e-5)

            row = sender_vec + [
                is_sms, has_url, is_ip, has_short, susp_tld,
                subdomains, url_len, text_len, urgency_hits,
                exclamations, caps_ratio
            ]
            features.append(row)

        return np.array(features, dtype=np.float32)

    def _prepare_matrix(self, records: List[Dict[str, Any]], fit_vec: bool = False) -> np.ndarray:
        texts = [f"{r.get('subject_or_title', '')} {r.get('body_text', '')}" for r in records]
        if fit_vec:
            tfidf_mat = self.vectorizer.fit_transform(texts)
        else:
            tfidf_mat = self.vectorizer.transform(texts)

        dense_mat = self._extract_dense_features(records)
        return np.hstack([tfidf_mat, dense_mat])

    def fit(self, records: List[Dict[str, Any]]) -> "MultiModalEnsembleClassifier":
        X = self._prepare_matrix(records, fit_vec=True)
        y = np.array([1.0 if r.get("label") == "phishing" else 0.0 for r in records], dtype=np.float32)

        n_samples = len(y)
        self.trees = []

        # Bootstrap aggregating (Bagging)
        for _ in range(self.n_trees):
            boot_idx = np.random.choice(n_samples, size=n_samples, replace=True)
            tree = SimpleDecisionTree(max_depth=self.max_depth, max_features=16)
            tree.fit(X[boot_idx], y[boot_idx])
            self.trees.append(tree)

        self.is_fitted = True
        return self

    def predict_single(self, record: Dict[str, Any]) -> Dict[str, Any]:
        X = self._prepare_matrix([record], fit_vec=False)
        tree_preds = [tree.predict_row(X[0]) for tree in self.trees]
        prob_phish = float(np.mean(tree_preds))
        pred_label = "phishing" if prob_phish >= 0.50 else "legitimate"

        return {
            "model": "Multi-Modal Feature Ensemble (Random Forest)",
            "risk_score": round(prob_phish, 4),
            "prediction": pred_label
        }

    def predict_batch(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.predict_single(r) for r in records]

    def save(self, filepath: str = "models/ensemble_forest.json"):
        bundle = {
            "vectorizer_vocab": self.vectorizer.vocabulary,
            "vectorizer_feature_names": self.vectorizer.feature_names,
            "vectorizer_idf": self.vectorizer.idf.tolist(),
            "trees": [tree.root.to_dict() for tree in self.trees],
            "max_depth": self.max_depth,
            "n_trees": self.n_trees
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(bundle, f)

    def load(self, filepath: str = "models/ensemble_forest.json"):
        with open(filepath, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        self.vectorizer.vocabulary = bundle["vectorizer_vocab"]
        self.vectorizer.feature_names = bundle["vectorizer_feature_names"]
        self.vectorizer.idf = np.array(bundle["vectorizer_idf"], dtype=np.float32)
        self.trees = []
        for t_dict in bundle["trees"]:
            tree = SimpleDecisionTree(max_depth=bundle.get("max_depth", 4))
            tree.root = SimpleDecisionNode.from_dict(t_dict)
            self.trees.append(tree)
        self.is_fitted = True
        return self
