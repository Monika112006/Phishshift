"""
Pure NumPy TF-IDF Vectorizer & Calibrated Logistic Regression.
Model 2 for FR-02: Self-contained, portable, zero-DLL dependency linear NLP classifier.
Computes calibrated probabilities and exact token coefficient attributions for FR-04.
"""

import math
import re
import json
import numpy as np
from typing import List, Dict, Any, Tuple


class SimpleTfidfVectorizer:
    def __init__(self, min_df: int = 2, max_features: int = 2500, ngram_range: Tuple[int, int] = (1, 2)):
        self.min_df = min_df
        self.max_features = max_features
        self.ngram_range = ngram_range
        self.vocabulary: Dict[str, int] = {}
        self.idf: np.ndarray = np.array([])
        self.feature_names: List[str] = []

    def _tokenize(self, text: str) -> List[str]:
        tokens = re.findall(r"\b[a-zA-Z0-9_\-\.\[\]]+\b", text.lower())
        results = []
        if self.ngram_range[0] <= 1:
            results.extend(tokens)
        if self.ngram_range[1] >= 2 and len(tokens) >= 2:
            results.extend([f"{tokens[i]}_{tokens[i+1]}" for i in range(len(tokens) - 1)])
        return results

    def fit(self, texts: List[str]) -> "SimpleTfidfVectorizer":
        doc_count = len(texts)
        df_counts: Dict[str, int] = {}

        for text in texts:
            unique_terms = set(self._tokenize(text))
            for term in unique_terms:
                df_counts[term] = df_counts.get(term, 0) + 1

        filtered = {term: count for term, count in df_counts.items() if count >= self.min_df}
        sorted_terms = sorted(filtered.items(), key=lambda item: item[1], reverse=True)[:self.max_features]
        self.vocabulary = {term: idx for idx, (term, _) in enumerate(sorted_terms)}
        self.feature_names = [term for term, _ in sorted_terms]

        idf_list = [math.log((1.0 + doc_count) / (1.0 + filtered[term])) + 1.0 for term in self.feature_names]
        self.idf = np.array(idf_list, dtype=np.float32)
        return self

    def transform(self, texts: List[str]) -> np.ndarray:
        matrix = np.zeros((len(texts), len(self.feature_names)), dtype=np.float32)
        for i, text in enumerate(texts):
            tokens = self._tokenize(text)
            counts: Dict[str, int] = {}
            for t in tokens:
                if t in self.vocabulary:
                    counts[t] = counts.get(t, 0) + 1

            for term, count in counts.items():
                col_idx = self.vocabulary[term]
                tf = 1.0 + math.log(count)
                matrix[i, col_idx] = tf * self.idf[col_idx]

            norm = np.linalg.norm(matrix[i])
            if norm > 0:
                matrix[i] /= norm

        return matrix

    def fit_transform(self, texts: List[str]) -> np.ndarray:
        return self.fit(texts).transform(texts)


class TFIDFLinearClassifier:
    def __init__(self, c_param: float = 1.5, epochs: int = 120, lr: float = 0.08, l2_reg: float = 0.001):
        self.c_param = c_param
        self.epochs = epochs
        self.lr = lr
        self.l2_reg = l2_reg
        self.vectorizer = SimpleTfidfVectorizer()
        self.weights: np.ndarray = np.array([])
        self.bias: float = 0.0
        self.is_fitted = False

    def _prepare_text(self, records: List[Dict[str, Any]]) -> List[str]:
        texts = []
        for r in records:
            subject = r.get("subject_or_title", "")
            body = r.get("body_text", "")
            sender = r.get("sender_domain_type", "")
            url_meta = r.get("sanitized_url_features", {})
            url_str = url_meta.get("domain", "") + (" shortener" if url_meta.get("has_shortener") else "")
            combined = f"channel_{r.get('channel', 'email')} sender_{sender} {subject} {body} {url_str}"
            texts.append(combined)
        return texts

    def fit(self, records: List[Dict[str, Any]]) -> "TFIDFLinearClassifier":
        texts = self._prepare_text(records)
        X = self.vectorizer.fit_transform(texts)
        y = np.array([1.0 if r.get("label") == "phishing" else 0.0 for r in records], dtype=np.float32)

        n_pos = np.sum(y == 1.0)
        n_neg = np.sum(y == 0.0)
        total = len(y)
        w_pos = total / (2.0 * n_pos) if n_pos > 0 else 1.0
        w_neg = total / (2.0 * n_neg) if n_neg > 0 else 1.0
        sample_weights = np.where(y == 1.0, w_pos, w_neg)

        n_samples, n_features = X.shape
        self.weights = np.zeros(n_features, dtype=np.float32)
        self.bias = 0.0

        v_w = np.zeros(n_features, dtype=np.float32)
        v_b = 0.0
        momentum = 0.85
        batch_size = min(32, n_samples)

        for epoch in range(self.epochs):
            indices = np.random.permutation(n_samples)
            X_shuffled = X[indices]
            y_shuffled = y[indices]
            sw_shuffled = sample_weights[indices]

            for start in range(0, n_samples, batch_size):
                end = min(start + batch_size, n_samples)
                xb = X_shuffled[start:end]
                yb = y_shuffled[start:end]
                swb = sw_shuffled[start:end]

                z = np.clip(np.dot(xb, self.weights) + self.bias, -25.0, 25.0)
                preds = 1.0 / (1.0 + np.exp(-z))

                error = (preds - yb) * swb
                dw = np.dot(xb.T, error) / len(yb) + self.l2_reg * self.weights
                db = np.sum(error) / len(yb)

                v_w = momentum * v_w + self.lr * dw
                v_b = momentum * v_b + self.lr * db
                self.weights -= v_w
                self.bias -= v_b

        self.is_fitted = True
        return self

    def predict_single(self, record: Dict[str, Any]) -> Dict[str, Any]:
        text = self._prepare_text([record])[0]
        x_vec = self.vectorizer.transform([text])[0]
        z = np.clip(np.dot(x_vec, self.weights) + self.bias, -25.0, 25.0)
        prob_phish = float(1.0 / (1.0 + np.exp(-z)))
        pred_label = "phishing" if prob_phish >= 0.50 else "legitimate"

        top_cues = self.explain_instance(record, top_k=5)

        return {
            "model": "TF-IDF + Logistic Regression",
            "risk_score": round(prob_phish, 4),
            "prediction": pred_label,
            "top_risk_cues": top_cues["phishing_cues"],
            "top_safe_cues": top_cues["legitimate_cues"]
        }

    def predict_batch(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.predict_single(r) for r in records]

    def explain_instance(self, record: Dict[str, Any], top_k: int = 5) -> Dict[str, List[Tuple[str, float]]]:
        if not self.is_fitted:
            return {"phishing_cues": [], "legitimate_cues": []}

        text = self._prepare_text([record])[0]
        x_vec = self.vectorizer.transform([text])[0]
        nonzero = np.where(x_vec > 0)[0]

        scored = []
        for idx in nonzero:
            token = self.vectorizer.feature_names[idx]
            contribution = float(self.weights[idx] * x_vec[idx])
            scored.append((token, contribution))

        scored.sort(key=lambda item: item[1], reverse=True)

        phish = [(t, round(w, 4)) for t, w in scored if w > 0.05][:top_k]
        legit = [(t, round(abs(w), 4)) for t, w in reversed(scored) if w < -0.05][:top_k]

        return {"phishing_cues": phish, "legitimate_cues": legit}

    def save(self, filepath: str = "models/tfidf_linear.json"):
        bundle = {
            "vocabulary": self.vectorizer.vocabulary,
            "feature_names": self.vectorizer.feature_names,
            "idf": self.vectorizer.idf.tolist(),
            "weights": self.weights.tolist(),
            "bias": float(self.bias)
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(bundle, f)

    def load(self, filepath: str = "models/tfidf_linear.json"):
        with open(filepath, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        self.vectorizer.vocabulary = bundle["vocabulary"]
        self.vectorizer.feature_names = bundle["feature_names"]
        self.vectorizer.idf = np.array(bundle["idf"], dtype=np.float32)
        self.weights = np.array(bundle["weights"], dtype=np.float32)
        self.bias = bundle["bias"]
        self.is_fitted = True
        return self
