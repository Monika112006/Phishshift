"""
Model Benchmark and Comparative Evaluation Pipeline for PhishShift.
Fulfills FR-02: Compare rules, TF-IDF linear classifier, and third chosen model.
Fulfills FR-03: Evaluate in-distribution vs holdout campaign generalization.
Zero-DLL dependencies (NumPy based), portable, saves models & experiment records.
"""

import json
import time
from typing import Dict, List, Any
import numpy as np
from src.models.rule_based import RuleBasedClassifier
from src.models.tfidf_linear import TFIDFLinearClassifier
from src.models.ensemble_model import MultiModalEnsembleClassifier


def compute_metrics(y_true: List[int], y_pred: List[int], y_prob: List[float]) -> Dict[str, Any]:
    n = len(y_true)
    if n == 0:
        return {}

    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)

    acc = (tp + tn) / n
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    # Mann-Whitney U for ROC-AUC
    pos_probs = [p for yt, p in zip(y_true, y_prob) if yt == 1]
    neg_probs = [p for yt, p in zip(y_true, y_prob) if yt == 0]
    n_pos, n_neg = len(pos_probs), len(neg_probs)

    if n_pos > 0 and n_neg > 0:
        # Rank sum
        pairs = sum(1.0 if p > n else (0.5 if p == n else 0.0) for p in pos_probs for n in neg_probs)
        auc = pairs / (n_pos * n_neg)
    else:
        auc = 0.5

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(auc, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "confusion_matrix": {
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "true_positive": tp
        }
    }


def train_and_benchmark(
    train_path: str = "data/train.json",
    val_path: str = "data/val.json",
    holdout_path: str = "data/holdout.json",
    save_models: bool = True
) -> Dict[str, Any]:
    with open(train_path, "r", encoding="utf-8") as f:
        train_data = json.load(f)
    with open(val_path, "r", encoding="utf-8") as f:
        val_data = json.load(f)
    with open(holdout_path, "r", encoding="utf-8") as f:
        holdout_data = json.load(f)

    y_val = [1 if r["label"] == "phishing" else 0 for r in val_data]
    y_holdout = [1 if r["label"] == "phishing" else 0 for r in holdout_data]

    # Model 1: Rules
    rules_clf = RuleBasedClassifier()

    # Model 2: TF-IDF Linear
    print("Fitting Model 2: TF-IDF + Logistic Regression...")
    tfidf_clf = TFIDFLinearClassifier()
    t0 = time.time()
    tfidf_clf.fit(train_data)
    train_time_tfidf = time.time() - t0

    # Model 3: Multi-Modal Ensemble
    print("Fitting Model 3: Multi-Modal Random Forest...")
    ensemble_clf = MultiModalEnsembleClassifier(n_trees=30, max_depth=4)
    t0 = time.time()
    ensemble_clf.fit(train_data)
    train_time_ens = time.time() - t0

    if save_models:
        tfidf_clf.save("models/tfidf_linear.json")
        ensemble_clf.save("models/ensemble_forest.json")
        print("Models serialized to models/*.json.")

    models_to_test = [
        ("Rule-Based Heuristics", rules_clf, 0.0),
        ("TF-IDF + Logistic Regression", tfidf_clf, train_time_tfidf),
        ("Multi-Modal Random Forest", ensemble_clf, train_time_ens)
    ]

    benchmark_results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset_split": {
            "train_size": len(train_data),
            "val_size": len(val_data),
            "holdout_size": len(holdout_data)
        },
        "models": {}
    }

    print("\n" + "=" * 88)
    print(f"{'Model':<30} | {'Val Acc':<8} | {'Val F1':<8} | {'Holdout Acc':<12} | {'Holdout F1':<10} | {'ROC-AUC':<8}")
    print("-" * 88)

    for name, clf, train_time in models_to_test:
        # Evaluate on In-Distribution Validation
        t0 = time.time()
        val_preds = clf.predict_batch(val_data)
        val_latency_ms = ((time.time() - t0) / max(1, len(val_data))) * 1000.0

        val_y_pred = [1 if p["prediction"] == "phishing" else 0 for p in val_preds]
        val_y_prob = [p["risk_score"] for p in val_preds]
        val_metrics = compute_metrics(y_val, val_y_pred, val_y_prob)

        # Evaluate on Out-of-Distribution Holdout (FR-03)
        t0 = time.time()
        holdout_preds = clf.predict_batch(holdout_data)
        holdout_latency_ms = ((time.time() - t0) / max(1, len(holdout_data))) * 1000.0

        holdout_y_pred = [1 if p["prediction"] == "phishing" else 0 for p in holdout_preds]
        holdout_y_prob = [p["risk_score"] for p in holdout_preds]
        holdout_metrics = compute_metrics(y_holdout, holdout_y_pred, holdout_y_prob)

        benchmark_results["models"][name] = {
            "training_time_sec": round(train_time, 4),
            "inference_latency_ms": round(val_latency_ms, 2),
            "validation_in_distribution": val_metrics,
            "holdout_out_of_distribution": holdout_metrics
        }

        print(f"{name:<30} | {val_metrics['accuracy']:<8} | {val_metrics['f1_score']:<8} | {holdout_metrics['accuracy']:<12} | {holdout_metrics['f1_score']:<10} | {holdout_metrics['roc_auc']:<8}")

    print("=" * 88 + "\n")

    with open("evidence/model_benchmark_results.json", "w", encoding="utf-8") as f:
        json.dump(benchmark_results, f, indent=2)

    print("Benchmark results saved to evidence/model_benchmark_results.json")
    return benchmark_results


if __name__ == "__main__":
    train_and_benchmark()
