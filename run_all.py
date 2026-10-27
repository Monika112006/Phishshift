"""
Master Pipeline Runner for PhishShift Message Risk Scanner.
Executes the complete project lifecycle end-to-end:
1. Data Generation (450+ curated records)
2. FR-01 Near-Duplicate Template Deduplication (CP-2)
3. FR-03 Campaign-Separated Holdout Partitioning (CP-3)
4. FR-02 Multi-Model Benchmark (Rules, TF-IDF Linear, Random Forest)
5. FR-05 Robustness Drift & Urgent Legitimate FPR (CP-5)
6. Acceptance Tests (AT-01, AT-02, AT-03) & Mentor Checkpoints (CP-1, CP-4)
"""

import sys
import time
from src.data_generator import build_and_save_data
from src.deduplication import run_deduplication_pipeline
from src.split import split_by_campaign
from src.evaluation.benchmark import train_and_benchmark
from src.evaluation.robustness import run_full_robustness_evaluation
from src.evaluation.acceptance_tests import run_acceptance_tests


def run_complete_phishshift_pipeline():
    print("=" * 75)
    print("             PHISHSHIFT (ML-07) - MASTER PIPELINE EXECUTION")
    print("=" * 75)

    start_total = time.time()

    # Step 1: Data Generation
    print("\n[Step 1/6] Generating Curated Dataset & Manifest (Section 05)...")
    build_and_save_data()

    # Step 2: Deduplication (FR-01, CP-2)
    print("\n[Step 2/6] Running Template Deduplication (FR-01, CP-2)...")
    run_deduplication_pipeline(threshold=0.94)

    # Step 3: Campaign Split (FR-03, CP-3)
    print("\n[Step 3/6] Running Campaign-Separated Holdout Split (FR-03, CP-3)...")
    split_by_campaign()

    # Step 4: Multi-Model Benchmark (FR-02)
    print("\n[Step 4/6] Training & Benchmarking 3 Model Architectures (FR-02)...")
    train_and_benchmark(save_models=True)

    # Step 5: Robustness & FP Analysis (FR-05, CP-5)
    print("\n[Step 5/6] Evaluating Robustness Drift & Urgent Benign FPR (FR-05, CP-5)...")
    run_full_robustness_evaluation()

    # Step 6: Acceptance Tests & Checkpoints (AT-01..03, CP-1, CP-4)
    print("\n[Step 6/6] Running Acceptance Tests (AT-01, AT-02, AT-03) & Checkpoints...")
    run_acceptance_tests()

    elapsed = round(time.time() - start_total, 2)
    print("\n" + "=" * 75)
    print(f"  ALL REQUIREMENTS COMPLETED SUCCESSFULLY IN {elapsed}s!")
    print("  Artifacts Saved:")
    print("    - Models: models/tfidf_linear.json, models/ensemble_forest.json")
    print("    - Datasets: data/phishshift_raw.json, data/phishshift_deduped.json, data/train.json, data/val.json, data/holdout.json")
    print("    - Evidence Logs: evidence/*.json")
    print("  To launch Web UI: python app/server.py (http://localhost:8000)")
    print("  To run CLI scan: python -m src.cli scan --body '...'")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    run_complete_phishshift_pipeline()
