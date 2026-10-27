"""
Campaign-Separated Dataset Splitter for PhishShift.
Fulfills FR-03: Use campaign-separated holdout to test generalization to unseen templates.
Fulfills CP-3: Campaign-based test and confusion analysis, not random accuracy only.
Guarantees zero campaign leakage between training and holdout partitions.
"""

import json
import random
from typing import Dict, List, Any


def split_by_campaign(
    input_file: str = "data/phishshift_deduped.json",
    train_out: str = "data/train.json",
    val_out: str = "data/val.json",
    holdout_out: str = "data/holdout.json",
    proof_out: str = "evidence/cp3_campaign_split_proof.json",
    val_ratio: float = 0.20,
    random_seed: int = 42
):
    with open(input_file, "r", encoding="utf-8") as f:
        records: List[Dict[str, Any]] = json.load(f)

    # Separate holdout campaigns based on the is_holdout flag or predefined holdout campaign names
    holdout_campaign_names = {
        "phish_novel_mfa_session_bypass",
        "phish_unfamiliar_supply_chain_phish",
        "legit_holdout_executive_announcements"
    }

    train_val_records = []
    holdout_records = []

    for r in records:
        if r.get("campaign_group") in holdout_campaign_names or r.get("is_holdout", False):
            holdout_records.append(r)
        else:
            train_val_records.append(r)

    # In-distribution split for train and val
    random.seed(random_seed)
    random.shuffle(train_val_records)

    split_idx = int(len(train_val_records) * (1 - val_ratio))
    train_records = train_val_records[:split_idx]
    val_records = train_val_records[split_idx:]

    # Save partitions
    with open(train_out, "w", encoding="utf-8") as f:
        json.dump(train_records, f, indent=2)

    with open(val_out, "w", encoding="utf-8") as f:
        json.dump(val_records, f, indent=2)

    with open(holdout_out, "w", encoding="utf-8") as f:
        json.dump(holdout_records, f, indent=2)

    # Audit for zero campaign leakage
    train_campaigns = set(r["campaign_group"] for r in train_records)
    val_campaigns = set(r["campaign_group"] for r in val_records)
    holdout_campaigns = set(r["campaign_group"] for r in holdout_records)

    leakage = train_campaigns.intersection(holdout_campaigns)

    proof = {
        "checkpoint": "CP-3",
        "requirement": "FR-03: Campaign-separated holdout",
        "total_records_processed": len(records),
        "split_counts": {
            "train": len(train_records),
            "val_in_distribution": len(val_records),
            "holdout_out_of_distribution": len(holdout_records)
        },
        "campaign_distribution": {
            "train_campaigns": sorted(list(train_campaigns)),
            "val_campaigns": sorted(list(val_campaigns)),
            "holdout_campaigns": sorted(list(holdout_campaigns))
        },
        "zero_leakage_verified": len(leakage) == 0,
        "leaked_campaigns": list(leakage)
    }

    with open(proof_out, "w", encoding="utf-8") as f:
        json.dump(proof, f, indent=2)

    print(f"FR-03 Split Completed:")
    print(f"  Train records: {len(train_records)} (Campaigns: {len(train_campaigns)})")
    print(f"  Val records:   {len(val_records)}")
    print(f"  Holdout unseen records: {len(holdout_records)} (Campaigns: {len(holdout_campaigns)})")
    print(f"  Zero Leakage Verified: {proof['zero_leakage_verified']}")
    print(f"  Proof written to: {proof_out}")


if __name__ == "__main__":
    split_by_campaign()
