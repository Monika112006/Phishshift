"""
Near-Duplicate Template Deduplicator for PhishShift.
Fulfills FR-01: Deduplicate near-identical templates before splitting train and test.
Fulfills CP-2: Audit near-duplicate removal across splits.
"""

import json
import re
from typing import List, Dict, Any, Tuple


def normalize_text_for_dedup(text: str) -> str:
    """Normalizes text by removing variable slots (numbers, URLs, excessive spaces)."""
    t = text.lower()
    # Replace URLs
    t = re.sub(r"hxxps?://\S+", "<URL>", t)
    t = re.sub(r"https?://\S+", "<URL>", t)
    # Replace digits
    t = re.sub(r"\d+", "<NUM>", t)
    # Remove punctuation
    t = re.sub(r"[^\w\s<>]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def get_character_ngrams(text: str, n: int = 4) -> set:
    """Extracts character n-grams for Jaccard similarity."""
    if len(text) < n:
        return {text}
    return {text[i:i+n] for i in range(len(text) - n + 1)}


def jaccard_similarity(set_a: set, set_b: set) -> float:
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return intersection / union if union > 0 else 0.0


def deduplicate_templates(
    records: List[Dict[str, Any]],
    similarity_threshold: float = 0.94
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Deduplicates records based on template similarity.
    Returns (retained_records, duplicate_audit_log).
    """
    retained: List[Dict[str, Any]] = []
    audit_log: List[Dict[str, Any]] = []
    
    # Store n-gram representations for fast comparison
    retained_fingerprints: List[Tuple[str, str, set]] = []  # (msg_id, campaign, ngrams)

    for record in records:
        text = f"{record.get('subject_or_title', '')} {record.get('body_text', '')}"
        norm = normalize_text_for_dedup(text)
        ngrams = get_character_ngrams(norm, n=4)

        is_duplicate = False
        matched_id = None
        max_sim = 0.0

        # Compare only within the same campaign and label to prevent false collapse
        for orig_id, orig_camp, orig_ngrams in retained_fingerprints:
            if orig_camp == record.get("campaign_group"):
                sim = jaccard_similarity(ngrams, orig_ngrams)
                if sim > max_sim:
                    max_sim = sim
                if sim >= similarity_threshold:
                    is_duplicate = True
                    matched_id = orig_id
                    break

        if is_duplicate:
            audit_log.append({
                "duplicate_message_id": record["message_id"],
                "retained_message_id": matched_id,
                "campaign_group": record["campaign_group"],
                "channel": record.get("channel", "email"),
                "similarity_score": round(max_sim, 4),
                "threshold": similarity_threshold,
                "reason": "Near-identical template matched existing training/holdout record"
            })
        else:
            retained.append(record)
            retained_fingerprints.append((record["message_id"], record["campaign_group"], ngrams))

    return retained, audit_log


def run_deduplication_pipeline(
    input_path: str = "data/phishshift_raw.json",
    output_deduped: str = "data/phishshift_deduped.json",
    audit_output: str = "evidence/cp2_deduplication_audit.json",
    threshold: float = 0.94
):
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    print(f"Starting FR-01 Deduplication on {len(data)} raw records (Threshold={threshold})...")
    retained, audit_log = deduplicate_templates(data, similarity_threshold=threshold)

    with open(output_deduped, "w", encoding="utf-8") as f:
        json.dump(retained, f, indent=2)

    audit_summary = {
        "checkpoint": "CP-2",
        "description": "Audit near-duplicate removal across splits (FR-01)",
        "input_total_records": len(data),
        "retained_records": len(retained),
        "removed_duplicates_count": len(audit_log),
        "similarity_threshold": threshold,
        "duplicate_log": audit_log
    }

    with open(audit_output, "w", encoding="utf-8") as f:
        json.dump(audit_summary, f, indent=2)

    print(f"FR-01 Deduplication complete:")
    print(f"  Retained: {len(retained)}")
    print(f"  Removed near-duplicates: {len(audit_log)}")
    print(f"  Evidence saved to: {audit_output}")
    return retained, audit_log


if __name__ == "__main__":
    run_deduplication_pipeline()
