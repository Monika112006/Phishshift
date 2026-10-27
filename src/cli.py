"""
Command Line Interface (CLI) for PhishShift Message Risk Scanner.
Provides rapid terminal triage, model benchmarking, and verification commands.
"""

import argparse
import json
import sys
from src.engine import PhishShiftEngine
from src.models.rule_based import RuleBasedClassifier
from src.models.tfidf_linear import TFIDFLinearClassifier
from src.models.ensemble_model import MultiModalEnsembleClassifier
from src.evaluation.benchmark import train_and_benchmark
from src.evaluation.acceptance_tests import run_acceptance_tests


def get_engine() -> PhishShiftEngine:
    rules = RuleBasedClassifier()
    try:
        tfidf = TFIDFLinearClassifier().load("models/tfidf_linear.json")
        ens = MultiModalEnsembleClassifier().load("models/ensemble_forest.json")
    except Exception:
        print("[Warning] Trained model files not found in models/. Initializing untrained models...")
        tfidf = TFIDFLinearClassifier()
        ens = MultiModalEnsembleClassifier()
    return PhishShiftEngine(rules, tfidf, ens)


def main():
    parser = argparse.ArgumentParser(
        description="PhishShift: Message Risk Scanner & Triage Tool (Decision Support)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: scan
    scan_p = subparsers.add_parser("scan", help="Scan a single email or SMS message")
    scan_p.add_argument("--subject", type=str, default="", help="Subject line or message title")
    scan_p.add_argument("--body", type=str, required=True, help="Message body text")
    scan_p.add_argument("--sender", type=str, default="internal_corporate",
                        choices=["internal_corporate", "free_webmail", "spoofed_lookalike", "suspicious_random", "external_partner"],
                        help="Sender domain category")
    scan_p.add_argument("--channel", type=str, default="email", choices=["email", "sms"], help="Message channel")
    scan_p.add_argument("--url", type=str, default="", help="Inert/defanged URL found in message")

    # Command: benchmark
    subparsers.add_parser("benchmark", help="Train and benchmark all 3 models")

    # Command: test
    subparsers.add_parser("test", help="Run acceptance tests (AT-01 to AT-03) and Checkpoints")

    args = parser.parse_args()

    if args.command == "scan":
        engine = get_engine()
        result = engine.analyze_message(
            subject=args.subject,
            body=args.body,
            sender_domain_type=args.sender,
            channel=args.channel,
            inert_url=args.url
        )

        print("\n" + "=" * 65)
        print("          PHISHSHIFT MESSAGE RISK SCANNER")
        print("=" * 65)
        print(f"VERDICT:             {result['verdict']}")
        print(f"COMPOSITE RISK SCORE: {result['composite_risk_score']} / 1.0000")
        print(f"ABSTAIN FOR TRIAGE:  {result['is_abstain']}")
        if result['is_abstain']:
            print(f"ABSTAIN REASON:      {result['abstain_reason']}")
        print("-" * 65)
        print("INDIVIDUAL MODEL BREAKDOWN:")
        for m_key, m_val in result["model_breakdown"].items():
            print(f"  - {m_val['model']:<30}: Score = {m_val['risk_score']} ({m_val['prediction']})")
        print("-" * 65)
        print("IDENTIFIED RISK CUES:")
        if result["risk_cues"]:
            for cue in result["risk_cues"]:
                print(f"  [!] ({cue['category']}) {cue['cue']}")
        else:
            print("  (None detected)")
        print("-" * 65)
        print("IDENTIFIED SAFE CUES:")
        if result["safe_cues"]:
            for cue in result["safe_cues"]:
                print(f"  [+] ({cue['category']}) {cue['cue']}")
        else:
            print("  (None detected)")
        print("-" * 65)
        print(f"{result['disclaimer']}")
        print("=" * 65 + "\n")

    elif args.command == "benchmark":
        print("Starting PhishShift Model Benchmark Pipeline...")
        train_and_benchmark()

    elif args.command == "test":
        print("Running Acceptance Tests (AT-01, AT-02, AT-03) & Mentor Checkpoints...")
        run_acceptance_tests()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
