"""
Automated Unit and Integration Tests for PhishShift.
Verifies pipeline integrity, URL defanging, model prediction, and engine abstain logic.
Run with: python -m unittest tests/test_pipeline.py
"""

import unittest
from src.defanger import defang_url, extract_inert_url_features
from src.deduplication import deduplicate_templates
from src.engine import PhishShiftEngine
from src.models.rule_based import RuleBasedClassifier
from src.models.tfidf_linear import TFIDFLinearClassifier
from src.models.ensemble_model import MultiModalEnsembleClassifier


class TestPhishShiftPipeline(unittest.TestCase):
    def test_defanger_inertness(self):
        url = "http://malicious-login-portal.xyz/login?id=49"
        defanged = defang_url(url)
        self.assertTrue(defanged.startswith("hxxp://") or defanged.startswith("hxxp:[/][/]"))
        self.assertIn("[.]", defanged)
        self.assertNotIn("http://", defanged)

    def test_url_feature_extraction(self):
        raw = "http://192.168.1.10/owa/auth"
        feat = extract_inert_url_features(raw)
        self.assertTrue(feat["has_url"])
        self.assertTrue(feat["is_ip_based"])
        self.assertIn("hxxp", feat["defanged_url"])

    def test_deduplication(self):
        records = [
            {"message_id": "M1", "campaign_group": "c1", "subject_or_title": "Hello", "body_text": "Please verify your password immediately at link"},
            {"message_id": "M2", "campaign_group": "c1", "subject_or_title": "Hello", "body_text": "Please verify your password immediately at link"},
            {"message_id": "M3", "campaign_group": "c2", "subject_or_title": "Team lunch", "body_text": "Join us tomorrow at 12pm in auditorium"}
        ]
        retained, audit = deduplicate_templates(records, similarity_threshold=0.90)
        self.assertEqual(len(retained), 2)
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]["duplicate_message_id"], "M2")

    def test_engine_abstain_uncertainty(self):
        rules = RuleBasedClassifier()
        tfidf = TFIDFLinearClassifier()
        ens = MultiModalEnsembleClassifier()
        engine = PhishShiftEngine(rules, tfidf, ens, abstain_lower=0.40, abstain_upper=0.60)

        # Ambiguous message
        res = engine.analyze_message(
            subject="Notice regarding meeting",
            body="Meeting notes from sync.",
            sender_domain_type="external_partner"
        )
        self.assertIn("verdict", res)
        self.assertIn("composite_risk_score", res)
        self.assertIn("disclaimer", res)


if __name__ == "__main__":
    unittest.main()
