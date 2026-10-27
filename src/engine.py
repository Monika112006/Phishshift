"""
PhishShift Multi-Model Risk Scanner and Triage Engine.
Fulfills FR-04: Add reject/abstain option and safe explanation of risk cues.
Fulfills NFR-01, NFR-02, NFR-03: Inert URL processing, PII safety, decision-support disclaimer.
"""

from typing import Dict, Any, List
from src.defanger import extract_inert_url_features
from src.models.rule_based import RuleBasedClassifier
from src.models.tfidf_linear import TFIDFLinearClassifier
from src.models.ensemble_model import MultiModalEnsembleClassifier


SAFETY_DISCLAIMER = (
    "NOTICE: PhishShift is an educational triage and decision-support system. "
    "Classifications represent probabilistic risk indicators and do NOT guarantee safety. "
    "Suspicious messages should be escalated to your Security Operations Center (SOC)."
)


class PhishShiftEngine:
    def __init__(
        self,
        rules_model: RuleBasedClassifier = None,
        tfidf_model: TFIDFLinearClassifier = None,
        ensemble_model: MultiModalEnsembleClassifier = None,
        abstain_lower: float = 0.38,
        abstain_upper: float = 0.62
    ):
        self.rules_model = rules_model or RuleBasedClassifier()
        self.tfidf_model = tfidf_model or TFIDFLinearClassifier()
        self.ensemble_model = ensemble_model or MultiModalEnsembleClassifier()
        self.abstain_lower = abstain_lower
        self.abstain_upper = abstain_upper

    def analyze_message(
        self,
        subject: str,
        body: str,
        sender_domain_type: str = "internal_corporate",
        channel: str = "email",
        inert_url: str = ""
    ) -> Dict[str, Any]:
        """
        Runs comprehensive triage across all 3 models, determines abstain status,
        and aggregates safe interpretable risk cues.
        """
        # Ensure URL features are safely extracted and defanged (NFR-01)
        url_features = extract_inert_url_features(inert_url)

        record = {
            "message_id": "SCAN-QUERY",
            "channel": channel,
            "subject_or_title": subject,
            "body_text": body,
            "sanitized_url_features": url_features,
            "sender_domain_type": sender_domain_type
        }

        # Run predictions
        rule_res = self.rules_model.predict_single(record)
        tfidf_res = self.tfidf_model.predict_single(record) if self.tfidf_model.is_fitted else {
            "model": "TF-IDF + Logistic Regression", "risk_score": 0.5, "prediction": "unknown", "top_risk_cues": [], "top_safe_cues": []
        }
        ensemble_res = self.ensemble_model.predict_single(record) if self.ensemble_model.is_fitted else {
            "model": "Multi-Modal Random Forest", "risk_score": 0.5, "prediction": "unknown"
        }

        s_rule = rule_res["risk_score"]
        s_tfidf = tfidf_res["risk_score"]
        s_ens = ensemble_res["risk_score"]

        # Weighted aggregate score (35% TF-IDF, 45% Multi-Modal Ensemble, 20% Heuristics)
        if self.ensemble_model.is_fitted and self.tfidf_model.is_fitted:
            composite_score = round(0.35 * s_tfidf + 0.45 * s_ens + 0.20 * s_rule, 4)
        else:
            composite_score = s_rule

        # FR-04: Reject / Abstain Logic
        # Condition 1: Composite score falls within uncertainty band [abstain_lower, abstain_upper]
        in_uncertainty_zone = self.abstain_lower <= composite_score <= self.abstain_upper
        
        # Condition 2: High inter-model variance/disagreement
        scores = [s_rule, s_tfidf, s_ens] if self.ensemble_model.is_fitted else [s_rule]
        model_conflict = (max(scores) - min(scores)) >= 0.45

        if in_uncertainty_zone or model_conflict:
            triage_verdict = "ABSTAIN / NEEDS HUMAN REVIEW"
            verdict_badge = "warning"
            abstain_reason = (
                f"Model uncertainty is high (Composite score {composite_score} in [{self.abstain_lower}, {self.abstain_upper}]) "
                f"or models produced conflicting signals (Spread: {round(max(scores) - min(scores), 2)})."
            )
        elif composite_score > self.abstain_upper:
            triage_verdict = "FLAGGED AS SUSPICIOUS (PHISHING)"
            verdict_badge = "danger"
            abstain_reason = "High confidence malicious indicators detected."
        else:
            triage_verdict = "LIKELY LEGITIMATE"
            verdict_badge = "safe"
            abstain_reason = "Standard enterprise communication patterns detected."

        # Compile comprehensive risk cues (FR-04 Explainability)
        risk_cues = []
        for r in rule_res.get("triggered_rules", []):
            risk_cues.append({"category": "Heuristic Rule", "cue": r, "severity": "medium"})

        for token, weight in tfidf_res.get("top_risk_cues", []):
            risk_cues.append({"category": "Suspicious Vocabulary", "cue": f"Word '{token}' (+{weight})", "severity": "high" if weight > 0.4 else "medium"})

        if url_features.get("has_url"):
            if url_features.get("is_ip_based"):
                risk_cues.append({"category": "Inert URL Structure", "cue": "Target is a raw IP address rather than a domain name", "severity": "high"})
            if url_features.get("has_shortener"):
                risk_cues.append({"category": "Inert URL Structure", "cue": "Target uses URL shortener obscuring final destination", "severity": "medium"})
            if url_features.get("suspicious_tld"):
                risk_cues.append({"category": "Inert URL Structure", "cue": f"Defanged domain uses high-abuse TLD: {url_features.get('domain')}", "severity": "high"})

        safe_cues = []
        for token, weight in tfidf_res.get("top_safe_cues", []):
            safe_cues.append({"category": "Legitimate Vocabulary", "cue": f"Word '{token}' (-{weight})"})
        if sender_domain_type == "internal_corporate":
            safe_cues.append({"category": "Sender Verification", "cue": "Sender is identified as an internal corporate domain"})

        return {
            "composite_risk_score": composite_score,
            "verdict": triage_verdict,
            "verdict_badge": verdict_badge,
            "is_abstain": in_uncertainty_zone or model_conflict,
            "abstain_reason": abstain_reason,
            "model_breakdown": {
                "rule_based": rule_res,
                "tfidf_linear": tfidf_res,
                "ensemble_forest": ensemble_res
            },
            "sanitized_url_analysis": url_features,
            "risk_cues": risk_cues,
            "safe_cues": safe_cues,
            "disclaimer": SAFETY_DISCLAIMER
        }
