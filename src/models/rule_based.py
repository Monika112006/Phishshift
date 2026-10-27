"""
Rule-Based Phishing Heuristics Engine.
Model 1 for FR-02: Baseline rule classifier.
Provides deterministic heuristic scoring and rule trigger explanations.
"""

import re
from typing import Dict, Any, List, Tuple


class RuleBasedClassifier:
    """Heuristic rule-based expert system for detecting phishing cues."""

    def __init__(self):
        # Heuristic rules with weights
        self.urgency_patterns = [
            (re.compile(r"\b(immediately|urgent|critical|action required|without delay|by midnight)\b", re.I), 0.20, "High urgency phrasing"),
            (re.compile(r"\b(expire[sd]? in \d+|within \d+\s*(?:hours|h|mins?))\b", re.I), 0.25, "Time-pressure deadline detected"),
            (re.compile(r"\b(account (?:suspended|disabled|locked|terminated))\b", re.I), 0.25, "Account suspension threat"),
        ]

        self.credential_financial_patterns = [
            (re.compile(r"\b(password (?:expires|reset|synchronization|renewal))\b", re.I), 0.15, "Password modification request"),
            (re.compile(r"\b(direct deposit|routing number|w-2|salary disbursement)\b", re.I), 0.25, "Sensitive payroll/banking inquiry"),
            (re.compile(r"\b(wire transfer|gift cards?|remittance|escrow)\b", re.I), 0.30, "Financial transfer / gift card request"),
            (re.compile(r"\b(token synchronization|handshake challenge|trust claim)\b", re.I), 0.20, "Synthetic identity handshake prompt")
        ]

        self.sender_risk_weights = {
            "internal_corporate": -0.35,  # Strong indicator of legitimate internal message
            "free_webmail": 0.30,         # High risk for executive or corporate request
            "spoofed_lookalike": 0.45,    # High risk domain
            "suspicious_random": 0.40,    # Unrecognized random sender
            "external_partner": 0.10
        }

    def predict_single(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluates a message and returns score, prediction, and triggered rules."""
        text = f"{record.get('subject_or_title', '')} {record.get('body_text', '')}"
        sender_type = record.get("sender_domain_type", "unknown")
        url_features = record.get("sanitized_url_features", {})

        raw_score = 0.0
        triggered_rules: List[str] = []

        # 1. Evaluate urgency patterns
        for pattern, weight, desc in self.urgency_patterns:
            if pattern.search(text):
                raw_score += weight
                triggered_rules.append(desc)

        # 2. Evaluate credential & financial patterns
        for pattern, weight, desc in self.credential_financial_patterns:
            if pattern.search(text):
                raw_score += weight
                triggered_rules.append(desc)

        # 3. Evaluate sender domain type
        sender_weight = self.sender_risk_weights.get(sender_type, 0.0)
        raw_score += sender_weight
        if sender_weight > 0:
            triggered_rules.append(f"High-risk sender domain type: {sender_type}")
        elif sender_weight < 0:
            triggered_rules.append(f"Trusted sender domain type: {sender_type}")

        # 4. Evaluate inert URL features
        if url_features.get("has_url"):
            if url_features.get("is_ip_based"):
                raw_score += 0.35
                triggered_rules.append("Inert URL targets raw IP address")
            if url_features.get("has_shortener"):
                raw_score += 0.25
                triggered_rules.append("Inert URL uses public URL shortening service")
            if url_features.get("suspicious_tld"):
                raw_score += 0.30
                triggered_rules.append("Inert URL uses high-risk/abused TLD (.xyz, .top, .buzz, etc.)")
            if url_features.get("subdomain_count", 0) >= 3:
                raw_score += 0.15
                triggered_rules.append("Deep subdomain nesting detected in inert link")

        # Bound probability to [0.0, 1.0]
        prob = max(0.0, min(1.0, raw_score))
        pred_label = "phishing" if prob >= 0.50 else "legitimate"

        return {
            "model": "Rule-Based Heuristics",
            "risk_score": round(prob, 4),
            "prediction": pred_label,
            "triggered_rules": triggered_rules
        }

    def predict_batch(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.predict_single(r) for r in records]
