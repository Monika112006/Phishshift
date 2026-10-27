"""
Defanger and Inert URL Feature Extractor for PhishShift.
Ensures NFR-01: No live URLs or fetches; all URLs are made inert (hxxp, [.], etc.)
and extracts structural URL features safely.
"""

import re
from typing import Dict, Any, List


def defang_url(url: str) -> str:
    """Converts a live URL into a safe, inert string."""
    if not url:
        return ""
    # Replace http/https with hxxp/hxxps
    defanged = re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE)
    # Defang dots in domain/path
    defanged = defanged.replace(".", "[.]")
    # Defang colon slashes if not already changed
    defanged = defanged.replace("://", ":[/][/]")
    return defanged


def refang_for_feature_parsing_only(inert_url: str) -> str:
    """Restores defanged string internally only for lexical parsing without network call."""
    if not inert_url:
        return ""
    s = inert_url.replace(":[//][/]", "://").replace(":[//]", "://").replace(":[//[/]]", "://")
    s = s.replace("[.]", ".")
    s = re.sub(r"^hxxp", "http", s, flags=re.IGNORECASE)
    return s


def extract_inert_url_features(raw_or_inert_url: str) -> Dict[str, Any]:
    """
    Extracts structural safety and threat features from an inert/defanged URL
    without making any external network connection or fetching content.
    """
    if not raw_or_inert_url:
        return {
            "has_url": False,
            "defanged_url": "",
            "domain": "",
            "is_ip_based": False,
            "has_shortener": False,
            "subdomain_count": 0,
            "suspicious_tld": False,
            "url_length": 0
        }

    # Always ensure the stored URL is defanged
    defanged = defang_url(raw_or_inert_url) if not ("hxxp" in raw_or_inert_url or "[.]" in raw_or_inert_url) else raw_or_inert_url
    
    # Parse internally using regex safely
    normalized = refang_for_feature_parsing_only(defanged)
    
    # Check IP pattern
    ip_pattern = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    is_ip = bool(re.search(ip_pattern, normalized))
    
    # Extract domain part
    domain_match = re.search(r"https?://([^/:\s]+)", normalized, flags=re.IGNORECASE)
    domain = domain_match.group(1).lower() if domain_match else ""
    
    # Known shorteners
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly", "ow.ly", "shorturl.at"}
    has_shortener = any(sh in domain for sh in shorteners)
    
    # Suspicious or high-risk TLDs often abused in fast-flux phishing
    suspicious_tlds = {".xyz", ".top", ".buzz", ".work", ".click", ".link", ".club", ".country", ".support-update.com"}
    has_suspicious_tld = any(domain.endswith(tld) for tld in suspicious_tlds)
    
    subdomain_count = max(0, len(domain.split(".")) - 2) if domain and not is_ip else 0

    return {
        "has_url": True,
        "defanged_url": defanged,
        "domain": domain.replace(".", "[.]"),
        "is_ip_based": is_ip,
        "has_shortener": has_shortener,
        "subdomain_count": subdomain_count,
        "suspicious_tld": has_suspicious_tld,
        "url_length": len(normalized)
    }
