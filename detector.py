"""
detector.py - URL Feature Extraction and Risk Scoring Engine
============================================================
CNS Concept: Static URL Analysis for Phishing Detection
This module performs rule-based analysis on URLs without visiting them.
It extracts features and calculates a risk score to classify URLs as
Safe, Suspicious, or Phishing.

Author: Phishing Detection System
Project: Computer and Network Security (CNS) College Project
"""

import re
import urllib.parse
from typing import Dict, List, Tuple

# ============================================================
# CNS Concept: Suspicious Keywords commonly used in phishing
# Attackers use these terms to create urgency and trick users
# ============================================================
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "account", "password",
    "secure", "update", "bank", "payment", "confirm", "free",
    "bonus", "signin", "sign-in", "webscr", "ebayisapi", "cmd",
    "credential", "wallet", "suspend", "recover", "billing",
    "invoice", "refund", "prize", "winner", "claim", "validate"
]

# ============================================================
# CNS Concept: Suspicious TLDs and domain patterns used by attackers
# ============================================================
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"]

SUSPICIOUS_DOMAIN_PATTERNS = [
    r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}",   # IP-like patterns
    r"(paypal|google|facebook|amazon|apple|microsoft|netflix|bank)[^.]*\.",  # Brand impersonation
    r"[a-z]{15,}",                           # Very long random-looking strings
]

# ============================================================
# SCORING CONFIGURATION - Rule-Based Risk Scoring System
# Each feature adds points to the overall risk score (max 100)
# CNS Concept: Quantified security assessment through heuristics
# ============================================================
SCORING_CONFIG = {
    "no_https":              15,   # CNS: HTTP lacks TLS/SSL encryption
    "ip_address":            25,   # Legitimate sites rarely use raw IPs
    "url_length_medium":     10,   # Length > 75 chars
    "url_length_long":       15,   # Length > 120 chars (stacked with medium)
    "at_symbol":             20,   # '@' in URL redirects browser to address after it
    "too_many_subdomains":   15,   # e.g., login.secure.bank.fake.com
    "suspicious_keyword":    10,   # Per suspicious keyword found (capped at 20)
    "too_many_hyphens":       5,   # e.g., my-secure-bank-login.com
    "suspicious_tld":        20,   # Suspicious TLDs — heavily abused for phishing
    "suspicious_domain_pat": 20,   # Brand impersonation — strong phishing signal
    "double_slash_redirect":  10,  # // in path (redirect trick)
    "prefix_suffix_dash":    10,   # Hyphen in domain (e.g., paypal-secure.com)
    "hex_encoding":          10,   # %XX encoding in URL (obfuscation)
    "port_in_url":           10,   # Non-standard port usage
    "multiple_dots_domain":  10,   # Too many dots in domain
}

# ============================================================
# Risk Level Thresholds
# CNS Concept: Tiered threat classification system
# ============================================================
RISK_THRESHOLDS = {
    "LOW":       (0, 29),
    "SUSPICIOUS": (30, 59),
    "HIGH":      (60, 100),
}


def extract_features(url: str) -> Dict:
    """
    Extract security-relevant features from a URL.
    
    CNS Concept: Feature extraction is the foundation of any URL-based
    phishing detection system. We analyze the URL structure without
    visiting the website, making this a safe static analysis approach.
    
    Args:
        url: The URL string to analyze
        
    Returns:
        Dictionary containing all extracted features and their values
    """
    features = {}
    
    # Ensure URL has a scheme for proper parsing
    if not url.startswith(("http://", "https://", "ftp://")):
        url_to_parse = "http://" + url
    else:
        url_to_parse = url
    
    try:
        parsed = urllib.parse.urlparse(url_to_parse)
    except Exception:
        return {"parse_error": True}
    
    netloc = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = url

    # ----------------------------------------------------------
    # Feature 1: HTTPS Check
    # CNS Concept: HTTPS uses TLS/SSL to encrypt data in transit.
    # HTTP is unencrypted and susceptible to man-in-the-middle attacks.
    # ----------------------------------------------------------
    features["has_https"] = url_to_parse.startswith("https://")
    features["scheme"] = parsed.scheme

    # ----------------------------------------------------------
    # Feature 2: IP Address in URL
    # CNS Concept: Legitimate organizations use domain names, not raw IPs.
    # Attackers use IPs to bypass domain-based blacklists.
    # ----------------------------------------------------------
    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
    features["has_ip_address"] = bool(re.search(ip_pattern, netloc))

    # ----------------------------------------------------------
    # Feature 3: URL Length
    # Phishing URLs tend to be longer to hide malicious components
    # ----------------------------------------------------------
    features["url_length"] = len(full_url)

    # ----------------------------------------------------------
    # Feature 4: @ Symbol in URL
    # CNS Concept: The '@' character causes browsers to ignore everything
    # before it. e.g., http://legit.com@evil.com → goes to evil.com
    # ----------------------------------------------------------
    features["has_at_symbol"] = "@" in netloc or "@" in url

    # ----------------------------------------------------------
    # Feature 5: Number of Dots (Subdomains)
    # CNS Concept: Attackers add subdomains to mimic legit domains
    # e.g., secure.paypal.login.evil.com
    # ----------------------------------------------------------
    domain_parts = netloc.split(".")
    features["subdomain_count"] = max(0, len(domain_parts) - 2)
    features["dot_count"] = netloc.count(".")

    # ----------------------------------------------------------
    # Feature 6: Number of Hyphens in Domain
    # e.g., paypal-secure-login.com is suspicious
    # ----------------------------------------------------------
    domain_only = netloc.split(":")[0]  # remove port if present
    features["hyphen_count"] = domain_only.count("-")
    features["has_prefix_suffix"] = "-" in domain_only

    # ----------------------------------------------------------
    # Feature 7: Suspicious Keywords in URL
    # CNS Concept: Social engineering uses urgency-inducing words
    # ----------------------------------------------------------
    url_lower = full_url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    features["suspicious_keywords"] = found_keywords
    features["keyword_count"] = len(found_keywords)

    # ----------------------------------------------------------
    # Feature 8: Suspicious TLD (Top Level Domain)
    # Some TLDs are heavily abused by attackers due to free/cheap registration
    # ----------------------------------------------------------
    tld = "." + netloc.split(".")[-1].split(":")[0] if "." in netloc else ""
    features["tld"] = tld
    features["has_suspicious_tld"] = tld.lower() in SUSPICIOUS_TLDS

    # ----------------------------------------------------------
    # Feature 9: Brand Impersonation / Suspicious Domain Pattern
    # CNS Concept: Attackers clone legitimate brand names in domains
    # ----------------------------------------------------------
    suspicious_domain_found = False
    for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
        if re.search(pattern, netloc.lower()):
            suspicious_domain_found = True
            break
    features["has_suspicious_domain_pattern"] = suspicious_domain_found

    # ----------------------------------------------------------
    # Feature 10: Double Slash Redirect
    # e.g., http://example.com//redirect?url=http://evil.com
    # ----------------------------------------------------------
    features["has_double_slash"] = "//" in path

    # ----------------------------------------------------------
    # Feature 11: Hex Encoding / Obfuscation
    # CNS Concept: URL encoding (%20, %2F etc.) used to obfuscate malicious content
    # ----------------------------------------------------------
    features["has_hex_encoding"] = bool(re.search(r"%[0-9a-fA-F]{2}", full_url))

    # ----------------------------------------------------------
    # Feature 12: Non-standard Port
    # Legitimate sites use standard ports (80/443); others are suspicious
    # ----------------------------------------------------------
    if ":" in netloc and not netloc.startswith("["):  # exclude IPv6
        port_match = re.search(r":(\d+)", netloc)
        if port_match:
            port = int(port_match.group(1))
            features["port"] = port
            features["has_nonstandard_port"] = port not in (80, 443, 8080, 8443)
        else:
            features["port"] = None
            features["has_nonstandard_port"] = False
    else:
        features["port"] = None
        features["has_nonstandard_port"] = False

    # ----------------------------------------------------------
    # Feature 13: Query string length
    # ----------------------------------------------------------
    features["query_length"] = len(query)

    # Store parsed components for reference
    features["domain"] = netloc
    features["path"] = path
    features["query"] = query

    return features


def calculate_risk_score(features: Dict) -> Tuple[int, List[str], List[str]]:
    """
    Calculate risk score based on extracted features.
    
    CNS Concept: Rule-based expert system for threat assessment.
    Each rule represents a known phishing indicator backed by
    cybersecurity research and real-world attack patterns.
    
    Args:
        features: Dictionary of extracted URL features
        
    Returns:
        Tuple of (risk_score, reasons_list, positive_points_list)
    """
    if features.get("parse_error"):
        return 85, ["URL could not be parsed - highly suspicious"], []
    
    score = 0
    reasons = []        # Suspicious findings
    positives = []      # Safe characteristics
    
    # ----------------------------------------------------------
    # Rule 1: HTTPS Check
    # ----------------------------------------------------------
    if not features.get("has_https"):
        score += SCORING_CONFIG["no_https"]
        reasons.append("URL does not use HTTPS (no SSL/TLS encryption)")
    else:
        positives.append("HTTPS is enabled (secure connection)")
    
    # ----------------------------------------------------------
    # Rule 2: IP Address Detection
    # ----------------------------------------------------------
    if features.get("has_ip_address"):
        score += SCORING_CONFIG["ip_address"]
        reasons.append("URL uses an IP address instead of a domain name")
    else:
        positives.append("No IP address detected in URL")
    
    # ----------------------------------------------------------
    # Rule 3: URL Length
    # ----------------------------------------------------------
    url_len = features.get("url_length", 0)
    if url_len > 120:
        score += SCORING_CONFIG["url_length_medium"] + SCORING_CONFIG["url_length_long"]
        reasons.append(f"URL is very long ({url_len} characters — typical phishing URLs are excessively long)")
    elif url_len > 75:
        score += SCORING_CONFIG["url_length_medium"]
        reasons.append(f"URL is longer than normal ({url_len} characters)")
    else:
        positives.append(f"Normal URL length ({url_len} characters)")
    
    # ----------------------------------------------------------
    # Rule 4: @ Symbol
    # ----------------------------------------------------------
    if features.get("has_at_symbol"):
        score += SCORING_CONFIG["at_symbol"]
        reasons.append("URL contains '@' symbol (can redirect to a different domain)")
    else:
        positives.append("No '@' symbol detected")
    
    # ----------------------------------------------------------
    # Rule 5: Subdomains
    # ----------------------------------------------------------
    subdomain_count = features.get("subdomain_count", 0)
    if subdomain_count >= 3:
        score += SCORING_CONFIG["too_many_subdomains"]
        reasons.append(f"URL has too many subdomains ({subdomain_count}) — possible domain spoofing")
    elif subdomain_count == 2:
        score += 5
        reasons.append(f"URL has multiple subdomains ({subdomain_count})")
    else:
        positives.append("Normal subdomain structure")
    
    # ----------------------------------------------------------
    # Rule 6: Suspicious Keywords (capped contribution)
    # ----------------------------------------------------------
    keywords = features.get("suspicious_keywords", [])
    if keywords:
        keyword_score = min(len(keywords) * SCORING_CONFIG["suspicious_keyword"], 30)
        score += keyword_score
        reasons.append(f"URL contains suspicious keyword(s): {', '.join(keywords)}")
    else:
        positives.append("No suspicious keywords detected")
    
    # ----------------------------------------------------------
    # Rule 7: Hyphens in Domain
    # ----------------------------------------------------------
    hyphen_count = features.get("hyphen_count", 0)
    if hyphen_count >= 3:
        score += SCORING_CONFIG["too_many_hyphens"]
        reasons.append(f"Domain has many hyphens ({hyphen_count}) — common in fake domains")
    elif hyphen_count >= 1:
        score += 3
        reasons.append(f"Domain contains hyphen(s) ({hyphen_count})")
    else:
        positives.append("No hyphens in domain name")
    
    # ----------------------------------------------------------
    # Rule 8: Suspicious TLD
    # ----------------------------------------------------------
    if features.get("has_suspicious_tld"):
        score += SCORING_CONFIG["suspicious_tld"]
        reasons.append(f"URL uses a suspicious top-level domain ({features.get('tld')})")
    else:
        positives.append("Domain uses a common, trusted TLD")
    
    # ----------------------------------------------------------
    # Rule 9: Suspicious Domain Pattern (Brand Impersonation)
    # ----------------------------------------------------------
    if features.get("has_suspicious_domain_pattern"):
        score += SCORING_CONFIG["suspicious_domain_pat"]
        reasons.append("Domain pattern matches known phishing techniques (possible brand impersonation)")
    else:
        positives.append("No suspicious domain patterns detected")
    
    # ----------------------------------------------------------
    # Rule 10: Double Slash Redirect
    # ----------------------------------------------------------
    if features.get("has_double_slash"):
        score += SCORING_CONFIG["double_slash_redirect"]
        reasons.append("URL contains double slash in path (possible redirect trick)")
    
    # ----------------------------------------------------------
    # Rule 11: Hex Encoding
    # ----------------------------------------------------------
    if features.get("has_hex_encoding"):
        score += SCORING_CONFIG["hex_encoding"]
        reasons.append("URL contains hex-encoded characters (possible obfuscation technique)")
    
    # ----------------------------------------------------------
    # Rule 12: Non-standard Port
    # ----------------------------------------------------------
    if features.get("has_nonstandard_port"):
        score += SCORING_CONFIG["port_in_url"]
        reasons.append(f"URL uses non-standard port ({features.get('port')}) — suspicious for web traffic")

    # Cap score at 100
    score = min(score, 100)
    
    return score, reasons, positives


def get_risk_level(score: int) -> str:
    """
    Convert numeric risk score to categorical risk level.
    
    CNS Concept: Threat classification based on quantified risk assessment
    """
    if score <= 29:
        return "LOW"
    elif score <= 59:
        return "SUSPICIOUS"
    else:
        return "HIGH"


def get_recommendation(risk_level: str, score: int) -> str:
    """
    Generate user-friendly recommendation based on risk assessment.
    
    CNS Concept: Security awareness and user guidance
    """
    if risk_level == "LOW":
        return (
            "This URL appears relatively safe based on structural analysis. "
            "Always verify the domain name carefully before entering passwords "
            "or financial information. HTTPS alone does not guarantee safety."
        )
    elif risk_level == "SUSPICIOUS":
        return (
            "This URL shows some suspicious characteristics. Exercise caution — "
            "do not enter passwords or personal information unless you are absolutely "
            "certain of the website's legitimacy. Verify the domain through official channels."
        )
    else:
        return (
            "This URL exhibits multiple high-risk characteristics commonly associated "
            "with phishing attacks. We strongly recommend NOT visiting this URL. "
            "If you received this link via email or message, report it as phishing."
        )


def analyze_url(url: str) -> Dict:
    """
    Main analysis function — orchestrates feature extraction and risk scoring.
    
    This is the primary entry point for URL analysis. It performs:
    1. Input validation
    2. Feature extraction (static analysis)
    3. Risk score calculation
    4. Risk classification
    5. Result compilation
    
    CNS Concept: Defense-in-depth through multi-layered URL inspection
    
    Args:
        url: The URL string to analyze
        
    Returns:
        Complete analysis result dictionary
    """
    # Sanitize URL - remove leading/trailing whitespace
    url = url.strip()
    
    # Basic input validation
    if not url:
        return {
            "error": "Empty URL provided",
            "url": url,
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "reasons": [],
            "positives": [],
            "features": {},
            "recommendation": "Please enter a valid URL.",
        }
    
    # Check minimum URL structure
    if len(url) < 4:
        return {
            "error": "URL is too short to be valid",
            "url": url,
            "risk_score": 100,
            "risk_level": "HIGH",
            "reasons": ["URL is too short to be a legitimate web address"],
            "positives": [],
            "features": {},
            "recommendation": "This does not appear to be a valid URL.",
        }
    
    # Extract features (static analysis — no HTTP requests made)
    features = extract_features(url)
    
    # Calculate risk score using rule-based system
    risk_score, reasons, positives = calculate_risk_score(features)
    
    # Determine categorical risk level
    risk_level = get_risk_level(risk_score)
    
    # Generate recommendation text
    recommendation = get_recommendation(risk_level, risk_score)
    
    # Build analysis table for display
    analysis_table = build_analysis_table(features)
    
    return {
        "url": url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "positives": positives,
        "features": features,
        "analysis_table": analysis_table,
        "recommendation": recommendation,
        "disclaimer": (
            "⚠️ This is an automated analysis based on URL structure only. "
            "It is not a guarantee of safety or maliciousness. "
            "Always use your judgment and verify through official sources."
        )
    }


def build_analysis_table(features: Dict) -> List[Dict]:
    """
    Build a structured table of feature analysis results for UI display.
    
    Args:
        features: Extracted feature dictionary
        
    Returns:
        List of dicts with feature name, status, and detail
    """
    table = []

    def row(feature, status, detail):
        return {"feature": feature, "status": status, "detail": detail}

    # HTTPS
    if features.get("has_https"):
        table.append(row("HTTPS / SSL", "safe", "Enabled — data is encrypted in transit"))
    else:
        table.append(row("HTTPS / SSL", "danger", f"Not enabled — uses {features.get('scheme', 'unknown').upper()}"))

    # IP Address
    if features.get("has_ip_address"):
        table.append(row("IP Address in URL", "danger", "Detected — legitimate sites use domain names"))
    else:
        table.append(row("IP Address in URL", "safe", "Not detected"))

    # URL Length
    url_len = features.get("url_length", 0)
    if url_len > 120:
        table.append(row("URL Length", "danger", f"{url_len} characters — Very long (suspicious)"))
    elif url_len > 75:
        table.append(row("URL Length", "warning", f"{url_len} characters — Above normal"))
    else:
        table.append(row("URL Length", "safe", f"{url_len} characters — Normal"))

    # @ Symbol
    if features.get("has_at_symbol"):
        table.append(row("@ Symbol", "danger", "Detected in URL — can be used to redirect to different domain"))
    else:
        table.append(row("@ Symbol", "safe", "Not detected"))

    # Subdomains
    sub_count = features.get("subdomain_count", 0)
    if sub_count >= 3:
        table.append(row("Subdomains", "danger", f"{sub_count} subdomains — excessive (possible spoofing)"))
    elif sub_count == 2:
        table.append(row("Subdomains", "warning", f"{sub_count} subdomains — slightly elevated"))
    else:
        table.append(row("Subdomains", "safe", f"{sub_count} subdomain(s) — normal"))

    # Suspicious Keywords
    keywords = features.get("suspicious_keywords", [])
    if keywords:
        table.append(row("Suspicious Keywords", "warning", f"Found: {', '.join(keywords)}"))
    else:
        table.append(row("Suspicious Keywords", "safe", "None detected"))

    # Hyphens
    hyphens = features.get("hyphen_count", 0)
    if hyphens >= 3:
        table.append(row("Hyphens in Domain", "danger", f"{hyphens} hyphens — common in fake domains"))
    elif hyphens >= 1:
        table.append(row("Hyphens in Domain", "warning", f"{hyphens} hyphen(s) — slightly suspicious"))
    else:
        table.append(row("Hyphens in Domain", "safe", "None"))

    # TLD
    tld = features.get("tld", "")
    if features.get("has_suspicious_tld"):
        table.append(row("Top-Level Domain (TLD)", "danger", f"{tld} — frequently used in phishing"))
    else:
        table.append(row("Top-Level Domain (TLD)", "safe", f"{tld} — common TLD"))

    # Domain Pattern
    if features.get("has_suspicious_domain_pattern"):
        table.append(row("Domain Pattern", "danger", "Matches known phishing/impersonation pattern"))
    else:
        table.append(row("Domain Pattern", "safe", "No suspicious patterns detected"))

    # Hex Encoding
    if features.get("has_hex_encoding"):
        table.append(row("URL Encoding", "warning", "Hex-encoded characters detected (possible obfuscation)"))
    else:
        table.append(row("URL Encoding", "safe", "No suspicious encoding"))

    # Port
    if features.get("has_nonstandard_port"):
        table.append(row("Port Number", "warning", f"Non-standard port {features.get('port')} detected"))
    else:
        table.append(row("Port Number", "safe", "Standard port (or none specified)"))

    return table
