"""
PhishShift - Risk Explanations and Uncertainty Module
Provides rule-based heuristics, observed indicator extraction,
risk level mapping, and uncertainty/abstention calibration.
"""

import re
from typing import Dict, List, Tuple, Any
import numpy as np

# Configurable Suspicious Lexical Indicators
URGENCY_KEYWORDS = [
    "immediately", "urgent", "24 hours", "48 hours", "suspended", "expire",
    "critical", "unauthorized", "legal action", "overdue", "locked", "restriction",
    "shut down", "action required", "compromised", "terminate"
]

CREDENTIAL_FINANCIAL_KEYWORDS = [
    "verify", "password", "pin", "routing number", "direct deposit", "gift card",
    "ssn", "social security", "wallet", "crypto", "ethereum", "refund",
    "claim prize", "wire transfer", "unclaimed", "re-enter", "credentials"
]

EXECUTIVE_IMPERSONATION_KEYWORDS = [
    "gift cards", "apple gift card", "voucher codes", "at your desk", "favor", "ceo", "offsite"
]

SAFE_LEGITIMATE_CONTEXT_KEYWORDS = [
    "scheduled maintenance", "routine upgrade", "floating holiday", "open enrollment",
    "agenda attached", "sprint retrospective", "coffee", "lunch", "dental cleaning",
    "prescription", "pickup", "grocery"
]

def analyze_observed_indicators(text: str, url_features: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Extracts concrete, observable security and contextual indicators from message text and URLs.
    Distinguishes observed concrete facts from model-inferred probabilities.
    """
    text_lower = text.lower()
    
    found_urgency = [w for w in URGENCY_KEYWORDS if w in text_lower]
    found_cred_fin = [w for w in CREDENTIAL_FINANCIAL_KEYWORDS if w in text_lower]
    found_executive = [w for w in EXECUTIVE_IMPERSONATION_KEYWORDS if w in text_lower]
    found_safe_cues = [w for w in SAFE_LEGITIMATE_CONTEXT_KEYWORDS if w in text_lower]
    
    # URL indicators
    url_flags = []
    if url_features:
        if url_features.get("is_ip_url", 0) == 1:
            url_flags.append("Raw IPv4 Host in URL (bypasses domain registration)")
        if url_features.get("has_shortener", 0) == 1:
            url_flags.append("URL Masking Shortener Detected (hides destination)")
        if url_features.get("has_suspicious_tld", 0) == 1:
            url_flags.append("Suspicious / High-Abuse Top-Level Domain (.xyz, .top, .live)")
        if url_features.get("max_subdomains", 0) >= 3:
            url_flags.append("Excessive Subdomain Depth (deceptive brand impersonation)")
    else:
        # Inline basic URL indicator checks if url_features not passed
        if re.search(r'https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}', text, re.IGNORECASE):
            url_flags.append("Raw IPv4 Host in URL")
        if re.search(r'bit\.ly|tinyurl\.com|t\.co|goo\.gl', text, re.IGNORECASE):
            url_flags.append("URL Masking Shortener Detected")
            
    # Currency symbols
    has_currency = bool(re.search(r'[\$€£]', text))
    if has_currency:
        found_cred_fin.append("currency symbol ($/€/£)")

    # All-caps words (excluding common single-letter tokens)
    caps_words = [w for w in re.findall(r'\b[A-Z]{3,}\b', text) if w not in {"THE", "AND", "FOR", "NOT", "YES", "EST", "PST"}]
    
    return {
        "urgency_cues": found_urgency,
        "credential_financial_cues": found_cred_fin,
        "executive_cues": found_executive,
        "safe_context_cues": found_safe_cues,
        "url_flags": url_flags,
        "caps_words": caps_words[:5]
    }

def rule_based_scorer(text: str, url_features: Dict[str, Any] = None) -> Tuple[int, str, List[str]]:
    """
    Heuristic baseline scorer:
    Calculates a risk score (0-100) based on weighted configurable security indicators.
    Returns: (score, risk_category, explanations)
    """
    obs = analyze_observed_indicators(text, url_features)
    score = 0
    reasons = []
    
    # 1. URL Risks (High weight)
    if obs["url_flags"]:
        for flag in obs["url_flags"]:
            score += 25
            reasons.append(f"Suspicious URL Characteristic: {flag}")
            
    # 2. Urgency language
    if obs["urgency_cues"]:
        score += min(len(obs["urgency_cues"]) * 12, 30)
        reasons.append(f"Urgency Language: {', '.join(obs['urgency_cues'])}")
        
    # 3. Credential & Financial Harvesting
    if obs["credential_financial_cues"]:
        score += min(len(obs["credential_financial_cues"]) * 12, 30)
        reasons.append(f"Credential/Financial Lures: {', '.join(obs['credential_financial_cues'])}")
        
    # 4. Executive Gift Card Impersonation (BEC)
    if obs["executive_cues"]:
        score += 35
        reasons.append("Executive Gift Card / Urgent Lure (Business Email Compromise pattern)")
        
    # 5. Excessive Capitalization
    if obs["caps_words"]:
        score += 10
        reasons.append(f"Aggressive Capitalization: {', '.join(obs['caps_words'])}")
        
    # 6. Mitigating safe cues
    if obs["safe_context_cues"] and score < 50:
        score = max(0, score - 20)
        reasons.append(f"Legitimate Operational Context: {', '.join(obs['safe_context_cues'])}")
        
    score = min(100, max(0, score))
    
    if score >= 50:
        category = "Likely Phishing"
    elif score >= 25:
        category = "Uncertain"
    else:
        category = "Likely Legitimate"
        
    return score, category, reasons

def evaluate_risk_and_uncertainty(
    ml_probability: float,
    rule_score: int,
    observed_indicators: Dict[str, Any],
    lower_threshold: float = 0.35,
    upper_threshold: float = 0.65
) -> Dict[str, Any]:
    """
    Combines calibrated ML probability with heuristic baseline observations to determine:
    - Final Category: Likely Phishing, Likely Legitimate, or Uncertain (Abstain)
    - Risk Level: High, Medium, Low
    - Model Confidence vs. Heuristic Agreement
    - Clear, actionable safety advice
    """
    reasons = []
    
    # Check for direct conflict or ambiguity
    is_uncertain = False
    uncertainty_reason = ""
    
    # 1. Model ambiguity range
    if lower_threshold <= ml_probability <= upper_threshold:
        is_uncertain = True
        uncertainty_reason = f"Statistical model probability ({ml_probability:.1%}) falls within the abstention margin [{lower_threshold:.0%}-{upper_threshold:.0%}]."
        
    # 2. Conflicting evidence (e.g. low ML probability but strong suspicious URL or high heuristic score)
    if ml_probability < lower_threshold and rule_score >= 50:
        is_uncertain = True
        uncertainty_reason = "Model predicted low risk, but observed structural indicators (e.g. IP-based URL or urgent threats) warrant caution."
        
    if ml_probability > upper_threshold and rule_score < 10 and observed_indicators["safe_context_cues"]:
        is_uncertain = True
        uncertainty_reason = "Statistical model flagged phishing tokens, but message exhibits strong legitimate operational patterns."

    # Final Classification Determination
    if is_uncertain:
        category = "Uncertain"
        risk_level = "Medium Risk (Manual Verification Required)"
        status_color = "warning"
        safety_rec = (
            "⚠️ Do not click any links or enter credentials. Verify this message through an independent, "
            "known channel (e.g., call the organization using an official phone number, or visit their website directly)."
        )
    elif ml_probability > upper_threshold or rule_score >= 65:
        category = "Likely Phishing"
        risk_level = "High Risk (Potential Threat)"
        status_color = "danger"
        safety_rec = (
            "🚨 Exercise extreme caution. This message shows strong characteristics of social engineering. "
            "Never provide credentials, download attachments, or follow links provided in this message."
        )
    else:
        category = "Likely Legitimate"
        risk_level = "Low Risk"
        status_color = "success"
        safety_rec = (
            "✅ This message appears consistent with legitimate communication. However, no automated scanner "
            "can guarantee 100% safety. Always remain mindful of unexpected requests."
        )

    return {
        "category": category,
        "risk_level": risk_level,
        "ml_probability": round(float(ml_probability), 4),
        "rule_score": int(rule_score),
        "is_uncertain": is_uncertain,
        "uncertainty_reason": uncertainty_reason,
        "safety_recommendation": safety_rec,
        "status_color": status_color,
        "observed_indicators": observed_indicators
    }
