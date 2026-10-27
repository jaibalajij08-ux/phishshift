"""
PhishShift — Message Risk Scanner
Interactive Streamlit Web Dashboard for Defensive Cybersecurity Training
"""

import os
import sys
import streamlit as st
import joblib
import pandas as pd
import numpy as np

# Add src to python path for imports
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)

from clean_data import normalize_text, extract_safe_url_features
from risk_explanations import (
    analyze_observed_indicators,
    rule_based_scorer,
    evaluate_risk_and_uncertainty
)

# Page configuration
st.set_page_config(
    page_title="PhishShift — Message Risk Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Harmless Preloaded Demonstrations
SAMPLE_MESSAGES = {
    "-- Select a sample message --": "",
    "Phishing Email: Bank Credential Harvest": (
        "Subject: CRITICAL: Immediate Account Verification Required\n\n"
        "Dear Customer, we detected unauthorized attempts to access your online banking profile from an unknown device. "
        "To safeguard your funds, your account has been temporarily restricted. "
        "Verify your identity immediately at https://secure-bank-login.update-support.example.com/verify to restore access within 24 hours."
    ),
    "Phishing SMS: Package Redelivery Fee Scam": (
        "USPS Alert: Your package is on hold due to incomplete street address and an unpaid $1.99 redelivery fee. "
        "Update info at http://bit.ly.example.com/usps-track within 12h or package will be returned to sender."
    ),
    "Phishing Email: Executive Gift Card (BEC)": (
        "Subject: Quick Favor / Are you at your desk?\n\n"
        "Hi, I am tied up in an all-day executive client meeting. "
        "I need you to urgently purchase five $100 Apple gift cards for a customer presentation. "
        "Please email me the scratch-off voucher codes as soon as possible. Thanks, CEO."
    ),
    "Legitimate Email: Scheduled IT Maintenance": (
        "Subject: Scheduled Server Maintenance Notice: Sunday 2 AM\n\n"
        "The IT Infrastructure team will perform scheduled maintenance on internal file servers this Sunday "
        "between 2:00 AM and 4:00 AM. Access may be temporarily intermittent. No action is required on your part."
    ),
    "Legitimate SMS: Two-Factor Authentication Code": (
        "Your verification code is 482910. It expires in 10 minutes. "
        "Do not share this code with anyone. If you did not request this, please change your password."
    ),
    "Ambiguous / Edge Case: Urgent Meeting Follow-up": (
        "URGENT: Please review the updated budget allocation spreadsheet before our 3 PM board call today."
    )
}

@st.cache_resource
def load_models():
    """Loads pre-trained pipelines cached in memory to ensure fast startup."""
    best_path = os.path.join(BASE_DIR, "models", "best_model.joblib")
    comp_path = os.path.join(BASE_DIR, "models", "comparison_model.joblib")
    
    best_model = joblib.load(best_path) if os.path.exists(best_path) else None
    comp_model = joblib.load(comp_path) if os.path.exists(comp_path) else None
    return best_model, comp_model

best_model, comp_model = load_models()

# -------------------------------------------------------------
# Sidebar Configuration & Project Information
# -------------------------------------------------------------
with st.sidebar:
    st.image("https://img.shields.io/badge/Security-PhishShift_v1.0-blue?style=for-the-badge", use_container_width=True)
    st.title("🛡️ About PhishShift")
    st.markdown(
        """
        **PhishShift** is an educational cybersecurity prototype designed to analyze **email** and **SMS** messages 
        and safely assess potential phishing risk.
        
        ### 🔍 How it Works
        1. **Safe Feature Extraction**: Parses lexical and URL signals (IP hosts, subdomains, shorteners) *offline*.
        2. **Multi-Model Scoring**:
           - **Rule-Based Baseline** (Heuristic rules)
           - **TF-IDF + Logistic Regression** (Primary ML)
           - **TF-IDF + Naive Bayes** (Comparison ML)
        3. **Explainability & Abstention**: Shows observed flags and abstains as **Uncertain** if confidence is ambiguous.
        """
    )
    st.divider()
    
    st.subheader("📊 Model Comparison")
    metrics_path = os.path.join(BASE_DIR, "results", "metrics.csv")
    if os.path.exists(metrics_path):
        m_df = pd.read_csv(metrics_path)
        st.dataframe(m_df, hide_index=True)
    else:
        st.info("Train models via `python src/train_model.py` to view benchmark metrics.")
        
    st.divider()
    st.markdown(
        """
        > 🔒 **Privacy Guarantee**: Submitted messages are evaluated entirely in local memory. 
        > No inputs are stored or transmitted to external services.
        """
    )

# -------------------------------------------------------------
# Main Application Header
# -------------------------------------------------------------
st.title("PhishShift — Message Risk Scanner")
st.caption("A defensive educational prototype for analyzing suspicious communication patterns without opening external links.")

# Sample Selection Row
col_sample, col_clear = st.columns([4, 1])
with col_sample:
    selected_sample = st.selectbox(
        "Load a Harmless Demo Sample:",
        options=list(SAMPLE_MESSAGES.keys()),
        index=0,
        help="Select a realistic pre-configured example to test the scanner."
    )

# Session state handling for clear/reset
if "input_message" not in st.session_state:
    st.session_state.input_message = ""

if selected_sample != "-- Select a sample message --":
    st.session_state.input_message = SAMPLE_MESSAGES[selected_sample]

with col_clear:
    st.write("") # Spacer
    st.write("") 
    if st.button("🔄 Reset Input", use_container_width=True):
        st.session_state.input_message = ""
        st.rerun()

# Text Area Input
user_input = st.text_area(
    "Paste the email subject/body or SMS message to analyze:",
    value=st.session_state.input_message,
    height=160,
    placeholder="e.g., URGENT: Your account has been suspended. Click here to verify credentials..."
)

# Analyze Button
analyze_button = st.button("🚀 Analyze Message Risk", type="primary", use_container_width=True)

# -------------------------------------------------------------
# Inference and Risk Presentation
# -------------------------------------------------------------
if analyze_button:
    # 1. Input Validation
    cleaned_input = normalize_text(user_input)
    if not cleaned_input or len(cleaned_input.strip()) == 0:
        st.error("❌ Validation Error: Message input is empty. Please enter text or choose a sample message.")
    elif len(cleaned_input.split()) < 3 and len(cleaned_input) < 15:
        st.warning("⚠️ Input Warning: The message is extremely brief (< 3 words). Detection accuracy may be reduced.")
    elif len(cleaned_input) > 10000:
        st.error("❌ Input Error: Message exceeds maximum permitted length (10,000 characters).")
    elif best_model is None:
        st.error("❌ Model Error: Pre-trained model pipeline not found in `models/best_model.joblib`.")
    else:
        # 2. Offline Lexical and URL Feature Extraction
        url_features = extract_safe_url_features(cleaned_input)
        observed = analyze_observed_indicators(cleaned_input, url_features)
        rule_score, rule_cat, rule_reasons = rule_based_scorer(cleaned_input, url_features)
        
        # 3. Model Inference
        ml_prob = best_model.predict_proba([cleaned_input])[0, 1]
        
        # Comparison Model Inference (if present)
        comp_prob = comp_model.predict_proba([cleaned_input])[0, 1] if comp_model else None
        
        # 4. Uncertainty & Risk Assessment
        assessment = evaluate_risk_and_uncertainty(ml_prob, rule_score, observed)
        
        st.divider()
        st.subheader("📋 Assessment Results")
        
        # Top Metrics Banner
        col_res1, col_res2, col_res3 = st.columns(3)
        
        with col_res1:
            if assessment["category"] == "Likely Phishing":
                st.error(f"### 🚨 {assessment['category']}")
            elif assessment["category"] == "Uncertain":
                st.warning(f"### ⚠️ {assessment['category']}")
            else:
                st.success(f"### ✅ {assessment['category']}")
            st.caption(f"Risk Level: **{assessment['risk_level']}**")

        with col_res2:
            st.metric(
                label="Primary ML Phishing Probability",
                value=f"{ml_prob:.1%}",
                delta=f"Heuristic Baseline: {rule_score}/100"
            )
            
        with col_res3:
            if comp_prob is not None:
                st.metric(
                    label="Comparison (Naive Bayes) Probability",
                    value=f"{comp_prob:.1%}",
                    delta=f"Diff: {abs(ml_prob - comp_prob):.1%}"
                )
            else:
                st.metric(label="Heuristic Risk Score", value=f"{rule_score} / 100")

        # Uncertainty Warning Callout
        if assessment["is_uncertain"]:
            st.warning(
                f"**Uncertainty Notice**: {assessment['uncertainty_reason']}\n\n"
                "The system cannot make a definitive prediction with high confidence. Proceed cautiously."
            )

        # Actionable Safety Recommendation
        st.info(f"**Safety Recommendation**: {assessment['safety_recommendation']}")

        # -------------------------------------------------------------
        # Detailed Indicator Breakdown
        # -------------------------------------------------------------
        st.subheader("🔍 Breakdown of Observed Indicators vs. Model Inferences")
        
        col_obs, col_url = st.columns(2)
        
        with col_obs:
            st.markdown("#### 📝 Text & Psychological Signals")
            if observed["urgency_cues"]:
                st.markdown(f"- ⏳ **Urgency Tokens Detected**: `{', '.join(observed['urgency_cues'])}`")
            if observed["credential_financial_cues"]:
                st.markdown(f"- 💳 **Credential/Financial Lures**: `{', '.join(observed['credential_financial_cues'])}`")
            if observed["executive_cues"]:
                st.markdown(f"- 👔 **Executive/Voucher Patterns**: `{', '.join(observed['executive_cues'])}`")
            if observed["caps_words"]:
                st.markdown(f"- 📢 **Prominent Uppercase Words**: `{', '.join(observed['caps_words'])}`")
            if observed["safe_context_cues"]:
                st.markdown(f"- 🛡️ **Operational Context Indicators**: `{', '.join(observed['safe_context_cues'])}`")
            if not (observed["urgency_cues"] or observed["credential_financial_cues"] or observed["executive_cues"]):
                st.markdown("- *No conspicuous social engineering keywords detected.*")

        with col_url:
            st.markdown("#### 🔗 Safe Lexical URL Characteristics")
            st.markdown(f"- **Total URLs Present**: `{url_features['url_count']}`")
            if url_features["is_ip_url"] == 1:
                st.markdown("- 🚩 **Raw IPv4 Address URL**: Yes (bypasses domain registration)")
            if url_features["has_shortener"] == 1:
                st.markdown("- 🚩 **URL Masking / Shortener**: Detected")
            if url_features["has_suspicious_tld"] == 1:
                st.markdown("- 🚩 **Suspicious TLD**: Detected")
            if url_features["max_subdomains"] >= 2:
                st.markdown(f"- 🚩 **Excessive Subdomains**: Depth = {url_features['max_subdomains']}")
            st.markdown(f"- **Max URL Character Entropy (NumPy)**: `{url_features['url_entropy']}`")

        # Expandable Technical Explanation
        with st.expander("🛠️ View Complete Heuristic Audit & Defense Rationale"):
            st.markdown(f"**Rule Scorer Explanation Steps**:")
            if rule_reasons:
                for r in rule_reasons:
                    st.write(f"• {r}")
            else:
                st.write("• No penalty or heuristic flags triggered.")
            st.caption(
                "Note: Rule scoring acts as a baseline heuristic check. In production, machine learning "
                "models evaluate structural n-gram weights in combination with these observed characteristics."
            )

# -------------------------------------------------------------
# Footer & Defensive Disclaimer
# -------------------------------------------------------------
st.divider()
st.caption(
    "⚠️ **Educational & Defensive Disclaimer**: PhishShift is a machine learning prototype intended for cybersecurity training "
    "and educational awareness. It does not guarantee 100% detection accuracy. Never click unverified hyperlinks or download "
    "untrusted attachments based solely on automated scanner outputs."
)
