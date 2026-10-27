"""
PhishShift - Automated Tests for Model Predictions, Explanations & Robustness
"""

import sys
import os
import pytest
import joblib

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
from clean_data import extract_safe_url_features
from risk_explanations import (
    analyze_observed_indicators,
    rule_based_scorer,
    evaluate_risk_and_uncertainty
)
from robustness_test import ROBUSTNESS_TEST_CASES

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BEST_MODEL_PATH = os.path.join(BASE_DIR, "models", "best_model.joblib")
COMP_MODEL_PATH = os.path.join(BASE_DIR, "models", "comparison_model.joblib")

def test_models_exist_and_loadable():
    assert os.path.exists(BEST_MODEL_PATH), f"Primary model missing at {BEST_MODEL_PATH}"
    assert os.path.exists(COMP_MODEL_PATH), f"Comparison model missing at {COMP_MODEL_PATH}"
    
    model_lr = joblib.load(BEST_MODEL_PATH)
    model_nb = joblib.load(COMP_MODEL_PATH)
    assert hasattr(model_lr, "predict_proba")
    assert hasattr(model_nb, "predict_proba")

def test_phishing_message_prediction():
    model = joblib.load(BEST_MODEL_PATH)
    phish_msg = (
        "CRITICAL ALERT: Your bank account is locked due to unauthorized access. "
        "Verify your credentials immediately at http://192.168.1.105/auth within 24 hours."
    )
    prob = model.predict_proba([phish_msg])[0, 1]
    assert prob > 0.5, f"Expected phishing probability > 0.5, got {prob}"

def test_legitimate_message_prediction():
    model = joblib.load(BEST_MODEL_PATH)
    legit_msg = (
        "Hi team, attached are the notes and action items from our weekly sync. "
        "Please review section 3 before Thursday's standup. Best, Alex."
    )
    prob = model.predict_proba([legit_msg])[0, 1]
    assert prob < 0.5, f"Expected legitimate probability < 0.5, got {prob}"

def test_explanation_generation():
    msg = "URGENT: Verify your direct deposit routing number immediately at http://bit.ly/pay-now."
    url_feats = extract_safe_url_features(msg)
    observed = analyze_observed_indicators(msg, url_feats)
    score, category, reasons = rule_based_scorer(msg, url_feats)
    
    assert "urgent" in observed["urgency_cues"]
    assert "verify" in observed["credential_financial_cues"]
    assert len(observed["url_flags"]) > 0
    assert score >= 50
    assert category == "Likely Phishing"
    assert len(reasons) > 0

def test_uncertainty_handling_borderline():
    # Artificially test borderline probability
    borderline_prob = 0.52
    assessment = evaluate_risk_and_uncertainty(
        ml_probability=borderline_prob,
        rule_score=20,
        observed_indicators={"safe_context_cues": [], "urgency_cues": []}
    )
    assert assessment["is_uncertain"] is True
    assert assessment["category"] == "Uncertain"

def test_robustness_test_suite_data():
    assert len(ROBUSTNESS_TEST_CASES) >= 8
    for case in ROBUSTNESS_TEST_CASES:
        assert "original" in case
        assert "modified" in case
        assert "expected_label" in case
