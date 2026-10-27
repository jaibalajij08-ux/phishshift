"""
PhishShift - Robustness Testing Suite
Tests how model predictions behave under adversarial and real-world perturbations:
1. Capitalization changes
2. Extra whitespace & tab injections
3. Punctuation manipulation
4. Harmless wording / synonym substitutions
5. Equivalent URL variations
6. Legitimate messages with urgent language
7. Novel / unfamiliar phishing lures
8. Obfuscated character leetspeak
"""

import os
import sys
import pandas as pd
import numpy as np
import joblib

# Ensure UTF-8 console output
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from clean_data import extract_safe_url_features
from risk_explanations import rule_based_scorer, evaluate_risk_and_uncertainty

ROBUSTNESS_TEST_CASES = [
    {
        "test_id": "ROB-01",
        "variation_name": "Aggressive All-Caps Transformation",
        "description": "Tests if shouting in all-caps distorts TF-IDF tokenization or probability.",
        "original": "Dear customer, your bank account access has been restricted. Please verify immediately at http://secure-bank.example.com.",
        "modified": "DEAR CUSTOMER, YOUR BANK ACCOUNT ACCESS HAS BEEN RESTRICTED. PLEASE VERIFY IMMEDIATELY AT HTTP://SECURE-BANK.EXAMPLE.COM.",
        "expected_label": "Phishing"
    },
    {
        "test_id": "ROB-02",
        "variation_name": "Excessive Whitespace & Tab Insertion",
        "description": "Tests resistance against whitespace padding designed to break regex boundaries.",
        "original": "USPS: Your package #8821 is on hold. Pay $1.99 redelivery fee at http://usps-redeliver.example.com.",
        "modified": "USPS:   Your    package   #8821   is   on   hold.   Pay   $1.99   fee   at   http://usps-redeliver.example.com.",
        "expected_label": "Phishing"
    },
    {
        "test_id": "ROB-03",
        "variation_name": "Punctuation Obfuscation",
        "description": "Tests word-boundary resilience when periods and hyphens are injected into keywords.",
        "original": "URGENT: Your password will expire today. Update credentials immediately.",
        "modified": "U.R.G.E.N.T: Your p-a-s-s-w-o-r-d will expire today. Update c.r.e.d.e.n.t.i.a.l.s immediately.",
        "expected_label": "Phishing"
    },
    {
        "test_id": "ROB-04",
        "variation_name": "Harmless Synonym Substitution",
        "description": "Replaces blatant urgency tokens with polite bureaucratic synonyms.",
        "original": "Immediate verification required. Verify your credentials within 24 hours or face suspension.",
        "modified": "Kind verification requested. Please review your account profile at your earliest convenience to maintain service.",
        "expected_label": "Phishing"
    },
    {
        "test_id": "ROB-05",
        "variation_name": "Equivalent URL Protocol and Host Casing",
        "description": "Tests URL feature extraction when casing and protocols are altered.",
        "original": "Please verify your account at https://portal.example.com/login.",
        "modified": "Please verify your account at HTTP://PORTAL.EXAMPLE.COM/LOGIN.",
        "expected_label": "Phishing"
    },
    {
        "test_id": "ROB-06",
        "variation_name": "Legitimate Operational Urgency (False Positive Test)",
        "description": "Tests whether legitimate internal IT messages with urgent deadlines trigger false alarms.",
        "original": "Urgent deadline: All engineers must submit their quarterly compliance training by 5 PM today.",
        "modified": "CRITICAL DEADLINE TODAY: Mandatory safety compliance certification closes at 5:00 PM. No extension granted.",
        "expected_label": "Legitimate"
    },
    {
        "test_id": "ROB-07",
        "variation_name": "Novel Unfamiliar Template (MFA Push Fatigue)",
        "description": "Tests detection on a zero-day phrasing style not present in training data.",
        "original": "Your Microsoft 365 password has expired. Click here to reset.",
        "modified": "Multiple repeated Duo MFA push requests detected from unknown device. Tap here to approve or deny request: http://192.168.1.10/mfa-gate.",
        "expected_label": "Phishing"
    },
    {
        "test_id": "ROB-08",
        "variation_name": "Character Leetspeak / Homoglyph Evasion",
        "description": "Substitutes letters with symbols (@ for a, 0 for o) to evade static tokenizers.",
        "original": "Security warning: unauthorized banking login detected. Confirm password now.",
        "modified": "Secur!ty w@rn!ng: unauth0r!zed b@nk!ng l0g!n detected. C0nf!rm p@ssw0rd n0w.",
        "expected_label": "Phishing"
    }
]

def run_robustness_tests():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    model_path = os.path.join(base_dir, "models", "best_model.joblib")
    results_dir = os.path.join(base_dir, "results")
    
    print("=" * 60)
    print(" PhishShift: Running Robustness Stress Testing Suite")
    print("=" * 60)
    
    pipeline = joblib.load(model_path)
    records = []
    
    for case in ROBUSTNESS_TEST_CASES:
        orig = case["original"]
        mod = case["modified"]
        
        # Original evaluation
        orig_prob = pipeline.predict_proba([orig])[0, 1]
        orig_rule, _, _ = rule_based_scorer(orig, extract_safe_url_features(orig))
        orig_eval = evaluate_risk_and_uncertainty(orig_prob, orig_rule, {})
        orig_cat = orig_eval["category"]
        
        # Modified evaluation
        mod_prob = pipeline.predict_proba([mod])[0, 1]
        mod_rule, _, _ = rule_based_scorer(mod, extract_safe_url_features(mod))
        mod_eval = evaluate_risk_and_uncertainty(mod_prob, mod_rule, {})
        mod_cat = mod_eval["category"]
        
        prediction_changed = (orig_cat != mod_cat)
        
        # Check if change caused an erroneous classification
        expected = case["expected_label"]
        if expected == "Phishing":
            caused_error = (mod_cat == "Likely Legitimate")
        else:
            caused_error = (mod_cat == "Likely Phishing")
            
        # Explanatory comment
        if prediction_changed:
            if mod_cat == "Uncertain":
                comment = "Shifted to Uncertain: the perturbation reduced feature confidence, prompting safe abstention."
            elif caused_error:
                comment = f"Vulnerability detected: modification successfully evaded detection (labeled {mod_cat})."
            else:
                comment = f"Prediction changed from {orig_cat} to {mod_cat}."
        else:
            comment = f"Robust: successfully maintained {mod_cat} assessment despite perturbation."
            
        records.append({
            "Test_ID": case["test_id"],
            "Variation_Name": case["variation_name"],
            "Original_Category": orig_cat,
            "Original_Prob": f"{orig_prob:.1%}",
            "Modified_Category": mod_cat,
            "Modified_Prob": f"{mod_prob:.1%}",
            "Prediction_Changed": "YES" if prediction_changed else "NO",
            "Caused_Error": "YES" if caused_error else "NO",
            "Behavior_Analysis": comment
        })
        
    df_results = pd.DataFrame(records)
    csv_path = os.path.join(results_dir, "robustness_results.csv")
    df_results.to_csv(csv_path, index=False)
    print(f"[OK] Robustness results saved to: {csv_path}\n")
    
    print("-" * 75)
    for r in records:
        print(f"[{r['Test_ID']}] {r['Variation_Name']}")
        print(f"  Orig: {r['Original_Category']} ({r['Original_Prob']}) -> Mod: {r['Modified_Category']} ({r['Modified_Prob']})")
        print(f"  Changed? {r['Prediction_Changed']} | Caused Error? {r['Caused_Error']}")
        print(f"  Analysis: {r['Behavior_Analysis']}\n")
    print("=" * 75)
    return df_results

if __name__ == "__main__":
    run_robustness_tests()
