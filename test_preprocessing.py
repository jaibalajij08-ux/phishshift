"""
PhishShift - Automated Tests for Preprocessing and Safe Feature Extraction
"""

import sys
import os
import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from clean_data import normalize_text, extract_safe_url_features, calculate_shannon_entropy

def test_normalize_text_whitespace():
    raw = "Hello    team,   please   review   notes."
    cleaned = normalize_text(raw)
    assert cleaned == "Hello team, please review notes."

def test_normalize_text_exclamation_capping():
    raw = "ACT NOW!!!!!!!! Account will be suspended!!!!"
    cleaned = normalize_text(raw)
    assert "!!!!" not in cleaned
    assert "!!!" in cleaned

def test_normalize_text_preserves_currency():
    raw = "You received $4,500.00 in your account. Settle fee of €20."
    cleaned = normalize_text(raw)
    assert "$" in cleaned
    assert "€" in cleaned

def test_extract_safe_url_features_no_url():
    text = "Hey, are you free for coffee this afternoon?"
    feats = extract_safe_url_features(text)
    assert feats["has_url"] == 0
    assert feats["url_count"] == 0
    assert feats["is_ip_url"] == 0

def test_extract_safe_url_features_standard_url():
    text = "Visit our docs at https://portal.example.com/login for details."
    feats = extract_safe_url_features(text)
    assert feats["has_url"] == 1
    assert feats["url_count"] == 1
    assert feats["is_ip_url"] == 0

def test_extract_safe_url_features_ip_address():
    text = "Decline transfer here: http://192.168.1.100/cancel-wire"
    feats = extract_safe_url_features(text)
    assert feats["has_url"] == 1
    assert feats["is_ip_url"] == 1

def test_extract_safe_url_features_shortener():
    text = "Track your parcel: http://bit.ly/track-now-12"
    feats = extract_safe_url_features(text)
    assert feats["has_url"] == 1
    assert feats["has_shortener"] == 1

def test_extract_safe_url_features_subdomain_depth():
    text = "Authenticate at https://secure.login.bank.update.example.com/auth"
    feats = extract_safe_url_features(text)
    assert feats["max_subdomains"] >= 3

def test_calculate_shannon_entropy():
    # Uniform text has higher entropy than single repeated character
    entropy_uniform = calculate_shannon_entropy("abcdefghijk")
    entropy_single = calculate_shannon_entropy("aaaaaaaaaaa")
    assert entropy_single == 0.0
    assert entropy_uniform > 3.0
