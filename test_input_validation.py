"""
PhishShift - Automated Tests for Input Validation and Edge Cases
"""

import sys
import os
import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
from clean_data import normalize_text

def test_empty_string_input():
    cleaned = normalize_text("")
    assert cleaned == ""

def test_whitespace_only_input():
    cleaned = normalize_text("   \t  \n   ")
    assert cleaned == ""

def test_none_input_handling():
    cleaned = normalize_text(None)
    assert cleaned == ""

def test_very_long_input_preservation():
    long_text = "Standard message token. " * 500
    cleaned = normalize_text(long_text)
    assert len(cleaned) > 5000
    assert "Standard message token." in cleaned

def test_unusual_unicode_control_characters():
    # Zero-width spaces, null bytes
    malformed = "Urgent\u200b update\x00 required"
    cleaned = normalize_text(malformed)
    assert "\x00" not in cleaned
    assert "Urgent" in cleaned
