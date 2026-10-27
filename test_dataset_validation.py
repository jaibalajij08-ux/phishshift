"""
PhishShift - Automated Tests for Dataset Validation
"""

import os
import pandas as pd
import pytest

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "raw_messages.csv")
REQUIRED_COLUMNS = [
    "message_id",
    "channel",
    "subject",
    "body",
    "sanitized_url_features",
    "sender_domain_category",
    "label",
    "campaign_id",
    "collection_date",
    "source",
    "license"
]

def test_raw_dataset_file_exists():
    assert os.path.exists(DATA_PATH), f"Raw dataset not found at {DATA_PATH}"

def test_raw_dataset_schema():
    df = pd.read_csv(DATA_PATH)
    for col in REQUIRED_COLUMNS:
        assert col in df.columns, f"Required column '{col}' missing from raw dataset"

def test_raw_dataset_minimum_samples():
    df = pd.read_csv(DATA_PATH)
    assert len(df) >= 400, f"Dataset has only {len(df)} samples, expected >= 400"

def test_raw_dataset_labels():
    df = pd.read_csv(DATA_PATH)
    unique_labels = set(df["label"].unique())
    assert unique_labels.issubset({0, 1}), f"Labels contain non-binary values: {unique_labels}"

def test_raw_dataset_no_critical_nulls():
    df = pd.read_csv(DATA_PATH)
    critical_cols = ["message_id", "channel", "body", "label", "campaign_id"]
    for col in critical_cols:
        assert df[col].isnull().sum() == 0, f"Critical column '{col}' contains null values"

def test_channels_valid():
    df = pd.read_csv(DATA_PATH)
    unique_channels = set(df["channel"].unique())
    assert unique_channels.issubset({"Email", "SMS"}), f"Unexpected channel: {unique_channels}"
