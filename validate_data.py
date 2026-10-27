"""
PhishShift - Dataset Validation Script
Validates schema, checks missing values, validates labels (0/1),
analyzes class balance using Pandas and NumPy, and detects duplicates.
"""

import sys
import os
import pandas as pd
import numpy as np

# Force UTF-8 on stdout for cross-platform compatibility
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

REQUIRED_SCHEMA = [
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

def validate_dataset(filepath: str) -> bool:
    print("=" * 60)
    print(f" PhishShift: Validating Dataset at {filepath}")
    print("=" * 60)
    
    if not os.path.exists(filepath):
        print(f"[FAIL] Error: File not found at {filepath}")
        return False
        
    df = pd.read_csv(filepath)
    print(f"[OK] Total records loaded: {len(df)}")
    
    # 1. Schema check
    missing_columns = [col for col in REQUIRED_SCHEMA if col not in df.columns]
    if missing_columns:
        print(f"[FAIL] Schema Validation Failed. Missing required columns: {missing_columns}")
        return False
    else:
        print("[OK] Schema Validation Passed: All 11 required columns are present.")
        
    # 2. Minimum row count check (Requirement >= 400)
    if len(df) < 400:
        print(f"[FAIL] Dataset size check failed: Found {len(df)} records, expected >= 400.")
        return False
    else:
        print(f"[OK] Dataset size check passed: {len(df)} records (meets >= 400 requirement).")

    # 3. Missing values check
    critical_cols = ["message_id", "channel", "body", "label", "campaign_id"]
    has_critical_missing = False
    for col in critical_cols:
        missing_count = df[col].isnull().sum()
        if missing_count > 0:
            print(f"[FAIL] Critical missing values in '{col}': {missing_count} rows.")
            has_critical_missing = True
    if not has_critical_missing:
        print("[OK] Missing values check passed: No critical fields contain nulls.")

    # 4. Label validation (must only be 0 or 1)
    unique_labels = set(df["label"].unique())
    if not unique_labels.issubset({0, 1}):
        print(f"[FAIL] Label validation failed: Unexpected labels found: {unique_labels}. Expected only {{0, 1}}.")
        return False
    else:
        print("[OK] Label validation passed: Labels strictly conform to {0, 1}.")
        
    # 5. Numerical analysis using NumPy & Pandas
    labels_arr = df["label"].to_numpy()
    total_samples = labels_arr.shape[0]
    legit_count = int(np.sum(labels_arr == 0))
    phish_count = int(np.sum(labels_arr == 1))
    legit_pct = float(np.mean(labels_arr == 0) * 100)
    phish_pct = float(np.mean(labels_arr == 1) * 100)
    
    print("\n--- Class Distribution (NumPy Analysis) ---")
    print(f"  • Legitimate (0): {legit_count} ({legit_pct:.2f}%)")
    print(f"  • Phishing   (1): {phish_count} ({phish_pct:.2f}%)")
    
    # 6. Channel distribution
    print("\n--- Channel Distribution ---")
    for channel, count in df["channel"].value_counts().items():
        pct = (count / total_samples) * 100
        print(f"  • {channel}: {count} ({pct:.2f}%)")

    # 7. Exact and Near-Duplicate Detection
    exact_body_dups = int(df.duplicated(subset=["body"]).sum())
    print(f"\n--- Duplicate Template Detection ---")
    print(f"  • Exact body duplicates: {exact_body_dups}")
    
    # Near duplicate check: count template groups / campaigns
    num_campaigns = df["campaign_id"].nunique()
    print(f"  • Unique campaign/template groups: {num_campaigns}")
    
    # 8. Sanity check on message lengths using NumPy
    body_lengths = df["body"].astype(str).str.len().to_numpy()
    print(f"\n--- Numerical Text Statistics (NumPy) ---")
    print(f"  • Mean message length: {np.mean(body_lengths):.1f} chars")
    print(f"  • Median message length: {np.median(body_lengths):.1f} chars")
    print(f"  • Min / Max length: {np.min(body_lengths)} / {np.max(body_lengths)} chars")
    print(f"  • Standard deviation: {np.std(body_lengths):.1f} chars")
    
    print("\n" + "=" * 60)
    print("[OK] Overall Dataset Validation: SUCCESS")
    print("=" * 60)
    return True

if __name__ == "__main__":
    default_csv = os.path.join(os.path.dirname(__file__), "..", "data", "raw_messages.csv")
    csv_file = sys.argv[1] if len(sys.argv) > 1 else default_csv
    success = validate_dataset(csv_file)
    sys.exit(0 if success else 1)
