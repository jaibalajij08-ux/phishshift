"""
PhishShift - Data Preprocessing & Safe Feature Engineering Pipeline
Handles text normalization, safe lexical URL feature extraction,
campaign-aware splitting, and EDA chart generation using Pandas, NumPy, and Matplotlib.
"""

import os
import re
import math
import sys
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg') # Headless backend for server/CLI environments
import matplotlib.pyplot as plt

# Ensure UTF-8 output
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Regular expression patterns for safe URL analysis
URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+', re.IGNORECASE)
IP_REGEX = re.compile(r'https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?(?:/[^\s]*)?', re.IGNORECASE)
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".live", ".biz", ".online", ".work", ".click", ".surf", ".support", ".rest"}

def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon character entropy using NumPy for randomness analysis."""
    if not text:
        return 0.0
    chars, counts = np.unique(list(text), return_counts=True)
    probabilities = counts / len(text)
    # Shannon entropy: -sum(p * log2(p))
    entropy = -np.sum(probabilities * np.log2(probabilities))
    return float(entropy)

def extract_safe_url_features(text: str) -> dict:
    """
    Safely extract lexical characteristics from URL strings in text.
    Zero network requests, zero DNS resolution, zero external requests.
    """
    urls = URL_REGEX.findall(text)
    has_url = 1 if len(urls) > 0 else 0
    url_count = len(urls)
    
    is_ip_url = 0
    has_shortener = 0
    has_suspicious_tld = 0
    max_subdomains = 0
    max_url_entropy = 0.0
    
    for u in urls:
        # Check IP address URL
        if IP_REGEX.search(u):
            is_ip_url = 1
            
        clean_u = re.sub(r'^https?://', '', u, flags=re.IGNORECASE).split('/')[0].split(':')[0]
        
        # Check URL shortener
        for s in SHORTENER_DOMAINS:
            if s in clean_u.lower():
                has_shortener = 1
                break
                
        # Check suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if clean_u.lower().endswith(tld):
                has_suspicious_tld = 1
                break
                
        # Subdomain count
        dots = clean_u.count('.')
        subdomains = max(0, dots - 1)
        if subdomains > max_subdomains:
            max_subdomains = subdomains
            
        # Entropy
        ent = calculate_shannon_entropy(u)
        if ent > max_url_entropy:
            max_url_entropy = ent

    return {
        "has_url": has_url,
        "url_count": url_count,
        "is_ip_url": is_ip_url,
        "has_shortener": has_shortener,
        "has_suspicious_tld": has_suspicious_tld,
        "max_subdomains": max_subdomains,
        "url_entropy": round(max_url_entropy, 3)
    }

def normalize_text(text: str) -> str:
    """
    Normalizes text while strictly preserving cybersecurity signals:
    - Retains dollar signs ($) and financial markers
    - Retains urgency exclamation marks
    - Replaces URLs with a safe token placeholder while keeping structure
    - Retains token casing features without destruction
    """
    if not isinstance(text, str):
        return ""
    
    # Replace multiple spaces/tabs with single space
    cleaned = re.sub(r'[ \t]+', ' ', text)
    # Normalize excessive exclamation marks to max 3
    cleaned = re.sub(r'!{4,}', '!!!', cleaned)
    # Strip dangerous control characters
    cleaned = "".join(ch for ch in cleaned if ch.isprintable() or ch in '\n\r\t')
    return cleaned.strip()

def preprocess_and_clean(raw_csv_path: str, output_csv_path: str, charts_dir: str):
    print("=" * 60)
    print(" PhishShift: Starting Preprocessing Pipeline")
    print("=" * 60)
    
    df = pd.read_csv(raw_csv_path)
    print(f"[INFO] Loaded {len(df)} raw records from {raw_csv_path}")
    
    # Fill missing subject for SMS with empty string
    df["subject"] = df["subject"].fillna("")
    df["body"] = df["body"].fillna("")
    
    # Clean text
    df["clean_subject"] = df["subject"].apply(normalize_text)
    df["clean_body"] = df["body"].apply(normalize_text)
    
    # Create unified text representation
    df["full_text"] = df.apply(
        lambda r: f"{r['clean_subject']} {r['clean_body']}".strip() if r['clean_subject'] else r['clean_body'],
        axis=1
    )
    
    # Extract safe lexical URL features
    print("[INFO] Extracting safe lexical URL features without network requests...")
    url_features_list = [extract_safe_url_features(txt) for txt in df["full_text"]]
    url_df = pd.DataFrame(url_features_list)
    
    # Merge URL features into main dataframe
    df = pd.concat([df, url_df], axis=1)
    
    # Add numerical text length and word count using NumPy operations
    body_arr = df["full_text"].to_numpy()
    df["char_length"] = np.array([len(t) for t in body_arr], dtype=np.int32)
    df["word_count"] = np.array([len(t.split()) for t in body_arr], dtype=np.int32)
    
    # Check deduplication metrics
    initial_count = len(df)
    unique_templates = df.drop_duplicates(subset=["full_text"])
    print(f"[INFO] Initial rows: {initial_count} | Unique text templates: {len(unique_templates)}")
    
    # Save cleaned dataset
    os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
    df.to_csv(output_csv_path, index=False)
    print(f"[OK] Cleaned dataset saved to: {output_csv_path}")
    
    # Generate Visualizations
    generate_eda_visualizations(df, charts_dir)
    return df

def generate_eda_visualizations(df: pd.DataFrame, charts_dir: str):
    """Generates three distinct, professional Matplotlib figures."""
    os.makedirs(charts_dir, exist_ok=True)
    print(f"[INFO] Generating EDA visualizations in {charts_dir}...")
    
    # Set style
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    
    # -------------------------------------------------------------
    # Chart 1: Class and Channel Distribution
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 5))
    cross_tab = pd.crosstab(df["channel"], df["label"])
    cross_tab.columns = ["Legitimate (0)", "Phishing (1)"]
    
    x = np.arange(len(cross_tab.index))
    width = 0.35
    
    legit_vals = cross_tab["Legitimate (0)"].to_numpy()
    phish_vals = cross_tab["Phishing (1)"].to_numpy()
    
    rects1 = ax.bar(x - width/2, legit_vals, width, label='Legitimate', color='#2ecc71', edgecolor='black', alpha=0.85)
    rects2 = ax.bar(x + width/2, phish_vals, width, label='Phishing', color='#e74c3c', edgecolor='black', alpha=0.85)
    
    ax.set_ylabel('Number of Messages', fontsize=12, fontweight='bold')
    ax.set_title('PhishShift: Message Distribution by Channel and Class', fontsize=14, fontweight='bold', pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(cross_tab.index, fontsize=11, fontweight='bold')
    ax.legend(frameon=True, facecolor='white', framealpha=0.9)
    
    # Add value annotations
    for rect in rects1 + rects2:
        h = rect.get_height()
        ax.annotate(f'{int(h)}', xy=(rect.get_x() + rect.get_width()/2, h),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold')
                    
    plt.tight_layout()
    chart1_path = os.path.join(charts_dir, "class_and_channel_distribution.png")
    plt.savefig(chart1_path, dpi=300)
    plt.close()
    print(f"  [OK] Saved Chart 1: {chart1_path}")
    
    # -------------------------------------------------------------
    # Chart 2: Character Length Distribution (NumPy Analysis)
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 5))
    legit_lens = df[df["label"] == 0]["char_length"].to_numpy()
    phish_lens = df[df["label"] == 1]["char_length"].to_numpy()
    
    bins = np.linspace(0, max(np.max(legit_lens), np.max(phish_lens)) + 20, 25)
    
    ax.hist(legit_lens, bins=bins, alpha=0.6, label=f'Legitimate (Mean: {np.mean(legit_lens):.1f})', color='#3498db', edgecolor='black')
    ax.hist(phish_lens, bins=bins, alpha=0.6, label=f'Phishing (Mean: {np.mean(phish_lens):.1f})', color='#e67e22', edgecolor='black')
    
    # Add vertical lines for medians using NumPy
    ax.axvline(np.median(legit_lens), color='#2980b9', linestyle='dashed', linewidth=2, label=f'Legit Median: {np.median(legit_lens):.0f}')
    ax.axvline(np.median(phish_lens), color='#d35400', linestyle='dashed', linewidth=2, label=f'Phish Median: {np.median(phish_lens):.0f}')
    
    ax.set_xlabel('Message Character Length', fontsize=12, fontweight='bold')
    ax.set_ylabel('Frequency', fontsize=12, fontweight='bold')
    ax.set_title('PhishShift: Message Character Length Distribution', fontsize=14, fontweight='bold', pad=12)
    ax.legend(frameon=True, facecolor='white', framealpha=0.9)
    
    plt.tight_layout()
    chart2_path = os.path.join(charts_dir, "message_length_distribution.png")
    plt.savefig(chart2_path, dpi=300)
    plt.close()
    print(f"  [OK] Saved Chart 2: {chart2_path}")
    
    # -------------------------------------------------------------
    # Chart 3: Top Observed Security Indicators by Class
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(9, 5))
    
    # Compute indicator frequencies using NumPy
    indicators = {
        "Contains URL": df["has_url"].to_numpy(),
        "IP-Address URL": df["is_ip_url"].to_numpy(),
        "URL Shortener": df["has_shortener"].to_numpy(),
        "Suspicious TLD": df["has_suspicious_tld"].to_numpy(),
        "Contains '$'": df["full_text"].str.contains(r'\$', regex=True).astype(int).to_numpy(),
        "Urgent '!'": df["full_text"].str.contains(r'!', regex=True).astype(int).to_numpy(),
    }
    
    labels_arr = df["label"].to_numpy()
    names = list(indicators.keys())
    legit_rates = []
    phish_rates = []
    
    for name in names:
        arr = indicators[name]
        legit_rate = float(np.mean(arr[labels_arr == 0]) * 100)
        phish_rate = float(np.mean(arr[labels_arr == 1]) * 100)
        legit_rates.append(legit_rate)
        phish_rates.append(phish_rate)
        
    y = np.arange(len(names))
    height = 0.35
    
    ax.barh(y - height/2, legit_rates, height, label='Legitimate Rate (%)', color='#2ecc71', edgecolor='black', alpha=0.85)
    ax.barh(y + height/2, phish_rates, height, label='Phishing Rate (%)', color='#e74c3c', edgecolor='black', alpha=0.85)
    
    ax.set_xlabel('Occurrence Rate (%)', fontsize=12, fontweight='bold')
    ax.set_title('PhishShift: Prevalence of Suspicious Indicators by Class', fontsize=14, fontweight='bold', pad=12)
    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=11, fontweight='bold')
    ax.set_xlim(0, 105)
    ax.legend(loc='lower right', frameon=True, facecolor='white', framealpha=0.9)
    
    plt.tight_layout()
    chart3_path = os.path.join(charts_dir, "top_phishing_vs_legit_indicators.png")
    plt.savefig(chart3_path, dpi=300)
    plt.close()
    print(f"  [OK] Saved Chart 3: {chart3_path}")
    print("[OK] All 3 EDA visualizations successfully created.")

if __name__ == "__main__":
    raw_csv = os.path.join(os.path.dirname(__file__), "..", "data", "raw_messages.csv")
    cleaned_csv = os.path.join(os.path.dirname(__file__), "..", "data", "cleaned_messages.csv")
    charts_folder = os.path.join(os.path.dirname(__file__), "..", "results", "charts")
    preprocess_and_clean(raw_csv, cleaned_csv, charts_folder)
