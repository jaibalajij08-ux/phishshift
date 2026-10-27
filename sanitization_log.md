# PhishShift — Data Sanitization & Cleaning Log

## 1. Overview
This log documents the text normalization, security signal preservation, and safe lexical feature extraction procedures implemented in [`src/clean_data.py`](file:///C:/Users/hp/.gemini/antigravity/scratch/PhishShift/src/clean_data.py).

---

## 2. Text Normalization Decisions

| Normalization Step | Methodology | Security Rationale |
| :--- | :--- | :--- |
| **Whitespace collapsing** | `re.sub(r'[ \t]+', ' ', text)` | Removes deceptive tab/space padding used in SMS phishing without affecting meaning. |
| **Exclamation Mark Capping** | `re.sub(r'!{4,}', '!!!', text)` | Preserves urgent emotional punctuation signal while preventing unbounded token length inflation. |
| **Financial Symbol Preservation** | Dollar (`$`), Euro (`€`), Pound (`£`) retained | **Preserved intentionally**: Financial extortion, fake lottery prizes, and direct deposit lures heavily utilize currency symbols. |
| **Control Character Removal** | Strip non-printable / zero-width characters | Removes invisible zero-width Unicode spaces (e.g. `\u200b`) often used in modern email evasion. |
| **Safe Unified Representation** | `full_text = subject + " " + body` | Integrates deceptive urgency in subject lines with message payloads for holistic TF-IDF vectorization. |

---

## 3. Safe URL Feature Extraction (Zero Network Calls)

All URL features are extracted through pure regex and string parsing. Under no circumstances are URLs resolved via DNS, probed via HTTP requests, or rendered in a headless browser:

1. **`has_url`** (`0` or `1`): Indicates presence of any URI scheme (`http://`, `https://`, `www.`).
2. **`is_ip_url`** (`0` or `1`): Flags URLs hosting raw IPv4 addresses (e.g. `http://192.168.10.88/`), a prominent indicator of malicious ad-hoc phishing kits avoiding domain registration.
3. **`has_shortener`** (`0` or `1`): Detects prominent URL masking services (`bit.ly`, `tinyurl.com`, `t.co`, etc.) commonly leveraged in SMS smishing attacks to bypass spam keyword filters.
4. **`has_suspicious_tld`** (`0` or `1`): Detects high-abuse Top-Level Domains (`.xyz`, `.top`, `.club`, `.live`, `.biz`, `.online`, etc.).
5. **`max_subdomains`** (`int`): Quantifies nested domain hierarchy depth (e.g. `secure.bank.update-auth.example.com` has 3 subdomains), which is characteristic of subdomain takeover and deceptive branding.
6. **`url_entropy`** (`float`): Calculates Shannon character entropy using **NumPy** arrays to detect randomized domain generation algorithms (DGA) and hex-encoded phishing path tokens.

---

## 4. Leakage-Safe Campaign Splitting Strategy
- Phishing and legitimate messages often share template patterns (e.g. 6 variations of a Chase alert, 6 variations of an IT password notice).
- If standard random train/test split were used, near-identical messages from the same campaign would be present in both training and test sets, artificially inflating accuracy (data leakage).
- **PhishShift Solution**: In [`src/train_model.py`](file:///C:/Users/hp/.gemini/antigravity/scratch/PhishShift/src/train_model.py), we group the dataset by `campaign_id` and ensure that all messages belonging to a given campaign are placed exclusively into either the train partition or the test partition.
