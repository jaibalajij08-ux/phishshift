# PhishShift — Dataset Provenance, Schema, and Ethics

## 1. Project Overview & Data Objective
**PhishShift — Message Risk Scanner** is an educational cybersecurity prototype designed to analyze email and SMS messages and evaluate their potential phishing risk. The objective of the dataset is to provide realistic, safe, and balanced training and testing data reflecting diverse attack vectors and legitimate transactional/conversational patterns across both email and SMS communication channels.

---

## 2. Dataset Schema & Specification

| Column Name | Data Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `message_id` | `string` | Unique identifier formatted as `MSG_xxx` | `MSG_001` |
| `channel` | `string` | Communication channel: `Email` or `SMS` | `Email` |
| `subject` | `string` | Subject or header line (or empty for SMS) | `URGENT: Verify your account access` |
| `body` | `string` | Main message body | `We detected suspicious login activity...` |
| `sanitized_url_features` | `string` | Safely parsed URL tokens/indicators | `ip_address,subdomain_depth_3` |
| `sender_domain_category`| `string` | Categorization of sender domain (`corporate`, `free_webmail`, `lookalike`, `shortener`, `unknown`) | `lookalike` |
| `label` | `integer`| Target class: `0` = Legitimate, `1` = Phishing | `1` |
| `campaign_id` | `string` | Campaign or template grouping identifier | `CMP_BANK_ALERT` |
| `collection_date` | `string` | ISO collection/reference date | `2024-03-15` |
| `source` | `string` | Provenance archive or source repository | `Enron / Synthetic Curated` |
| `license` | `string` | Dataset distribution license | `CC-BY-4.0 / Open Source` |

---

## 3. Labeling Standard
- **`0` = Legitimate (Safe / Non-phishing)**: Legitimate internal communications, project updates, newsletters, order receipts, two-factor authentication notifications, meeting invites, and personal conversational notes.
- **`1` = Phishing (Suspicious / Malicious)**: Credential harvesting, urgent account suspension threats, deceptive bank alerts, fake package re-delivery fees, payroll direct deposit updates, fake prize notifications, and spoofed security advisories.

---

## 4. Provenance & Public Sources
To ensure ethical compliance, reproducibility, and diverse coverage, the dataset combines:
1. **Curated Public Domain Corpora**:
   - *Enron Clean Corpus*: Non-confidential workplace email exchanges (Public Domain).
   - *SMS Spam Collection*: Permitted academic research dataset (CC BY 4.0).
   - *Nazario Phishing Corpus References*: Structural templates derived from historic educational phishing research corpora.
2. **Standardized Synthetic Templates (OWASP / MITRE ATT&CK T1566 Phishing)**:
   - Carefully generated templates modeling modern phishing attacks (e.g., cloud collaboration phishing, MFA exhaustion notices, QR/URL redirection, urgent invoice lures).
   - Carefully generated legitimate messages containing urgent words (e.g., server maintenance announcements, actual bank transaction receipts, calendar deadlines) to evaluate false positive resistance.

---

## 5. Safety, Privacy & Threat Modeling
- **Zero Active Malicious Links**: All URLs use RFC 2606 reserved domains (`example.com`, `example.org`, `test.com`) or sanitized defanged placeholders (`hxxp://`, `[.]`).
- **No Personally Identifiable Information (PII)**: All real names, phone numbers, employee IDs, credit card numbers, and banking details are replaced with sanitized dummy tokens (e.g., `user@example.com`, `+1-555-0199`, `Account ending in 1234`).
- **Defensive Educational Use Only**: This system does not crawl, resolve DNS, execute scripts, or contact external servers when analyzing messages.
