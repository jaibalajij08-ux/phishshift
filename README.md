# PhishShift — Message Risk Scanner

An educational, defensive cybersecurity machine learning prototype that evaluates email and SMS messages for phishing risks.

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![Framework](https://img.shields.io/badge/ML-Scikit--Learn%20%7C%20NumPy-orange.svg)](https://scikit-learn.org/)

---

## 📌 Project Overview
Phishing remains one of the primary attack vectors in modern social engineering attacks. **PhishShift** is an educational, interactive machine learning scanner that:
1. Safely analyzes email and SMS text along with sanitized URL structures.
2. Classifies incoming messages into:
   - **Likely Phishing** (High Risk)
   - **Likely Legitimate** (Low Risk)
   - **Uncertain / Abstain** (Ambiguous context requiring manual review)
3. Highlights concrete suspicious indicators (urgency cues, impersonation patterns, deceptive links).
4. Compares three distinct detection paradigms:
   - **Rule-Based Baseline** (configurable security heuristics)
   - **TF-IDF + Logistic Regression / Linear SVM** (primary statistical ML model)
   - **TF-IDF + Multinomial Naive Bayes** (probabilistic baseline model)
5. Performs robustness stress-testing against text modifications (casing, typos, whitespace, synonym substitutions).

> ⚠️ **Defensive Educational Tool Notice**: PhishShift performs offline lexical and structural feature inspection. It does not resolve DNS records, click hyperlinks, or interact with external malicious infrastructure.

---

## 🛠️ Technology Stack
- **Python 3.12**: Core programming language and logic
- **NumPy**: Vector operations, risk probability calibration, array computations, and threshold calculations
- **Pandas**: Data ingestion, schema validation, deduplication, and feature structuring
- **Scikit-Learn**: TF-IDF feature extraction, model pipelines, train/test splitting, and evaluation metrics
- **Streamlit**: Modern interactive web interface
- **Matplotlib**: Confusion matrices, class distributions, and performance visualizations
- **Joblib**: Model serialization and persistence
- **Pytest**: Automated test suite for validation, preprocessing, and inference

---

## 📁 Repository Structure
```text
PhishShift/
├── app.py                      # Streamlit interactive web dashboard
├── requirements.txt            # Project dependencies
├── README.md                   # Project documentation and setup guide
├── .gitignore                  # Git untracked patterns
├── data/
│   ├── raw_messages.csv        # Initial raw corpus (400+ examples)
│   └── cleaned_messages.csv    # Cleaned, normalized, and validated dataset
├── models/
│   ├── best_model.joblib       # Primary trained pipeline
│   └── comparison_model.joblib # Comparison benchmark pipeline
├── src/
│   ├── clean_data.py           # Preprocessing, normalization & safe URL extraction
│   ├── train_model.py          # Leakage-safe model training & evaluation
│   ├── evaluate_model.py       # Metrics, confusion matrix, false-positive analysis
│   ├── risk_explanations.py    # Indicator extraction & uncertainty calibration
│   └── robustness_test.py      # Adversarial and perturbation stress testing
├── tests/
│   ├── test_preprocessing.py   # Unit tests for text cleaning and URL features
│   ├── test_predictions.py     # Unit tests for model inference
│   └── test_input_validation.py # Unit tests for empty/invalid inputs
├── results/
│   ├── metrics.csv             # Comparative performance metrics
│   └── charts/                 # Visualizations and confusion matrices
├── docs/
│   ├── data_sources.md         # Data provenance and schema documentation
│   ├── experiment_log.md       # Hyperparameter tuning and model runs
│   └── sanitization_log.md     # Text and URL defanging records
└── reports/
    └── final_report.pdf        # Academic project summary report
```

---

## 🚀 Setup & Execution Guide (Windows)

### 1. Clone or Open the Workspace
Open terminal in the project directory:
```powershell
cd C:\Users\hp\.gemini\antigravity\scratch\PhishShift
```

### 2. Activate the Virtual Environment
```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Verify Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Validate Dataset & Train Models
```powershell
python src/validate_data.py
python src/train_model.py
```

### 5. Run the Automated Tests
```powershell
pytest -v
```

### 6. Launch the Streamlit Web Application
```powershell
streamlit run app.py
```

---

## 🗓️ 7-Day Implementation Schedule
- [x] **Day 1**: Specification review, environment setup, directory structure, dataset acquisition (400+ rows), schema validation.
- [ ] **Day 2**: Data preprocessing pipeline, safe URL features, duplicate detection, EDA visualizations with Matplotlib & NumPy.
- [ ] **Day 3**: Rule-based baseline, TF-IDF + Logistic Regression/SVM, TF-IDF + Naive Bayes, pipeline persistence.
- [ ] **Day 4**: Model comparison, uncertainty threshold calibration, robustness testing suite.
- [ ] **Day 5**: Streamlit web interface with real-time risk indicators, sample messages, and safety notices.
- [ ] **Day 6**: Automated test coverage (pytest), edge case validation, experiment logging, draft report.
- [ ] **Day 7**: Clean reproduction check, final documentation, demonstration rehearsal, deployment readiness.
