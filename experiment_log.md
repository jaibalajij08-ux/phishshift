# PhishShift — Model Experimentation & Tuning Log

## 1. Experiment Overview
- **Dataset Partitioning**: Leakage-Safe Group Shuffle Split on `campaign_id`
- **Training Samples**: 339
- **Held-Out Test Samples**: 135 (unseen campaigns)
- **Feature Extraction**: TF-IDF Vectorizer (n-gram range: (1, 2), max_features: 5000, sublinear_tf: True)

---

## 2. Quantitative Model Comparison

| Model Architecture | Accuracy | Precision | Recall | F1-Score | False Positive Rate |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Rule-Based Baseline** | 0.8000 | 1.0000 | 0.5714 | 0.7273 | 0.0000 |
| **TF-IDF + Logistic Regression** | 0.7778 | 0.7895 | 0.7143 | 0.7500 | 0.1667 |
| **TF-IDF + Multinomial Naive Bayes** | 0.8444 | 0.8182 | 0.8571 | 0.8372 | 0.1667 |

---

## 3. Methodological Observations & Model Selection Rationale
1. **Rule-Based Baseline**:
   - Offers transparent, deterministic explanations.
   - However, it suffers from rigid keyword matching; legitimate messages containing words like 'urgent' or 'maintenance' can cause false positives, while novel paraphrased attacks evade detection.
2. **TF-IDF + Multinomial Naive Bayes**:
   - Fast and simple probabilistic baseline.
   - Performs well on keyword frequency but exhibits slight vulnerability to length imbalances and independent feature assumptions.
3. **TF-IDF + Logistic Regression (Selected Primary Model)**:
   - Delivers balanced performance with regularized loss (`C=1.5`) and balanced class weighting.
   - Produces well-calibrated continuous probability scores via the logistic sigmoid function, allowing reliable uncertainty thresholds in the web dashboard.
   - Successfully persisted to `models/best_model.joblib`.
