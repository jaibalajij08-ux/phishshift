"""
PhishShift - Model Training & Evaluation Pipeline
Implements:
1. Leakage-safe campaign/template splitting
2. Approach A: Rule-Based Baseline
3. Approach B: TF-IDF + Logistic Regression (Primary ML Model)
4. Approach C: TF-IDF + Multinomial Naive Bayes (Comparison ML Model)
5. Metric computation (Accuracy, Precision, Recall, F1, FPR) using Scikit-Learn & NumPy
6. Model persistence using Joblib
7. Confusion matrix visualizations using Matplotlib
"""

import os
import sys
import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
)
from sklearn.model_selection import GroupShuffleSplit

# Ensure UTF-8 console output
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from risk_explanations import rule_based_scorer
from clean_data import extract_safe_url_features

def leakage_safe_split(df: pd.DataFrame, test_size: float = 0.25, random_state: int = 42):
    """
    Splits messages by campaign_id so all templates from a given campaign
    are strictly isolated to either Train or Test, preventing template data leakage.
    """
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    groups = df["campaign_id"].to_numpy()
    
    train_idx, test_idx = next(gss.split(df, df["label"], groups=groups))
    train_df = df.iloc[train_idx].copy().reset_index(drop=True)
    test_df = df.iloc[test_idx].copy().reset_index(drop=True)
    
    print("\n--- Leakage-Safe Campaign Splitting Summary ---")
    print(f"Total Campaigns: {df['campaign_id'].nunique()}")
    print(f"Train Campaigns: {train_df['campaign_id'].nunique()} ({len(train_df)} samples)")
    print(f"Test Campaigns:  {test_df['campaign_id'].nunique()} ({len(test_df)} samples)")
    
    train_legit = int(np.sum(train_df["label"] == 0))
    train_phish = int(np.sum(train_df["label"] == 1))
    test_legit = int(np.sum(test_df["label"] == 0))
    test_phish = int(np.sum(test_df["label"] == 1))
    
    print(f"Train Class Distribution: Legit={train_legit}, Phish={train_phish}")
    print(f"Test Class Distribution:  Legit={test_legit}, Phish={test_phish}")
    
    return train_df, test_df

def compute_fpr(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """Calculate False Positive Rate (FPR = FP / (FP + TN)) using NumPy."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return float(fpr)

def evaluate_predictions(name: str, y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    """Calculates all key evaluation metrics using scikit-learn and NumPy."""
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = compute_fpr(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred)
    
    return {
        "Model": name,
        "Accuracy": round(acc, 4),
        "Precision": round(prec, 4),
        "Recall": round(rec, 4),
        "F1-Score": round(f1, 4),
        "False Positive Rate": round(fpr, 4),
        "Confusion Matrix": cm
    }

def train_and_evaluate_all():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cleaned_csv = os.path.join(base_dir, "data", "cleaned_messages.csv")
    models_dir = os.path.join(base_dir, "models")
    results_dir = os.path.join(base_dir, "results")
    charts_dir = os.path.join(results_dir, "charts")
    docs_dir = os.path.join(base_dir, "docs")
    
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)
    os.makedirs(charts_dir, exist_ok=True)
    os.makedirs(docs_dir, exist_ok=True)
    
    print("=" * 60)
    print(" PhishShift: Starting Model Training & Benchmark Pipeline")
    print("=" * 60)
    
    df = pd.read_csv(cleaned_csv)
    train_df, test_df = leakage_safe_split(df, test_size=0.25, random_state=42)
    
    X_train = train_df["full_text"]
    y_train = train_df["label"].to_numpy()
    
    X_test = test_df["full_text"]
    y_test = test_df["label"].to_numpy()
    
    # -------------------------------------------------------------
    # 1. Approach A: Rule-Based Heuristic Baseline
    # -------------------------------------------------------------
    print("\n[1/3] Evaluating Approach A: Rule-Based Heuristic Baseline...")
    rule_preds = []
    for text in X_test:
        url_feats = extract_safe_url_features(text)
        score, cat, reasons = rule_based_scorer(text, url_feats)
        # Predict 1 if likely phishing or uncertain with high score
        pred = 1 if score >= 35 else 0
        rule_preds.append(pred)
    rule_preds = np.array(rule_preds)
    rule_metrics = evaluate_predictions("Rule-Based Baseline", y_test, rule_preds)
    
    # -------------------------------------------------------------
    # 2. Approach B: TF-IDF + Logistic Regression (Primary ML Model)
    # -------------------------------------------------------------
    print("[2/3] Training Approach B: TF-IDF + Logistic Regression...")
    lr_pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=5000,
            sublinear_tf=True,
            strip_accents='unicode'
        )),
        ("clf", LogisticRegression(
            C=1.5,
            class_weight='balanced',
            max_iter=1000,
            random_state=42
        ))
    ])
    
    lr_pipeline.fit(X_train, y_train)
    lr_preds = lr_pipeline.predict(X_test)
    lr_metrics = evaluate_predictions("TF-IDF + Logistic Regression", y_test, lr_preds)
    
    best_model_path = os.path.join(models_dir, "best_model.joblib")
    joblib.dump(lr_pipeline, best_model_path)
    print(f"  [OK] Saved primary model pipeline to: {best_model_path}")
    
    # -------------------------------------------------------------
    # 3. Approach C: TF-IDF + Multinomial Naive Bayes (Comparison)
    # -------------------------------------------------------------
    print("[3/3] Training Approach C: TF-IDF + Multinomial Naive Bayes...")
    nb_pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=5000,
            sublinear_tf=True,
            strip_accents='unicode'
        )),
        ("clf", MultinomialNB(alpha=0.5))
    ])
    
    nb_pipeline.fit(X_train, y_train)
    nb_preds = nb_pipeline.predict(X_test)
    nb_metrics = evaluate_predictions("TF-IDF + Multinomial Naive Bayes", y_test, nb_preds)
    
    comp_model_path = os.path.join(models_dir, "comparison_model.joblib")
    joblib.dump(nb_pipeline, comp_model_path)
    print(f"  [OK] Saved comparison model pipeline to: {comp_model_path}")
    
    # -------------------------------------------------------------
    # 4. Metrics Reporting & Comparison Table
    # -------------------------------------------------------------
    all_metrics = [rule_metrics, lr_metrics, nb_metrics]
    summary_rows = []
    for m in all_metrics:
        summary_rows.append({
            "Model": m["Model"],
            "Accuracy": m["Accuracy"],
            "Precision": m["Precision"],
            "Recall": m["Recall"],
            "F1-Score": m["F1-Score"],
            "False_Positive_Rate": m["False Positive Rate"]
        })
        
    metrics_df = pd.DataFrame(summary_rows)
    metrics_csv_path = os.path.join(results_dir, "metrics.csv")
    metrics_df.to_csv(metrics_csv_path, index=False)
    print(f"\n[OK] Comparative metrics saved to: {metrics_csv_path}")
    
    print("\n" + "=" * 70)
    print(f"{'Model':<35} | {'Acc':<6} | {'Prec':<6} | {'Rec':<6} | {'F1':<6} | {'FPR':<6}")
    print("-" * 70)
    for r in summary_rows:
        print(f"{r['Model']:<35} | {r['Accuracy']:<6.4f} | {r['Precision']:<6.4f} | {r['Recall']:<6.4f} | {r['F1-Score']:<6.4f} | {r['False_Positive_Rate']:<6.4f}")
    print("=" * 70)
    
    # -------------------------------------------------------------
    # 5. Visualizing Confusion Matrices
    # -------------------------------------------------------------
    plot_confusion_matrices(all_metrics, charts_dir)
    
    # -------------------------------------------------------------
    # 6. Generate Experiment Log
    # -------------------------------------------------------------
    generate_experiment_log(all_metrics, len(train_df), len(test_df), docs_dir)
    return metrics_df

def plot_confusion_matrices(metrics_list: list, charts_dir: str):
    """Generates side-by-side comparison heatmaps of confusion matrices."""
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))
    
    for ax, m in zip(axes, metrics_list):
        cm = m["Confusion Matrix"]
        im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
        ax.set_title(m["Model"], fontsize=11, fontweight='bold', pad=10)
        
        tick_marks = np.arange(2)
        ax.set_xticks(tick_marks)
        ax.set_yticks(tick_marks)
        ax.set_xticklabels(['Legitimate (0)', 'Phishing (1)'], fontweight='bold')
        ax.set_yticklabels(['Legitimate (0)', 'Phishing (1)'], fontweight='bold')
        
        ax.set_ylabel('Actual Label', fontweight='bold')
        ax.set_xlabel('Predicted Label', fontweight='bold')
        
        # Annotate numbers
        thresh = cm.max() / 2.
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(j, i, format(cm[i, j], 'd'),
                        ha="center", va="center",
                        color="white" if cm[i, j] > thresh else "black",
                        fontsize=14, fontweight='bold')
                        
    plt.tight_layout()
    cm_path = os.path.join(charts_dir, "confusion_matrices.png")
    plt.savefig(cm_path, dpi=300)
    plt.close()
    print(f"[OK] Confusion matrices chart saved to: {cm_path}")

def generate_experiment_log(metrics_list: list, train_size: int, test_size: int, docs_dir: str):
    """Outputs structured experiment documentation."""
    exp_log_path = os.path.join(docs_dir, "experiment_log.md")
    
    content = f"""# PhishShift — Model Experimentation & Tuning Log

## 1. Experiment Overview
- **Dataset Partitioning**: Leakage-Safe Group Shuffle Split on `campaign_id`
- **Training Samples**: {train_size}
- **Held-Out Test Samples**: {test_size} (unseen campaigns)
- **Feature Extraction**: TF-IDF Vectorizer (n-gram range: (1, 2), max_features: 5000, sublinear_tf: True)

---

## 2. Quantitative Model Comparison

| Model Architecture | Accuracy | Precision | Recall | F1-Score | False Positive Rate |
| :--- | :--- | :--- | :--- | :--- | :--- |
"""
    for m in metrics_list:
        content += f"| **{m['Model']}** | {m['Accuracy']:.4f} | {m['Precision']:.4f} | {m['Recall']:.4f} | {m['F1-Score']:.4f} | {m['False Positive Rate']:.4f} |\n"
        
    content += """
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
"""
    with open(exp_log_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[OK] Experiment log updated at: {exp_log_path}")

if __name__ == "__main__":
    train_and_evaluate_all()
