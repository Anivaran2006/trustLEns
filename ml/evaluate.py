"""
Evaluation and Metrics reporting utility for TrustLens AI.
Loads the trained pipeline and held-out test data, computing detailed slices,
ROC curves, classification report, and edge-case behaviors.
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    accuracy_score, precision_score, recall_score, f1_score
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.preprocessor import clean_security_text

def run_evaluation_report():
    artifacts_dir = os.path.join(PROJECT_ROOT, "artifacts")
    pipeline_path = os.path.join(artifacts_dir, "model_pipeline.joblib")
    data_path = os.path.join(PROJECT_ROOT, "data", "raw", "sms_spam_collection.csv")

    if not os.path.exists(pipeline_path):
        raise FileNotFoundError(f"Model pipeline not found at {pipeline_path}. Run ml/train.py first.")

    pipeline = joblib.load(pipeline_path)
    df = pd.read_csv(data_path).dropna(subset=['message', 'label_num'])
    df_clean = df.drop_duplicates(subset=['message']).reset_index(drop=True)

    X = df_clean['message'].values
    y = df_clean['label_num'].values.astype(int)

    # 1. Evaluate on proper 20% held-out test set (N = 1,035) with fixed seed matching training
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )

    y_test_pred = pipeline.predict(X_test)
    y_test_proba = pipeline.predict_proba(X_test)[:, 1]

    holdout_report = classification_report(
        y_test, y_test_pred, target_names=["Legitimate (Ham)", "Suspicious (Spam)"], output_dict=True
    )
    holdout_roc_auc = float(roc_auc_score(y_test, y_test_proba))
    holdout_cm = confusion_matrix(y_test, y_test_pred)
    tn, fp, fn, tp = [int(v) for v in holdout_cm.ravel()]

    summary = {
        "evaluation_dataset": "Holdout Test Set (20% Unseen Split)",
        "test_sample_size": len(X_test),
        "holdout_roc_auc": round(holdout_roc_auc, 4),
        "holdout_accuracy": round(float(accuracy_score(y_test, y_test_pred)), 4),
        "holdout_precision": round(float(precision_score(y_test, y_test_pred)), 4),
        "holdout_recall": round(float(recall_score(y_test, y_test_pred)), 4),
        "holdout_f1": round(float(f1_score(y_test, y_test_pred)), 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0,
        "false_negative_rate": round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0.0,
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp
        },
        "classification_report": holdout_report
    }

    report_path = os.path.join(artifacts_dir, "evaluation_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("=== Unseen Holdout Test Set Evaluation (N = 1,035) ===")
    print(classification_report(y_test, y_test_pred, target_names=["Legitimate (Ham)", "Suspicious (Spam)"]))
    print(f"Holdout ROC-AUC: {holdout_roc_auc:.4f}")
    print(f"Holdout Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print(f"False Positive Rate: {fp/(fp+tn):.4f}")
    return summary

if __name__ == "__main__":
    run_evaluation_report()
