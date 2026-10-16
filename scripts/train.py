"""
Model training CLI script for PhishGuard AI.
Trains Context-Aware FeatureUnion (TF-IDF Word + Char + Threat Feats) + Calibrated Logistic Regression.
"""

import os
import sys

# Ensure UTF-8 output on Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure workspace root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.model import PhishGuardClassifier, DEFAULT_MODEL_PATH


def main():
    dataset_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "dataset.csv")

    if not os.path.exists(dataset_path):
        print(f"[-] Dataset not found at {dataset_path}")
        print("[*] Running download script first...")
        from scripts.download_data import download_and_prepare_dataset
        download_and_prepare_dataset()

    print("[*] Initializing PhishGuardClassifier...")
    clf = PhishGuardClassifier(model_path=DEFAULT_MODEL_PATH)

    print(f"[*] Training on {dataset_path}...")
    metrics = clf.train(dataset_path=dataset_path, test_size=0.2, random_state=42, save_after=True)

    cm = metrics["confusion_matrix"]
    m = metrics["metrics"]

    print("\n" + "=" * 62)
    print("🎯 PhishGuard AI - Model Training & Evaluation Results")
    print("=" * 62)
    print(f"Total Samples   : {metrics['total_samples']:,}")
    print(f"Training Set    : {metrics['train_samples']:,}")
    print(f"Holdout Test Set: {metrics['test_samples']:,}")
    print(f"Legitimate (0)  : {metrics['legit_samples']:,}")
    print(f"Phishing/Spam(1): {metrics['phish_samples']:,}")
    print("-" * 62)
    print("📊 Core Classification Metrics:")
    print(f"  • Accuracy    : {m['accuracy'] * 100:.2f}%")
    print(f"  • Precision   : {m['precision'] * 100:.2f}%")
    print(f"  • Recall      : {m['recall'] * 100:.2f}%")
    print(f"  • F1-Score    : {m['f1_score'] * 100:.2f}%")
    print(f"  • ROC-AUC     : {m['roc_auc'] * 100:.2f}%")
    print(f"  • Specificity : {cm['specificity'] * 100:.2f}%")
    print(f"  • False Pos % : {cm['false_positive_rate'] * 100:.2f}%")
    print(f"  • False Neg % : {cm['false_negative_rate'] * 100:.2f}%")
    print("-" * 62)
    print("🔍 Holdout Confusion Matrix:")
    print("                  Predicted Legit    Predicted Phish")
    print(f"  Actual Legit  : {cm['true_negatives']:<18} {cm['false_positives']} (False Positives)")
    print(f"  Actual Phish  : {cm['false_negatives']:<18} {cm['true_positives']} (True Positives)")
    print("-" * 62)
    print("🏆 Top Learned Threat & Feature Weights:")
    for feat in metrics.get("top_phishing_features", [])[:10]:
        print(f"  [+] Phish: {feat}")
    for feat in metrics.get("top_legit_features", [])[:5]:
        print(f"  [-] Legit: {feat}")
    print("=" * 62)
    print(f"[+] Model successfully saved to {DEFAULT_MODEL_PATH}\n")


if __name__ == "__main__":
    main()
