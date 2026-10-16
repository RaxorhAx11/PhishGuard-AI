"""
Machine Learning Classifier module for PhishGuard AI.
Combines TF-IDF Word & Char N-Grams with Dense Threat Feature Extraction
and Logistic Regression with Probability Calibration (CalibratedClassifierCV).
"""

import os
import joblib
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

from src.preprocessing import clean_text, validate_input, ThreatFeatureExtractor


class ModelError(Exception):
    """Base exception for model-related errors."""
    pass


class ModelNotLoadedError(ModelError):
    """Raised when an ML prediction is attempted without a loaded model."""
    pass


class DatasetError(ModelError):
    """Raised when dataset loading or validation fails."""
    pass


MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
DEFAULT_MODEL_PATH = os.path.join(MODEL_DIR, "phishguard_model.joblib")


def get_risk_tier(calibrated_prob: float) -> Tuple[str, str, str, str]:
    """
    Maps calibrated probability to risk tier and action guidance.
    Risk levels: Low, Medium, High.
    
    Returns:
        (risk_level, badge_color, summary, guidance)
    """
    if calibrated_prob < 0.35:
        return (
            "Low",
            "#10b981",  # Emerald
            "Low Risk of Social Engineering",
            "This message displays language patterns consistent with authentic, legitimate communications. Minimal threat indicators detected, though always remain vigilant.",
        )
    elif calibrated_prob < 0.70:
        return (
            "Medium",
            "#f59e0b",  # Amber
            "Medium Suspicion / Ambiguous Content",
            "This message contains subtle indicators, mixed signals, or borderline phrasing found in phishing campaigns. Treat with caution and independently verify the sender.",
        )
    else:
        return (
            "High",
            "#ef4444",  # Red
            "High Risk / Phishing Indicators Detected",
            "Strong indicators of deceptive social engineering, urgency manipulation, or credential theft tactics detected. Do not click links, open attachments, or disclose credentials.",
        )


class PhishGuardClassifier:
    """
    Context-aware classifier combining TF-IDF N-grams + Dense Threat Features + Calibrated Logistic Regression.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.pipeline: Optional[Pipeline] = None
        self.metadata: Dict[str, Any] = {}

    def is_loaded(self) -> bool:
        """Returns True if the ML model pipeline is loaded and ready."""
        return self.pipeline is not None

    def load(self, path: Optional[str] = None) -> None:
        """
        Loads the trained model from disk.
        Raises ModelNotLoadedError on failure; never silently falls back to rules.
        """
        target_path = path or self.model_path
        if not os.path.exists(target_path):
            raise ModelNotLoadedError(
                f"Model file not found at '{target_path}'. Please train the model first using the training script or dashboard."
            )

        try:
            saved_data = joblib.load(target_path)
            if not isinstance(saved_data, dict) or "pipeline" not in saved_data:
                raise ModelNotLoadedError(
                    f"Invalid model file format at '{target_path}'. Expected dictionary containing 'pipeline'."
                )
            self.pipeline = saved_data["pipeline"]
            self.metadata = saved_data.get("metadata", {})
            self.model_path = target_path
        except Exception as e:
            self.pipeline = None
            if isinstance(e, ModelNotLoadedError):
                raise
            raise ModelNotLoadedError(f"Failed to load machine learning model from '{target_path}': {str(e)}") from e

    def train(
        self,
        dataset_path: str,
        test_size: float = 0.2,
        random_state: int = 42,
        save_after: bool = True,
    ) -> Dict[str, Any]:
        """
        Trains the context-aware pipeline with calibrated probability scaling on labeled dataset.
        Computes accuracy, precision, recall, f1-score, roc-auc, and a full confusion matrix.
        """
        if not os.path.exists(dataset_path):
            raise DatasetError(
                f"Dataset not found at '{dataset_path}'. Please ensure the real dataset exists before training."
            )

        try:
            df = pd.read_csv(dataset_path)
        except Exception as e:
            raise DatasetError(f"Failed to parse dataset at '{dataset_path}': {str(e)}") from e

        if "text" not in df.columns or "label" not in df.columns:
            raise DatasetError(
                f"Dataset at '{dataset_path}' must contain 'text' and 'label' columns. Found: {list(df.columns)}"
            )

        # Clean and validate records
        df = df.dropna(subset=["text", "label"]).copy()
        df["text"] = df["text"].astype(str)
        df["label"] = df["label"].astype(int)

        # Deduplicate records based on standardized cleaned text to prevent train/test data leakage
        clean_keys = df["text"].apply(clean_text)
        df = df.loc[~clean_keys.duplicated()].copy()

        if len(df) < 50:
            raise DatasetError(f"Dataset has only {len(df)} samples, which is too small for reliable ML training.")

        # Train/Test Split
        X_train, X_test, y_train, y_test = train_test_split(
            df["text"], df["label"], test_size=test_size, random_state=random_state, stratify=df["label"]
        )

        # 1. Word-level TF-IDF (captures domain terminology and vocabulary)
        word_tfidf = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=12000,
            sublinear_tf=True,
            min_df=2,
            preprocessor=clean_text,
            strip_accents="unicode",
        )

        # 2. Character-level TF-IDF (captures subword patterns, typosquatting like 'micros0ft', 'paypa1')
        char_tfidf = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            max_features=8000,
            sublinear_tf=True,
            min_df=3,
            preprocessor=clean_text,
        )

        # 3. Dense Threat & Behavioral Feature Extractor
        threat_feats = ThreatFeatureExtractor()

        # Combine all representations
        feature_union = FeatureUnion([
            ("word_tfidf", word_tfidf),
            ("char_tfidf", char_tfidf),
            ("threat_feats", threat_feats),
        ])

        # 4. Base Classifier with balanced class weights
        base_lr = LogisticRegression(
            C=2.5,
            max_iter=1000,
            class_weight="balanced",
            solver="lbfgs",
            random_state=random_state,
        )

        # 5. Calibrated Classifier to ensure probabilities reflect true empirical risk
        calibrated_clf = CalibratedClassifierCV(
            estimator=base_lr,
            method="sigmoid",
            cv=5,
        )

        pipeline = Pipeline([
            ("features", feature_union),
            ("classifier", calibrated_clf),
        ])

        # Train full pipeline
        pipeline.fit(X_train, y_train)

        # Evaluate on holdout test set
        y_pred = pipeline.predict(X_test)
        y_prob = pipeline.predict_proba(X_test)[:, 1]

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        try:
            auc = float(roc_auc_score(y_test, y_prob))
        except Exception:
            auc = 0.0

        # Detailed Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        cm_metrics = {
            "matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
            "specificity": round(float(tn / (tn + fp)), 4) if (tn + fp) > 0 else 0.0,
            "false_positive_rate": round(float(fp / (fp + tn)), 4) if (fp + tn) > 0 else 0.0,
            "false_negative_rate": round(float(fn / (fn + tp)), 4) if (fn + tp) > 0 else 0.0,
        }

        # Classification report dict
        clf_rep = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

        # Extract top predictive features from base Logistic Regression models
        top_phishing_features: List[str] = []
        top_legit_features: List[str] = []
        try:
            word_names = [f"word:{n}" for n in word_tfidf.get_feature_names_out()]
            char_names = [f"char:{n}" for n in char_tfidf.get_feature_names_out()]
            dense_names = [f"dense:{n}" for n in threat_feats.get_feature_names_out()]
            all_feature_names = np.array(word_names + char_names + dense_names)

            coefs = np.mean([clf.estimator.coef_[0] for clf in calibrated_clf.calibrated_classifiers_], axis=0)
            top_phish_idx = np.argsort(coefs)[-20:][::-1]
            top_legit_idx = np.argsort(coefs)[:20]

            top_phishing_features = [str(all_feature_names[i]) for i in top_phish_idx]
            top_legit_features = [str(all_feature_names[i]) for i in top_legit_idx]
        except Exception:
            pass

        metadata = {
            "trained_at": datetime.now().isoformat(),
            "total_samples": len(df),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "phish_samples": int((df["label"] == 1).sum()),
            "legit_samples": int((df["label"] == 0).sum()),
            "metrics": {
                "accuracy": round(acc, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "roc_auc": round(auc, 4),
            },
            "confusion_matrix": cm_metrics,
            "classification_report": clf_rep,
            "top_phishing_features": top_phishing_features,
            "top_legit_features": top_legit_features,
            "dataset_path": dataset_path,
        }

        self.pipeline = pipeline
        self.metadata = metadata

        if save_after:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump({"pipeline": pipeline, "metadata": metadata}, self.model_path)

        return metadata

    def predict(self, raw_text: str) -> Dict[str, Any]:
        """
        Runs context-aware inference on raw input text.
        
        CRITICAL: Never silently replaces ML failure with rules.
        Raises ModelNotLoadedError if model is not loaded.
        Raises ValueError if input fails validation.
        """
        if not self.is_loaded():
            raise ModelNotLoadedError(
                "Machine learning model is not loaded. Train or load the model before predicting."
            )

        is_valid, err_msg = validate_input(raw_text)
        if not is_valid:
            raise ValueError(err_msg)

        # Get calibrated probabilities from the full pipeline
        probabilities = self.pipeline.predict_proba([raw_text])[0]
        legit_prob = float(probabilities[0])
        phish_prob = float(probabilities[1])

        # Determine predicted binary class
        prediction_label = 1 if phish_prob >= 0.50 else 0
        class_name = "Phishing / Social Engineering" if prediction_label == 1 else "Legitimate Communication"

        # Calibrated risk level mapping
        risk_level, badge_color, summary, guidance = get_risk_tier(phish_prob)

        # Calculate Calibrated Risk Index (0 - 100)
        risk_score_index = int(round(phish_prob * 100))

        cleaned = clean_text(raw_text)

        return {
            "prediction": prediction_label,
            "class_name": class_name,
            "is_phishing": bool(prediction_label == 1),
            "calibrated_phish_probability": phish_prob,
            "calibrated_legit_probability": legit_prob,
            "risk_score_index": risk_score_index,
            "risk_level": risk_level,
            "badge_color": badge_color,
            "summary": summary,
            "guidance": guidance,
            "cleaned_text": cleaned,
            "warning": (
                "STATISTICAL ESTIMATE DISCLAIMER: This risk score reflects calibrated empirical "
                "patterns from historical training corpora. It is an algorithmic estimation and NOT a "
                "guarantee or cybersecurity warranty. Attackers constantly evolve methods; always verify "
                "sensitive requests through independent out-of-band communication."
            ),
        }
