"""
Tests for ML classifier, calibration, prediction, evaluation metrics, and error handling.
"""

import os
import pytest
from src.model import (
    PhishGuardClassifier,
    ModelNotLoadedError,
    DatasetError,
    get_risk_tier,
    DEFAULT_MODEL_PATH,
)


def test_get_risk_tier_calibration():
    # Low risk
    level, color, summary, _ = get_risk_tier(0.15)
    assert level == "Low"
    assert color == "#10b981"

    # Medium risk
    level, color, summary, _ = get_risk_tier(0.45)
    assert level == "Medium"
    assert color == "#f59e0b"

    # High risk
    level, color, summary, _ = get_risk_tier(0.85)
    assert level == "High"
    assert color == "#ef4444"


def test_unloaded_model_raises_error():
    clf = PhishGuardClassifier(model_path="non_existent_path.joblib")
    assert not clf.is_loaded()

    with pytest.raises(ModelNotLoadedError) as exc_info:
        clf.predict("Some test text for classification")
    assert "not loaded" in str(exc_info.value).lower()


def test_missing_model_file_load_raises():
    clf = PhishGuardClassifier(model_path="missing_model_file_12345.joblib")
    with pytest.raises(ModelNotLoadedError):
        clf.load()


def test_predict_loaded_model_phishing():
    clf = PhishGuardClassifier(model_path=DEFAULT_MODEL_PATH)
    clf.load()
    assert clf.is_loaded()

    phish_text = (
        "URGENT: Your bank account has been suspended due to unauthorized transactions. "
        "Click here immediately to verify your password and identity or access will be terminated."
    )
    result = clf.predict(phish_text)

    assert result["is_phishing"] is True
    assert result["risk_level"] in ["High", "Medium"]
    assert 0.0 <= result["calibrated_phish_probability"] <= 1.0
    assert 0 <= result["risk_score_index"] <= 100
    assert "STATISTICAL ESTIMATE DISCLAIMER" in result["warning"]


def test_predict_loaded_model_legitimate():
    clf = PhishGuardClassifier(model_path=DEFAULT_MODEL_PATH)
    clf.load()

    legit_cases = [
        "Hi John, hope you are doing well. Please find attached the notes from yesterday's team lunch. Let me know if you would like to reschedule our catch-up on Thursday.",
        "Your monthly statement for checking account ending in 4102 is now ready to view. To access your statement, sign in to your account at our official website. Thank you for choosing Chase.",
        "Your Amazon order #112-9842145 has shipped via UPS. Expected delivery is Friday. Track package at official carrier site. Thank you for your purchase.",
    ]

    for text in legit_cases:
        result = clf.predict(text)
        assert result["risk_level"] == "Low", f"Expected Low risk for legit email, got {result['risk_level']}"
        assert result["calibrated_phish_probability"] < 0.35
        assert result["is_phishing"] is False


def test_predict_invalid_inputs():
    clf = PhishGuardClassifier(model_path=DEFAULT_MODEL_PATH)
    clf.load()

    with pytest.raises(ValueError):
        clf.predict("")

    with pytest.raises(ValueError):
        clf.predict("   ")

    with pytest.raises(ValueError):
        clf.predict("too short")


def test_dataset_error_on_missing_file():
    clf = PhishGuardClassifier()
    with pytest.raises(DatasetError):
        clf.train(dataset_path="completely_fake_dataset_path.csv")


def test_evaluation_metrics_and_confusion_matrix_in_metadata():
    clf = PhishGuardClassifier(model_path=DEFAULT_MODEL_PATH)
    clf.load()

    meta = clf.metadata
    assert "metrics" in meta
    assert "confusion_matrix" in meta

    m = meta["metrics"]
    assert "accuracy" in m and m["accuracy"] > 0.90
    assert "precision" in m and m["precision"] > 0.90
    assert "recall" in m and m["recall"] > 0.90
    assert "f1_score" in m and m["f1_score"] > 0.90
    assert "roc_auc" in m and m["roc_auc"] > 0.95

    cm = meta["confusion_matrix"]
    assert "true_negatives" in cm
    assert "false_positives" in cm
    assert "false_negatives" in cm
    assert "true_positives" in cm
    assert "specificity" in cm
    assert "false_positive_rate" in cm
    assert "false_negative_rate" in cm

    total_cm = cm["true_negatives"] + cm["false_positives"] + cm["false_negatives"] + cm["true_positives"]
    assert total_cm == meta["test_samples"]
    assert cm["false_positive_rate"] < 0.05  # FPR should be under 5%
