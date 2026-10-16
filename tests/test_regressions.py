"""
Regression tests for PhishGuard AI.
Verifies fixes for:
1. Quick-demo button ID mismatches in app.py
2. Previously failed subtle phishing detections (False Negatives: S3, S4, V1, V2)
3. False positives on legitimate bank fraud alerts (FP4) and operational communications (FP1-FP3, FP5, FP6)
"""

import os
import re
import pytest

from src.model import PhishGuardClassifier, DEFAULT_MODEL_PATH
from src.samples import SAMPLE_MESSAGES
from src.tactics import analyze_tactics


@pytest.fixture(scope="module")
def classifier():
    clf = PhishGuardClassifier(DEFAULT_MODEL_PATH)
    clf.load()
    return clf


# =====================================================================
# 1. Quick-Demo Button ID Mismatch Regressions
# =====================================================================

def test_demo_button_ids_match_sample_library():
    """
    Ensure every sample ID referenced by demo buttons in app.py exactly
    matches an existing record in SAMPLE_MESSAGES in src/samples.py.
    """
    app_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app.py")
    assert os.path.exists(app_path), "app.py must exist"

    with open(app_path, "r", encoding="utf-8") as f:
        app_content = f.read()

    # Extract all button lookup IDs: s["id"] == "..."
    referenced_ids = re.findall(r's\[["\']id["\']\]\s*==\s*["\']([^"\']+)["\']', app_content)
    assert len(referenced_ids) >= 4, f"Expected at least 4 demo button lookups, found {len(referenced_ids)}"

    sample_id_map = {s["id"]: s for s in SAMPLE_MESSAGES}

    for button_id in referenced_ids:
        assert button_id in sample_id_map, (
            f"Demo button in app.py references unknown sample ID '{button_id}'. "
            f"Available IDs: {list(sample_id_map.keys())}"
        )
        sample = sample_id_map[button_id]
        assert "content" in sample and len(sample["content"].strip()) > 20, (
            f"Sample '{button_id}' has missing or empty content"
        )


def test_specific_repaired_demo_button_ids():
    """Verify specifically the three previously broken button IDs."""
    sample_ids = {s["id"] for s in SAMPLE_MESSAGES}
    assert "subtle_ceo_giftcard" in sample_ids
    assert "subtle_docusign_lure" in sample_ids
    assert "legit_meeting_sync" in sample_ids


# =====================================================================
# 2. False Negative Regressions (Subtle Social Engineering)
# =====================================================================

def test_regression_s3_vendor_invoice_iban_change(classifier):
    """
    Regression test for S3 (Vendor bank details / IBAN payment diversion).
    Previously failed with prob=0.4474 (Legit, 0 tactics).
    """
    text = (
        "Hi team, please find attached invoice #4920 for last month services. "
        "Note our bank details have changed to New Horizon Bank IBAN GB29NWBK60161331926819. "
        "Please process payment today."
    )
    tactics = analyze_tactics(text)
    assert "sensitive_info" in tactics, "Must detect sensitive_info tactic for bank details/IBAN"
    matched_phrases = [p.lower() for p in tactics["sensitive_info"]["phrases"]]
    assert any("bank details have changed" in p or "iban" in p for p in matched_phrases)

    res = classifier.predict(text)
    assert res["is_phishing"] is True, f"S3 must be classified as phishing, got {res}"
    assert res["calibrated_phish_probability"] >= 0.50
    assert res["risk_level"] in ("High", "Medium")


def test_regression_s4_mfa_push_it_helpdesk(classifier):
    """
    Regression test for S4 (IT Helpdesk impersonation + Duo MFA push approval).
    Previously failed with prob=0.1700 (Legit, 0 tactics).
    """
    text = (
        "Hi Sarah, this is Kevin from internal IT Helpdesk. "
        "We are performing mandatory security updates on your workstation. "
        "A Duo MFA push was just sent to your phone, please approve it so we can complete setup."
    )
    tactics = analyze_tactics(text)
    assert "impersonation" in tactics, "Must detect IT Helpdesk impersonation"
    assert "sensitive_info" in tactics, "Must detect MFA push approval request"

    res = classifier.predict(text)
    assert res["is_phishing"] is True, f"S4 must be classified as phishing, got {res}"
    assert res["calibrated_phish_probability"] >= 0.50
    assert res["risk_level"] in ("High", "Medium")


def test_regression_v1_paraphrased_payroll_scam(classifier):
    """
    Regression test for V1 (Paraphrased payroll salary direct transfer diversion).
    Previously failed with prob=0.1347 (Legit, 0 tactics).
    """
    text = (
        "Hello payroll office, could you kindly swap my monthly salary direct transfer "
        "account to my new credit union account before next payroll cycle? "
        "Let me know what paperwork is needed."
    )
    tactics = analyze_tactics(text)
    assert len(tactics) > 0, "Must detect manipulation tactics in paraphrased payroll request"
    assert "sensitive_info" in tactics, "Must detect payroll / direct transfer diversion"

    res = classifier.predict(text)
    assert res["is_phishing"] is True, f"V1 must be classified as phishing, got {res}"
    assert res["calibrated_phish_probability"] >= 0.50


def test_regression_v2_paraphrased_giftcard_scam(classifier):
    """
    Regression test for V2 (Paraphrased executive gift voucher request).
    Previously failed with prob=0.1231 (Legit, 0 tactics).
    """
    text = (
        "Quick favor - I am currently tied up in a client conference and unable to step out. "
        "Can you quickly grab several electronic store vouchers for the team reward? I will reimburse you."
    )
    tactics = analyze_tactics(text)
    assert "sensitive_info" in tactics, "Must detect store voucher request"
    matched_phrases = [p.lower() for p in tactics["sensitive_info"]["phrases"]]
    assert any("store vouchers" in p or "reimburse" in p for p in matched_phrases)

    res = classifier.predict(text)
    assert res["is_phishing"] is True, f"V2 must be classified as phishing, got {res}"
    assert res["calibrated_phish_probability"] >= 0.50


# =====================================================================
# 3. False Positive Regressions (Legitimate Banking & Operational Alerts)
# =====================================================================

def test_regression_fp4_bank_fraud_alert_sms(classifier):
    """
    Regression test for FP4 (Legitimate bank 2-way fraud alert SMS).
    Previously flagged as phishing with prob=0.7737 (High Risk).
    """
    text = (
        "Fraud Alert: Did you attempt a $45.20 purchase at Target? "
        "Reply YES or NO. We will never ask for your card number or PIN."
    )
    # Ensure negative assertion prevents sensitive_info false alarm
    tactics = analyze_tactics(text)
    assert "sensitive_info" not in tactics, "Disclaimer 'never ask for card/PIN' must not trigger sensitive_info"

    res = classifier.predict(text)
    assert res["is_phishing"] is False, f"Legitimate fraud alert SMS must be classified as Legit, got {res}"
    assert res["risk_level"] == "Low", f"Expected Low risk tier, got {res['risk_level']}"
    assert res["calibrated_phish_probability"] < 0.35


def test_regression_benign_administrative_messages(classifier):
    """Verify that operational and administrative communications remain low risk."""
    benign_cases = [
        (
            "HR Open Enrollment",
            "Urgent reminder from HR Department: Benefits open enrollment ends today at 5pm. "
            "Please make sure to submit your health insurance selections on the employee portal.",
        ),
        (
            "Legal NDA",
            "Attached is the mutual non-disclosure agreement for review and signature before our partner call on Thursday. "
            "Please let legal know if you have redlines.",
        ),
        (
            "Password Expiration",
            "Your corporate network password will expire in 5 days. "
            "You can change your password by pressing Ctrl+Alt+Del on your workstation.",
        ),
        (
            "CEO All-Hands",
            "Message from the CEO: All hands meeting tomorrow at 9am to discuss Q4 results and company strategy. "
            "Please arrive on time.",
        ),
        (
            "IT Server Maintenance",
            "IT Helpdesk Notice: Scheduled server maintenance this Saturday between 2am and 4am. "
            "Internal network services may be temporarily unavailable.",
        ),
    ]

    for name, text in benign_cases:
        res = classifier.predict(text)
        assert res["is_phishing"] is False, f"Benign message '{name}' misclassified as phishing (prob={res['calibrated_phish_probability']:.4f})"
        assert res["risk_level"] == "Low", f"Benign message '{name}' received non-Low risk level ({res['risk_level']})"
