"""
End-to-End verification script for PhishGuard AI.
Tests every sample message, risk score boundaries, tactic extraction, and safety guarantees.
"""

from src.model import PhishGuardClassifier, DEFAULT_MODEL_PATH
from src.tactics import analyze_tactics, generate_highlighted_html
from src.samples import SAMPLE_MESSAGES


def test_e2e_all_samples():
    clf = PhishGuardClassifier(DEFAULT_MODEL_PATH)
    clf.load()
    assert clf.is_loaded()

    for s in SAMPLE_MESSAGES:
        pred = clf.predict(s["content"])
        tactics = analyze_tactics(s["content"])

        # Risk score must be between 0 and 100
        assert 0 <= pred["risk_score_index"] <= 100
        assert 0.0 <= pred["calibrated_phish_probability"] <= 1.0
        assert pred["risk_level"] in ["Low", "Medium", "High"]

        if s["category"] in ["Obvious Phishing", "Subtle Phishing"]:
            assert len(tactics) > 0, f"Phishing sample {s['id']} should trigger tactics"
            assert pred["risk_level"] in ["High", "Medium"], f"Sample {s['id']} should be High or Medium risk"
            assert pred["is_phishing"] is True, f"Sample {s['id']} should be classified as phishing"
        elif s["category"] == "Legitimate Communication":
            assert pred["risk_level"] == "Low", f"Legitimate sample {s['id']} should be Low risk, got {pred['risk_level']}"
            assert pred["is_phishing"] is False, f"Legitimate sample {s['id']} should be classified as legitimate"
        elif s["category"] == "Security-Sensitive / Borderline":
            # Security-sensitive messages (e.g. password resets, bank statements) carry low to high operational suspicion
            assert pred["risk_level"] in ["Low", "Medium", "High"]

        # HTML generation should be valid
        html_out = generate_highlighted_html(s["content"], tactics)
        assert len(html_out) > 0
        assert "<div" in html_out


def test_e2e_subtle_phishing_cases():
    """Explicitly verify that sophisticated modern spear-phishing cases are caught."""
    clf = PhishGuardClassifier(DEFAULT_MODEL_PATH)
    clf.load()

    subtle_cases = [
        "Hi HR, I need to update my direct deposit bank routing information before this Friday payroll cutoff. I attached the new voided check details.",
        "Are you at your desk right now? I need you to purchase 5 Apple gift cards of $100 each for a client gift presentation right away. Do not call me as I am in a board meeting.",
        "Sarah has shared a confidential document 'Q4_Executive_Compensation_Plan.pdf' with you on OneDrive. Click here to view document: http://onedrive-share-doc.ru/view",
        "Please review and electronically sign 'Employment Contract Amendment 2026' sent via DocuSign. Completion required by end of business today: http://docusign-envelope-review.com",
        "You have 3 incoming emails held in quarantine server due to SPF mismatch. Release messages to your inbox: https://mail-quarantine-portal.net/release",
    ]

    for text in subtle_cases:
        res = clf.predict(text)
        assert res["is_phishing"] is True, f"Failed to detect subtle phishing: {text}"
        assert res["risk_level"] in ["High", "Medium"]
