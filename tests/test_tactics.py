"""
Tests for social engineering tactic detection and phrase extraction.
"""

from src.tactics import analyze_tactics, generate_highlighted_html, get_all_matched_spans


def test_analyze_tactics_empty():
    assert analyze_tactics("") == {}
    assert analyze_tactics(None) == {}
    assert analyze_tactics("   ") == {}


def test_analyze_tactics_urgency():
    text = "Immediate action required! Your code expires today. Act now within 24 hours."
    tactics = analyze_tactics(text)
    assert "urgency" in tactics
    assert len(tactics["urgency"]["matches"]) >= 2
    assert any("act now" in p.lower() or "immediate" in p.lower() for p in tactics["urgency"]["phrases"])


def test_analyze_tactics_threats():
    text = "Your account will be suspended due to unauthorized access. Legal action will follow."
    tactics = analyze_tactics(text)
    assert "threats" in tactics
    assert any("suspended" in p.lower() or "unauthorized access" in p.lower() for p in tactics["threats"]["phrases"])


def test_analyze_tactics_impersonation():
    text = "Official notice from the IT Department and Microsoft Security team regarding your mailbox."
    tactics = analyze_tactics(text)
    assert "impersonation" in tactics
    assert any("it department" in p.lower() or "microsoft security" in p.lower() for p in tactics["impersonation"]["phrases"])


def test_analyze_tactics_sensitive_info():
    text = "Click here to login and enter your password and Social Security Number to unlock."
    tactics = analyze_tactics(text)
    assert "sensitive_info" in tactics
    assert any("password" in p.lower() or "social security" in p.lower() for p in tactics["sensitive_info"]["phrases"])


def test_analyze_tactics_bec_payroll():
    text = "Please update my direct deposit bank routing information before this Friday payroll cutoff."
    tactics = analyze_tactics(text)
    assert "sensitive_info" in tactics
    assert any("direct deposit" in p.lower() or "routing" in p.lower() for p in tactics["sensitive_info"]["phrases"])


def test_analyze_tactics_ceo_giftcards():
    text = "Are you at your desk right now? Please purchase 5 Apple gift cards for a client presentation. Do not call me."
    tactics = analyze_tactics(text)
    assert "impersonation" in tactics or "sensitive_info" in tactics
    assert any("gift cards" in p.lower() for p in tactics["sensitive_info"]["phrases"])


def test_analyze_tactics_deceptive_lures():
    text = "Sarah has shared a confidential document with you on OneDrive. Click here to view document and electronically sign via DocuSign."
    tactics = analyze_tactics(text)
    assert "deceptive_lures" in tactics
    assert any("shared a confidential document" in p.lower() or "docusign" in p.lower() for p in tactics["deceptive_lures"]["phrases"])


def test_analyze_tactics_benign_text_no_false_alarm():
    text = "Your Amazon order #112 has shipped via UPS. Thank you for your purchase."
    tactics = analyze_tactics(text)
    # Plain "Amazon" in order receipt without "security/support/fraud" must not trigger impersonation
    assert "impersonation" not in tactics
    assert len(tactics) == 0


def test_get_all_matched_spans_non_overlapping():
    text = "Act now immediately to avoid account suspended."
    tactics = analyze_tactics(text)
    spans = get_all_matched_spans(tactics)
    assert len(spans) > 0
    # Ensure spans are strictly chronological and non-overlapping
    for i in range(len(spans) - 1):
        assert spans[i][1] <= spans[i + 1][0]


def test_generate_highlighted_html():
    text = "Act now to verify your password."
    tactics = analyze_tactics(text)
    html_output = generate_highlighted_html(text, tactics)
    assert "<mark" in html_output
    assert "password" in html_output


def test_analyze_tactics_locked_and_restricted_accounts():
    text = "Your account has been locked due to suspicious activity. Card has been placed on hold."
    tactics = analyze_tactics(text)
    assert "threats" in tactics
    threat_phrases = [p.lower() for p in tactics["threats"]["phrases"]]
    assert any("locked" in p for p in threat_phrases)
    assert any("suspicious activity" in p for p in threat_phrases)
    assert any("placed on hold" in p for p in threat_phrases)


def test_analyze_tactics_indirect_credentials_and_identity():
    text = "Send us your password to verify your identity as soon as possible without delay."
    tactics = analyze_tactics(text)
    assert "sensitive_info" in tactics
    assert "urgency" in tactics
    sensitive_phrases = [p.lower() for p in tactics["sensitive_info"]["phrases"]]
    urgency_phrases = [p.lower() for p in tactics["urgency"]["phrases"]]
    assert any("send us your password" in p for p in sensitive_phrases)
    assert any("verify your identity" in p for p in sensitive_phrases)
    assert any("as soon as possible" in p for p in urgency_phrases)
    assert any("without delay" in p for p in urgency_phrases)


def test_analyze_tactics_negation_extended():
    cases = [
        "We will never ask you to send your password or PIN.",
        "Chase will never ask for your password in an email or text.",
        "Our security team will never contact you to verify your identity.",
        "Do not send your password to anyone claiming to be support.",
    ]
    for c in cases:
        tactics = analyze_tactics(c)
        assert "sensitive_info" not in tactics, f"False alarm on security disclaimer: {c}"

