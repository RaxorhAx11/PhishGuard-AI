"""
Tests for preprocessing and input validation.
"""

import pytest
from src.preprocessing import clean_text, validate_input, ThreatFeatureExtractor


def test_validate_input_valid():
    text = "Dear employee, please review the attached corporate meeting agenda for tomorrow."
    is_valid, msg = validate_input(text)
    assert is_valid is True
    assert msg == ""


def test_validate_input_empty():
    for text in ["", "   ", "\n\t  ", None]:
        is_valid, msg = validate_input(text)
        assert is_valid is False
        assert "empty" in msg.lower() or "none" in msg.lower()


def test_validate_input_too_short():
    for text in ["hi", "abc", "12345", "hello!"]:
        is_valid, msg = validate_input(text, min_chars=10)
        assert is_valid is False
        assert "too short" in msg.lower()


def test_validate_input_insufficient_alphanumeric():
    text = "!@#$%^&*()_+-=~`"
    is_valid, msg = validate_input(text)
    assert is_valid is False
    assert "insufficient readable text" in msg.lower()


def test_clean_text_normalizes_urls_intelligently():
    # Generic URL
    raw_gen = "Please visit https://example.com/blog/article.html for news."
    cleaned_gen = clean_text(raw_gen)
    assert "http_url_token" in cleaned_gen

    # Credential/Auth URL
    raw_auth = "Please visit https://malicious-domain.com/login?token=abc to verify."
    cleaned_auth = clean_text(raw_auth)
    assert "auth_action_url_token" in cleaned_auth

    # IP address URL
    raw_ip = "Connect to http://192.168.1.1/dashboard now."
    cleaned_ip = clean_text(raw_ip)
    assert "ip_address_url_token" in cleaned_ip


def test_clean_text_normalizes_email():
    raw = "Contact our team at security@company-domain.org for info."
    cleaned = clean_text(raw)
    assert "email_address_token" in cleaned
    assert "security@" not in cleaned


def test_clean_text_normalizes_currency_and_phones():
    raw = "Your account was charged $499.99. Call 1-800-555-0199 now."
    cleaned = clean_text(raw)
    assert "currency_amount_token" in cleaned
    assert "phone_number_token" in cleaned


def test_clean_text_strips_subject_header():
    raw = "Subject: Urgent Security Notice\n\nPlease check your inbox."
    cleaned = clean_text(raw)
    assert not cleaned.startswith("subject:")
    assert "urgent security notice" in cleaned


def test_threat_feature_extractor():
    extractor = ThreatFeatureExtractor()
    texts = [
        "Urgent! Please verify your password immediately at http://192.168.1.1/login",
        "Hi team, meeting tomorrow at 2pm in room 4.",
    ]
    feats = extractor.transform(texts)
    assert feats.shape == (2, 14)
    # The phishing text should have higher urgency/threat/sensitive feature values
    assert feats[0, 1] == 1.0  # has_ip_url
    assert feats[0, 4] >= 1.0  # urgency matches
