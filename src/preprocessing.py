"""
Pre-processing, feature extraction, and input validation utilities for PhishGuard AI.
"""

import math
import re
from typing import List, Tuple
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin


SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "cutt.ly"
}

AUTH_KEYWORDS = {
    "login", "signin", "verify", "auth", "password", "update", "confirm", "unlock", "secure"
}


def validate_input(text: str, min_chars: int = 10) -> Tuple[bool, str]:
    """
    Validates user text input.

    Returns:
        (is_valid, error_message): Tuple indicating validity and failure reason if any.
    """
    if text is None:
        return False, "Input cannot be None. Please enter email or SMS content."

    stripped = text.strip()
    if not stripped:
        return False, "Input cannot be empty. Please paste or type an email or SMS message."

    if len(stripped) < min_chars:
        return (
            False,
            f"Input is too short ({len(stripped)} characters). Please provide at least {min_chars} characters for a reliable context-aware analysis.",
        )

    # Check if text contains at least some alphanumeric characters
    alnum_count = sum(c.isalnum() for c in stripped)
    if alnum_count < 5:
        return (
            False,
            "Input contains insufficient readable text (too few letters or numbers).",
        )

    return True, ""


def _replace_url(match: re.Match) -> str:
    """Classifies a URL into specific threat-aware tokens."""
    url = match.group(0).lower()

    # Check for raw IP address in URL host (e.g. http://192.168.1.1/ or http://45.33.21.10)
    if re.search(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)", url):
        return " ip_address_url_token "

    # Check for common link shorteners
    for shortener in SHORTENER_DOMAINS:
        if shortener in url:
            return " shortened_url_token "

    # Check for authentication / credential harvest action paths
    for kw in AUTH_KEYWORDS:
        if f"/{kw}" in url or f"?{kw}" in url or f"&{kw}" in url:
            return " auth_action_url_token "

    return " http_url_token "


def clean_text(text: str, keep_tokens: bool = True) -> str:
    """
    Cleans and standardizes raw email or SMS text for NLP feature extraction.
    
    Args:
        text: Raw input string.
        keep_tokens: If True, replaces URLs and emails with normalized tokens.
    
    Returns:
        Cleaned, lowercased string.
    """
    if not text:
        return ""

    text = str(text)

    # Remove standard Email Subject header prefix if present
    text = re.sub(r"^(?:subject\s*:\s*)+", "", text, flags=re.IGNORECASE).strip()

    if keep_tokens:
        # Context-aware URL tokenization
        text = re.sub(
            r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\-.~:?#\[\]@!$&'()*+,;=]*",
            _replace_url,
            text,
            flags=re.IGNORECASE,
        )
        # Normalize email addresses
        text = re.sub(
            r"[\w\.-]+@[\w\.-]+\.\w+",
            " email_address_token ",
            text,
            flags=re.IGNORECASE,
        )
        # Normalize phone numbers (requiring explicit separator structure to avoid tracking numbers)
        text = re.sub(
            r"\b(?:\+\d{1,2}\s?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}\b",
            " phone_number_token ",
            text,
        )
        # Normalize currency amounts (e.g. $500, €1,000, £250)
        text = re.sub(r"[\$€£¥]\s*\d+(?:[.,]\d+)?\b", " currency_amount_token ", text)

    # Normalize multiple whitespace, tabs, and newlines
    text = re.sub(r"[\r\n\t]+", " ", text)
    text = re.sub(r"\s{2,}", " ", text)

    return text.strip().lower()


class ThreatFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Custom Scikit-learn Transformer that computes dense contextual threat features
    from raw or pre-cleaned text to complement TF-IDF n-grams.
    """

    def fit(self, X, y=None):
        return self

    def transform(self, X) -> np.ndarray:
        features = []
        # Lazy import to avoid circular dependencies
        from src.tactics import analyze_tactics

        for raw_item in X:
            text = str(raw_item)
            cleaned = clean_text(text)
            text_len = len(text)

            # URL Features
            ip_url_count = len(re.findall(r"ip_address_url_token", cleaned))
            short_url_count = len(re.findall(r"shortened_url_token", cleaned))
            auth_url_count = len(re.findall(r"auth_action_url_token", cleaned))
            gen_url_count = len(re.findall(r"http_url_token", cleaned))
            total_url_count = ip_url_count + short_url_count + auth_url_count + gen_url_count

            # Social engineering tactics
            tactics = analyze_tactics(text)
            urgency_matches = tactics.get("urgency", {}).get("match_count", 0)
            threat_matches = tactics.get("threats", {}).get("match_count", 0)
            impersonation_matches = tactics.get("impersonation", {}).get("match_count", 0)
            sensitive_matches = tactics.get("sensitive_info", {}).get("match_count", 0)
            lure_matches = tactics.get("deceptive_lures", {}).get("match_count", 0)
            total_tactics = len(tactics)

            # Stylistic / Psychological indicators
            exclamation_count = text.count("!")
            uppercase_chars = sum(1 for c in text if c.isupper())
            uppercase_ratio = uppercase_chars / max(text_len, 1)
            currency_count = len(re.findall(r"[\$€£¥]", text))

            row = [
                float(total_url_count),
                float(ip_url_count > 0),
                float(short_url_count > 0),
                float(auth_url_count > 0),
                float(urgency_matches),
                float(threat_matches),
                float(impersonation_matches),
                float(sensitive_matches),
                float(lure_matches),
                float(total_tactics),
                float(exclamation_count),
                float(uppercase_ratio),
                float(currency_count),
                float(min(math.log1p(text_len) / 8.0, 1.0)),
            ]
            features.append(row)

        return np.array(features, dtype=np.float32)

    def get_feature_names_out(self, input_features=None):
        return np.array([
            "total_url_count",
            "has_ip_url",
            "has_short_url",
            "has_auth_url",
            "urgency_matches",
            "threat_matches",
            "impersonation_matches",
            "sensitive_matches",
            "lure_matches",
            "total_tactics",
            "exclamation_count",
            "uppercase_ratio",
            "currency_count",
            "log_text_len",
        ])
