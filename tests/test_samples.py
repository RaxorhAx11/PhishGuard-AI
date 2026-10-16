"""
Tests to ensure all bundled sample messages are valid and accurately processed.
"""

from src.samples import SAMPLE_MESSAGES
from src.preprocessing import validate_input
from src.tactics import analyze_tactics


def test_sample_messages_validity():
    assert len(SAMPLE_MESSAGES) >= 6

    for sample in SAMPLE_MESSAGES:
        assert "id" in sample
        assert "title" in sample
        assert "content" in sample
        assert "category" in sample

        # Check input validation
        is_valid, msg = validate_input(sample["content"])
        assert is_valid is True, f"Sample '{sample['id']}' failed validation: {msg}"


def test_sample_messages_phishing_have_tactics():
    phishing_samples = [s for s in SAMPLE_MESSAGES if "Phishing" in s["category"]]
    for s in phishing_samples:
        tactics = analyze_tactics(s["content"])
        assert len(tactics) > 0, f"Phishing sample {s['id']} should trigger at least one tactic"
