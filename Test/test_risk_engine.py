import pytest
from risk_engine import calculate_risk_score, classify_risk


def test_calculate_risk_score_clean():
    """
    Test with clean stats (no malicious)
    """
    stats = {"malicious": 0, "suspicious": 0, "harmless": 55, "undetected": 36}
    score = calculate_risk_score(stats)
    assert score == 0.0


def test_calculate_risk_score_empty():
    # Test with empty stats
    stats = {}
    assert calculate_risk_score(stats) == 0.0


def test_classify_risk_high():
    # Test HIGH risk classification
    assert classify_risk(0.5) == "HIGH"


def test_classify_risk_medium():
    # Test MEDIUM risk classification
    assert classify_risk(0.2) == "MEDIUM"


def test_classify_risk_LOW():
    # Test LOW risk classification
    assert classify_risk(0.05) == "LOW"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
