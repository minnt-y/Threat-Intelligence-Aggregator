import logging
from typing import Literal

# Temporary logging configuration
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Risk thresholds
HIGH_THRESHOLD = 0.3  # 30% malicious
MEDIUM_THRESHOLD = 0.1


def calculate_risk_score(stats: dict) -> float:
    """
    Calculate risk score from VT analysis stats.
    Score = malicious + suspicious / total
    """
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    total = malicious + suspicious + harmless + undetected
    if total == 0:
        return 0.0

    score = (malicious + suspicious) / total
    return round(score, 2)


def classify_risk(score: float) -> Literal["HIGH", "MEDIUM", "LOW"]:
    """
    Classify risk level based on score.
    """
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    elif score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    else:
        return "LOW"


def analyze_ip(stats: dict, ip_address: str) -> dict:
    """
    Full analysis: calculate score and classify risk.
    """
    score = calculate_risk_score(stats)
    level = classify_risk(score)

    result = {"ip": ip_address, "score": score, "level": level, "stats": stats}

    logging.info(f"Risk analysis for {ip_address}: {level} ({score})")
    return result


if __name__ == "__main__":
    # Test with public IP (8.8.8.8)
    test_stats = {
        "malicious": 0,
        "suspicious": 0,
        "undetected": 36,
        "harmless": 55,
        "timeout": 0,
    }

    result = analyze_ip(test_stats, "8.8.8.8")
    print(f"Result: {result}")

    # Test with suspicious IP (simulated)
    test_stats_bad = {
        "malicious": 10,
        "suspicious": 5,
        "undetected": 20,
        "harmless": 30,
        "timeout": 0,
    }

    result_bad = analyze_ip(test_stats_bad, "evil.com")
    print(f"Result: {result_bad}")
