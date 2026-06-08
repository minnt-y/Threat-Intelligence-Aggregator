import logging
from models import ThreatIntel

# Configure logging to provide trace information
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s-%(levelname)s-%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def test_intel_validation():
    """Runs validation tests against the ThreatIntel model."""

    # Test case: Valid data
    valid_data = {"title": "Phishing Campaign", "severity": 3, "ioc": "1.1.1.1"}
    try:
        intel = ThreatIntel(**valid_data)
        logging.info(f"Validation passed for:{intel.title}")
    except Exception as e:
        logging.error(f"Validation failed:{e}")

    # Test case: Invalid data(Severity out of range)
    invalid_data = {"title": "Mailformed Entry", "severity": 10, "ioc": "1.1.1.1"}
    try:
        ThreatIntel(**invalid_data)
    except Exception as e:
        logging.warning(f"Data validation blocked an entry:{e}")


if __name__ == "__main__":
    test_intel_validation()
