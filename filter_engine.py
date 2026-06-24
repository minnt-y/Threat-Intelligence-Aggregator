import logging
from typing import Literal

# Temporary logging configuration
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Whitelist: known safe domains/IPs
WHITELIST = {
    # Public DNS
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",  # Cloudflare
    "9.9.9.9",
    "149.112.112.112",  # Quad9
    "114.114.114.114",  # China 114
    # Domains
    "google.com",
    "cloudflare.com",
    "github.com",
}

# Blacklist: known malicious (example)
BLACKLIST = {
    "example-malicious.com",
    "192.0.2.100",  # TST-NET-1, example IP
}


def check_filter(ioc_value: str, ioc_type: Literal["ipv4", "domain"]) -> dict:
    """
    Check if IOC is in whitelist or blacklist.
    Returns: {"action": "allow", "reason": "whitelist"} etc.
    """

    # Check whitelist first
    if ioc_value in WHITELIST:
        logging.info(f"Filter: {ioc_value} -> WHITELIST")
        return {"action": "allow", "reason": "whitelist", "ioc": ioc_value}

    # Check blacklist
    if ioc_value in BLACKLIST:
        logging.warning(f"Filter: {ioc_value} -> BLACKLIST")
        return {"action": "block", "reason": "blacklist", "ioc": ioc_value}

    # Neither: proceed to VT query
    logging.info(f"Filter: {ioc_value} -> NEUTRAL (query VT)")
    return {"action": "query", "reason": "neutral", "ioc": ioc_value}


if __name__ == "__main__":
    # Test blacklist
    print(check_filter("example-malicious.com", "domian"))

    # Test neutral
    print(check_filter("unknown-bad.com", "domian"))
