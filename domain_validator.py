import socket
from typing import Dict, List
from logger_config import setup_logger

logger = setup_logger(__name__)


def validate_domain(domain: str) -> Dict:
    try:
        # Get IP address from domain (A record)
        ip = socket.gethostbyname(domain)
        logger.info(f"Domain {domain} resolved to {ip}")
        return {"domain": domain, "exists": True, "ip": ip}
    except socket.gaierror:
        # DNS resolution failed
        logger.warning(f"Domain {domain} does not exist")
        return {"domain": domain, "exists": False, "ip": None}


def validate_domains(domains: List[str]) -> List[Dict]:
    """
    Validate multiple domains
    """
    results = []
    for domain in domains:
        result = validate_domain(domain)
        results.append(result)
    return results


def filter_valid_domains(domains: List[str]) -> List[str]:
    """
    Return only valid (existing) domains
    """
    valid = []
    for domain in domains:
        result = validate_domain(domain)
        if result["exists"]:
            valid.append(domain)
    return valid


if __name__ == "__main__":
    # Test with real and fake domains
    test_domains = ["google.com", "cloudflare.com", "fake-domain-089.xy"]
    print("=== Single Validation ===")
    for domain in test_domains:
        result = validate_domain(domain)
        print(f"{domain}: {result}")

    print("\n=== Filter Valid ===")
    valid_only = filter_valid_domains(test_domains)
    print(f"Valid domains: {valid_only}")
