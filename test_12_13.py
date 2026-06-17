from typing import Literal
from filter_engine import check_filter
from intel_fetcher import VTClient
from risk_engine import analyze_ip
from ioc_extractor import extract_iocs_flat

client = VTClient()


def analyze_with_filter(ioc_value: str, ioc_type: Literal["ipv4", "domain"]):
    # 1. check filter
    filter_result = check_filter(ioc_value, ioc_type)

    if filter_result["action"] == "allow":
        print(f"SKIP (whitelist): {ioc_value}")
        return None

    if filter_result["action"] == "block":
        print(f"BLOCK (blacklist): {ioc_value}")
        return {"ioc": ioc_value, "level": "HIGH", "reason": "blacklist"}

    # 2. query VT
    stats = client.get_ip_report(ioc_value)
    if stats:
        return analyze_ip(stats, ioc_value)
    return None


def analyze_text(text: str):
    """
    Extract iocs from text and analyze
    """
    print(f"\n=== Analyzing text: {text[: 50]}... ===")

    iocs = extract_iocs_flat(text)
    if not iocs:
        print("No IOCs found.")
        return []

    results = []
    for ioc in iocs:
        print(f"\n--- Processing {ioc['type']}: {ioc['value']}---")
        result = analyze_with_filter(ioc["value"], ioc["type"])
        results.append(result)

    return results


# Test 1 (single IOC)
print("=" * 40)
print("TEST: single IOC")
print("=" * 40)
print(analyze_with_filter("8.8.8.8", "ipv4"))  # Skip
print(analyze_with_filter("unknown.com", "domain"))  # Query VT

# Test 2 (extract from text)
print("\n" + "=" * 40)
print("TEST: extract from text")
print("=" * 40)

test_text = """
Suspicious activity from 192.168.1.1 and 1.1.1.1.
Malicious domain: evil.com
File hash: d41d8cd98f00b204e9800998ecf8427e
CVE-2021-44228
"""

analyze_text(test_text)
