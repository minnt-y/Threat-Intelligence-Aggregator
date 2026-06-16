import re
import logging
from typing import List, Dict

# Temporary logging configuration
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Regex patterns for IOC extraction
IOC_PATTERNS = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "ipv6": r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
    "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
    "url": r"https?://[^\s/$.?#].[^\s]*",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "cve": r"CVE-\d{4}-\d{4,}\b",
}


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Extract all IOCs from a given text.
    """
    results = {ioc_type: [] for ioc_type in IOC_PATTERNS}

    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = re.findall(pattern, text)
        # Remove duplicates while preserving order
        seen = set()
        unique_matches = []
        for match in matches:
            match_lower = match.lower()
            if match_lower not in seen:
                seen.add(match_lower)
                unique_matches.append(match)

        results[ioc_type] = unique_matches
        if unique_matches:
            logging.info(f"Found {len(unique_matches)} {ioc_type}(s)")

    return results


def extract_iocs_flat(text: str) -> List[Dict]:
    """
    Extract IOCs as flat list with type annotation
    """
    results = extract_iocs(text)
    flat = []
    for ioc_type, values in results.items():
        for value in values:
            flat.append({"type": ioc_type, "value": value})
    return flat


if __name__ == "__main__":
    # Test text with mixed IOCs
    test_text = """
    Suspicious activity detected from 192.168.1.1 and 10.0.0.1.
    Malicious domain: evil.com and sub.evil.co.uk.
    File hash: d41d8cd98f00b204e9800998ecf8427e
    Another hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    CVE reference: CVE-2021-44228
    URL: http://evil.com/payload.exe
    """

    print("=== Grouped Results ===")
    results = extract_iocs(test_text)
    for ioc_type, values in results.items():
        if values:
            print((f"{ioc_type}: {values}"))

    print("\n=== Flat Results ===")
    flat = extract_iocs_flat(test_text)
    for item in flat:
        print(item)
