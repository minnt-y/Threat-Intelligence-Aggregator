import logging
from typing import Dict, List, Optional

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Known threat actor profiles (simplified)
THREAT_ACTORS = {
    "APT28": {
        "aliases": ["Fancy Bear", "Sofacy"],
        "ttps": ["spear-phishing", "zero-day", "VPN exploit"],
        "targets": ["government", "military", "election"],
        "infrastructure": ["185.220.101.0/24", "ssl-apt28.com"],
    },
    "Lazarus": {
        "aliases": ["Hidden Cobra", "ZINC"],
        "ttps": ["supply-chain", "cryptocurrency", "ransomware"],
        "targets": ["financial", "crypto-exchange", "media"],
        "infrastructure": ["192.168.100.0/24", "lazarus-c2.net"],
    },
    "MageCart": {
        "aliases": ["TEMP.MageCart"],
        "ttps": ["web-skimming", "e-commerce", "javascript injection"],
        "targets": ["e-commerce", "payment", "retail"],
        "infrastructure": ["magecart-js.com", "checkout-stealer.net"],
    },
}


def match_attribution(ioc_value: str, ioc_type: str, ttp: str = "") -> Optional[Dict]:
    """
    Match IOC against known threat actor profiles.
    Returns attribution result if match found.
    """
    matches = []

    for actor_name, profile in THREAT_ACTORS.items():
        score = 0
        reasons = []

        # Check infrastructure match
        if ioc_value in profile["infrastructure"]:
            score += 50
            reasons.append(f"infrastructure match: {ioc_value}")

        # Check TTP match
        if ttp and ttp.lower() in [t.lower() for t in profile["ttps"]]:
            score += 30
            reasons.append(f"TTP match: {ttp}")

        if score > 0:
            matches.append(
                {
                    "actor": actor_name,
                    "aliases": profile["aliases"],
                    "score": score,
                    "confidence": (
                        "LOW" if score < 40 else "MEDIUM" if score < 70 else "HIGH"
                    ),
                    "reasons": reasons,
                }
            )

    # Return highest score match (after checking all actors)
    if matches:
        matches.sort(key=lambda x: x["score"], reverse=True)
        best = matches[0]
        logging.info(f"Attribution: {best['actor']} (confidence: {best['confidence']})")
        return best

    logging.info("No attribution match found")
    return None


def analyze_with_attribution(ioc_value: str, ioc_type: str, ttp: str = "") -> Dict:
    """
    Full analysis: risk score + threat attribution.
    """
    result = {
        "ioc": ioc_value,
        "type": ioc_type,
        "attribution": match_attribution(ioc_value, ioc_type, ttp),
    }

    if result["attribution"]:
        print(f"WARNING: Possible {result['attribution']['actor']} activity!")
    else:
        print(f"No known threat actor attribution for {ioc_value}")

    return result


if __name__ == "__main__":
    # Test 1: Known APT28 infrastructure
    print("=" * 50)
    analyze_with_attribution("ssl-apt28.com", "domain", "spear-phishing")

    # Test 2: Unknown IOC
    print("\n" + "=" * 50)
    analyze_with_attribution("unknown-evil.xyz", "domain", "ransomware")

    # Test 3: Lazarus TTP match
    print("\n" + "=" * 50)
    analyze_with_attribution("192.168.1.1", "ipv4", "cryptocurrency")
