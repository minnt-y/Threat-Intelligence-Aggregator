import logging
from typing import Dict, List, Optional

from ioc_extractor import extract_iocs_flat
from domain_validator import validate_domain
from filter_engine import check_filter
from intel_fetcher import VTClient
from risk_engine import analyze_ip
from attribution_engine import analyze_with_attribution

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class IntelligenceEngine:
    """
    Unified threat intelligence analysis engine.
    Orchestrates the full pipeline: extract -> validate -> filter -> query -> score -> attribute.
    """

    def __init__(self):
        self.vt_client = VTClient()
        logging.info("IntelligenceEngine initialized")

    def analyze_ioc(self, ioc_value: str, ioc_type: str) -> Optional[Dict]:
        """
        Analyze a single IOC through the full pipeline.
        """
        # Step 1: Filter (Whitelist / blacklist)
        filter_result = check_filter(ioc_value, ioc_type)
        if filter_result["action"] == "allow":
            logging.info(f"SKIP (Whitelist): {ioc_value}")
            return None
        if filter_result["action"] == "block":
            logging.warning(f"BLOCK(blacklist): {ioc_value}")
            return {
                "ioc": ioc_value,
                "type": ioc_type,
                "level": "HIGH",
                "reason": "blacklist",
            }

        # Step 2: Validate domain if applicable
        if ioc_type == "domain":
            validation = validate_domain(ioc_value)
            if not validation["exists"]:
                logging.warning(f"SKIP(invalid domain): {ioc_value}")
                return None

        # Step 3: Query VT API
        stats = self.vt_client.get_ip_report(ioc_value)
        if not stats:
            logging.error(f"VT query failed: {ioc_value}")
            return None

        # Step 4: Risk scoring
        risk_report = analyze_ip(stats, ioc_value)

        # Step 5: Threat attribution
        attribution = analyze_with_attribution(ioc_value, ioc_type)

        # Combine results
        return {
            "ioc": ioc_value,
            "type": ioc_type,
            "risk": risk_report,
            "attribution": attribution.get("attribution"),
        }

    def analyze_text(self, text: str) -> List[Dict]:
        """
        Analyze arbitrary text: extract IOCs and process each.
        """
        logging.info(f"Analyzing text: {text[:50]}...")

        # Extract IOCs
        iocs = extract_iocs_flat(text)
        if not iocs:
            logging.info("No IOCs found")
            return []

        logging.info(f"found {len(iocs)} IOC(s)")

        # Process each IOC
        results = []
        for ioc in iocs:
            result = self.analyze_ioc(ioc["value"], ioc["type"])
            if result:
                results.append(result)

        return results


if __name__ == "__main__":
    engine = IntelligenceEngine()

    # Test 1: Single text analysis
    test_text = """Malicious activity from 192.168.1.1 and evil.com.
File hash: d41d8cd98f00b204e9800998ecf8427e"""

    print("=" * 60)
    print("FULL PIPELINE TEST")
    print("=" * 60)

    results = engine.analyze_text(test_text)

    print(f"\n--- Results ({len(results)} item(s)) ---")
    for r in results:
        print(f"\nIOC: {r['ioc']}")
        print(f"  Risk Level: {r['risk']['level']}")
        print(f"  Score: {r['risk']['score']}")
        if r["attribution"]:
            print(
                f"  Attribution: {r['attribution']['actor']} ({r['attribution']['confidence']})"
            )
