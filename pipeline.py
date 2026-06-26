from typing import List, Dict, Optional
from logger_config import setup_logger

from ioc_extractor import extract_iocs_flat
from domain_validator import validate_domain
from filter_engine import check_filter
from intel_fetcher import VTClient
from risk_engine import analyze_ip
from attribution_engine import analyze_with_attribution

logger = setup_logger(__name__)


class ThreatPipeline:
    """
    End-to-end threat intelligence processing pipeline
    """

    def __init__(self):
        self.vt_client = VTClient()
        logger.info("Pipeline initialized")

    def process(self, text: str) -> List[Dict]:
        """
        Process raw text through full pipeline
        """
        logger.info(f"Processing text: {text[:50]}...")

        # Stage 1: Extract
        iocs = extract_iocs_flat(text)
        if not iocs:
            logger.info("No IOCs found")
            return []
        logger.info(f"Stage 1 - Extracted: {len(iocs)} IOC(s)")

        # Stage 2-6: Process each IOC
        results = []
        for ioc in iocs:
            result = self._process_single(ioc["value"], ioc["type"])
            if result:
                results.append(result)

        logger.info(f"Pipeline complete: {len(results)} result(s)")
        return results

    def _process_single(self, ioc_value: str, ioc_type: str) -> Optional[Dict]:
        """
        Process single IOC through remaining stages
        """
        # Stage 2: Validate (domains only)
        if ioc_type == "domain":
            validation = validate_domain(ioc_value)
            if not validation["exists"]:
                logger.info(f"Stage 2 - Invalid domain: {ioc_value}")
                return None

        # Stage 3: Filter
        filter_result = check_filter(ioc_value, ioc_type)
        if filter_result["action"] == "allow":
            logger.info(f"Stage 3 - Whitelist: {ioc_value}")
            return None
        if filter_result["action"] == "block":
            logger.warning(f"Stage 3 - Blacklist: {ioc_value}")
            return {
                "ioc": ioc_value,
                "type": ioc_type,
                "level": "HIGH",
                "reason": "blacklist",
                "attribution": None,
            }

        # Stage 4: Query VT
        stats = self.vt_client.get_ip_report(ioc_value)
        if not stats:
            logger.error(f"Stage 4 - VT failed: {ioc_value}")
            return None

        # Stage 5: Risk score
        risk = analyze_ip(stats, ioc_value)

        # Stage 6: Attribution
        attr = analyze_with_attribution(ioc_value, ioc_type)

        return {
            "ioc": ioc_value,
            "type": ioc_type,
            "risk": risk,
            "attribution": attr.get("attribution"),
        }


if __name__ == "__main__":
    pipeline = ThreatPipeline()

    test_text = """
    Suspicious activity from 192.168.1.1 and evil.com
    File hash: d41d8cd98f00b204e9800998ecf8427e
    """

    print("=" * 60)
    print("PIPELINE TEST")
    print("=" * 60)

    results = pipeline.process(test_text)

    print(f"\n--- Final Results ({len(results)} item(s))---")
    for r in results:
        print(f"\n  IOC: {r['ioc']}")
        if "risk" in r:
            print(f"  Risk: {r['risk']['level']} ({r['risk']['score']})")
        if r.get("attribution"):
            print(f"  Attribution: {r['attribution']['actor']}")
        if r.get("reason"):
            print(f"  Reason: {r['reason']}")
