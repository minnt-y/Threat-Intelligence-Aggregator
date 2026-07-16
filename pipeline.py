"""
ETL Pipeline: Fetch IOCs from APIs -> Transform -> Save to Database
"""

from typing import List, Dict, Optional
from datetime import datetime, timezone

from database import init_db, SessionLocal, IOC, Alert, Source
from intel_fetcher import IntelFetcher, IOC as FetcherIOC

from ioc_extractor import extract_iocs_flat


class IntelPipeline:
    """Pipeline to fetch, transform, and store threat intelligence."""

    def __init__(self):
        self.fetcher = IntelFetcher()

    def extract_from_text(self, text: str) -> List[Dict]:
        """
        Stage 1: Extract IOCs from raw text.
        """
        iocs = extract_iocs_flat(text)
        return [{"type": i["type"], "value": i["value"]} for i in iocs]

    def process_text(self, text: str) -> Dict:
        """
        Full pipeline from text: Extract -> Fetch -> Save.
        """
        print(f"\n{'='*50}")
        print("Processing text input...")
        print(f"{'='*50}")

        items = self.extract_from_text(text)
        if not items:
            print("No IOCs found in text")
            return {"total": 0, "saved": 0, "skipped": 0, "errors": 0}

        print(f"Extracted {len(items)} IOCs from text")
        return self.run_batch(items)

    def save_direct(self, items: List[Dict]) -> Dict:
        stats = {"total": len(items), "saved": 0, "skipped": 0, "errors": 0}

        db = SessionLocal()
        try:
            for item in items:
                fetcher_ioc = FetcherIOC(
                    ioc_value=item["value"],
                    ioc_type=item["type"],
                    risk_score=item.get("risk_score", 0),
                    risk_level=item.get("risk_level", "LOW"),
                    source_name=item.get("source_name", "manual"),
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
                success = self.process_single(db, fetcher_ioc)
                if success:
                    stats["saved"] += 1
                else:
                    stats["skipped"] += 1
        finally:
            db.close()

        return stats

    def _get_or_create_source(self, db, source_name: str) -> Source:
        """Get existing source or create new one."""
        source = db.query(Source).filter(Source.name == source_name).first()
        if not source:
            source = Source(
                name=source_name,
                description=f"Auto-created from {source_name} API",
                api_endpoint="",
            )
            db.add(source)
            db.commit()
            db.refresh(source)
        return source

    def _get_or_create_ioc(self, db, fetcher_ioc: FetcherIOC) -> IOC:
        """Get existing IOC or create new one (deduplication by value + type)."""
        ioc = (
            db.query(IOC)
            .filter(
                IOC.value == fetcher_ioc.ioc_value,
                IOC.type == fetcher_ioc.ioc_type,
            )
            .first()
        )

        if not ioc:
            ioc = IOC(
                value=fetcher_ioc.ioc_value,
                type=fetcher_ioc.ioc_type,
            )
            db.add(ioc)
            db.commit()
            db.refresh(ioc)
        else:
            # Update last_seen
            ioc.last_seen = datetime.now(timezone.utc)
            db.commit()

        return ioc

    def _alert_exists(self, db, ioc_id: int, source_id: int) -> bool:
        """Check if alert already exists for this IOC + source combination."""
        return (
            db.query(Alert)
            .filter(Alert.ioc_id == ioc_id, Alert.source_id == source_id)
            .first()
            is not None
        )

    def process_single(self, db, fetcher_ioc: FetcherIOC) -> bool:
        """Process a single IOC: save to DB if not duplicate."""
        try:
            # 1. Get or create source
            source = self._get_or_create_source(db, fetcher_ioc.source_name)

            # 2. Get or create IOC (deduplication)
            ioc = self._get_or_create_ioc(db, fetcher_ioc)

            # 3. Check if alert already exists
            if self._alert_exists(db, ioc.id, source.id):
                print(
                    f"  ↳ Skipped (duplicate): {fetcher_ioc.ioc_value} from {fetcher_ioc.source_name}"
                )
                return False

            # 4. Create alert
            alert = Alert(
                ioc_id=ioc.id,
                source_id=source.id,
                risk_level=fetcher_ioc.risk_level,
                risk_score=float(fetcher_ioc.risk_score),
                raw_data={
                    "fetched_at": fetcher_ioc.created_at,
                    "source_name": fetcher_ioc.source_name,
                },
            )
            db.add(alert)
            db.commit()

            print(
                f"  ✓ Saved: {fetcher_ioc.ioc_value} [{fetcher_ioc.risk_level}] from {fetcher_ioc.source_name}"
            )
            return True

        except Exception as e:
            db.rollback()
            print(f"  ✗ Error: {str(e)}")
            return False

    def run_batch(self, items: List[Dict], sources: List[str] = None) -> Dict:
        """
        Run full pipeline on a batch of items.
        items: [{"type": "ipv4", "value": "1.2.3.4"}, ...]
        """
        stats = {"total": 0, "saved": 0, "skipped": 0, "errors": 0}

        # Fetch all IOCs
        all_iocs = self.fetcher.fetch_batch(items)
        stats["total"] = len(all_iocs)

        print(f"\n{'='*50}")
        print(f"Fetched {len(all_iocs)} IOCs from APIs")
        print(f"{'='*50}")

        # Process each
        db = SessionLocal()
        try:
            for ioc in all_iocs:
                success = self.process_single(db, ioc)
                if success:
                    stats["saved"] += 1
                else:
                    stats["skipped"] += 1
        except Exception as e:
            db.rollback()
            stats["errors"] += 1
            print(f"Pipeline error: {e}")
        finally:
            db.close()

        print(f"\n{'='*50}")
        print(
            f"Done: {stats['saved']} saved, {stats['skipped']} skipped, {stats['errors']} errors"
        )
        print(f"{'='*50}")

        return stats


def run_demo():
    """Demo: Fetch and store sample IOCs."""
    init_db()

    pipeline = IntelPipeline()

    # 用真实恶意 IP 测试
    test_items = [
        {"type": "ipv4", "value": "185.220.101.182"},  # Tor exit node
        {"type": "ipv4", "value": "192.42.116.191"},  # Known malicious
        {"type": "ipv4", "value": "8.8.8.8"},  # Clean
        {"type": "domain", "value": "example.com"},  # Clean
    ]


# ========== Test ==========
if __name__ == "__main__":
    init_db()
    pipeline = IntelPipeline()

    # 1. 从API获取
    print("\n" + "=" * 60)
    print("TEST 1: API Fetch")
    print("=" * 60)
    test_items = [
        {"type": "ipv4", "value": "185.220.101.182"},
        {"type": "ipv4", "value": "8.8.8.8"},
    ]
    pipeline.run_batch(test_items)

    # 2. 从文本提取
    print("\n" + "=" * 60)
    print("TEST 2: Text Extraction")
    print("=" * 60)
    test_text = """
    Suspicious IPs: 192.168.1.1, 10.0.0.1
    Malicious domain: evil.com
    Hash: d41d8cd98f00b204e9800998ecf8427e
    """
    pipeline.process_text(test_text)

    # 3. 直接保存（不查 API）
    print("\n" + "=" * 60)
    print("TEST 3: Direct Save")
    print("=" * 60)
    manual_items = [
        {
            "value": "manual-test.com",
            "type": "domain",
            "risk_score": 95,
            "risk_level": "HIGH",
            "source_name": "manual",
        }
    ]
    pipeline.save_direct(manual_items)
