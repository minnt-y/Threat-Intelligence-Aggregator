import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from database import get_db, init_db
from crud import get_ioc_by_value, get_alerts_by_risk, alert_exists


def benchmark(func, *args, iterations=1000):
    """Run function N times and measure average time."""
    start = time.perf_counter()
    for _ in range(iterations):
        result = func(*args)
    end = time.perf_counter()
    avg_ms = (end - start) / iterations * 1000
    return avg_ms


if __name__ == "__main__":
    print("=" * 50)
    print("Day 35: Query Performance Test")
    print("=" * 50)

    init_db()
    db = next(get_db())

    # Insert test data: 100 IOCs + 100 Alerts
    from crud import create_ioc, create_source, create_alert
    from schemas import IOCCreate, SourceCreate, AlertCreate

    source = create_source(db, SourceCreate(name="vt", description="VT"))
    print("\nInserting 100 test IOCs and alerts...")
    for i in range(100):
        ioc = create_ioc(db, IOCCreate(value=f"10.0.0.{i}", type="ipv4"))
        create_alert(
            db,
            AlertCreate(
                ioc_id=ioc.id,
                source_id=source.id,
                risk_level="HIGH" if i % 2 == 0 else "LOW",
                risk_score=float(i),
            ),
        )
    print("Done.")

    # Benchmark
    print("\n--- Query Performance ---")

    t1 = benchmark(get_ioc_by_value, db, "10.0.0.50")
    print(f"get_ioc_by_value: {t1:.3f} ms")

    t2 = benchmark(get_alerts_by_risk, db, "HIGH")
    print(f"get_alerts_by_risk: {t2:.3f} ms")

    t3 = benchmark(alert_exists, db, 50, 1)
    print(f"alert_exists: {t3:.3f} ms")

    print("\n" + "=" * 50)
    print("Day 35 complete")
    print("=" * 50)
