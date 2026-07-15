import os
import time
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from database import get_db, init_db
from crud import create_ioc, create_alert, create_source
from schemas import IOCCreate, AlertCreate, SourceCreate
from analyzer import ThreatAnalyzer


def run_pipeline():
    """Run the full threat intelligence pipeline."""
    print(f"\n{'='*50}")
    print(f"Pipeline started at {datetime.now().isoformat()}")
    print(f"{'='*50}")

    # Step 1: Collect data (simulated)
    print("\n[1/4] Collecting threate intelligence...")
    db = next(get_db())

    source = create_source(
        db,
        SourceCreate(
            name="virustotal",
            description="VirusTotal API",
            api_endpoint="https://www.virustotal.com/api/v3",
        ),
    )

    # Simulate new IOCs
    timestamp = datetime.now().strftime("%H%M%S")
    new_iocs = [
        IOCCreate(value=f"192.168.1.{timestamp[-2:]}", type="ipv4"),
        IOCCreate(value=f"malware{timestamp}.com", type="domain"),
    ]

    for ioc_data in new_iocs:
        ioc = create_ioc(db, ioc_data)
        create_alert(
            db,
            AlertCreate(
                ioc_id=ioc.id,
                source_id=source.id,
                risk_level="HIGH",
                risk_score=85.0,
                raw_data={"malicious": 15, "harmless": 2},
            ),
        )

    print(f"Collected {len(new_iocs)} new IOCs")

    # Step 2: Analyze
    print("\n[2/4] Analyzing data...")
    analyzer = ThreatAnalyzer()

    analyzer.load_data().clean().transform()

    summary = analyzer.get_summary()
    print(f"Total alerts: {summary['total_alerts']}")
    print(f"Average risk: {summary['avg_risk_score']:.2f}")

    # Step 3: Generate report
    print("\n[3/4] Generating report...")
    report = analyzer.generate_report()

    # Step 4: Export
    print("\n[4/4] Exporting...")
    timestamp_dir = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"output/reports/{timestamp_dir}"
    os.makedirs(output_dir, exist_ok=True)

    analyzer.export_to_json(f"{output_dir}/report.json")
    analyzer.export_to_csv(f"{output_dir}/report.csv")

    print(f"\n✅ Pipeline complete. Report saved to {output_dir}")
    print(f"{'='*50}\n")


def start_scheduler():
    """Start the background scheduler."""
    scheduler = BackgroundScheduler()

    # Run every 6 hours (change to seconds=10 for testing)
    scheduler.add_job(
        run_pipeline,
        trigger=IntervalTrigger(seconds=10),
        id="threat_pipeline",
        name="Threat Intelligence Pipeline",
        replace_existing=True,
    )

    scheduler.start()
    print("Scheduler started. Running every 10 seconds (test mode).")
    print("Press Ctrl+C to exit.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down scheduler...")
        scheduler.shutdown()
        print("Scheduler stopped.")


if __name__ == "__main__":
    init_db()
    start_scheduler()
