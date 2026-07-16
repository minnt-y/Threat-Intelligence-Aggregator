import os
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    DateTime,
    JSON,
    ForeignKey,
    UniqueConstraint,
    event,
    Index,
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from datetime import datetime, timezone
from schemas import IOCResponse, AlertResponse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "threat_intel.db")
DEV_MODE = True

# SOLite database file
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

# Create engine
engine = create_engine(DATABASE_URL, echo=False)


# Enable foreign key constraints for SQLite
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


# Base class for models
Base = declarative_base()

# Session factory
SessionLocal = sessionmaker(bind=engine)


class IOC(Base):
    """ "IOC indicators table for deduplicated storage"""

    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(String, nullable=False)  # ipv4, domain, hash, etc.
    type = Column(String, nullable=False)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationship
    alerts = relationship("Alert", back_populates="ioc")
    attributions = relationship("Attribution", back_populates="ioc")

    # Add Index
    __table_args__ = (
        Index("idx_ioc_value", "value"),
        Index("idx_ioc_type", "type"),
        Index("idx_ioc_last_seen", "last_seen"),
    )


class Source(Base):
    """
    Intelligence source table
    """

    __tablename__ = "sources"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)  # virustotal, otx, manual
    description = Column(String)
    api_endpoint = Column(String)

    # Relationship
    alerts = relationship("Alert", back_populates="source")

    __table_args__ = (Index("idx_source_name", "name"),)


class Attribution(Base):
    """Threat attribution table"""

    __tablename__ = "attributions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    actor_name = Column(String, nullable=False)  # APT28, Lazarus
    confidence = Column(String)  # HIGH, MEDIUM, LOW
    reasons = Column(JSON)  # ["infrastructure match", "TTP match"]
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationship
    ioc = relationship("IOC", back_populates="attributions")

    __table_args__ = (
        Index("idx_attr_actor", "actor_name"),
        Index("idx_attr_ioc", "ioc_id"),
    )


class Alert(Base):
    """Alert record table."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    source_id = Column(Integer, ForeignKey("sources.id"), nullable=False)
    risk_level = Column(String, nullable=False)
    risk_score = Column(Float, default=0.0)
    raw_data = Column(JSON)  # VT raw response
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    ioc = relationship("IOC", back_populates="alerts")
    source = relationship("Source", back_populates="alerts")

    __table_args__ = (
        Index("idx_alert_ioc_source", "ioc_id", "source_id"),
        Index("idx_alert_risk_level", "risk_level"),
        Index("idx_alert_created_at", "created_at"),
    )


def init_db():
    """Create all tables (fallback if Alembic not used)."""
    Base.metadata.create_all(bind=engine)
    print("Database initialized with schema: alerts, iocs, sources, attributions")


def get_db():
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Test
if __name__ == "__main__":
    # Use Alembic to create tables (not Base.metadata.create_all)
    # alembic upgrade head  # Run this in terminal first
    init_db()
    db = next(get_db())

    from crud import (
        create_source,
        create_ioc,
        create_alert,
        get_risk_report,
        alert_exists,
        delete_old_iocs,
    )
    from schemas import SourceCreate, IOCCreate, AlertCreate
    from maintenance import get_db_stats, cleanup_database, delete_old_iocs
    from datetime import datetime, timezone, timedelta

    print("=" * 50)
    print("Day 25: CRUD Operations Test")
    print("=" * 50)

    # Test 1: Create Source
    source = create_source(
        db,
        SourceCreate(
            name="virustotal",
            description="VirusTotal API",
            api_endpoint="https://www.virustotal.com/api/v3",
        ),
    )
    print(f"\n✅ Source created: {source.name}")

    # Test 2: Create IOC
    ioc = create_ioc(db, IOCCreate(value="8.8.8.8", type="ipv4"))
    print(f"✅ IOC created: {ioc.value} ({ioc.type})")

    # Test 3: Create Alert
    alert = create_alert(
        db,
        AlertCreate(
            ioc_id=ioc.id,
            source_id=source.id,
            risk_level="LOW",
            risk_score=5.0,
            raw_data={"malicious": 0, "harmless": 55},
        ),
    )
    if alert:
        print(f"✅ Alert created: {alert.risk_level} risk")
    else:
        print("⚠️ Alert skipped (duplicate)")

    # Test 4: Deduplication check
    exists = alert_exists(db, ioc.id, source.id)
    print(f"✅ Alert exists check: {exists}")

    # Test 5: Risk Report
    report = get_risk_report(db)
    print(f"\n--- Risk Report ---")
    print(f"Total alerts: {report.total_alerts}")
    print(f"High: {report.high_risk_count}")
    print(f"Medium: {report.medium_risk_count}")
    print(f"Low: {report.low_risk_count}")

    print("\n" + "=" * 50)
    print("All CRUD tests passed!")
    print("=" * 50)

    # Test 6: Deduplication
    print("\n--- Test 6: Deduplication ---")
    ioc2 = create_ioc(db, IOCCreate(value="8.8.8.8", type="ipv4"))  # Same value
    print(f"Duplicate IOC returns same ID: {ioc.id == ioc2.id}")

    alert2 = create_alert(
        db,
        AlertCreate(
            ioc_id=ioc.id,
            source_id=source.id,
            risk_level="HIGH",
            risk_score=80.0,
            raw_data={"malicious": 10},
        ),
    )
    print(f"Duplicate alert skipped: {alert2 is None}")

    # Day 27 test
    print("\n--- Day 27: Maintenance ---")

    # Setup: Create test data
    source = create_source(db, SourceCreate(name="test", description="test"))

    # Old IOC (60 days ago)
    old_ioc = create_ioc(db, IOCCreate(value="1.1.1.1", type="ipv4"))
    old_ioc.last_seen = datetime.now(timezone.utc) - timedelta(days=60)
    db.commit()

    # Recent IOC
    new_ioc = create_ioc(db, IOCCreate(value="8.8.8.8", type="ipv4"))

    # Alerts
    create_alert(
        db,
        AlertCreate(
            ioc_id=old_ioc.id, source_id=source.id, risk_level="LOW", risk_score=1.0
        ),
    )
    create_alert(
        db,
        AlertCreate(
            ioc_id=new_ioc.id, source_id=source.id, risk_level="HIGH", risk_score=80.0
        ),
    )

    # Test 1: Stats before cleanup
    print("\n--- Before Cleanup ---")
    stats = get_db_stats(db)
    for key, value in stats.items():
        print(f"{key}: {value}")

    # Test 2: Cleanup old IOCs (30 days)
    print("\n--- Cleanup ---")
    deleted = delete_old_iocs(db, days=30)
    print(f"IOCs deleted: {deleted}")

    # Test 3: Stats after cleanup
    print("\n--- After Cleanup ---")
    stats = get_db_stats(db)
    for key, value in stats.items():
        print(f"{key}: {value}")

    print("\n" + "=" * 50)
    print("Day 27 tests passed!")
    print("=" * 50)
