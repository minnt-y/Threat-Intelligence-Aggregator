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

# Base class for models
Base = declarative_base()

# Session factory
SessionLocal = sessionmaker(bind=engine)


class IOC(Base):
    """ "IOC indicators table for deduplicated storage"""

    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(String, nullable=False)  # ipv4, domain, hash, etc
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

    def __repr__(self):
        return f"<IOC {self.value} ({self.type})>"


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

    def __repr__(self):
        return f"<Source {self.name}>"


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

    def __repr__(self):
        return f"<Attribution {self.actor_name}>"


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

    def __repr__(self):
        return f"<Alert {self.ioc.value} ({self.risk_level})>"


def init_db():
    if DEV_MODE and os.path.exists(DATABASE_PATH):
        os.remove(DATABASE_PATH)
        print("Removed old database")

    """Create all tables."""
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
    print(f"✅ Alert created: {alert.risk_level} risk")

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
