import os

DEV_MODE = True


def init_db():
    if DEV_MODE and os.path.exists("threat_intel.db"):
        os.remove("threat_intel.db")
        print("Removed old database")

    Base.metadata.create_all(bind=engine)
    print("Database initialized with schema: alerts, iocs, sources, attributions")


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

# SOLite database file
DATABASE_URL = "sqlite:///threat_intel.db"

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
    init_db()

    db = next(get_db())

    # Insert test source
    vt = Source(
        name="virustotal",
        description="VirusTotal API",
        api_endpoint="https://www.virustotal.com/api/v3",
    )
    db.add(vt)
    db.commit()

    # Insert test IOC
    ioc = IOC(value="8.8.8.8", type="ipv4")
    db.add(ioc)
    db.commit()

    # Insert test alert
    alert = Alert(
        ioc_id=ioc.id,
        source_id=vt.id,
        risk_level="LOW",
        risk_score=0.0,
        raw_data={"malicious": 0, "harmless": 55},
    )
    db.add(alert)
    db.commit()

    # Query with join
    result = db.query(Alert).join(IOC).join(Source).first()
    print(
        f"Alert: {result.ioc.value} | Source: {result.source.name} | Risk: {result.risk_level}"
    )
