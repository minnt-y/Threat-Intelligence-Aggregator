from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime, timezone

# SOLite database file
DATABASE_URL = "sqlite:///threat_intel.db"

# Create engine
engine = create_engine(DATABASE_URL, echo=False)

# Base class for models
Base = declarative_base()

# Session factory
SessionLocal = sessionmaker(bind=engine)


class AlertRecord(Base):
    """
    Database model for threat intelligence alerts.
    """

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_value = Column(String, nullable=False)
    ioc_type = Column(String, nullable=False)
    risk_level = Column(String, nullable=False)
    risk_score = Column(Float, default=0.0)
    source = Column(String, default="virustotal")
    attribution = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<Alert {self.ioc_value} ({self.risk_level})>"


def init_db():
    """Create all tables."""
    Base.metadata.create_all(bind=engine)
    print("Database initialized: threat_intel.db")


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

    # Test insert
    db = next(get_db())

    alert = AlertRecord(
        ioc_value="8.8.8.8",
        ioc_type="ipv4",
        risk_level="LOW",
        risk_score=0.0,
        source="virustotal",
    )

    db.add(alert)
    db.commit()

    print(f"Inserted: {alert}")

    # Test query
    results = db.query(AlertRecord).all()
    print(f"Total records: {len(results)}")
    for r in results:
        print(f"  {r.ioc_value} | {r.risk_level} | {r.created_at}")
