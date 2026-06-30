from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from database import IOC, Source, Alert, Attribution
from schemas import (
    IOCCreate,
    IOCResponse,
    SourceCreate,
    AlertCreate,
    AlertResponse,
    AttributionCreate,
    AttributionResponse,
    RiskReport,
)


# ========== IOC CRUD ===========
def create_ioc(db: Session, ioc: IOCCreate) -> IOC:
    """Create a new IOC or return existing one"""
    # Check for duplicates
    existing = db.query(IOC).filter(IOC.value == ioc.value).first()
    if existing:
        existing.last_seen = datetime.now(timezone.utc)
        db.commit()
        return existing

    db_ioc = IOC(value=ioc.value, type=ioc.type.value)
    db.add(db_ioc)
    db.commit()
    db.refresh(db_ioc)
    return db_ioc


def get_ioc_by_value(db: Session, value: str) -> Optional[IOC]:
    """Get IOC by value"""
    return db.query(IOC).filter(IOC.value == value).first()


def get_iocs(db: Session, skip: int = 0, limit: int = 100) -> List[IOC]:
    """Get IOCs with pagination"""
    return db.query(IOC).offset(skip).limit(limit).all()


# ========== Source CRUD ==========
def create_source(db: Session, source: SourceCreate) -> Optional[Source]:
    """Create a new source or return existing one"""
    existing = get_source_by_name(db, source.name)
    if existing:
        return existing

    db_source = Source(
        name=source.name,
        description=source.description,
        api_endpoint=source.api_endpoint,
    )
    db.add(db_source)
    db.commit()
    db.refresh(db_source)
    return db_source


def get_source_by_name(db: Session, name: str) -> Optional[Source]:
    """Get source by name"""
    return db.query(Source).filter(Source.name == name).first()


# ========== Alert CRUD ==========
def create_alert(db: Session, alert: AlertCreate) -> Optional[Alert]:
    """Cteate a new alert or return None if duplicate"""
    if alert_exists(db, alert.ioc_id, alert.source_id):
        return None  # skip duplicate

    db_alert = Alert(
        ioc_id=alert.ioc_id,
        source_id=alert.source_id,
        risk_level=alert.risk_level.value,
        risk_score=alert.risk_score,
        raw_data=alert.raw_data,
    )
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert


def get_alerts(db: Session, skip: int = 0, limit: int = 100) -> List[Alert]:
    """Get alerts with pagination"""
    return (
        db.query(Alert).order_by(desc(Alert.created_at)).offset(skip).limit(limit).all()
    )


def get_alerts_by_risk(db: Session, risk_level: str) -> List[Alert]:
    """Get alerts filtered by risk level."""
    return db.query(Alert).filter(Alert.risk_level == risk_level).all()


# ========== Attribution CRUD ==========
def create_attribution(
    db: Session, attribution: AttributionCreate
) -> Optional[Attribution]:
    """Create a new attribution or skip if duplicate."""
    existing = (
        db.query(Attribution)
        .filter(
            Attribution.ioc_id == attribution.ioc_id,
            Attribution.actor_name == attribution.actor_name,
        )
        .first()
    )
    if existing:
        return existing

    db_attr = Attribution(
        ioc_id=attribution.ioc_id,
        actor_name=attribution.actor_name,
        confidence=attribution.confidence.value if attribution.confidence else "LOW",
        reasons=attribution.reasons,
    )
    db.add(db_attr)
    db.commit()
    db.refresh(db_attr)
    return db_attr


# ========== Risk Report ==========
def get_risk_report(db: Session) -> RiskReport:
    """Generate risk statistics report."""
    total = db.query(Alert).count()
    high = db.query(Alert).filter(Alert.risk_level == "HIGH").count()
    medium = db.query(Alert).filter(Alert.risk_level == "MEDIUM").count()
    low = db.query(Alert).filter(Alert.risk_level == "LOW").count()

    # Top threat actors
    top_actors = (
        db.query(Attribution.actor_name, func.count(Attribution.id).label("count"))
        .group_by(Attribution.actor_name)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )

    # Recent IOCs (last 7 days)
    recent = (
        db.query(IOC)
        .filter(IOC.last_seen >= datetime.now(timezone.utc) - timedelta(days=7))
        .order_by(desc(IOC.last_seen))
        .limit(10)
        .all()
    )

    return RiskReport(
        total_alerts=total,
        high_risk_count=high,
        medium_risk_count=medium,
        low_risk_count=low,
        top_threat_actors=[
            {"actor": a.actor_name, "count": a.count} for a in top_actors
        ],
        recent_iocs=[IOCResponse.model_validate(i) for i in recent],
    )


# ========== Deduplication (Day 26) ==========
def alert_exists(db: Session, ioc_id: int, source_id: int) -> bool:
    """Check if alert already exists for this IOC from this source."""
    return (
        db.query(Alert)
        .filter(
            Alert.ioc_id == ioc_id,
            Alert.source_id == source_id,
        )
        .first()
        is not None
    )


# ========== Maintenance (Day 27) ==========
def delete_old_iocs(db: Session, days: int = 30) -> int:
    """Delete IOCs older than N days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    result = db.query(IOC).filter(IOC.last_seen < cutoff).delete()
    db.commit()
    return result
