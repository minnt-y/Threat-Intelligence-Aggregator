from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional

from database import IOC, Alert, Attribution, Source


def delete_old_iocs(db: Session, days: int = 30) -> int:
    """Delete IOCs not seen in the last N days"""
    from sqlalchemy import func, text

    # SQLite: use datetime function for comparison
    result = (
        db.query(IOC)
        .filter(IOC.last_seen < func.datetime("now", f"-{days} days"))
        .delete(synchronize_session=False)
    )
    db.commit()
    return result


def delete_old_alerts(db: Session, days: int = 90) -> int:
    """Delete alerts older than N days"""
    result = (
        db.query(Alert)
        .filter(Alert.created_at < func.datetime("now", f"-{days} days"))
        .delete(synchronize_session=False)
    )
    db.commit()
    return result


def delete_orphaned_attributions(db: Session) -> int:
    """Delete attribution whose IOC no longer exists"""
    from sqlalchemy import exists

    result = (
        db.query(Attribution)
        .filter(~exists().where(Attribution.ioc_id == IOC.id))
        .delete(synchronize_session=False)
    )
    db.commit()
    return result


def get_db_stats(db: Session) -> Dict[str, int]:
    """Get database record counts"""
    return {
        "total_iocs": db.query(IOC).count(),
        "total_alerts": db.query(Alert).count(),
        "total_sources": db.query(Source).count(),
        "old_iocs_30d": db.query(IOC)
        .filter(IOC.last_seen < func.datetime("now", "-30 days"))
        .count(),
        "old_alerts_90d": db.query(Alert)
        .filter(Alert.created_at < func.datetime("now", "-90 days"))
        .count(),
    }


def cleanup_database(
    db: Session, ioc_days: int = 30, alert_days: int = 90
) -> Dict[str, int]:
    """Run full cleanup and return stats"""
    stats = {
        "iocs_deleted": delete_old_iocs(db, ioc_days),
        "alerts_deleted": delete_old_alerts(db, alert_days),
        # "orphans_deleted": delete_orphaned_attributions(db),
    }
    return stats
