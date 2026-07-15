import pandas as pd
import numpy as np
from sqlalchemy import create_engine, text
from typing import Optional, Dict, List
from database import DATABASE_URL


class ThreatAnalyzer:
    """Analyzer for threat intelligence data"""

    def __init__(self, db_url: str = DATABASE_URL):
        """Initialize with database"""
        self.engine = create_engine(db_url)
        self.df: Optional[pd.DataFrame] = None

    def load_data(self) -> "ThreatAnalyzer":
        """Load data from dtabase."""
        query = """
        SELECT
            a.id as alert_id,
            a.risk_level,
            a.risk_score,
            a.created_at,
            a.raw_data,
            i.value as ioc_value,
            i.type as ioc_type,
            i.first_seen,
            i.last_seen,
            s.name as source_name
        FROM alerts a
        JOIN iocs i ON a.ioc_id = i.id
        JOIN sources s ON a.source_id = s.id
        """
        self.df = pd.read_sql(query, self.engine)
        return self

    def clean(self) -> "ThreatAnalyzer":
        """Clean and standardize data"""
        if self.df is None:
            raise ValueError("No data loaded. Call load_data() first.")

        # Remove duplicates
        self.df = self.df.drop_duplicates(subset=["alert_id"])

        # Handle missing values
        self.df["risk_level"] = self.df["risk_level"].str.upper()

        # Convert timestamps
        for col in ["created_at", "first_seen", "last_seen"]:
            self.df[col] = pd.to_datetime(self.df[col])

        # Remove outliers
        self.df = self.df[(self.df["risk_score"] >= 0) & (self.df["risk_score"] <= 100)]

        return self

    def transform(self) -> "ThreatAnalyzer":
        """Transform and engineer features."""
        if self.df is None:
            raise ValueError("No data loaded")

        # Risk level to numeric
        risk_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        self.df["risk_level_num"] = (
            self.df["risk_level"].map(risk_map).fillna(0).astype(int)
        )

        # Time features
        now = pd.Timestamp.now()
        self.df["days_since_first_seen"] = (now - self.df["first_seen"]).dt.days
        self.df["days_active"] = (self.df["last_seen"] - self.df["first_seen"]).dt.days

        # Risk category
        self.df["risk_category"] = pd.cut(
            self.df["risk_score"],
            bins=[0, 25, 50, 75, 100],
            labels=["Minimal", "Low", "Medium", "Critical"],
        )

        # Normalize
        min_score = self.df["risk_score"].min()
        max_score = self.df["risk_score"].max()
        if max_score > min_score:
            self.df["risk_score_norm"] = (self.df["risk_score"] - min_score) / (
                max_score - min_score
            )
        else:
            self.df["risk_score_norm"] = 0.0

        return self

    def get_risk_distribution(self) -> pd.Series:
        """Get risk level distribution."""
        return self.df["risk_level"].value_counts()

    def get_top_iocs(self, n: int = 5) -> pd.Series:
        """Get top N IOCs by alert count."""
        return self.df.groupby("ioc_value").size().sort_values(ascending=False).head(n)

    def get_top_threat_actors(self) -> pd.DataFrame:
        """Get most active threat actors (placeholder)."""
        # Will be implemented when attribution data is available
        return pd.DataFrame()

    def get_trend_data(self) -> pd.DataFrame:
        """Get daily alert trend."""
        return (
            self.df.groupby(self.df["created_at"].dt.date)
            .size()
            .reset_index(name="count")
        )

    def get_summary(self) -> Dict:
        """Get summary statistics."""
        return {
            "total_alerts": len(self.df),
            "avg_risk_score": self.df["risk_score"].mean(),
            "high_risk_pct": (self.df["risk_level"] == "HIGH").mean() * 100,
            "top_ioc": self.get_top_iocs(1).index[0] if len(self.df) > 0 else None,
        }

    def export_to_json(self, filepath: str):
        """Export processed data to JSON"""
        import os

        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        self.df.to_json(filepath, orient="records", indent=2, date_format="iso")
        self.df.to_json(filepath, orient="records", indent=2)

    def export_to_csv(self, filepath: str):
        """Export processed data to CSV."""
        self.df.to_csv(filepath, index=False)


# ========== Test ==========
if __name__ == "__main__":
    print("=" * 50)
    print("Day 31: Analyzer Class Test")
    print("=" * 50)

    # Setup test data
    from database import get_db, init_db
    from crud import create_ioc, create_alert, create_source
    from schemas import IOCCreate, AlertCreate, SourceCreate

    init_db()
    db = next(get_db())

    engine = create_engine(DATABASE_URL)
    with engine.connect() as conn:
        result = conn.execute(text("SELECT COUNT(*) FROM alerts"))
        if result.scalar() == 0:
            print("Inserting test data...")
            source = create_source(
                db,
                SourceCreate(
                    name="virustotal", description="VT", api_endpoint="https://vt.com"
                ),
            )
            ioc1 = create_ioc(db, IOCCreate(value="8.8.8.8", type="ipv4"))
            ioc2 = create_ioc(db, IOCCreate(value="example.com", type="domain"))
            create_alert(
                db,
                AlertCreate(
                    ioc_id=ioc1.id,
                    source_id=source.id,
                    risk_level="LOW",
                    risk_score=15.0,
                ),
            )
            create_alert(
                db,
                AlertCreate(
                    ioc_id=ioc2.id,
                    source_id=source.id,
                    risk_level="MEDIUM",
                    risk_score=55.0,
                ),
            )
            print("Test data inserted.")

    # Use Analyzer class
    analyzer = ThreatAnalyzer()
    analyzer.load_data().clean().transform()

    print(f"\nTotal alerts: {len(analyzer.df)}")

    print("\n--- Risk Distribution ---")
    print(analyzer.get_risk_distribution())

    print("\n--- Summary ---")
    for key, value in analyzer.get_summary().items():
        print(f"{key}: {value}")

    print("\n--- Top IOCs ---")
    print(analyzer.get_top_iocs())

    print("\n--- Trend ---")
    print(analyzer.get_trend_data())

    # Export
    analyzer.export_to_json("output/alerts.json")

    analyzer.export_to_csv("output/alerts.csv")
    print("\n✅ Exported to output/alerts.json and output/alerts.csv")

    print("\n" + "=" * 50)
    print("Day 31 complete!")
    print("=" * 50)
