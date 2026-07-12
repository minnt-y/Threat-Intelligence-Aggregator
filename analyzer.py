import pandas as pd
import numpy as np
from sqlalchemy import create_engine, text
from database import DATABASE_URL


def get_engine():
    """Create SQLAlchemy engine for Pandas"""
    return create_engine(DATABASE_URL)


def load_joined_data() -> pd.DataFrame:
    """Load alerts with IOC and source details"""
    engine = get_engine()
    query = """
    SELECT
        a.id as alert_id,
        a.risk_level,
        a.risk_score,
        a.created_at,
        i.value as ioc_value,
        i.type as ioc_type,
        i.first_seen,
        i.last_seen,
        s.name as source_name
    FROM alerts a
    JOIN iocs i ON a.ioc_id = i.id
    JOIN sources s ON a.source_id = s.id
    """
    df = pd.read_sql(query, engine)
    return df


# =============== Data Cleaning =================
def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """Clean and standardize data."""
    df_clean = df.copy()

    # Remove duplicates
    df_clean = df_clean.drop_duplicates(subset=["alert_id"])

    # Handle missing values
    df_clean["risk_score"] = df_clean["risk_score"].fillna(0)
    df_clean["description"] = df_clean.get("description", pd.Series()).fillna("Unknown")

    # Standardize risk_level to uppercase
    df_clean["risk_level"] = df_clean["risk_level"].str.upper()

    # Convert timestamps
    df_clean["created_at"] = pd.to_datetime(df_clean["created_at"])
    df_clean["first_seen"] = pd.to_datetime(df_clean["first_seen"])
    df_clean["last_seen"] = pd.to_datetime(df_clean["last_seen"])

    # Remove outliers (risk_score > 100 or < 0)
    df_clean = df_clean[(df_clean["risk_score"] >= 0) & (df_clean["risk_score"] <= 100)]

    return df_clean


# =============== Data Transformation ===================
def transform_risk_level(df: pd.DataFrame) -> pd.DataFrame:
    """Convert risk_level to numeric score"""
    risk_mapping = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    df["risk_level_num"] = df["risk_level"].map(risk_mapping).fillna(0).astype(int)
    return df


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract new features from data"""
    # Days since first seen
    now = pd.Timestamp.now()
    df["days_since_first_seen"] = (now - df["first_seen"]).dt.days

    # Days between first and last seen
    df["days_active"] = (df["last_seen"] - df["first_seen"]).dt.days

    # Risk category (binned)
    df["risk_category"] = pd.cut(
        df["risk_score"],
        bins=[0, 25, 50, 75, 100],
        labels=["Minimal", "Low", "Medium", "Critical"],
    )

    return df


def normalize_scores(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize risk_score to 0-1 range."""
    min_score = df["risk_score"].min()
    max_score = df["risk_score"].max()

    if max_score > min_score:
        df["risk_score_norm"] = (df["risk_score"] - min_score) / (max_score - min_score)
    else:
        df["risk_score_norm"] = 0.0

    return df


# ========== Analysis Functions ==========
def get_risk_distribution(df: pd.DataFrame) -> pd.Series:
    """Count alerts by risk level"""
    return df["risk_level"].value_counts()


def get_average_risk_score(df: pd.DataFrame) -> float:
    """Calculate average risk score"""
    return df["risk_score"].mean()


def get_top_iocs(df: pd.DataFrame, n: int = 5) -> pd.Series:
    """Get top N IOCs by alert count"""
    return df.groupby("ioc_value").size().sort_values(ascending=False).head(n)


def get_summary_stats(df: pd.DataFrame) -> pd.DataFrame:
    """Get summary statistics."""
    return df[["risk_score", "risk_level_num", "days_active"]].describe()


if __name__ == "__main__":
    print("=" * 50)
    print("Day 30: Data Transformation")
    print("=" * 50)

    # Setup data
    from database import get_db, init_db
    from crud import create_ioc, create_alert, create_source
    from schemas import IOCCreate, AlertCreate, SourceCreate

    init_db()
    db = next(get_db())

    # Insert test data
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(text("SELECT COUNT(*) FROM alerts"))
        count = result.scalar()

        if count == 0:
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
                    ioc_id=ioc1.id,
                    source_id=source.id,
                    risk_level="HIGH",
                    risk_score=85.0,
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
            print("Test data inserted")

    # Load and transform
    print("\n--- Loading Data ---")
    df = load_joined_data()
    print(f"Raw records: {len(df)}")

    print("\n--- Cleaning Data ---")
    df = clean_data(df)
    print(f"After cleaning: {len(df)}")
    print(f"Null values: {df.isnull().sum().sum()}")

    print("\n--- Transforming Data ---")
    df = transform_risk_level(df)
    df = extract_features(df)
    df = normalize_scores(df)

    print("\n--- New Columns ---")
    new_cols = [
        "risk_level_num",
        "days_since_first_seen",
        "days_active",
        "risk_category",
        "risk_score_norm",
    ]
    print(df[new_cols].head())

    print("\n--- Risk Distribution ---")
    print(get_risk_distribution(df))

    print("\n--- Summary Statistics ---")
    print(get_summary_stats(df))

    print("\n--- Top IOCs ---")
    print(get_top_iocs(df))

    print("\n" + "=" * 50)
    print("Day 30 complete")
    print("=" * 50)
