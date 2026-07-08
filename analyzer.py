import pandas as pd
from sqlalchemy import create_engine
from database import DATABASE_URL


def get_engine():
    """Create SQLAlchemy engine for Pandas"""
    return create_engine(DATABASE_URL)


def load_alerts_to_df() -> pd.DataFrame:
    """Load alerts table into Pandas DataFrame"""
    engine = get_engine()
    df = pd.read_sql("SELECT * FROM alerts", engine)
    return df


def load_iocs_to_df() -> pd.DataFrame:
    """Load IOCs table into Pandas DataFrame"""
    engine = get_engine()
    df = pd.read_sql("SELECT * FROM iocs", engine)
    return df


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
        s.name as source_name
    FROM alerts a
    JOIN iocs i ON a.ioc_id = i.id
    JOIN sources s ON a.source_id = s.id
    """
    df = pd.read_sql(query, engine)
    return df


def get_risk_distribution(df: pd.DataFrame) -> pd.Series:
    """Count alerts by risk level"""
    return df["risk_level"].value_counts()


def get_average_risk_score(df: pd.DataFrame) -> float:
    """Calculate average risk score"""
    return df["risk_score"].mean()


def get_top_iocs(df: pd.DataFrame, n: int = 5) -> pd.DataFrame:
    """Get top N IOCs by alert count"""
    return df.groupby("ioc_value").size().sort_values(ascending=False).head(n)


if __name__ == "__main__":
    print("=" * 50)
    print("Day 29: Pandas Data Analysis")
    print("=" * 50)

    # Insert test data if empty
    from database import get_db, init_db
    from crud import create_ioc, create_alert, create_source
    from schemas import IOCCreate, AlertCreate, SourceCreate

    init_db()
    db = next(get_db())

    # Check if data exists
    from sqlalchemy import text

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
            ioc = create_ioc(db, IOCCreate(value="8.8.8.8", type="ipv4"))
            create_alert(
                db,
                AlertCreate(
                    ioc_id=ioc.id, source_id=source.id, risk_level="LOW", risk_score=5.0
                ),
            )
            create_alert(
                db,
                AlertCreate(
                    ioc_id=ioc.id,
                    source_id=source.id,
                    risk_level="HIGH",
                    risk_score=80.0,
                ),
            )
            print("Test data inserted")

    # Load data
    df = load_joined_data()
    print(f"\nTotal records: {len(df)}")

    if len(df) == 0:
        print("No data found")
        exit()

    print(f"\nColumns: {list(df.columns)}")

    # Show sample
    print("\n--- Sample Data ---")
    print(df.head())

    # Risk distribution
    print("\n--- Risk Distribution ---")
    print(get_risk_distribution(df))

    # Average risk
    avg = get_average_risk_score(df)
    print(
        f"\n--- Average Risk Score: {get_average_risk_score(df):.2f}"
        if not pd.isna(avg)
        else "\n--- Average Risk Score: N/A"
    )

    # Top IOCs
    print("\n--- Top IOCs ---")
    print(get_top_iocs(df))

    print("\n" + "=" * 50)
    print("Day 29: Pandas Data Analysis Completed")
