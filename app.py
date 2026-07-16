import streamlit as st
import pandas as pd
from database import get_db, init_db
from crud import get_alerts, get_iocs
from analyzer import ThreatAnalyzer

st.set_page_config(
    page_title="Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
)


def load_data():
    """Load and cache data."""
    analyzer = ThreatAnalyzer()

    analyzer.load_data().clean().transform()
    return analyzer


# Sidebar
st.sidebar.title("🛡️ Threat Intel")
st.sidebar.markdown("---")

# Main content
st.title("Threat Intelligence Dashboard")

# Load data
analyzer = load_data()

# Metrics row
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Alerts", len(analyzer.df))

with col2:
    high_risk = len(analyzer.df[analyzer.df["risk_level"] == "HIGH"])
    st.metric("High Risk", high_risk)

with col3:
    avg_score = analyzer.df["risk_score"].mean()
    st.metric("Avg Risk Score", f"{avg_score:.1f}")

with col4:
    unique_iocs = analyzer.df["ioc_value"].nunique()
    st.metric("Unique IOCs", unique_iocs)

st.markdown("---")

# Charts
col_left, col_right = st.columns(2)

with col_left:
    st.subheader("Risk Distribution")
    risk_dist = analyzer.get_risk_distribution()
    st.bar_chart(risk_dist)

with col_right:
    st.subheader("Top IOCs")
    top_iocs = analyzer.get_top_iocs(10)

st.dataframe(top_iocs.reset_index().rename(columns={"index": "IOC", 0: "Count"}))

# Data table
st.markdown("---")
st.subheader("Alert Details")
st.dataframe(
    analyzer.df[
        ["alert_id", "ioc_value", "ioc_type", "risk_level", "risk_score", "source_name"]
    ]
)

# Footer
st.markdown("---")
st.caption("Threat Intelligence Aggregator")
