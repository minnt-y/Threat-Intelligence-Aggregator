import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from database import get_db, init_db
from analyzer import ThreatAnalyzer

st.set_page_config(
    page_title="Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_resource
def load_data():
    """Load and cache data."""
    analyzer = ThreatAnalyzer()

    analyzer.load_data().clean().transform()
    return analyzer


# Load Data
analyzer = load_data()

# Sidebar Filtration
st.sidebar.title("🛡️ Threat Intel")
st.sidebar.markdown("---")

st.sidebar.subheader("🔍 Filters")

# 1) Risk Level
risk_levels = st.sidebar.multiselect(
    "Risk Level",
    options=["HIGH", "MEDIUM", "LOW"],
    default=["HIGH", "MEDIUM", "LOW"],
)
# 2) IOC Type
ioc_types = st.sidebar.multiselect(
    "IOC Type",
    options=analyzer.df["ioc_type"].unique().tolist(),
    default=analyzer.df["ioc_type"].unique().tolist(),
)

# 3) Threat Actor
actor_list = analyzer.df.get("threat_actor", pd.Series()).dropna().unique().tolist()
if actor_list:
    selected_actors = st.sidebar.multiselect(
        "Threat Actor",
        options=actor_list,
        default=[],
    )
else:
    selected_actors = []
    st.sidebar.caption("No actor data available")

# 4) Date Range
st.sidebar.subheader("📅 Date Range")
min_date = analyzer.df["created_at"].min().date()
max_date = analyzer.df["created_at"].max().date()

date_range = st.sidebar.date_input(
    "Select range",
    value=(min_date, max_date),
    min_value=min_date,
    max_value=max_date,
)

st.sidebar.markdown("---")

# App Filtration
filtered_df = analyzer.df.copy()
# 1) Risk Level filtration
if risk_levels:
    filtered_df = filtered_df[filtered_df["risk_level"].isin(risk_levels)]
# 2) IOC Type filtration
if ioc_types:
    filtered_df = filtered_df[filtered_df["ioc_type"].isin(ioc_types)]
# 3) Threat Actor filtration
if selected_actors:
    filtered_df = filtered_df[filtered_df["threat_actor"].isin(selected_actors)]
# 4) Date Range Filtration
if len(date_range) == 2:
    start_date, end_date = date_range
    filtered_df = filtered_df[
        (filtered_df["created_at"].dt.date >= start_date)
        & (filtered_df["created_at"].dt.date <= end_date)
    ]

# Main content
st.title("Threat Intelligence Dashboard")

# Metrics
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Alerts", len(filtered_df))

with col2:
    high_risk = len(filtered_df[filtered_df["risk_level"] == "HIGH"])
    st.metric("High Risk", high_risk)

with col3:
    avg_score = filtered_df["risk_score"].mean() if len(filtered_df) > 0 else 0
    st.metric("Avg Risk Score", f"{avg_score:.1f}")

with col4:
    unique_iocs = filtered_df["ioc_value"].nunique()
    st.metric("Unique IOCs", unique_iocs)

st.markdown("---")

# Charts with Plotly
col_left, col_right = st.columns(2)

with col_left:
    st.subheader("Risk Distribution")
    risk_dist = filtered_df["risk_level"].value_counts().reset_index()
    risk_dist.columns = ["Risk Level", "Count"]

    fig = px.pie(
        risk_dist,
        values="Count",
        names="Risk Level",
        color="Risk Level",
        color_discrete_map={"HIGH": "#ff4444", "MEDIUM": "#ffaa00", "LOW": "#00aa00"},
        hole=0.4,
    )

    fig.update_traces(textposition="inside", textinfo="percent+label")
    st.plotly_chart(fig, use_container_width=True)

with col_right:
    st.subheader("Risk Score Trend")

    trend_df = filtered_df.copy()
    trend_df["created_at"] = pd.to_datetime(trend_df["created_at"])
    trend = (
        trend_df.groupby(trend_df["created_at"].dt.date)
        .size()
        .reset_index(name="count")
    )
    trend.columns = ["created_at", "count"]
    trend["created_at"] = pd.to_datetime(trend["created_at"])

    fig = px.line(
        trend,
        x="created_at",
        y="count",
        markers=True,
        line_shape="spline",
    )
    fig.update_layout(
        xaxis_title="Date",
        yaxis_title="Alert Count",
        showlegend=False,
    )
    fig.update_xaxes(
        tickformat="%Y-%m-%d",
        dtick="D1",
        tickangle=-45,
    )
    st.plotly_chart(fig, use_container_width=True)

# Second row
col_left2, col_right2 = st.columns(2)

with col_left2:
    st.subheader("Top Threat Actors")
    if (
        "threat_actor" in filtered_df.columns
        and filtered_df["threat_actor"].notna().any()
    ):
        actors = filtered_df["threat_actor"].value_counts().head(10).reset_index()
        actors.columns = ["actor_name", "ioc_count"]
        fig = px.bar(
            actors,
            x="ioc_count",
            y="actor_name",
            orientation="h",
        )

        fig.update_layout(yaxis=dict(autorange="reversed"))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No attribution data abailable")

with col_right2:
    st.subheader("IOC Type Distribution")
    type_dist = filtered_df["ioc_type"].value_counts().reset_index()
    type_dist.columns = ["Type", "Count"]

    fig = px.bar(
        type_dist,
        x="Type",
        y="Count",
        color="Type",
    )
    st.plotly_chart(fig, use_container_width=True)

# Data Table
st.markdown("---")
st.subheader("Alert Details")
st.dataframe(
    filtered_df[
        ["alert_id", "ioc_value", "ioc_type", "risk_level", "risk_score", "source_name"]
    ],
    use_container_width=True,
)

# Footer
st.markdown("---")
st.caption("Threat Intelligence Aggregator")
