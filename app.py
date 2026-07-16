import streamlit as st
import pandas as pd
import plotly.express as px
from analyzer import ThreatAnalyzer

st.set_page_config(
    page_title="Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
)

RISK_COLORS = {"HIGH": "#dc2626", "MEDIUM": "#f59e0b", "LOW": "#16a34a"}


@st.cache_resource
def load_data():
    """Load and cache data."""
    analyzer = ThreatAnalyzer()

    analyzer.load_data().clean().transform()
    return analyzer


# Load Data
analyzer = load_data()

# ========== Session State Initiate ==========
if "risk_levels" not in st.session_state:
    st.session_state.risk_levels = ["HIGH", "MEDIUM", "LOW"]
if "ioc_types" not in st.session_state:
    st.session_state.ioc_types = analyzer.df["ioc_type"].unique().tolist()
if "selected_actors" not in st.session_state:
    st.session_state.selected_actors = []
if "date_range" not in st.session_state:
    st.session_state.date_range = (
        analyzer.df["created_at"].min().date(),
        analyzer.df["created_at"].max().date(),
    )
if "table_page" not in st.session_state:
    st.session_state.table_page = 0
if "sort_by" not in st.session_state:
    st.session_state.sort_by = "risk_score"
if "sort_asc" not in st.session_state:
    st.session_state.sort_asc = False


# Sidebar
st.sidebar.title("🛡️ Threat Intel")
st.sidebar.markdown("---")
st.sidebar.subheader("🔍 Filters")

# 1) Risk Level
risk_levels = st.sidebar.multiselect(
    "Risk Level",
    options=["HIGH", "MEDIUM", "LOW"],
    default=st.session_state.risk_levels,
)
st.session_state.risk_levels = risk_levels

# 2) IOC Type
ioc_types = st.sidebar.multiselect(
    "IOC Type",
    options=analyzer.df["ioc_type"].unique().tolist(),
    default=st.session_state.ioc_types,
)
st.session_state.ioc_types = ioc_types

# 3) Threat Actor
actor_list = analyzer.df.get("threat_actor", pd.Series()).dropna().unique().tolist()
if actor_list:
    selected_actors = st.sidebar.multiselect(
        "Threat Actor",
        options=actor_list,
        default=st.session_state.selected_actors,
    )
    st.session_state.selected_actors = selected_actors
else:
    selected_actors = []
    st.sidebar.caption("No actor data available")

# 4) Date Range
st.sidebar.subheader("📅 Date Range")
min_date = analyzer.df["created_at"].min().date()
max_date = analyzer.df["created_at"].max().date()

date_range = st.sidebar.date_input(
    "Select range",
    value=st.session_state.date_range,
    min_value=min_date,
    max_value=max_date,
)
st.session_state.date_range = date_range
st.sidebar.markdown("---")

# Apply Filters
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
        color_discrete_map=RISK_COLORS,
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

# Table sorting + Pagination
st.markdown("---")
st.subheader("Alert Details")

# Sort Control
sort_col1, sort_col2 = st.columns(2)
with sort_col1:
    sort_by = st.selectbox(
        "Sort by",
        ["risk_score", "created_at", "alert_id", "ioc_value"],
        index=["risk_score", "created_at", "alert_id", "ioc_value"].index(
            st.session_state.sort_by
        ),
    )
    st.session_state.sort_by = sort_by
with sort_col2:
    sort_asc = st.checkbox("Ascending", value=st.session_state.sort_asc)
    st.session_state.sort_asc = sort_asc

# App sorting
sorted_df = filtered_df.sort_values(
    st.session_state.sort_by, ascending=st.session_state.sort_asc
)

# Paging
page_size = 20
total_pages = max(1, (len(sorted_df) + page_size - 1) // page_size)

page_col1, page_col2, page_col3 = st.columns([1, 2, 1])
with page_col1:
    if st.button("⬅️ Prev") and st.session_state.table_page > 0:
        st.session_state.table_page -= 1
with page_col2:
    st.session_state.table_page = st.number_input(
        "Page",
        min_value=0,
        max_value=total_pages - 1,
        value=st.session_state.table_page,
        step=1,
    )
    st.caption(f"Page {st.session_state.table_page + 1} of {total_pages}")
with page_col3:
    if st.button("Next ➡️") and st.session_state.table_page < total_pages - 1:
        st.session_state.table_page += 1

# Display the current page
start_idx = st.session_state.table_page * page_size
end_idx = min(start_idx + page_size, len(sorted_df))

st.dataframe(
    filtered_df[
        ["alert_id", "ioc_value", "ioc_type", "risk_level", "risk_score", "source_name"]
    ],
    use_container_width=True,
)

# Footer
st.markdown("---")
st.caption("Threat Intelligence Aggregator")
