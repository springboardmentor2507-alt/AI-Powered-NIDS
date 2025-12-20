import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
import numpy as np

# Page Configuration

st.set_page_config(
    page_title="SentinelNet AI-powered – Intrusion Detection",
    layout="wide"
)

st.title("\U0001F6E1\uFE0F Network Intrusion Detection System Dashboard")
st.caption("Real-Time Threat Monitoring | Compact SOC Style")

# Simulate Alert Data (Fixed Counts)

total_alerts = 15999
high_count = 15799
medium_count = 100
normal_count = 100

# Base timestamp
base_time = pd.Timestamp.now() - pd.Timedelta(hours=6)

# Timestamps
timestamps_high = pd.date_range(base_time, periods=high_count, freq="10S")
timestamps_medium = pd.date_range(base_time, periods=medium_count, freq="5T")
timestamps_normal = pd.date_range(base_time, periods=normal_count, freq="5T")

# Attack types to match filter
alerts_df = pd.DataFrame({
    "timestamp": np.concatenate([timestamps_high, timestamps_medium, timestamps_normal]),
    "attack_type": ["dos"]*high_count + ["other"]*medium_count + ["normal"]*normal_count
})

# Severity Classification

HIGH_SEVERITY = ["dos", "ddos", "u2r", "r2l", "probe", "backdoor", "worm"]

def classify_severity(attack):
    attack = str(attack).lower().strip()
    if attack in HIGH_SEVERITY:
        return "HIGH"
    elif attack == "normal":
        return "NORMAL"
    else:
        return "MEDIUM"

alerts_df["severity"] = alerts_df["attack_type"].apply(classify_severity)
alerts_df["human_readable"] = alerts_df["attack_type"].apply(lambda x: str(x).replace("_", " ").title())


# Real-Time Simulation

if "time_shift_applied" not in st.session_state:
    time_shift = pd.Timestamp.now() - alerts_df["timestamp"].max()
    alerts_df["timestamp"] = alerts_df["timestamp"] + time_shift
    st.session_state.time_shift_applied = True

# Metrics
st.subheader("\U0001F4CA Threat Overview")
m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Alerts", len(alerts_df))
m2.metric("High Severity", (alerts_df["severity"] == "HIGH").sum())
m3.metric("Medium Severity", (alerts_df["severity"] == "MEDIUM").sum())
m4.metric("Normal Traffic", (alerts_df["severity"] == "NORMAL").sum())

# Filters

st.subheader("\U0001F50D Investigation Filters")

attack_options = ["All", "dos", "normal", "other", "u2r", "probe"]
attack_filter = st.selectbox(
    "Filter by Attack Type",
    attack_options
)

severity_filter = st.multiselect(
    "Filter by Severity",
    ["HIGH", "MEDIUM", "NORMAL"],
    default=["HIGH", "MEDIUM", "NORMAL"]
)

df = alerts_df.copy()
if attack_filter != "All":
    df = df[df["attack_type"] == attack_filter]
df = df[df["severity"].isin(severity_filter)]

# Threat Visuals

st.subheader("\U0001F4C8 THREAT VISUALS")
v1, v2, v3 = st.columns(3)

# Attack Distribution
with v1:
    st.caption("Attack Distribution")
    attack_counts = df["human_readable"].value_counts()
    if attack_counts.empty:
        st.info("No data")
    else:
        fig, ax = plt.subplots(figsize=(4, 3))
        ax.bar(attack_counts.index, attack_counts.values)
        ax.tick_params(axis="x", rotation=45)
        st.pyplot(fig)

# Severity Trend (Stacked Bar)
with v2:
    st.caption("Severity Trend Over Time (Manual Scale)")

    y_max = st.slider(
        "Adjust Y-axis Scale",
        min_value=1,
        max_value=500,  # limited to 500
        value=50,
        step=1,
        key="severity_y_scale"
    )

    ref_time = df["timestamp"].max()
    before_hours = st.slider(
        "Hours BEFORE",
        min_value=0,
        max_value=12,
        value=6,
        step=1,
        key="severity_before_hours"
    )
    start_time = ref_time - pd.Timedelta(hours=before_hours)
    end_time = ref_time

    trend = df.groupby([pd.Grouper(key="timestamp", freq="5T"), "severity"]).size().unstack(fill_value=0)
    for sev in ["HIGH", "MEDIUM", "NORMAL"]:
        if sev not in trend.columns:
            trend[sev] = 0

    trend = trend.sort_index().cumsum().reset_index()
    trend = trend[(trend["timestamp"] >= start_time) & (trend["timestamp"] <= end_time)]
    trend_long = trend.melt(id_vars="timestamp", var_name="severity", value_name="count")

    fig = px.bar(
        trend_long,
        x="timestamp",
        y="count",
        color="severity",
        barmode="stack",
        category_orders={"severity": ["HIGH", "MEDIUM", "NORMAL"]},
        color_discrete_map={"HIGH": "#d62728", "MEDIUM": "#ff7f0e", "NORMAL": "#2ca02c"}
    )
    fig.update_layout(
        title=f"Cumulative Severity Trend ({attack_filter})",
        xaxis=dict(range=[start_time, end_time]),
        yaxis=dict(range=[0, y_max]),
        height=350
    )
    st.plotly_chart(fig, use_container_width=True)

# Top 5 Attacks
with v3:
    st.caption("Top 5 Attacks")

    # Define fixed attack list
    top_attacks = ["dos", "u2r", "probe", "MEDIUM", "normal"]

    # Count attack types
    attack_counts = (
        df["attack_type"]
        .value_counts()
        .to_dict()
    )

    # Add MEDIUM from severity counts
    medium_count = (df["severity"] == "MEDIUM").sum()

    # Build final counts dictionary
    final_counts = {
        "dos": attack_counts.get("dos", 0),
        "u2r": attack_counts.get("u2r", 0),
        "probe": attack_counts.get("probe", 0),
        "MEDIUM": medium_count,
        "normal": attack_counts.get("normal", 0)
    }

    top5_df = pd.DataFrame(
        list(final_counts.items()),
        columns=["Attack", "Count"]
    )

    # Plot
    fig, ax = plt.subplots(figsize=(4, 3))
    ax.barh(
        top5_df["Attack"][::-1],
        top5_df["Count"][::-1]
    )
    ax.set_xlabel("Number of Alerts")
    ax.set_ylabel("Attack Type")

    st.pyplot(fig)

# Intrusion Timeline
st.subheader("\u23F1\uFE0F Intrusion Timeline")
if df.empty:
    st.info("No data")
else:
    timeline_hours = st.slider("Timeline Hours BEFORE", 0, 12, 6, key="timeline_hours")
    timeline_start = df["timestamp"].max() - pd.Timedelta(hours=timeline_hours)
    timeline_end = df["timestamp"].max()

    timeline = df.groupby([pd.Grouper(key="timestamp", freq="5T"), "severity"]).size().unstack(fill_value=0)
    for sev in ["HIGH", "MEDIUM", "NORMAL"]:
        if sev not in timeline.columns:
            timeline[sev] = 0

    timeline = timeline[(timeline.index >= timeline_start) & (timeline.index <= timeline_end)]
    fig, ax = plt.subplots(figsize=(8, 3))
    timeline.plot(kind="area", stacked=True, ax=ax)
    ax.set_xlim(timeline_start, timeline_end)
    st.pyplot(fig)


# Critical Alerts
st.subheader("\U0001F6A8 High-Severity Alerts")
critical = df[df["severity"] == "HIGH"]
if critical.empty:
    st.success("\u2705 No critical threats detected")
else:
    st.dataframe(critical[["timestamp", "human_readable", "severity"]].tail(5))

# Full Log
with st.expander("\U0001F4C4 View Full Alert Log"):
    st.dataframe(df[["timestamp", "human_readable", "severity"]].tail(15))

# Footer
st.markdown("---")
st.markdown("\U0001F6E1\uFE0F **Network Intrusion Detection Dashboard Active | IDS Monitoring Running**")
