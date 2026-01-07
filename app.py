import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import plotly.express as px

# =====================================================
# PAGE CONFIG
# =====================================================
st.set_page_config(
    page_title="SentinelNet – AI Intrusion Detection",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown(
    "<h1 style='color:#ff4b4b;'>🛡️ SentinelNet – Network Intrusion Detection System</h1>",
    unsafe_allow_html=True
)
st.caption("Real-Time Threat Monitoring | SOC-Style Dashboard")

# =====================================================
# SIMULATED REAL-TIME ALERT DATA
# =====================================================
TOTAL_ALERTS = 15999
HIGH_COUNT = 15799
MEDIUM_COUNT = 100
NORMAL_COUNT = 100

base_time = pd.Timestamp.now() - pd.Timedelta(hours=6)

timestamps_high = pd.date_range(base_time, periods=HIGH_COUNT, freq="10S")
timestamps_medium = pd.date_range(base_time, periods=MEDIUM_COUNT, freq="5T")
timestamps_normal = pd.date_range(base_time, periods=NORMAL_COUNT, freq="5T")

alerts_df = pd.DataFrame({
    "timestamp": np.concatenate([timestamps_high, timestamps_medium, timestamps_normal]),
    "attack_type": (
        ["dos"] * HIGH_COUNT +
        ["other"] * MEDIUM_COUNT +
        ["normal"] * NORMAL_COUNT
    )
})

# =====================================================
# SEVERITY CLASSIFICATION
# =====================================================
HIGH_SEVERITY = ["dos", "ddos", "u2r", "r2l", "probe", "backdoor", "worm"]

def classify_severity(attack):
    attack = str(attack).lower()
    if attack in HIGH_SEVERITY:
        return "HIGH"
    elif attack == "normal":
        return "NORMAL"
    else:
        return "MEDIUM"

alerts_df["severity"] = alerts_df["attack_type"].apply(classify_severity)
alerts_df["label"] = alerts_df["attack_type"].str.upper()

# =====================================================
# REAL-TIME TIME SHIFT (SIMULATION)
# =====================================================
if "time_shift" not in st.session_state:
    shift = pd.Timestamp.now() - alerts_df["timestamp"].max()
    alerts_df["timestamp"] += shift
    st.session_state.time_shift = True

# =====================================================
# METRICS
# =====================================================
st.subheader("📊 Threat Overview")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Alerts", len(alerts_df))
c2.metric("High Severity", (alerts_df["severity"] == "HIGH").sum())
c3.metric("Medium Severity", (alerts_df["severity"] == "MEDIUM").sum())
c4.metric("Normal Traffic", (alerts_df["severity"] == "NORMAL").sum())

# =====================================================
# FILTERS
# =====================================================
st.subheader("Investigation Filters")

f1, f2 = st.columns(2)

with f1:
    attack_filter = st.selectbox(
        "Attack Type",
        ["All"] + sorted(alerts_df["attack_type"].unique())
    )

with f2:
    severity_filter = st.multiselect(
        "Severity Level",
        ["HIGH", "MEDIUM", "NORMAL"],
        default=["HIGH", "MEDIUM", "NORMAL"]
    )

df = alerts_df.copy()

if attack_filter != "All":
    df = df[df["attack_type"] == attack_filter]

df = df[df["severity"].isin(severity_filter)]

# =====================================================
# VISUAL ANALYTICS
# =====================================================
st.subheader("Threat Analytics")

v1, v2, v3 = st.columns(3)

# ------------------ Attack Distribution ------------------
with v1:
    st.caption("Attack Distribution")
    counts = df["label"].value_counts()
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.bar(counts.index, counts.values, color="#ed0606")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=45)
    st.pyplot(fig)

# ------------------ Severity Trend ------------------
with v2:
    st.caption("Severity Trend Over Time")

    trend = (
        df.groupby([pd.Grouper(key="timestamp", freq="5T"), "severity"])
        .size()
        .reset_index(name="count")
    )

    fig = px.area(
        trend,
        x="timestamp",
        y="count",
        color="severity",
        color_discrete_map={
            "HIGH": "#d62728",
            "MEDIUM": "#ff7f0e",
            "NORMAL": "#10ac10"
        },
        height=420
    )
    st.plotly_chart(fig, use_container_width=True)

# ------------------ Top Attacks ------------------
with v3:
    st.caption("Top Attacks")
    top = df["label"].value_counts().head(5)
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.barh(top.index[::-1], top.values[::-1], color="#ffa726")
    ax.set_xlabel("Alerts")
    st.pyplot(fig)

# =====================================================
# INTRUSION TIMELINE
# =====================================================
st.subheader("⏱ Intrusion Timeline")

timeline = (
    df.groupby([pd.Grouper(key="timestamp", freq="5T"), "severity"])
    .size()
    .unstack(fill_value=0)
)

fig, ax = plt.subplots(figsize=(10, 4))
timeline.plot(
    kind="area",
    stacked=True,
    ax=ax,
    color=["#d62728", "#ff7f0e", "#2ca02c"]
)
ax.set_ylabel("Alert Count")
st.pyplot(fig)

# =====================================================
# HIGH SEVERITY ALERTS
# =====================================================
st.subheader("🚨 High-Severity Alerts")

critical = df[df["severity"] == "HIGH"]

if critical.empty:
    st.success("✅ No critical threats detected")
else:
    st.dataframe(
        critical[["timestamp", "label", "severity"]].tail(10),
        use_container_width=True
    )

# =====================================================
# FULL LOG
# =====================================================
with st.expander("📄 View Full Alert Log"):
    st.dataframe(
        df[["timestamp", "label", "severity"]].tail(20),
        use_container_width=True
    )

# =====================================================
# FOOTER
# =====================================================
st.markdown("---")
st.markdown(
    "<center><b>🛡️ SentinelNet IDS Active | Continuous Threat Monitoring Enabled</b></center>",
    unsafe_allow_html=True
)
