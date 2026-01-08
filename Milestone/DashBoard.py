import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
import numpy as np

# Page Configuration

st.set_page_config(
    page_title="AI-powered Intrusion Detection System",
    layout="wide"
)

st.title(" Network Intrusion Detection System Dashboard")
st.caption("Real-Time Threat Monitoring System")

# load dataset
alerts = pd.read_csv("../Dataset/intrusion_alerts.csv")
realtime = pd.read_csv("../Dataset/realtime_predictions.csv")

# Metrics

st.subheader("\U0001F4CA Threat Overview")
m1, m2 = st.columns(2)
m1.metric("Total Alerts", len(realtime))
m2.metric("Normal Traffic", (realtime["severity"] == "Normal").sum())

m3, m4 = st.columns(2)
m3.metric("High Severity", (realtime["severity"] == "High").sum())
m4.metric("Medium Severity", (realtime["severity"] == "Medium").sum())

# Threat Visuals

st.subheader("\U0001F4C8 THREAT VISUALS")
v1, v2 = st.columns(2)

# Attack Distribution

with v1:
    st.caption("Attack Distribution")
    attack_counts = realtime["predicted_label"].value_counts()
    if attack_counts.empty:
        st.info("No data")
    else:
        fig, ax = plt.subplots(figsize=(4, 3))
        ax.bar(attack_counts.index, attack_counts.values)
        ax.tick_params(axis="x", rotation=45)
        st.pyplot(fig)

# Top 5 Attacks

with v2:
    counts = realtime["severity"].value_counts()

    st.caption("Severity Distribution")

    fig, ax = plt.subplots(figsize=(4, 4))
    ax.pie(
        counts.values,
        labels=counts.index,
        autopct="%1.1f%%",
        startangle=90
    )
    ax.axis("equal")  # Makes the pie chart circular    
    st.pyplot(fig)

# Full Log

with st.expander("\U0001F4C4 View Full Log"):
    st.dataframe(realtime[["timestamp", "true_label","predicted_label", "severity"]].tail(15))

# Full Log

with st.expander("\U0001F4C4 View Alert Log"):
    st.dataframe(alerts[["timestamp", "true_label","predicted_label", "severity"]].tail(15))

# Footer

st.markdown("---")
st.markdown("\U0001F6E1\uFE0F **Network Intrusion Detection Dashboard Active | IDS Monitoring Running**")
