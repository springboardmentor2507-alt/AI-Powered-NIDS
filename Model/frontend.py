import streamlit as st
import pandas as pd
import requests
import time
import plotly.express as px

# --- Setup ---
COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment",
    "urgent","hot","num_failed_logins","logged_in","num_compromised","root_shell","su_attempted",
    "num_root","num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

VISIBLE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", 
    "dst_bytes", "wrong_fragment", "count", "srv_count", 
    "serror_rate", "dst_host_count", "attack"
]

st.set_page_config(page_title="AI-NIDS Analytics", layout="wide")
st.title("🛡️ AI Network Intrusion Detection & Analytics")

# Initialize Session States
if 'history' not in st.session_state:
    st.session_state.history = pd.DataFrame(columns=VISIBLE_COLUMNS)
if 'alerts' not in st.session_state:
    st.session_state.alerts = []

# --- Sidebar Alert Center ---
st.sidebar.header("🚨 Threat Alert Log")
alert_sidebar = st.sidebar.container()

# --- Functions ---
def get_prediction(sample_data):
    try:
        resp = requests.post("http://127.0.0.1:5000/predict", json=sample_data, timeout=2)
        return resp.json().get('prediction', 'error') if resp.status_code == 200 else "server_err"
    except: return "offline"

def style_rows(row):
    color = '#d4edda' if row['attack'] == 'normal' else '#f8d7da'
    return [f'background-color: {color}'] * len(row)

# --- UI Components ---
st.subheader("📊 Live Analytics")
col1, col2, col3 = st.columns(3)
pie_chart = col1.empty()
line_chart = col2.empty()
bar_chart = col3.empty()

st.subheader("📑 Real-time Traffic Logs")
log_placeholder = st.empty()

# --- Simulation Loop ---
df_kdd = pd.read_csv("../Dataset/KDDTrain20.txt", names=COLUMNS + ["label", "difficulty"])

for i in range(len(df_kdd)):
    row_data = df_kdd.iloc[i]
    prediction = get_prediction(row_data.drop('label').to_dict())
    clean_pred = str(prediction).strip().lower()

    # --- ALERT TRIGGER LOGIC ---
    if clean_pred != 'normal' and clean_pred not in ['offline', 'server_err']:
        # 1. Pop-up notification
        st.toast(f"⚠️ ALERT: {clean_pred.upper()} detected!", icon="🚨")
        # 2. Add to sidebar list
        timestamp = time.strftime("%H:%M:%S")
        st.session_state.alerts.insert(0, f"[{timestamp}] {clean_pred.upper()} attack at index {i}")

    # Update Data
    display_data = {col: row_data[col] for col in VISIBLE_COLUMNS if col != "attack"}
    display_data["attack"] = clean_pred
    new_entry = pd.DataFrame([display_data])
    st.session_state.history = pd.concat([new_entry, st.session_state.history], ignore_index=True)
    
    # --- Update Analytics & Sidebar ---
    with alert_sidebar:
        for alert in st.session_state.alerts[:10]: # Show last 10 alerts
            st.error(alert)

    # Visualization Renders
    hist = st.session_state.history
    fig_pie = px.pie(hist, names='attack', hole=0.4, color='attack', 
                     color_discrete_map={'normal': '#28a745', 'neptune': '#dc3545', 'satan': '#ff4b4b'})
    pie_chart.plotly_chart(fig_pie, use_container_width=True)

    fig_line = px.line(hist, y='count', title="Connection Count Trend")
    line_chart.plotly_chart(fig_line, use_container_width=True)

    fig_bar = px.bar(hist['protocol_type'].value_counts().reset_index(), 
                     x='protocol_type', y='count', title="Protocol Mix")
    bar_chart.plotly_chart(fig_bar, use_container_width=True)

    # Render Table
    styled_df = hist.head(20).style.apply(style_rows, axis=1)
    log_placeholder.dataframe(styled_df, use_container_width=True)

    time.sleep(5)