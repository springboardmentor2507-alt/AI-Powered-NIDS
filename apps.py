import streamlit as st
import joblib
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import datetime

# -------------------------------
# 1. Page Configuration & Custom CSS
# -------------------------------
st.set_page_config(
    page_title="Sentin-AI | IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for a "Cybersecurity" Dashboard look
st.markdown("""
    <style>
        .main {
            background-color: #0E1117;
        }
        .stMetric {
            background-color: #262730;
            padding: 15px;
            border-radius: 10px;
            border: 1px solid #41444C;
        }
        div[data-testid="stMetricValue"] {
            color: #00FF99; /* Cyber Green */
        }
        h1, h2, h3 {
            color: #FFFFFF;
        }
    </style>
""", unsafe_allow_html=True)

# -------------------------------
# 2. Load Model & Data
# -------------------------------
@st.cache_resource
def load_data():
    # Ensure these files exist in your directory
    try:
        rf = joblib.load("random_forest_model.pkl")
        X_test = joblib.load("X_test.pkl")
        y_test = joblib.load("y_test.pkl")
        y_pred_rf = joblib.load("y_pred_rf.pkl")
        iso_pred = joblib.load("iso_pred.pkl")
        return rf, X_test, y_test, y_pred_rf, iso_pred
    except FileNotFoundError:
        st.error("🚨 Model files not found! Please generate .pkl files first.")
        st.stop()

rf, X_test, y_test, y_pred_rf, iso_pred = load_data()

# Create log data
log_data = X_test.copy().head(50)
log_data['Timestamp'] = [datetime.datetime.now() - datetime.timedelta(minutes=i) for i in range(50)]
log_data['Prediction'] = y_pred_rf[:50]
log_data['Status'] = log_data['Prediction'].apply(lambda x: "🔴 ALERT" if x != "Normal" else "✅ OK")

# Reorder columns
cols = ['Timestamp', 'Status', 'Prediction'] + [c for c in X_test.columns]
log_data = log_data[cols]

# -------------------------------
# 3. Sidebar: Controls & Live Input
# -------------------------------
with st.sidebar:
    st.title("🛡️ Sentin-AI Controls")
    st.markdown("---")
    
    st.subheader("🧪 Live Packet Prediction")
    input_values = []
    
    # Using an Expander for the form
    with st.expander("📝 Quick Packet Analysis", expanded=True):
        with st.form("sidebar_form"):
            timestamp = st.date_input("Timestamp")
            index = st.number_input("Index", value=0, step=1)
            for col in X_test.columns[:5]:  # Limit to first 5 features for sidebar space
                val = st.number_input(f"{col}", value=0.0, step=0.1, key=f"sidebar_{col}")
                input_values.append(val)
            submit_sidebar = st.form_submit_button("Analyze Packet")

    if submit_sidebar:
        new_sample = np.array(input_values).reshape(1, -1)
        rf_pred = rf.predict(new_sample)[0]
        rf_probs = rf.predict_proba(new_sample)[0]
        classes = rf.classes_
        
        if rf_pred != "Normal":
            st.error(f"🚨 ALERT: {rf_pred}")
        else:
            st.success("✅ Normal")
        
        st.metric("Prediction", rf_pred)
        st.caption(f"Confidence: {rf_probs.max():.2f}")
    
    st.markdown("---")
    st.info("System Status: 🟢 ONLINE")
    st.caption("Model: Random Forest + Isolation Forest")

# -------------------------------
# 4. Main Dashboard Header & KPI Row
# -------------------------------
st.title("🚨 Network Intrusion Detection System")
st.markdown("Real-time monitoring and anomaly detection dashboard.")
st.markdown("---")

# Calculate KPIs
accuracy = np.mean(y_pred_rf == y_test)
total_attacks = np.sum(y_test != "Normal")
anomaly_detected = np.sum(iso_pred == -1)
security_level = (1 - (total_attacks / len(y_test))) * 100

# KPI Columns
kpi1, kpi2, kpi3, kpi4 = st.columns(4)

kpi1.metric("🛡️ System Accuracy", f"{accuracy:.2%}", delta="Stable")
kpi2.metric("🔥 Total Attacks", f"{total_attacks}", delta="-High Risk", delta_color="inverse")
kpi3.metric("⚠️ Anomalies (IsoForest)", f"{anomaly_detected}", delta="Attention")
kpi4.metric("🔒 Security Score", f"{security_level:.1f}", delta="Safe")

st.markdown("---")
st.markdown("### 📊 Attack Category Distributions")

dist_col1, dist_col2, dist_col3 = st.columns(3)

with dist_col1:
    st.subheader("Predicted Attack Distribution")
    pred_counts = pd.Series(y_pred_rf).value_counts().reset_index()
    pred_counts.columns = ['Type', 'Count']
    fig_pred_bar = px.bar(pred_counts, x='Type', y='Count', title='', color='Type', color_discrete_sequence=px.colors.qualitative.Pastel)
    st.plotly_chart(fig_pred_bar, use_container_width=True)

with dist_col2:
    st.subheader("Actual Attack Distribution")
    actual_counts = pd.Series(y_test).value_counts().reset_index()
    actual_counts.columns = ['Type', 'Count']
    fig_actual_bar = px.bar(actual_counts, x='Type', y='Count', title='', color='Type', color_discrete_sequence=px.colors.qualitative.Pastel)
    st.plotly_chart(fig_actual_bar, use_container_width=True)

with dist_col3:
    st.subheader("Anomaly Detection Results")
    anomaly_df = pd.DataFrame({'Type': ['Normal', 'Anomaly'], 'Count': [np.sum(iso_pred == 1), np.sum(iso_pred == -1)]})
    fig_anomaly_bar = px.bar(anomaly_df, x='Type', y='Count', title='', color='Type', color_discrete_sequence=['#00FF99', '#FF4B4B'])
    st.plotly_chart(fig_anomaly_bar, use_container_width=True)

# -------------------------------
# 5. Visualizations Section (Interactive)
# -------------------------------
st.markdown("### 📊 Traffic Analysis & Threat Vector")

col1, col2 = st.columns([2, 1])

with col1:
    # 1. Attack Type Distribution (Bar Chart)
    # Create a DataFrame for the prediction counts
    pred_counts = pd.Series(y_pred_rf).value_counts().reset_index()
    pred_counts.columns = ['Type', 'Count']
    
    fig_bar = px.bar(
        pred_counts, 
        x='Type', 
        y='Count', 
        title='Distribution of Detected Traffic Types',
        color='Type',
        color_discrete_sequence=px.colors.qualitative.Pastel
    )
    fig_bar.update_layout(height=350, margin=dict(t=30, b=0, l=0, r=0))
    st.plotly_chart(fig_bar, use_container_width=True)

with col2:
    # 2. Confidence/Probabilities Gauge
    # We take the average attack probability of the test set for display
    avg_attack_prob = rf.predict_proba(X_test)[:, 1].mean()
    
    fig_gauge = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = avg_attack_prob * 100,
        title = {'text': "Avg Threat Probability"},
        gauge = {
            'axis': {'range': [None, 100]},
            'bar': {'color': "#FF4B4B"},
            'steps': [
                {'range': [0, 50], 'color': "#00FF99"},
                {'range': [50, 75], 'color': "#FFAA00"},
                {'range': [75, 100], 'color': "#FF0000"}],
        }
    ))
    fig_gauge.update_layout(height=350, margin=dict(t=50, b=10, l=30, r=30))
    st.plotly_chart(fig_gauge, use_container_width=True)

# -------------------------------
# 6. Deep Dive Tabs
# -------------------------------
tab1, tab2, tab3 = st.tabs(["📜 Recent Alert Logs", "📉 Performance Analysis", "🔍 Manual Prediction Result"])

# --- TAB 1: LOGS (Styled Dataframe) ---
with tab1:
    st.subheader("Simulated Live Stream Logs")
    
    status_options = ["All"] + sorted(log_data['Status'].unique())
    status_filter = st.selectbox("Filter by Status", status_options)
    
    if status_filter != "All":
        filtered_logs = log_data[log_data['Status'] == status_filter]
    else:
        filtered_logs = log_data
    
    # Color highlighting function
    def highlight_threat(row):
        return ['background-color: #3d0e0e' if row['Status'] == "🔴 ALERT" else '' for _ in row]

    st.dataframe(
        filtered_logs.style.apply(highlight_threat, axis=1),
        height=300,
        use_container_width=True
    )

# --- TAB 2: METRICS (ROC & Confusion Matrix) ---
with tab2:
    col_a, col_b, col_c = st.columns(3)
    
    with col_a:
        st.markdown("**Confusion Matrix Heatmap**")
        from sklearn.metrics import confusion_matrix
        cm = confusion_matrix(y_test, y_pred_rf)
        
        fig_cm = px.imshow(
            cm, 
            text_auto=True, 
            aspect="auto", 
            color_continuous_scale="Viridis",
            labels=dict(x="Predicted", y="Actual", color="Count")
        )
        st.plotly_chart(fig_cm, use_container_width=True)

    with col_b:
        st.markdown("**ROC Curve**")
        y_test_binary = np.where(y_test == "Normal", 0, 1)
        y_prob = rf.predict_proba(X_test)[:, 1]
        from sklearn.metrics import roc_curve, roc_auc_score
        fpr, tpr, _ = roc_curve(y_test_binary, y_prob)
        auc = roc_auc_score(y_test_binary, y_prob)
        
        fig_roc = px.area(
            x=fpr, y=tpr,
            title=f'ROC Curve (AUC={auc:.3f})',
            labels=dict(x='False Positive Rate', y='True Positive Rate'),
            width=700, height=400
        )
        fig_roc.add_shape(
            type='line', line=dict(dash='dash'),
            x0=0, x1=1, y0=0, y1=1
        )
        st.plotly_chart(fig_roc, use_container_width=True)

    with col_c:
        st.markdown("**Top 10 Feature Importances**")
        feature_importances = pd.DataFrame({'Feature': X_test.columns, 'Importance': rf.feature_importances_}).sort_values('Importance', ascending=False).head(10)
        fig_feat = px.bar(feature_importances, x='Importance', y='Feature', orientation='h', title='')
        st.plotly_chart(fig_feat, use_container_width=True)

# --- TAB 3: MANUAL PREDICTION RESULT ---
with tab3:
    st.subheader("Batch CSV Prediction")
    uploaded_file = st.file_uploader("Upload CSV file for batch prediction", type="csv")
    
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        # Assume columns match X_test.columns
        if set(df.columns) == set(X_test.columns):
            st.write("Data Preview:")
            st.dataframe(df.head())
            if st.button("Predict Attacks"):
                with st.spinner("Predicting..."):
                    preds = rf.predict(df.values)
                    probs = rf.predict_proba(df.values)
                    df['Predicted Attack'] = preds
                    df['Prediction Confidence'] = probs.max(axis=1)
                    st.write("Predictions:")
                    st.dataframe(df)
                    # Aggregate
                    pred_counts_batch = pd.Series(preds).value_counts().reset_index()
                    pred_counts_batch.columns = ['Type', 'Count']
                    fig_batch = px.bar(pred_counts_batch, x='Type', y='Count', title='Predicted Attack Distribution from Uploaded Data', color='Type', color_discrete_sequence=px.colors.qualitative.Pastel)
                    st.plotly_chart(fig_batch, use_container_width=True)
        else:
            st.error("CSV columns do not match the expected features.")
    
    st.markdown("---")
    st.subheader("Single Packet Analysis")
    input_values = []
    
    # Using an Expander for the form to keep sidebar clean
    with st.expander("📝 Manual Packet Injection", expanded=True):
        with st.form("new_case_form"):
            timestamp = st.date_input("Timestamp")
            index = st.number_input("Index", value=0, step=1)
            for col in X_test.columns:
                val = st.number_input(f"{col}", value=0.0, step=0.1)
                input_values.append(val)
            submit = st.form_submit_button("Analyze Packet")

    if submit:
        new_sample = np.array(input_values).reshape(1, -1)
        rf_pred = rf.predict(new_sample)[0]
        rf_probs = rf.predict_proba(new_sample)[0]
        classes = rf.classes_
        
        prob_df = pd.DataFrame({'Attack Type': classes, 'Probability': rf_probs})
        fig_prob = px.bar(prob_df, x='Attack Type', y='Probability', title='Prediction Probabilities', color='Attack Type', color_discrete_sequence=px.colors.qualitative.Pastel)
        st.plotly_chart(fig_prob, use_container_width=True)
        
        st.markdown("### Analysis Result")
        
        c1, c2 = st.columns([1, 3])
        
        with c1:
            if rf_pred != "Normal":
                st.error(f"🚨 INTRUSION DETECTED")
                st.metric("Attack Type", rf_pred)
            else:
                st.success(f"✅ TRAFFIC NORMAL")
                st.metric("Status", "Clean")
        
        with c2:
            st.markdown(f"**Highest Probability:** {rf_probs.max():.4f} for {classes[rf_probs.argmax()]}")
            st.progress(rf_probs.max())
            if rf_probs.max() > 0.5:
                st.warning("High confidence in prediction.")

# -------------------------------
# Footer
# -------------------------------
st.markdown("---")
st.markdown("© 2025 Sentin-AI Network Security | Developed for Research Purposes")