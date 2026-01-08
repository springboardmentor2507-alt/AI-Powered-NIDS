# libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import MinMaxScaler
from imblearn.over_sampling import ADASYN
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.metrics import precision_score, recall_score, f1_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import roc_curve, auc
from sklearn.preprocessing import label_binarize
from sklearn.multiclass import OneVsRestClassifier
from sklearn.metrics import RocCurveDisplay
import time
from datetime import datetime

df = pd.read_csv("../Dataset/balanced_df.csv")
# 11. Train Test Split
X = df.drop(["attack_category"], axis=1)   # keep only numerical + encoded columns
y = df["attack_category"]                           # target

# Normal train-test split (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.3,
    random_state=42,
    stratify=y
)

# 14. Unsupervised model training
y_train_bin = (y_train != 'Normal').astype(int)
y_test_bin = (y_test != 'Normal').astype(int)

X_train_normal = X_train[y_train == 'Normal']
print(f"Normal Train Size (for Anomaly Detection): {X_train_normal.shape}")

# 1. Isolation forest
iso_forest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42, n_jobs=-1)
iso_forest.fit(X_train_normal)  # Fit on Normal data
iso_preds_raw = iso_forest.predict(X_test)
iso_preds = np.where(iso_preds_raw == 1, 0, 1)

# 2. K-Means
kmeans = KMeans(n_clusters=1, random_state=42, n_init=10)
kmeans.fit(X_train_normal)
distances = kmeans.transform(X_test)
threshold = np.percentile(distances, 90)
kmeans_preds = (distances > threshold).astype(int).flatten()

# 15. Comparison of Model
print("Isolation Forest Results:")
print("Accuracy:", accuracy_score(y_test_bin, iso_preds))
print(classification_report(y_test_bin, iso_preds, target_names=['Normal', 'Anomaly']))

print("K-Means Anomaly Detection Results:")
print("Accuracy:", accuracy_score(y_test_bin, kmeans_preds))
print(classification_report(y_test_bin, kmeans_preds, target_names=['Normal', 'Anomaly']))

print("Selecting Best Model...")
best_model_name = "Random Forest"
print(f"Selected Model: {best_model_name}")

# 16. Hyperparameter grid
param_grid = {
    'n_estimators': [100, 200],
    'max_depth': [10, 20, None],
    'min_samples_split': [2, 5],
    'min_samples_leaf': [1, 2]
}

rf = RandomForestClassifier(random_state=42)

grid_search = GridSearchCV(
    estimator=rf,
    param_grid=param_grid,
    cv=5,                     # 5-fold cross validation
    scoring='accuracy',
    n_jobs=-1,
    verbose=2
)

# Fit tuned model
grid_search.fit(X_train, y_train)
print("Best Parameters:", grid_search.best_params_)
print("Best CV Score:", grid_search.best_score_)

# 17. Confusion Matrix
best_rf = grid_search.best_estimator_
tuned_pred = best_rf.predict(X_test)
cm = confusion_matrix(y_test, tuned_pred)

plt.figure(figsize=(8,6))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=best_rf.classes_,
            yticklabels=best_rf.classes_)
plt.title("Confusion Matrix - Tuned Random Forest")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.show()

# 18. ROC Curve
# Encode labels for multiclass ROC
le = LabelEncoder()
y_train_bin = le.fit_transform(y_train)
y_test_bin = le.transform(y_test)

# Binarize output
y_test_ovr = label_binarize(y_test_bin, classes=np.unique(y_test_bin))
n_classes = y_test_ovr.shape[1]

# Train OVR classifier
ovr_model = OneVsRestClassifier(best_rf)
ovr_model.fit(X_train, label_binarize(y_train_bin, classes=np.unique(y_train_bin)))

# Predict probabilities
y_score = ovr_model.predict_proba(X_test)

# Plot ROC Curve for every class
plt.figure(figsize=(10, 8))

for i in range(n_classes):
    fpr, tpr, _ = roc_curve(y_test_ovr[:, i], y_score[:, i])
    roc_auc = auc(fpr, tpr)
    plt.plot(fpr, tpr, label=f"Class {le.inverse_transform([i])[0]} (AUC = {roc_auc:.2f})")

plt.plot([0, 1], [0, 1], 'k--')
plt.title("Multiclass ROC Curve (One-vs-Rest)")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.legend()
plt.show()

# Milestone 4
# Real-Time Prediction Simulation Function
best_model = best_rf   # from GridSearchCV
class_labels = best_model.classes_

def simulate_realtime_detection(model, X_test, y_test, threshold=0.6):
    logs = []

    for i in range(len(X_test)):
        sample = X_test.iloc[i:i+1]
        true_label = y_test.iloc[i]

        # Prediction
        probs = model.predict_proba(sample)[0]
        pred_idx = np.argmax(probs)
        pred_label = class_labels[pred_idx]
        confidence = probs[pred_idx]

        # Alert logic
        alert = "NO"
        severity = "Normal"

        if pred_label != "Normal" and confidence >= threshold:
            alert = "YES"
            if pred_label in ["DoS", "Probe"]:
                severity = "High"
            elif pred_label in ["R2L"]:
                severity = "Medium"
            elif pred_label in ["U2R"]:
                severity = "Critical"

        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "predicted_label": pred_label,
            "true_label": true_label,
            "confidence": round(confidence, 3),
            "alert": alert,
            "severity": severity
        }

        logs.append(log_entry)

        # Simulate delay (optional)
        # time.sleep(0.05)

    return pd.DataFrame(logs)

realtime_logs = simulate_realtime_detection(
    best_model,
    X_test,
    y_test,
    threshold=0.6
)

realtime_logs.head()

# Generate Alerts Only
alerts = realtime_logs[realtime_logs["alert"] == "YES"]
alerts.head()

# Store Results in Files
realtime_logs.to_csv("../Dataset/realtime_predictions.csv", index=False)
alerts.to_csv("../Dataset/intrusion_alerts.csv", index=False)

print(" Network Intrusion Detection System - Real Time Prediction")
print("=========================================================")
print("SUMMARY")
print(f"Total Samples: {len(realtime_logs)}")
print(f"Total Alerts Generated: {len(alerts)}")
print(f"Total Alerts with High Severity: {len(alerts[alerts['severity'] == 'High'])}")
print(f"Total Alerts with Medium Severity: {len(alerts[alerts['severity'] == 'Medium'])}")
print(f"Total Alerts with Critical Severity: {len(alerts[alerts['severity'] == 'Critical'])}")
print(f"Unique attack: {len(alerts['predicted_label'].unique())}")
print("Attack types:")
print(alerts["predicted_label"].value_counts())
print(f"Severity distribution: {alerts["severity"].value_counts()}")
print(f"Accuracy: {accuracy_score(alerts['true_label'], alerts['predicted_label'])}")
print(f"Precision: {precision_score(alerts['true_label'], alerts['predicted_label'], average='weighted')}")
print(f"Recall: {recall_score(alerts['true_label'], alerts['predicted_label'], average='weighted')}")

print("\nREAL TIME LOGS")
print(realtime_logs.head())

print("\nINTRUSION ALERTS")
print(alerts.head())

# Store Results in Files
with open("../Dataset/intrusion_alerts.txt", "w") as f:
    for _, row in alerts.iterrows():
        f.write(
            f"[{row['timestamp']}] "
            f"ALERT | Type: {row['predicted_label']} | "
            f"Severity: {row['severity']} | "
            f"Confidence: {row['confidence']}\n"
        )

# Alerts by Attack Type distribution
attacks = alerts["predicted_label"].value_counts()
plt.figure(figsize=(6, 4))
colors = sns.color_palette("Set2", len(attacks))
attacks.plot(kind="bar", color=colors, edgecolor='black')
plt.xlabel("Attack Type")
plt.ylabel("Count")
plt.title("Attack Frequency", fontsize=14, color='black')
plt.tight_layout()
plt.show()

# Severity Distribution
plt.figure(figsize=(6,4))
alerts["severity"].value_counts().plot(kind="pie", autopct="%1.1f%%")
plt.title("Severity Distribution of Alerts")
plt.ylabel("")
plt.show()

print("Normal VS Attack")
normal_count = (realtime_logs["alert"] == "NO").sum()
attack_count = (realtime_logs["alert"] == "YES").sum()

plt.figure(figsize=(5, 4))
plt.bar(
    ["Normal Traffic", "Attack Traffic"],
    [normal_count, attack_count],
    color=['lightgreen', 'red'],
    edgecolor='black'
)
plt.xlabel("Traffic Type")
plt.ylabel("Number of Samples")
plt.title("Normal VS Attack", fontsize=14, color='black')
plt.tight_layout()
plt.show()