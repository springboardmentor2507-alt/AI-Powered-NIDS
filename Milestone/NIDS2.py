# libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier

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

# 12. Analysis of feature
rf = RandomForestClassifier(n_estimators=200, random_state=42)
rf.fit(X_train, y_train)

# Extract feature importance
importances = pd.Series(rf.feature_importances_, index=X.columns)

# Plot top features
top = importances.sort_values(ascending=False).head(20)
top.head()

plt.figure(figsize=(10,6))
top.plot(kind='barh')
plt.title("Important Features (Random Forest)")
plt.xlabel("Importance Score")
plt.gca().invert_yaxis()
plt.show()

# 13. Supervised learning Model training
# 1. Random Forest
rf_model = RandomForestClassifier(n_estimators=200, random_state=42)
rf_model.fit(X_train, y_train)
rf_pred = rf_model.predict(X_test)

# 2. Decision Tree
dt_model = DecisionTreeClassifier(max_depth=15, random_state=42)
dt_model.fit(X_train, y_train)
dt_pred = dt_model.predict(X_test)

# 3. Logistic Regression
log_model = LogisticRegression(max_iter=500, n_jobs=-1)
log_model.fit(X_train, y_train)
log_pred = log_model.predict(X_test)

# 4. Support Vector Machine
svm_model = SVC(kernel='rbf', C=1)
svm_model.fit(X_train, y_train)
svm_pred = svm_model.predict(X_test)

# 5. KNN Classifier
knn_model = KNeighborsClassifier(n_neighbors=5)
knn_model.fit(X_train, y_train)
knn_pred = knn_model.predict(X_test)

# Evaluation of Supervised model
models = {
    "Random Forest": rf_pred,
    "Decision Tree": dt_pred,
    "Logistic Regression": log_pred,
    "SVM": svm_pred,
    "KNN": knn_pred
}

for name, pred in models.items():
    print(f"\n===== {name} =====")
    print("Accuracy:", accuracy_score(y_test, pred))
    print(classification_report(y_test, pred))