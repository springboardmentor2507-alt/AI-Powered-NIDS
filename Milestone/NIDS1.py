# libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import MinMaxScaler
from imblearn.over_sampling import ADASYN
from sklearn.model_selection import train_test_split


# 1. Load Dataset
file_path = "../Dataset/KDDTrain20.txt"

columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
    "num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count","srv_count",
    "serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate","label","difficulty"
]

df = pd.read_csv(file_path, names=columns)

# 2. Assign Attack Categorization
dos = ["back","land","neptune","pod","smurf","teardrop","mailbomb","processtable","udpstorm","apache2","worm"]
probe = ["satan","ipsweep","nmap","portsweep","mscan","saint"]
r2l = ["guess_passwd","ftp_write","imap","phf","multihop","warezmaster","warezclient","spy","xlock","xsnoop","snmpguess","snmpgetattack","httptunnel","sendmail","named"]
u2r = ["buffer_overflow","loadmodule","rootkit","perl","sqlattack","xterm","ps"]

def map_attack(label):
    label = label.strip()
    if label == "normal":
        return "Normal"
    elif label in dos:
        return "DoS"
    elif label in probe:
        return "Probe"
    elif label in r2l:
        return "R2L"
    elif label in u2r:
        return "U2R"
    else:
        return "Unknown"

df["attack_category"] = df["label"].apply(map_attack)

#  3. Statistical data, missing value and duplicate
print(df.shape)
print(df.isnull().sum())
print(df.duplicated().sum())
print(df.describe().T)

# 4. Plot Label Distribution
plt.figure(figsize=(8,5))
df["label"].value_counts().plot(kind="bar")
plt.title("Distribution of Attack Labels")
plt.xlabel("Label")
plt.ylabel("Count")
plt.show()

# 5. Plot Attack Category Distribution

plt.figure(figsize=(6,4))
df["attack_category"].value_counts().plot(kind="bar", color="green")
plt.title("Attack Category Distribution")
plt.xlabel("Category")
plt.ylabel("Count")
plt.show()

# 6. Protocol & Service Counts
plt.figure(figsize=(6,4))
sns.countplot(data=df, x="protocol_type")
plt.title("Protocol Type Distribution")
plt.show()

plt.figure(figsize=(10,4))
df["service"].value_counts().nlargest(10).plot(kind="bar")
plt.title("Top 10 Most Used Services")
plt.show()

# 7. Correlation Heatmap
plt.figure(figsize=(15,10))
corr = df.corr(numeric_only=True)
sns.heatmap(corr, cmap="coolwarm",  linewidths=0.1)
plt.title("Correlation Heatmap of Numerical Features")
plt.show()

# 8. Categorical data encoding
le = LabelEncoder()
df["protocol_type"] = le.fit_transform(df["protocol_type"])
df["flag"] = le.fit_transform(df["flag"])
df["service"] = le.fit_transform(df["service"])

# 9. Normalizing numerical data
scaler = MinMaxScaler()
numerical_cols = df.select_dtypes(exclude='object').columns
df[numerical_cols] = scaler.fit_transform(df[numerical_cols])

# 10. Dataset balancing
X = df.drop(["label", "attack_category"], axis=1)
y = df["attack_category"]
adasyn = ADASYN()
X_res, y_res = adasyn.fit_resample(X, y)
df1 = pd.concat([X_res, y_res], axis=1)
print(df1.shape)
print(df1.duplicated().sum())

count1 = df["attack_category"].value_counts()
count2 = df1["attack_category"].value_counts()

# Combine into one dataframe
comparison = pd.DataFrame({
    "Dataset1": count1,
    "Dataset2": count2
}).fillna(0)

# Plot
comparison.plot(kind="bar", figsize=(10,5))
plt.title("Comparison of Attack Category Counts")
plt.xlabel("Attack Category")
plt.ylabel("Count")
plt.show()
df1.to_csv("balanced_df.csv", index = False)

# 11. Train Test Split
X = df1.drop(["attack_category"], axis=1)   # keep only numerical + encoded columns
y = df1["attack_category"]                           # target

# Normal train-test split (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.3,
    random_state=42,
    stratify=y
)