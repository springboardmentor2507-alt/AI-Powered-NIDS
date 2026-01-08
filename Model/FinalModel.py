import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.ensemble import RandomForestClassifier

# ... (Load data and map categories as per your notebook) ...
columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
    "num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count","srv_count",
    "serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate","label","difficulty"
]

df = pd.read_csv("../Dataset/KDDTrain20.txt", names=columns)
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

# 1. FIX: Separate Encoders
cat_cols = ['protocol_type', 'service', 'flag']
encoders = {}
for col in cat_cols:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    encoders[col] = le

X = df.drop(["label", "attack_category"], axis=1)
y = df["attack_category"]

# 2. SAVE MEDIANS: This provides a "neutral" background for the model
medians = X.median().to_dict()
joblib.dump(medians, 'medians.pkl')

# 3. Fit and Save Model/Scaler
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_scaled, y)

joblib.dump(model, 'nids_model.pkl')
joblib.dump(scaler, 'scaler.pkl')
joblib.dump(encoders, 'encoders.pkl')
joblib.dump(X.columns.tolist(), 'features.pkl')
print("Saved successfully")