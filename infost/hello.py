import pandas as pd

# 1. Define feature names
feature_names = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
    "count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "label"
]

# 2. Define attack lists and mapping
dos_attacks = ['back', 'land', 'neptune', 'pod', 'smurf', 'teardrop', 'apache2', 'mailbomb', 'processtable', 'udpstorm', 'worm', 'buffer_overflow']
probe_attacks = ['satan', 'ipsweep', 'nmap', 'portsweep', 'mscan', 'saint']
r2l_attacks = ['guess_passwd', 'ftp_write', 'imap', 'phf', 'multihop', 'warezmaster', 
               'warezclient', 'spy', 'xlock', 'xsnoop', 'snmpgetattack', 'snmpguess', 
               'httptunnel', 'sendmail', 'named']
u2r_attacks = ['rootkit', 'perl', 'loadmodule', 'ps', 'sqlattack']

attack_category_map = {}
for attack in dos_attacks:
    attack_category_map[attack] = 'DoS'
for attack in probe_attacks:
    attack_category_map[attack] = 'Probe'
for attack in r2l_attacks:
    attack_category_map[attack] = 'R2L'
for attack in u2r_attacks:
    attack_category_map[attack] = 'U2R'
attack_category_map['normal'] = 'normal'

# 3. Load data file FIRST!
test_path = r"C:\Users\madhu\OneDrive\Desktop\infost\KDDTest+.txt"
df_test = pd.read_csv(test_path, names=feature_names)

# 4. Now map attack labels
df_test['category'] = df_test['label'].map(attack_category_map)

# 5. Print for verification
print(df_test[['label', 'category']].head(10))
print(df_test.head().T)
print(df_test.info())
