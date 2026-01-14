"""
Dataset Loader for NSL-KDD and CICIDS2017 datasets
Handles downloading, extracting, and loading network intrusion datasets
"""

import pandas as pd
import numpy as np
import os
import zipfile
import requests
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import pickle

class DatasetLoader:
    """Load and preprocess network intrusion detection datasets"""
    
    def __init__(self, dataset_type='NSL-KDD'):
        self.dataset_type = dataset_type
        self.data_dir = 'data'
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.feature_names = []
        
        # Create data directory
        os.makedirs(self.data_dir, exist_ok=True)
    
    def load_nsl_kdd(self, train_file='data/KDDTrain+.csv', test_file='data/KDDTest+.csv'):
        """Load NSL-KDD dataset from CSV files"""
        
        # NSL-KDD column names
        column_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 
            'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 
            'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
            'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
            'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate',
            'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
            'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
            'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
            'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack_type', 'difficulty'
        ]
        
        if os.path.exists(train_file):
            print(f"Loading NSL-KDD dataset from {train_file}...")
            df_train = pd.read_csv(train_file, names=column_names)
            
            if os.path.exists(test_file):
                df_test = pd.read_csv(test_file, names=column_names)
            else:
                # Split train data if test not available
                df_train, df_test = train_test_split(df_train, test_size=0.2, random_state=42)
            
            return self._preprocess_nsl_kdd(df_train, df_test)
        else:
            print(f"Dataset file not found: {train_file}")
            print("Please download NSL-KDD dataset and place CSV files in the 'data' directory")
            print("Download from: https://www.unb.ca/cic/datasets/nsl.html")
            return False
    
    def _preprocess_nsl_kdd(self, df_train, df_test):
        """Preprocess NSL-KDD dataset"""
        
        # Remove difficulty column
        if 'difficulty' in df_train.columns:
            df_train = df_train.drop('difficulty', axis=1)
            df_test = df_test.drop('difficulty', axis=1)
        
        # Simplify attack types to binary or multi-class
        attack_mapping = {
            'normal': 'Normal',
            'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS', 'smurf': 'DoS', 'teardrop': 'DoS',
            'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe',
            'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L',
            'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
            'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R'
        }
        
        df_train['attack_category'] = df_train['attack_type'].str.lower().map(attack_mapping)
        df_test['attack_category'] = df_test['attack_type'].str.lower().map(attack_mapping)
        
        # Fill any unmapped values with 'Other'
        df_train['attack_category'] = df_train['attack_category'].fillna('Other')
        df_test['attack_category'] = df_test['attack_category'].fillna('Other')
        
        # Separate features and labels
        y_train = df_train['attack_category']
        y_test = df_test['attack_category']
        
        X_train = df_train.drop(['attack_type', 'attack_category'], axis=1)
        X_test = df_test.drop(['attack_type', 'attack_category'], axis=1)
        
        # Encode categorical features
        categorical_cols = X_train.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            le = LabelEncoder()
            X_train[col] = le.fit_transform(X_train[col].astype(str))
            X_test[col] = le.transform(X_test[col].astype(str))
        
        # Scale features
        self.scaler.fit(X_train)
        X_train = self.scaler.transform(X_train)
        X_test = self.scaler.transform(X_test)
        
        # Encode labels
        self.label_encoder.fit(y_train)
        y_train = self.label_encoder.transform(y_train)
        y_test = self.label_encoder.transform(y_test)
        
        self.X_train = X_train
        self.X_test = X_test
        self.y_train = y_train
        self.y_test = y_test
        self.feature_names = df_train.drop(['attack_type', 'attack_category'], axis=1).columns.tolist()
        
        print(f"Dataset loaded successfully!")
        print(f"Training samples: {len(X_train)}")
        print(f"Testing samples: {len(X_test)}")
        print(f"Attack categories: {list(self.label_encoder.classes_)}")
        
        return True
    
    def save_preprocessed_data(self, filename='data/preprocessed_data.pkl'):
        """Save preprocessed data for quick loading"""
        data = {
            'X_train': self.X_train,
            'X_test': self.X_test,
            'y_train': self.y_train,
            'y_test': self.y_test,
            'label_encoder': self.label_encoder,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }
        
        with open(filename, 'wb') as f:
            pickle.dump(data, f)
        
        print(f"Preprocessed data saved to {filename}")
    
    def load_preprocessed_data(self, filename='data/preprocessed_data.pkl'):
        """Load preprocessed data"""
        if os.path.exists(filename):
            with open(filename, 'rb') as f:
                data = pickle.load(f)
            
            self.X_train = data['X_train']
            self.X_test = data['X_test']
            self.y_train = data['y_train']
            self.y_test = data['y_test']
            self.label_encoder = data['label_encoder']
            self.scaler = data['scaler']
            self.feature_names = data['feature_names']
            
            print(f"Preprocessed data loaded from {filename}")
            return True
        return False
    
    def get_sample_packet(self, idx=None):
        """Get a random sample from test set for real-time prediction"""
        if self.X_test is None:
            return None
        
        if idx is None:
            idx = np.random.randint(0, len(self.X_test))
        
        features = self.X_test[idx]
        true_label = self.label_encoder.inverse_transform([self.y_test[idx]])[0]
        
        return features, true_label

# Create singleton instance
dataset_loader = DatasetLoader()
