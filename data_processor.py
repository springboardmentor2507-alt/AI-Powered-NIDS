"""
Data processing and feature engineering for NIDS
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder

class DataProcessor:
    """Process and prepare network traffic data for ML models"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = []
        
    def load_dataset(self, filepath):
        """
        Load network intrusion dataset (NSL-KDD or CICIDS2017 format)
        """
        try:
            df = pd.read_csv(filepath)
            print(f"Dataset loaded: {len(df)} records")
            return df
        except Exception as e:
            print(f"Error loading dataset: {e}")
            return None
    
    def clean_data(self, df):
        """
        Clean dataset: handle missing values, duplicates
        """
        # Remove duplicates
        original_size = len(df)
        df = df.drop_duplicates()
        print(f"Removed {original_size - len(df)} duplicate records")
        
        # Handle missing values
        df = df.fillna(df.median(numeric_only=True))
        
        return df
    
    def encode_categorical(self, df, columns):
        """
        Encode categorical features
        """
        for col in columns:
            if col in df.columns:
                df[col] = self.label_encoder.fit_transform(df[col].astype(str))
        
        return df
    
    def normalize_features(self, df, exclude_columns=[]):
        """
        Normalize numerical features
        """
        numerical_cols = df.select_dtypes(include=[np.number]).columns
        numerical_cols = [col for col in numerical_cols if col not in exclude_columns]
        
        df[numerical_cols] = self.scaler.fit_transform(df[numerical_cols])
        
        return df
    
    def feature_selection(self, df, n_features=20):
        """
        Select top n features based on importance
        """
        # This is a simplified version
        # In production, use actual feature importance from trained models
        if len(df.columns) > n_features:
            self.feature_columns = df.columns[:n_features].tolist()
            return df[self.feature_columns]
        
        self.feature_columns = df.columns.tolist()
        return df
    
    def split_data(self, df, target_column, test_size=0.2):
        """
        Split data into training and testing sets
        """
        from sklearn.model_selection import train_test_split
        
        X = df.drop(columns=[target_column])
        y = df[target_column]
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        print(f"Training set: {len(X_train)} records")
        print(f"Testing set: {len(X_test)} records")
        
        return X_train, X_test, y_train, y_test
    
    def extract_features(self, packet_data):
        """
        Extract features from raw packet data
        """
        features = {
            'protocol': packet_data.get('protocol', 'TCP'),
            'source_port': packet_data.get('source_port', 0),
            'dest_port': packet_data.get('dest_port', 0),
            'packet_size': packet_data.get('packet_size', 0),
            'duration': np.random.randint(0, 100),
            'src_bytes': np.random.randint(0, 10000),
            'dst_bytes': np.random.randint(0, 10000)
        }
        
        return features

# Create singleton instance
data_processor = DataProcessor()
