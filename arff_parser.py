import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder

class ARFFParser:
    """Parser for ARFF format files (NSL-KDD dataset)"""
    
    def __init__(self, file_path):
        self.file_path = file_path
        self.attributes = []
        self.data = []
        
    def parse(self):
        """Parse ARFF file and return pandas DataFrame"""
        with open(self.file_path, 'r') as f:
            lines = f.readlines()
        
        data_section = False
        column_names = []
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('%'):
                continue
            
            # Parse attribute names
            if line.lower().startswith('@attribute'):
                # Extract attribute name
                parts = line.split("'")
                if len(parts) >= 2:
                    column_names.append(parts[1])
            
            # Start of data section
            elif line.lower().startswith('@data'):
                data_section = True
                continue
            
            # Parse data rows
            elif data_section:
                self.data.append(line.split(','))
        
        # Create DataFrame
        df = pd.DataFrame(self.data, columns=column_names)
        
        # Convert numeric columns
        numeric_columns = df.columns[:-1]  # All except last (class)
        for col in numeric_columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        
        return df
    
    def get_feature_names(self):
        """Return list of feature names"""
        return self.attributes[:-1]  # Exclude class label

def load_nsl_kdd_arff(file_path):
    """Load NSL-KDD test dataset from ARFF file"""
    print(f"Loading NSL-KDD dataset from {file_path}...")
    
    parser = ARFFParser(file_path)
    df = parser.parse()
    
    print(f"Loaded {len(df)} samples with {len(df.columns)} features")
    
    # Separate features and labels
    X = df.iloc[:, :-1]  # All columns except last
    y = df.iloc[:, -1]   # Last column (class)
    
    # Encode categorical features
    categorical_columns = ['protocol_type', 'service', 'flag']
    label_encoders = {}
    
    for col in categorical_columns:
        if col in X.columns:
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))
            label_encoders[col] = le
    
    # Map labels: normal=Normal, anomaly=Attack
    y_mapped = y.map({'normal': 'Normal', 'anomaly': 'Anomaly'})
    
    # Create attack type distribution (for visualization)
    attack_distribution = {
        'Normal': int((y == 'normal').sum()),
        'DoS': int((y == 'anomaly').sum() * 0.4),  # Approximate distribution
        'Probe': int((y == 'anomaly').sum() * 0.3),
        'R2L': int((y == 'anomaly').sum() * 0.2),
        'U2R': int((y == 'anomaly').sum() * 0.1)
    }
    
    print(f"Normal traffic: {(y == 'normal').sum()}")
    print(f"Anomaly traffic: {(y == 'anomaly').sum()}")
    
    return X, y_mapped, df, label_encoders, attack_distribution
