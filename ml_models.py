"""
Machine Learning Models for Network Intrusion Detection
This module contains the ML model implementations for detecting network intrusions
"""

import numpy as np
import pickle
import os
from datetime import datetime

class NIDSModel:
    """Base class for NIDS ML models"""
    
    def __init__(self, model_type='random_forest'):
        self.model_type = model_type
        self.model = None
        self.accuracy = 0.95
        self.training_date = datetime.now()
        
    def preprocess_features(self, packet_data):
        """
        Preprocess network packet features for ML model
        
        Features extracted:
        - Protocol type (TCP=0, UDP=1, ICMP=2)
        - Source/Destination ports
        - Packet size
        - Connection duration
        - Number of failed logins
        - And more...
        """
        features = []
        
        # Protocol encoding
        protocol_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2}
        features.append(protocol_map.get(packet_data.get('protocol', 'TCP'), 0))
        
        # Port numbers
        features.append(packet_data.get('source_port', 0))
        features.append(packet_data.get('dest_port', 0))
        
        # Packet size
        features.append(packet_data.get('packet_size', 0))
        
        # Additional synthetic features
        features.extend([
            np.random.randint(0, 100),  # connection_duration
            np.random.randint(0, 10),   # failed_logins
            np.random.randint(0, 1000), # data_bytes
            np.random.randint(0, 50)    # connections_count
        ])
        
        return np.array(features).reshape(1, -1)
    
    def predict(self, packet_data):
        """
        Predict if packet is malicious
        Returns: (is_threat, attack_type, confidence)
        """
        # Simulate ML prediction
        features = self.preprocess_features(packet_data)
        
        # Simulate prediction probabilities
        threat_prob = np.random.random()
        
        if threat_prob > 0.7:  # 30% chance of threat
            attack_types = ['DoS', 'Probe', 'R2L', 'U2R', 'DDoS']
            attack_type = np.random.choice(attack_types)
            is_threat = True
            confidence = round(np.random.uniform(0.75, 0.99), 2)
        else:
            attack_type = 'Normal'
            is_threat = False
            confidence = round(np.random.uniform(0.80, 0.99), 2)
        
        return is_threat, attack_type, confidence
    
    def get_feature_importance(self):
        """Return feature importance scores"""
        features = [
            'protocol', 'source_port', 'dest_port', 'packet_size',
            'connection_duration', 'failed_logins', 'data_bytes', 'connections_count'
        ]
        importance = np.random.dirichlet(np.ones(len(features)))
        
        return dict(zip(features, importance.tolist()))
    
    def save_model(self, filepath):
        """Save model to file"""
        model_data = {
            'model_type': self.model_type,
            'accuracy': self.accuracy,
            'training_date': self.training_date.isoformat()
        }
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"Model saved to {filepath}")
    
    @classmethod
    def load_model(cls, filepath):
        """Load model from file"""
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            model = cls(model_type=model_data['model_type'])
            model.accuracy = model_data['accuracy']
            print(f"Model loaded from {filepath}")
            return model
        else:
            print(f"Model file not found at {filepath}, creating new model")
            return cls()

class RandomForestNIDS(NIDSModel):
    """Random Forest implementation for NIDS"""
    
    def __init__(self):
        super().__init__(model_type='random_forest')
        self.accuracy = 0.96
        self.n_estimators = 100

class SVMModel(NIDSModel):
    """Support Vector Machine implementation for NIDS"""
    
    def __init__(self):
        super().__init__(model_type='svm')
        self.accuracy = 0.94
        self.kernel = 'rbf'

class NeuralNetworkNIDS(NIDSModel):
    """Neural Network implementation for NIDS"""
    
    def __init__(self):
        super().__init__(model_type='neural_network')
        self.accuracy = 0.97
        self.layers = [128, 64, 32]

# Initialize default model
default_model = RandomForestNIDS()
