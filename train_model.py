"""
Train ML models on network intrusion dataset
"""

import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from dataset_loader import dataset_loader
import os

class ModelTrainer:
    """Train and evaluate ML models for NIDS"""
    
    def __init__(self):
        self.models = {}
        self.results = {}
        self.best_model = None
        self.best_model_name = None
        self.best_accuracy = 0
    
    def train_random_forest(self, X_train, y_train, X_test, y_test):
        """Train Random Forest model"""
        print("\n" + "="*50)
        print("Training Random Forest Classifier...")
        print("="*50)
        
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1,
            verbose=1
        )
        
        rf_model.fit(X_train, y_train)
        y_pred = rf_model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        print(f"\nRandom Forest Accuracy: {accuracy:.4f}")
        
        self.models['RandomForest'] = rf_model
        self.results['RandomForest'] = {
            'accuracy': accuracy,
            'predictions': y_pred
        }
        
        if accuracy > self.best_accuracy:
            self.best_accuracy = accuracy
            self.best_model = rf_model
            self.best_model_name = 'RandomForest'
        
        return rf_model, accuracy
    
    def train_svm(self, X_train, y_train, X_test, y_test):
        """Train SVM model"""
        print("\n" + "="*50)
        print("Training SVM Classifier...")
        print("="*50)
        
        # Use a subset for SVM due to computational constraints
        sample_size = min(10000, len(X_train))
        indices = np.random.choice(len(X_train), sample_size, replace=False)
        
        svm_model = SVC(
            kernel='rbf',
            C=1.0,
            random_state=42,
            verbose=True
        )
        
        svm_model.fit(X_train[indices], y_train[indices])
        y_pred = svm_model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        print(f"\nSVM Accuracy: {accuracy:.4f}")
        
        self.models['SVM'] = svm_model
        self.results['SVM'] = {
            'accuracy': accuracy,
            'predictions': y_pred
        }
        
        if accuracy > self.best_accuracy:
            self.best_accuracy = accuracy
            self.best_model = svm_model
            self.best_model_name = 'SVM'
        
        return svm_model, accuracy
    
    def train_neural_network(self, X_train, y_train, X_test, y_test):
        """Train Neural Network model"""
        print("\n" + "="*50)
        print("Training Neural Network...")
        print("="*50)
        
        nn_model = MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            activation='relu',
            solver='adam',
            max_iter=50,
            random_state=42,
            verbose=True
        )
        
        nn_model.fit(X_train, y_train)
        y_pred = nn_model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        print(f"\nNeural Network Accuracy: {accuracy:.4f}")
        
        self.models['NeuralNetwork'] = nn_model
        self.results['NeuralNetwork'] = {
            'accuracy': accuracy,
            'predictions': y_pred
        }
        
        if accuracy > self.best_accuracy:
            self.best_accuracy = accuracy
            self.best_model = nn_model
            self.best_model_name = 'NeuralNetwork'
        
        return nn_model, accuracy
    
    def train_all_models(self, X_train, y_train, X_test, y_test):
        """Train all models and compare"""
        print("\n" + "="*70)
        print("  TRAINING NETWORK INTRUSION DETECTION MODELS")
        print("="*70)
        
        # Train Random Forest
        self.train_random_forest(X_train, y_train, X_test, y_test)
        
        # Train Neural Network (skip SVM for faster training)
        self.train_neural_network(X_train, y_train, X_test, y_test)
        
        # Print summary
        print("\n" + "="*50)
        print("  MODEL COMPARISON")
        print("="*50)
        for model_name, results in self.results.items():
            print(f"{model_name}: {results['accuracy']:.4f}")
        
        print(f"\nBest Model: {self.best_model_name} (Accuracy: {self.best_accuracy:.4f})")
        
        return self.best_model, self.best_model_name
    
    def save_best_model(self, filename='models/best_model.pkl'):
        """Save the best performing model"""
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        model_data = {
            'model': self.best_model,
            'model_name': self.best_model_name,
            'accuracy': self.best_accuracy,
            'label_encoder': dataset_loader.label_encoder,
            'scaler': dataset_loader.scaler,
            'feature_names': dataset_loader.feature_names
        }
        
        with open(filename, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"\nBest model saved to {filename}")
    
    def load_trained_model(self, filename='models/best_model.pkl'):
        """Load a trained model"""
        if os.path.exists(filename):
            with open(filename, 'rb') as f:
                model_data = pickle.load(f)
            
            self.best_model = model_data['model']
            self.best_model_name = model_data['model_name']
            self.best_accuracy = model_data['accuracy']
            
            print(f"Model loaded: {self.best_model_name} (Accuracy: {self.best_accuracy:.4f})")
            return model_data
        return None

if __name__ == '__main__':
    print("="*70)
    print("  SentinelNet NIDS - Model Training")
    print("="*70)
    
    # Load dataset
    if not dataset_loader.load_preprocessed_data():
        print("\nPreprocessed data not found. Loading raw dataset...")
        if dataset_loader.load_nsl_kdd():
            dataset_loader.save_preprocessed_data()
        else:
            print("\nERROR: Could not load dataset!")
            print("Please download the NSL-KDD dataset and place the CSV files in the 'data' directory")
            exit(1)
    
    # Train models
    trainer = ModelTrainer()
    best_model, best_name = trainer.train_all_models(
        dataset_loader.X_train,
        dataset_loader.y_train,
        dataset_loader.X_test,
        dataset_loader.y_test
    )
    
    # Save best model
    trainer.save_best_model()
    
    print("\n" + "="*70)
    print("  Training Complete!")
    print("="*70)
