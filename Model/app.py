from flask import Flask, request, jsonify
import pandas as pd
import joblib
import numpy as np

app = Flask(__name__)

# --- LOAD YOUR ASSETS ---
# Ensure you saved these from your KDD1.ipynb using joblib.dump()
model = joblib.load('nids_model.pkl')
# You need the encoders to turn "tcp" into 1, etc.
encoders = joblib.load('encoders.pkl') 

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        df = pd.DataFrame([data])
        
        # 1. Preprocess categorical features exactly like the notebook
        categorical_cols = ['protocol_type', 'service', 'flag']
        for col in categorical_cols:
            if col in df.columns:
                le = encoders[col]
                # Handle new/unseen labels gracefully
                df[col] = df[col].map(lambda s: le.transform([s])[0] if s in le.classes_ else 0)

        # 2. Ensure order of columns matches training exactly (42 columns)
        # Convert to numpy array to remove feature names warning
        prediction = model.predict(df.values)[0]
        
        return jsonify({'prediction': str(prediction)})
    
    except Exception as e:
        print(f"Backend Error: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)