# Dataset Setup Guide for SentinelNet NIDS

This guide explains how to set up the NSL-KDD dataset to use real intrusion detection with trained ML models.

## Quick Start

### Option 1: Use Simulation Mode (No Setup Required)
Simply run `python app.py` - the system will work in simulation mode without any dataset.

### Option 2: Use Real Dataset & Trained Models

## Step-by-Step Setup

### 1. Download the NSL-KDD Dataset

**Download Links:**
- **NSL-KDD Dataset**: https://www.unb.ca/cic/datasets/nsl.html
- **Direct Download**: https://github.com/defcom17/NSL_KDD

**What you need:**
- `KDDTrain+.txt` or `KDDTrain+.csv`
- `KDDTest+.txt` or `KDDTest+.csv`

### 2. Prepare Dataset Files

1. Create a `data` directory in your project folder:
   ```bash
   mkdir data
   ```

2. Place the downloaded files in the `data` directory

3. If files are `.txt`, rename them to `.csv`:
   ```bash
   # Windows
   ren data\KDDTrain+.txt KDDTrain+.csv
   ren data\KDDTest+.txt KDDTest+.csv
   
   # macOS/Linux
   mv data/KDDTrain+.txt data/KDDTrain+.csv
   mv data/KDDTest+.txt data/KDDTest+.csv
   ```

Your directory structure should look like:
```
SentinelNet-NIDS/
├── data/
│   ├── KDDTrain+.csv
│   └── KDDTest+.csv
├── app.py
├── train_model.py
└── dataset_loader.py
```

### 3. Train the Models

Run the training script:

```bash
python train_model.py
```

This will:
- Load and preprocess the NSL-KDD dataset
- Train multiple ML models (Random Forest, Neural Network)
- Compare model performance
- Save the best model to `models/best_model.pkl`
- Save preprocessed data for faster loading

**Expected Output:**
```
==================================================================
  TRAINING NETWORK INTRUSION DETECTION MODELS
==================================================================

Dataset loaded successfully!
Training samples: 125973
Testing samples: 22544
Attack categories: ['DoS', 'Normal', 'Probe', 'R2L', 'U2R']

==================================================
Training Random Forest Classifier...
==================================================
[Random Forest training progress...]

Random Forest Accuracy: 0.9645

==================================================
Training Neural Network...
==================================================
[Neural Network training progress...]

Neural Network Accuracy: 0.9512

==================================================
  MODEL COMPARISON
==================================================
RandomForest: 0.9645
NeuralNetwork: 0.9512

Best Model: RandomForest (Accuracy: 0.9645)

Best model saved to models/best_model.pkl

==================================================================
  Training Complete!
==================================================================
```

### 4. Run the Application

```bash
python app.py
```

You should see:
```
======================================================================
  SentinelNet NIDS - Network Intrusion Detection System
======================================================================

✓ Trained model loaded successfully!
  Model: RandomForest
  Accuracy: 96.45%

✓ Test dataset loaded: 22544 samples

  Mode: TRAINED MODEL
  Model: RandomForest
  Accuracy: 96.45%

  Dashboard: http://localhost:5000
======================================================================
```

### 5. Access the Dashboard

Open your browser to **http://localhost:5000**

The dashboard will now show:
- Real predictions from trained ML models
- Actual dataset samples being analyzed
- True model accuracy (not simulated)

## Dataset Information

### NSL-KDD Dataset

**Attack Categories:**
- **Normal**: Legitimate network traffic
- **DoS**: Denial of Service attacks (back, land, neptune, pod, smurf, teardrop)
- **Probe**: Surveillance and probing attacks (ipsweep, nmap, portsweep, satan)
- **R2L**: Remote to Local attacks (ftp_write, guess_passwd, imap, multihop, phf, spy, warezclient, warezmaster)
- **U2R**: User to Root attacks (buffer_overflow, loadmodule, perl, rootkit)

**Dataset Size:**
- Training: ~125,000 records
- Testing: ~22,000 records
- Features: 41 features per record

**Features Include:**
- Duration of connection
- Protocol type (TCP, UDP, ICMP)
- Service (HTTP, FTP, SMTP, etc.)
- Connection flags
- Bytes sent/received
- Failed login attempts
- Root access attempts
- And many more...

## Troubleshooting

### Issue: "Dataset file not found"

**Solution:**
- Ensure CSV files are in the `data` directory
- Check file names: `KDDTrain+.csv` and `KDDTest+.csv`
- Verify files are not empty

### Issue: Training takes too long

**Solution:**
- The training script uses Random Forest and Neural Network (SVM is commented out for speed)
- On a modern CPU, training should take 5-15 minutes
- You can reduce the dataset size for testing:
  ```python
  # In train_model.py, add after loading:
  X_train = X_train[:10000]  # Use only 10,000 samples
  y_train = y_train[:10000]
  ```

### Issue: Out of memory during training

**Solution:**
- Reduce batch size or dataset size
- Use only Random Forest model (comment out Neural Network)
- Close other applications to free up RAM

### Issue: Model accuracy shown as 95% instead of real accuracy

**Solution:**
- This means the trained model wasn't loaded
- Check if `models/best_model.pkl` exists
- Re-run `python train_model.py`
- Restart the Flask app

## Switching Between Modes

### Use Simulation Mode:
```bash
# Delete or rename the trained model
mv models/best_model.pkl models/best_model.pkl.backup
python app.py
```

### Use Trained Model Mode:
```bash
# Restore the trained model
mv models/best_model.pkl.backup models/best_model.pkl
python app.py
```

## Advanced: Custom Dataset

To use a different dataset (like CICIDS2017):

1. Modify `dataset_loader.py` to support your dataset format
2. Update column names and preprocessing logic
3. Train models with your data
4. The rest of the system will work automatically

## Performance

**Simulation Mode:**
- Instant startup
- Random predictions
- ~95% simulated accuracy
- No training required

**Trained Model Mode:**
- ~5-15 minute training time (one-time)
- Real ML predictions on actual data
- 94-97% real accuracy
- Uses test dataset samples

## Next Steps

1. Experiment with different ML algorithms
2. Tune hyperparameters for better accuracy
3. Add more sophisticated feature engineering
4. Implement real-time packet capture with Scapy
5. Deploy models to production environment
