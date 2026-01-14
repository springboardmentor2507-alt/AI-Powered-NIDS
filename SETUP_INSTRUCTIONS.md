# SentinelNet NIDS - Complete Setup Guide

## Step-by-Step Instructions (No Errors)

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Verify Data Directory Setup

Your test dataset has been automatically added to the project!

Run this to verify:
```bash
python setup_data.py
```

You should see:
```
✓ 'data' directory already exists
✓ KDDTest+.arff found
  Dataset contains 22544 lines
```

### 3. Run the Application

```bash
python app.py
```

The application will:
- Start fresh with all values at 0
- Load the NSL-KDD test dataset
- Use pre-trained models to classify network traffic
- Display real intrusion detection results on the dashboard

### 4. Access the Dashboard

Open your browser to: **http://localhost:5000**

### 5. Start Monitoring

Click the **"Start Monitoring"** button in the top-right corner.

You'll see:
- Real-time statistics updating
- Attack types from actual dataset (DoS, Probe, R2L, U2R)
- Threat severity levels
- Recent alerts with real packet data
- Packet analysis showing source IPs, destinations, and classifications

---

## What the App Does

✅ **Resets to 0 on each restart** - Fresh start every time
✅ **Uses real NSL-KDD test data** - No simulation, actual network traffic
✅ **Pre-trained ML models** - Random Forest classifier included
✅ **Real-time predictions** - Classifies each packet as Normal or Attack type
✅ **Professional dashboard** - Charts, alerts, and monitoring interface

---

## Troubleshooting

### Issue: "ARFF file not found"

**Solution:** The file should already be in `data/KDDTest+.arff`. Verify by running:
```bash
python setup_data.py
```

### Issue: "No module named 'scipy'"

**Solution:** Reinstall dependencies:
```bash
pip install -r requirements.txt
```

### Issue: Port 5000 already in use

**Solution:** Kill the existing process or change the port in `app.py`:
```python
app.run(debug=True, port=5001)  # Change to any available port
```

---

## File Structure

```
sentinelnet-nids/
├── app.py                    # Main Flask application
├── arff_parser.py           # Parses NSL-KDD ARFF format
├── ml_models.py             # Pre-trained ML models
├── data_processor.py        # Data preprocessing
├── setup_data.py            # Verify data setup
├── requirements.txt         # Python dependencies
├── data/
│   └── KDDTest+.arff       # Test dataset (22,544 samples)
├── templates/
│   └── index.html          # Dashboard HTML
└── static/
    ├── css/
    │   └── style.css       # Dashboard styling
    └── js/
        └── app.js          # Frontend JavaScript
```

---

## Ready to Run!

Everything is configured. Just run:
```bash
python app.py
```

And open **http://localhost:5000** in your browser! 🚀
