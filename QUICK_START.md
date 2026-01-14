# SentinelNet NIDS - Quick Start Guide

## Overview
This Network Intrusion Detection System uses real NSL-KDD dataset for threat detection with automatic statistics reset on each startup.

## File Structure
```
sentinelnet-nids/
├── app.py                 # Main Flask application
├── arff_parser.py         # ARFF format parser
├── requirements.txt       # Python dependencies
├── data/
│   └── KDDTest+.arff     # NSL-KDD test dataset (place here)
├── templates/
│   └── index.html        # Dashboard UI
└── static/
    ├── css/
    │   └── style.css     # Styles
    └── js/
        └── app.js        # Frontend logic
```

## Installation & Setup

### Step 1: Install Dependencies
```bash
# Install Python packages
pip install -r requirements.txt
```

### Step 2: Add Dataset (IMPORTANT)
Place your `KDDTest+.arff` file in the `data/` directory:

```bash
# Create data directory if it doesn't exist
mkdir data

# Copy your ARFF file
# Place KDDTest+.arff into the data/ folder
```

### Step 3: Run the Application
```bash
python app.py
```

### Step 4: Access Dashboard
Open your browser and navigate to:
```
http://localhost:5000
```

## Features

### Fresh Start on Every Run
- All statistics reset to **0** when you restart the app
- No persistent data between sessions
- Clean slate for each monitoring session

### Dataset Mode
When `KDDTest+.arff` is present:
- Uses real NSL-KDD test data for predictions
- Classifies normal vs anomaly traffic
- Displays actual network intrusion patterns

### Simulation Mode
When dataset is not available:
- Falls back to simulated packet generation
- Still fully functional for demonstration
- Random but realistic attack patterns

### Dashboard Controls
1. **Start Monitoring** - Begin real-time packet analysis
2. **Stop Monitoring** - Pause monitoring
3. **Refresh Data** - Update statistics display
4. **Reset Stats** - Reset all counters to 0

## Dashboard Sections

### 1. Statistics Cards
- Total Packets Analyzed
- Threats Detected
- Normal Traffic
- Model Accuracy

### 2. Attack Distribution Chart
- Visual breakdown of attack types
- DoS, Probe, R2L, U2R categories

### 3. Threat Severity Levels
- Low, Medium, High, Critical
- Progress bars with percentages

### 4. Recent Alerts
- High/Critical severity alerts only
- Timestamp, source IP, attack type

### 5. Packet Analysis Table
- Real-time packet details
- Source/destination info
- Attack classification

## Troubleshooting

### Issue: Dataset not loading
**Solution:**
- Verify `KDDTest+.arff` is in the `data/` directory
- Check file permissions
- Ensure file is not corrupted

### Issue: Port 5000 already in use
**Solution:**
```bash
# Use a different port
python app.py --port 5001
```

Or modify `app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=5001)
```

### Issue: Python 3.13 dependency errors
**Solution:**
```bash
# Uninstall conflicting packages
pip uninstall numpy pandas scikit-learn -y

# Reinstall with compatible versions
pip install -r requirements.txt
```

## Key Points

✓ **Fresh Start**: Statistics always start at 0  
✓ **Real Data**: Uses actual NSL-KDD test dataset  
✓ **No Training Required**: Works directly with test data  
✓ **Automatic Fallback**: Works without dataset (simulation mode)  
✓ **Real-time Monitoring**: Live packet analysis and alerts  

## Next Steps

1. Ensure dataset is in place
2. Run the application
3. Click "Start Monitoring"
4. Observe real-time threat detection
5. Use "Reset Stats" to clear and start fresh

## Support

For issues or questions, check the console output when running `python app.py` for detailed status messages.
