# SentinelNet - AI-Powered Network Intrusion Detection System (NIDS)

![SentinelNet Dashboard](https://via.placeholder.com/800x400/0f172a/2563eb?text=SentinelNet+NIDS+Dashboard)

An advanced Network Intrusion Detection System powered by Machine Learning algorithms for real-time detection and classification of network threats.

## Features

- **Real-time Network Monitoring**: Continuous analysis of network traffic with live updates
- **AI-Powered Detection**: Machine learning models (Random Forest, SVM, Neural Networks) for accurate threat detection
- **Interactive Dashboard**: Beautiful, responsive web interface with real-time statistics and visualizations
- **Multi-Attack Classification**: Detects various attack types including DoS, DDoS, Probe, R2L, and U2R
- **Alert Management**: Automatic alert generation for high-severity threats
- **Performance Metrics**: Track model accuracy, packets analyzed, and threat statistics
- **Zero Database Dependency**: In-memory storage for quick setup and testing

## Project Structure

```
SentinelNet-NIDS/
│
├── app.py                  # Main Flask application
├── ml_models.py            # Machine learning models implementation
├── data_processor.py       # Data processing and feature engineering
├── requirements.txt        # Python dependencies
│
├── templates/
│   └── index.html         # Dashboard HTML template
│
├── static/
│   ├── css/
│   │   └── style.css      # Dashboard styling
│   └── js/
│       └── app.js         # Dashboard JavaScript logic
│
└── README.md              # This file
```

## Prerequisites

Before running the application, ensure you have the following installed:

- Python 3.8 or higher
- pip (Python package manager)
- A modern web browser (Chrome, Firefox, Safari, or Edge)

## Installation Steps

### Step 1: Clone or Download the Project

```bash
# If using Git
git clone <repository-url>
cd SentinelNet-NIDS

# Or download and extract the ZIP file
```

### Step 2: Create a Virtual Environment (Recommended)

Creating a virtual environment helps isolate project dependencies.

**On Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**On macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

You should see `(venv)` in your terminal prompt, indicating the virtual environment is active.

### Step 3: Install Dependencies

Install all required Python packages:

```bash
pip install -r requirements.txt
```

This will install:
- Flask (web framework)
- Flask-CORS (Cross-Origin Resource Sharing)
- NumPy (numerical computing)
- Pandas (data manipulation)
- scikit-learn (machine learning)

### Step 4: Verify Installation

Check if all packages are installed correctly:

```bash
pip list
```

You should see all the packages from requirements.txt listed.

## Running the Application

### Step 1: Start the Flask Server

From the project root directory (where app.py is located), run:

```bash
python app.py
```

You should see output similar to:

```
Starting SentinelNet NIDS...
Dashboard will be available at http://localhost:5000
 * Running on http://0.0.0.0:5000
 * Debug mode: on
```

### Step 2: Access the Dashboard

Open your web browser and navigate to:

```
http://localhost:5000
```

You should see the SentinelNet dashboard interface.

### Step 3: Start Monitoring

1. Click the **"Start Monitoring"** button in the top-right corner
2. The system will begin simulating network traffic analysis
3. Watch as statistics, alerts, and packet information update in real-time
4. The dashboard auto-refreshes every 5 seconds while monitoring is active

## Using the Dashboard

### Main Features

#### 1. Statistics Cards (Top Section)
- **Total Packets**: Number of packets analyzed
- **Threats Detected**: Number of malicious packets identified
- **Normal Traffic**: Number of legitimate packets
- **Model Accuracy**: Current ML model performance

#### 2. Attack Type Distribution Chart
- Visual breakdown of detected attack types
- Doughnut chart showing DoS, Probe, R2L, U2R, DDoS attacks
- Click the refresh icon to update

#### 3. Threat Severity Levels
- Bar chart showing threat distribution by severity
- Critical, High, Medium, and Low severity counts

#### 4. Recent Alerts
- List of high-severity threats detected
- Shows timestamp, severity level, and attack details
- Automatically updates with new alerts

#### 5. Recent Packet Analysis
- Detailed view of analyzed network packets
- Shows source/destination IPs and ports
- Displays attack classification and confidence score

#### 6. System Controls
- **Refresh Data**: Manually update all dashboard components
- **Reset Statistics**: Clear all data and start fresh (requires confirmation)

### Monitoring Controls

- **Start Monitoring**: Begins continuous network traffic simulation
- **Stop Monitoring**: Pauses traffic analysis (data is retained)
- **Status Indicator**: Shows whether monitoring is active (green) or inactive (gray)

## Understanding the Output

### Attack Types

- **Normal**: Legitimate network traffic
- **DoS (Denial of Service)**: Attacks that flood a network or system
- **DDoS (Distributed DoS)**: Coordinated DoS attacks from multiple sources
- **Probe**: Reconnaissance attacks scanning for vulnerabilities
- **R2L (Remote to Local)**: Unauthorized access from remote machines
- **U2R (User to Root)**: Privilege escalation attacks

### Severity Levels

- **Critical**: Immediate action required, high-impact threats
- **High**: Significant threats requiring prompt attention
- **Medium**: Moderate threats that should be investigated
- **Low**: Minor threats or suspicious activity

### Confidence Score

The ML model provides a confidence percentage (75-99%) for each classification, indicating how certain it is about the prediction.

## Troubleshooting

### Common Issues and Solutions

#### 1. Port Already in Use

**Error**: `Address already in use`

**Solution**: 
- Another application is using port 5000
- Stop the other application or change the port in `app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=5001)  # Changed to 5001
```

#### 2. Module Not Found Error

**Error**: `ModuleNotFoundError: No module named 'flask'`

**Solution**:
- Ensure virtual environment is activated
- Reinstall dependencies: `pip install -r requirements.txt`

#### 3. Dashboard Not Loading

**Problem**: Blank page or errors in browser

**Solution**:
- Check browser console for errors (F12 → Console tab)
- Ensure Flask server is running
- Clear browser cache and reload (Ctrl+Shift+R or Cmd+Shift+R)
- Check if all static files are present in `static/` directories

#### 4. Charts Not Displaying

**Problem**: Chart containers are empty

**Solution**:
- Ensure Chart.js CDN is accessible (requires internet connection)
- Check browser console for JavaScript errors
- Try refreshing the page

#### 5. No Data Appearing

**Problem**: Dashboard shows zeros or empty states

**Solution**:
- Click "Start Monitoring" button
- Wait a few seconds for data generation
- Click "Refresh Data" button
- Check Flask terminal for errors

#### 6. Virtual Environment Issues

**Problem**: Cannot activate virtual environment

**Solution on Windows**:
- If getting execution policy error:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Solution on macOS/Linux**:
- Ensure you have correct permissions:
```bash
chmod +x venv/bin/activate
```

## Stopping the Application

To stop the Flask server:

1. Go to the terminal where the server is running
2. Press `Ctrl+C` (or `Cmd+C` on macOS)
3. The server will shut down gracefully

To deactivate the virtual environment:

```bash
deactivate
```

## Customization and Extension

### Modifying Simulation Parameters

Edit `app.py` to adjust simulation behavior:

```python
# Change attack probability (line ~30)
ATTACK_TYPES = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R', 'DDoS']
# Adjust weights: [Normal, DoS, Probe, R2L, U2R, DDoS]
weights=[70, 10, 8, 5, 2, 5]  # Higher Normal = less attacks

# Change monitoring interval (line ~140)
time.sleep(random.uniform(0.5, 2))  # Adjust delay between packets
```

### Adding Real Network Capture

To integrate with actual network traffic:

1. Install Scapy: `pip install scapy`
2. Modify `app.py` to capture real packets
3. Extract features from actual network data
4. Feed to ML models for classification

### Training Custom Models

To train models with real datasets (NSL-KDD, CICIDS2017):

1. Download dataset from provided links
2. Use `data_processor.py` to preprocess data
3. Implement training in `ml_models.py`
4. Save trained models using pickle
5. Load models in `app.py` for predictions

## Project Architecture

### Backend (Python/Flask)

- **app.py**: REST API endpoints, background monitoring thread
- **ml_models.py**: ML model classes and prediction logic
- **data_processor.py**: Feature extraction and data preprocessing

### Frontend (HTML/CSS/JavaScript)

- **index.html**: Dashboard structure and layout
- **style.css**: Professional cybersecurity-themed styling
- **app.js**: Real-time data fetching, chart updates, user interactions

### API Endpoints

- `GET /`: Dashboard homepage
- `GET /api/statistics`: Current system statistics
- `GET /api/alerts`: Recent security alerts
- `GET /api/recent-packets`: Latest analyzed packets
- `GET /api/attack-distribution`: Attack type breakdown
- `POST /api/monitoring/start`: Start monitoring
- `POST /api/monitoring/stop`: Stop monitoring
- `GET /api/monitoring/status`: Check monitoring status
- `POST /api/reset`: Reset all statistics

## Performance Considerations

### Memory Usage

- In-memory storage limits:
  - Maximum 50 alerts retained
  - Statistics persist until reset
  - No long-term data storage

### Scalability

For production use:
- Implement database storage (PostgreSQL, MongoDB)
- Add rate limiting and caching
- Use message queues (Redis, RabbitMQ) for packet processing
- Deploy with production WSGI server (Gunicorn, uWSGI)

## Security Notes

This is a demonstration/educational system. For production:

- Implement authentication and authorization
- Use HTTPS/TLS encryption
- Validate and sanitize all inputs
- Implement proper logging and auditing
- Follow security best practices for web applications

## Future Enhancements

- Real-time packet capture from network interfaces
- Integration with actual datasets (NSL-KDD, CICIDS2017)
- Advanced anomaly detection with unsupervised learning
- Email/SMS alert notifications
- Export reports (PDF, CSV)
- Multi-user support with role-based access
- Historical data analysis and trends
- Integration with SIEM systems

## Educational Resources

### Datasets

- **NSL-KDD**: https://www.unb.ca/cic/datasets/nsl.html
- **CICIDS2017**: https://www.unb.ca/cic/datasets/ids-2017.html

### Learn More About

- Network security fundamentals
- Machine learning for cybersecurity
- Flask web development
- Network packet analysis with Scapy
- Intrusion detection systems (IDS/IPS)

## License

This project is for educational purposes. Feel free to modify and extend for learning and research.

## Support

For issues or questions:
1. Check the Troubleshooting section
2. Review Flask and Python documentation
3. Examine browser console for client-side errors
4. Check Flask terminal output for server-side errors

## Credits

Developed as an AI-powered Network Intrusion Detection System demonstration project.

---

**Note**: This system simulates network traffic for demonstration. For real-world deployment, integrate with actual network capture tools and trained ML models using production datasets.
