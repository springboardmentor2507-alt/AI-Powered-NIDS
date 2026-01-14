# SentinelNet NIDS - Detailed Setup Guide

This guide provides step-by-step instructions for setting up the SentinelNet Network Intrusion Detection System on different operating systems.

## Table of Contents

1. [Windows Setup](#windows-setup)
2. [macOS Setup](#macos-setup)
3. [Linux Setup](#linux-setup)
4. [Docker Setup (Optional)](#docker-setup-optional)
5. [Verification Steps](#verification-steps)

---

## Windows Setup

### Prerequisites Installation

#### 1. Install Python

1. Download Python 3.8+ from [python.org](https://www.python.org/downloads/)
2. Run the installer
3. **Important**: Check "Add Python to PATH" during installation
4. Click "Install Now"

Verify installation:
```cmd
python --version
pip --version
```

#### 2. Install Git (Optional)

Download from [git-scm.com](https://git-scm.com/download/win)

### Project Setup

#### 1. Download Project

**Option A - Using Git:**
```cmd
git clone <repository-url>
cd SentinelNet-NIDS
```

**Option B - Manual Download:**
- Download ZIP file
- Extract to desired location
- Open Command Prompt in that folder

#### 2. Create Virtual Environment

```cmd
python -m venv venv
```

#### 3. Activate Virtual Environment

```cmd
venv\Scripts\activate
```

You should see `(venv)` before your command prompt.

#### 4. Install Dependencies

```cmd
pip install -r requirements.txt
```

#### 5. Run Application

```cmd
python app.py
```

#### 6. Access Dashboard

Open browser to: `http://localhost:5000`

### Common Windows Issues

**Issue**: "execution policy" error when activating venv

**Solution**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Issue**: Python not recognized

**Solution**: Add Python to PATH manually:
1. Search "Environment Variables" in Windows
2. Edit "Path" variable
3. Add Python installation directory

---

## macOS Setup

### Prerequisites Installation

#### 1. Install Homebrew (if not installed)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### 2. Install Python

```bash
brew install python@3.11
```

Verify:
```bash
python3 --version
pip3 --version
```

### Project Setup

#### 1. Download Project

```bash
git clone <repository-url>
cd SentinelNet-NIDS
```

#### 2. Create Virtual Environment

```bash
python3 -m venv venv
```

#### 3. Activate Virtual Environment

```bash
source venv/bin/activate
```

#### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

#### 5. Run Application

```bash
python app.py
```

#### 6. Access Dashboard

Open browser to: `http://localhost:5000`

### Common macOS Issues

**Issue**: SSL certificate errors during pip install

**Solution**:
```bash
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

**Issue**: Permission denied

**Solution**:
```bash
chmod +x venv/bin/activate
```

---

## Linux Setup

### Prerequisites Installation (Ubuntu/Debian)

#### 1. Update System

```bash
sudo apt update
sudo apt upgrade
```

#### 2. Install Python and Dependencies

```bash
sudo apt install python3 python3-pip python3-venv
```

Verify:
```bash
python3 --version
pip3 --version
```

### Prerequisites Installation (Fedora/CentOS/RHEL)

```bash
sudo dnf install python3 python3-pip
```

### Project Setup

#### 1. Download Project

```bash
git clone <repository-url>
cd SentinelNet-NIDS
```

#### 2. Create Virtual Environment

```bash
python3 -m venv venv
```

#### 3. Activate Virtual Environment

```bash
source venv/bin/activate
```

#### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

#### 5. Run Application

```bash
python app.py
```

#### 6. Access Dashboard

Open browser to: `http://localhost:5000`

### Common Linux Issues

**Issue**: "externally-managed-environment" error (Python 3.11+)

**Solution**: Always use virtual environment (which you should be doing)

**Issue**: Port 5000 in use

**Solution**:
```bash
# Find process using port 5000
sudo lsof -i :5000

# Kill the process
sudo kill -9 <PID>
```

---

## Docker Setup (Optional)

For containerized deployment:

### 1. Create Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
```

### 2. Create docker-compose.yml

```yaml
version: '3.8'

services:
  sentinelnet:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./:/app
    environment:
      - FLASK_ENV=development
```

### 3. Build and Run

```bash
docker-compose up --build
```

Access at: `http://localhost:5000`

---

## Verification Steps

After setup, verify everything works:

### 1. Check Server Status

Terminal should show:
```
Starting SentinelNet NIDS...
Dashboard will be available at http://localhost:5000
* Running on http://0.0.0.0:5000
```

### 2. Test Dashboard

1. Open `http://localhost:5000` in browser
2. You should see the SentinelNet dashboard
3. All sections should be visible (no errors)

### 3. Test Monitoring

1. Click "Start Monitoring" button
2. Status should change to "Monitoring Active"
3. Statistics should start updating
4. After a few seconds, data should appear

### 4. Test API Endpoints

```bash
# Test statistics endpoint
curl http://localhost:5000/api/statistics

# Test monitoring status
curl http://localhost:5000/api/monitoring/status
```

### 5. Check Browser Console

1. Press F12 to open Developer Tools
2. Go to Console tab
3. Should see: "[v0] Initializing SentinelNet Dashboard..."
4. No red errors should appear

---

## Environment Variables (Optional)

Create a `.env` file for configuration:

```env
FLASK_ENV=development
FLASK_DEBUG=True
HOST=0.0.0.0
PORT=5000
```

Modify `app.py` to use these:

```python
import os
from dotenv import load_dotenv

load_dotenv()

if __name__ == '__main__':
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'True') == 'True'
    
    app.run(debug=debug, host=host, port=port)
```

Install python-dotenv:
```bash
pip install python-dotenv
```

---

## Production Deployment

For production use, consider:

### 1. Use Production WSGI Server

Install Gunicorn:
```bash
pip install gunicorn
```

Run with:
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### 2. Set Up Reverse Proxy

Use Nginx or Apache to proxy requests to Flask.

### 3. Enable HTTPS

Use Let's Encrypt for SSL certificates.

### 4. Implement Database

Replace in-memory storage with PostgreSQL or MongoDB.

---

## Next Steps

After successful setup:

1. Read the main [README.md](README.md)
2. Explore the dashboard features
3. Review the code to understand implementation
4. Try customizing simulation parameters
5. Consider integrating real datasets

---

## Getting Help

If you encounter issues not covered here:

1. Check terminal output for error messages
2. Check browser console (F12) for JavaScript errors
3. Verify all files are present and properly named
4. Ensure virtual environment is activated
5. Try reinstalling dependencies

---

**Happy Monitoring!**
