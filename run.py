"""
SentinelNet NIDS - Main Entry Point
Simple script to run the application with proper configuration
"""

import json
import sys
from app import app

def load_config():
    """Load configuration from config.json"""
    try:
        with open('config.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("Warning: config.json not found, using default configuration")
        return None
    except json.JSONDecodeError:
        print("Error: Invalid JSON in config.json")
        sys.exit(1)

def main():
    """Main entry point"""
    print("=" * 60)
    print("   SentinelNet - AI-Powered Network Intrusion Detection   ")
    print("=" * 60)
    print()
    
    config = load_config()
    
    if config:
        host = config['server']['host']
        port = config['server']['port']
        debug = config['server']['debug']
    else:
        host = '0.0.0.0'
        port = 5000
        debug = True
    
    print(f"Starting SentinelNet NIDS...")
    print(f"Server: http://localhost:{port}")
    print(f"Debug Mode: {'ON' if debug else 'OFF'}")
    print()
    print("Press Ctrl+C to stop the server")
    print("-" * 60)
    print()
    
    try:
        app.run(debug=debug, host=host, port=port)
    except KeyboardInterrupt:
        print("\n\nShutting down SentinelNet NIDS...")
        print("Goodbye!")
        sys.exit(0)

if __name__ == '__main__':
    main()
