import os

def setup_data_directory():
    """Create data directory if it doesn't exist"""
    if not os.path.exists('data'):
        os.makedirs('data')
        print("✓ Created 'data' directory")
    else:
        print("✓ 'data' directory already exists")
    
    # Check if test file exists
    if os.path.exists('data/KDDTest+.arff'):
        print("✓ KDDTest+.arff found")
        # Count lines
        with open('data/KDDTest+.arff', 'r') as f:
            lines = len(f.readlines())
        print(f"  Dataset contains {lines} lines")
    else:
        print("✗ KDDTest+.arff not found")
        print("  Please place your KDDTest+.arff file in the 'data' directory")
    
    print("\n" + "="*50)
    print("Setup complete! You can now run: python app.py")
    print("="*50)

if __name__ == "__main__":
    setup_data_directory()
