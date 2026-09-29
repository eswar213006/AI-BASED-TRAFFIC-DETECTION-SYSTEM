import os

# Base Directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Directories
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
DATABASE_DIR = os.path.join(BASE_DIR, 'database')

# Files
DATABASE_PATH = os.path.join(DATABASE_DIR, 'network_ids.db')
MODEL_PATH = os.path.join(MODELS_DIR, 'intrusion_model.pkl')
TRAFFIC_CSV_PATH = os.path.join(DATA_DIR, 'network_traffic.csv')
ALERTS_CSV_PATH = os.path.join(DATA_DIR, 'alerts.csv')

# Flask Configuration
SECRET_KEY = os.environ.get('SECRET_KEY', 'cyber-security-ids-secret-key-2026')
DEBUG = True
PORT = 5000
HOST = '127.0.0.1'

# Live Monitoring Settings
MONITORING_INTERVAL = 3  # seconds
