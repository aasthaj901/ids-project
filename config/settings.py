import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Network interface to monitor
#INTERFACE = os.environ.get('NETWORK_INTERFACE', 'Wi-Fi')  # Change as needed

# Threat Intelligence settings
THREAT_INTEL_UPDATE_INTERVAL = 6  # hours
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
ALIENVAULT_API_KEY = os.environ.get('ALIENVAULT_API_KEY', '')

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')
THREAT_INTEL_DIR = os.path.join(DATA_DIR, 'threat_intel')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'model_output', 'pca_model.pkl')


# Ensure directories exist
for directory in [DATA_DIR, THREAT_INTEL_DIR, LOGS_DIR]:
    os.makedirs(directory, exist_ok=True)

# DPI settings
PACKET_BUFFER_SIZE = 1000  # Max packets to buffer before processing
ML_PROCESSING_INTERVAL = 5  # seconds between ML processing