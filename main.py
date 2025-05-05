import logging
import os
import time
import sys
import threading

from src.packet_capture import PacketCapture
from src.dpi_layer import DPILayer
from src.ml_layer import MLLayer
from src.traffic_simulator import TrafficSimulator
from src.threat_intelligence import ThreatIntelligence
from config.settings import LOGS_DIR

# Ensure log directory exists
os.makedirs(LOGS_DIR, exist_ok=True)

# Define log file names
PACKET_LOG_FILE = 'packets.log'
BLOCK_LOG_FILE = 'blocked.log'
MAIN_LOG_FILE = 'ids.log'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, MAIN_LOG_FILE)),
        logging.StreamHandler()
    ]
)

# Set up specific loggers
packet_handler = logging.FileHandler(os.path.join(LOGS_DIR, PACKET_LOG_FILE))
packet_logger = logging.getLogger('all_packets')
packet_logger.setLevel(logging.INFO)
packet_logger.addHandler(packet_handler)

block_handler = logging.FileHandler(os.path.join(LOGS_DIR, BLOCK_LOG_FILE))
block_logger = logging.getLogger('blocked_traffic')
block_logger.setLevel(logging.INFO)
block_logger.addHandler(block_handler)

# Main logger
logger = logging.getLogger('ids')

def simulate_traffic(traffic_sim):
    """Function to periodically simulate traffic"""
    try:
        while True:
            logger.info("Simulating network traffic...")
            traffic_sim.generate_mixed_traffic(benign_count=8, malicious_count=5)
            time.sleep(10)
    except KeyboardInterrupt:
        logger.info("Traffic simulation stopped")
    except Exception as e:
        logger.error(f"Error in traffic simulation: {e}")

def main():
    try:
        # Initialize threat intelligence once
        threat_intel = ThreatIntelligence()

        # Pass it to DPI layer
        dpi_layer = DPILayer(threat_intel)
        ml_layer = MLLayer()

        # Set up packet capture
        packet_capture = PacketCapture(dpi_layer, ml_layer, packet_logger)
        packet_capture.start()
        packet_capture.start_ml_processing()

        # Start traffic simulation
        traffic_sim = TrafficSimulator(threat_intel)
        traffic_thread = threading.Thread(target=simulate_traffic, args=(traffic_sim,), daemon=True)
        traffic_thread.start()

        # Keep running
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        logger.info("Shutting down...")
        packet_capture.stop()
        packet_capture.stop_ml_processing()
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error in main function: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
