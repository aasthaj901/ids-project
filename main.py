import time
import logging
import threading
import signal
import sys
from config.logging_config import setup_logging
from src.dpi_layer import DPILayer
from src.ml_layer import MLLayer
from src.packet_capture import PacketCapture
from src.threat_intelligence import ThreatIntelligence
from src.traffic_simulator import TrafficSimulator  # Import the traffic simulator

# Setup logging
logger, block_logger, packet_logger = setup_logging()

def main():
    logger.info("Starting Intrusion Detection System")
    
    # Initialize components
    dpi_layer = DPILayer()
    ml_layer = MLLayer()
    packet_capture = PacketCapture(dpi_layer, ml_layer, packet_logger)
    
    # Signal handler for graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Shutting down...")
        packet_capture.stop()
        ml_layer.stop_processing()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start components
    packet_capture.start()
    ml_layer.start_processing(packet_capture)
    
    logger.info("IDS is running. Press Ctrl+C to stop.")

    # Threat Intelligence check (example usage)
    ti = ThreatIntelligence()
    logger.info(f"Is 8.8.8.8 malicious? {ti.is_malicious('8.8.8.8')}")

    # Simulate suspicious traffic
    traffic_simulator = TrafficSimulator(ti)  # Create TrafficSimulator instance
    logger.info("Simulating suspicious traffic...")
    traffic_simulator.generate_suspicious_traffic()  # Simulate traffic

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        packet_capture.stop()
        ml_layer.stop_processing()

if __name__ == "__main__":
    main()
