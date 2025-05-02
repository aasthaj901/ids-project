import pandas as pd
import numpy as np
import time
import threading
import pickle
import logging
import os
from config.settings import MODEL_PATH, ML_PROCESSING_INTERVAL

logger = logging.getLogger('ids')
block_logger = logging.getLogger('blocked_traffic')

class MLLayer:
    def __init__(self):
        self.model = self._load_model()
        self.processing_thread = None
        self.running = False
    
    def _load_model(self):
        """Load the ML model if it exists"""
        if os.path.exists(MODEL_PATH):
            logger.info(f"Loading ML model from {MODEL_PATH}")
            try:
                with open(MODEL_PATH, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                logger.error(f"Error loading model: {e}")
                return None
        else:
            logger.warning(f"No model found at {MODEL_PATH}, ML detection disabled")
            return None
    
    def extract_features(self, packet):
        """Extract features from packet for ML model"""
        features = {
            'timestamp': time.time(),
            'src_ip': packet[IP].src if packet.haslayer(IP) else None,
            'dst_ip': packet[IP].dst if packet.haslayer(IP) else None,
            'protocol': packet[IP].proto if packet.haslayer(IP) else None,
            'size': len(packet),
            'ttl': packet[IP].ttl if packet.haslayer(IP) else None,
            # TCP specific features
            'tcp_sport': packet[TCP].sport if packet.haslayer(TCP) else None,
            'tcp_dport': packet[TCP].dport if packet.haslayer(TCP) else None,
            'tcp_flags': str(packet[TCP].flags) if packet.haslayer(TCP) else None,
            'tcp_window': packet[TCP].window if packet.haslayer(TCP) else None,
            # UDP specific features
            'udp_sport': packet[UDP].sport if packet.haslayer(UDP) else None,
            'udp_dport': packet[UDP].dport if packet.haslayer(UDP) else None,
            'udp_len': packet[UDP].len if packet.haslayer(UDP) else None,
            # Add more features as needed
        }
        return features
    
    def preprocess_data(self, df):
        """Preprocess the DataFrame for ML model"""
        if df.empty:
            return None
            
        # Handle missing values
        df = df.fillna(0)
        
        # Feature engineering could go here
        
        # Select the features your model was trained on
        # This is a placeholder - adjust based on your actual model
        model_features = [
            'protocol', 'size', 'ttl', 'tcp_window',
            'tcp_sport', 'tcp_dport', 'udp_sport', 'udp_dport'
        ]
        
        # Filter to only include features your model expects
        available_features = [f for f in model_features if f in df.columns]
        
        return df[available_features]
    
    def process_buffer(self, packet_buffer):
        """Process a buffer of packets with the ML model"""
        if not self.model or not packet_buffer:
            return []
            
        try:
            # Convert to DataFrame
            df = pd.DataFrame(packet_buffer)
            
            # Store the original IPs for blocking
            src_ips = df['src_ip'].copy() if 'src_ip' in df.columns else []
            
            # Preprocess
            df_processed = self.preprocess_data(df)
            if df_processed is None or df_processed.empty:
                return []
            
            # Make predictions
            predictions = self.model.predict(df_processed)
            
            # Find malicious packets
            malicious_indices = [i for i, pred in enumerate(predictions) if pred == 1]
            malicious_ips = set()
            
            for idx in malicious_indices:
                if idx < len(src_ips):
                    ip = src_ips.iloc[idx]
                    if ip and ip not in malicious_ips:
                        malicious_ips.add(ip)
                        block_logger.info(f"ML model detected malicious traffic from {ip}")
            
            return list(malicious_ips)
            
        except Exception as e:
            logger.error(f"Error in ML processing: {e}")
            return []
    
    def start_processing(self, packet_capture):
        """Start background thread for ML processing"""
        self.running = True
        
        def processing_loop():
            while self.running:
                # Get the current buffer
                buffer = packet_capture.get_and_clear_buffer()
                
                if buffer:
                    # Process with ML model
                    malicious_ips = self.process_buffer(buffer)
                    
                    # Update threat intelligence with newly detected IPs
                    for ip in malicious_ips:
                        packet_capture.dpi_layer.threat_intel.malicious_ips.add(ip)
                
                # Sleep for a bit
                time.sleep(ML_PROCESSING_INTERVAL)
        
        self.processing_thread = threading.Thread(target=processing_loop)
        self.processing_thread.daemon = True
        self.processing_thread.start()
    
    def stop_processing(self):
        """Stop the ML processing thread"""
        self.running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=2)