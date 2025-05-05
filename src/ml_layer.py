import pandas as pd
import numpy as np
import time
import threading
import joblib
import logging
import os
from scapy.all import IP, TCP, UDP
from config.settings import MODEL_PATH, ML_PROCESSING_INTERVAL

logger = logging.getLogger('ids')
block_logger = logging.getLogger('blocked_traffic')

class MLLayer:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = None
        self._load_model_and_dependencies()
        
        self.processing_thread = None
        self.running = False
        self.suspicious_ips = set()
        self._lock = threading.Lock()
        self.packet_buffer = []

    def _load_model_and_dependencies(self):
        """Load the trained ML model, scaler, and feature names from disk"""
        model_dir = os.path.dirname(MODEL_PATH)
        
        try:
            # Load the model
            if os.path.exists(MODEL_PATH):
                logger.info(f"[MLLayer] Loading ML model from {MODEL_PATH}")
                self.model = joblib.load(MODEL_PATH)
            else:
                logger.warning(f"[MLLayer] No model found at {MODEL_PATH}, ML detection disabled")
                return
            
            # Load the scaler
            scaler_path = os.path.join(model_dir, "robust_scaler.pkl")
            if os.path.exists(scaler_path):
                logger.info(f"[MLLayer] Loading scaler from {scaler_path}")
                self.scaler = joblib.load(scaler_path)
            else:
                logger.warning(f"[MLLayer] No scaler found. Feature scaling disabled.")
            
            # Load the feature names
            features_path = os.path.join(model_dir, "feature_names.pkl")
            if os.path.exists(features_path):
                logger.info(f"[MLLayer] Loading feature names from {features_path}")
                self.feature_names = joblib.load(features_path)
            else:
                logger.warning(f"[MLLayer] No feature names found. Using default feature extraction.")
                
            logger.info("[MLLayer] Successfully loaded model and dependencies")
            
        except Exception as e:
            logger.error(f"[MLLayer] Error loading model or dependencies: {e}")
            self.model = None

    def extract_features(self, packet):
        """Extract features from the network packet for ML use"""
        if not packet.haslayer(IP):
            return None
        
        # Basic packet info
        features = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol_type_icmp': 1 if packet[IP].proto == 1 else 0,
            'protocol_type_tcp': 1 if packet[IP].proto == 6 else 0,
            'protocol_type_udp': 1 if packet[IP].proto == 17 else 0,
            'duration': 0,  # Will be computed over time for a connection
            'src_bytes': len(packet),
            'dst_bytes': 0,  # Will be updated when we see reverse traffic
            'land': 1 if packet[IP].src == packet[IP].dst else 0,
            'wrong_fragment': 1 if packet[IP].frag != 0 else 0,
            'urgent': 1 if packet.haslayer(TCP) and packet[TCP].flags & 0x20 else 0,
        }
        
        # TCP specific features
        if packet.haslayer(TCP):
            features.update({
                'flag_S0': 1 if packet[TCP].flags == 0x02 else 0,  # SYN
                'flag_SF': 1 if packet[TCP].flags & 0x01 else 0,   # FIN
                'flag_REJ': 1 if packet[TCP].flags & 0x04 else 0,  # RST
                'logged_in': 0,  # This requires session tracking
                'count': 1,      # Simplified: need to track over time
                'srv_count': 1,  # Simplified
                'serror_rate': 0,
                'srv_serror_rate': 0,
                'rerror_rate': 0,
                'srv_rerror_rate': 0,
                'same_srv_rate': 1,  # Simplified
                'diff_srv_rate': 0,
                'srv_diff_host_rate': 0,
                'dst_host_count': 1,  # Simplified
                'dst_host_srv_count': 1,  # Simplified
                'dst_host_same_srv_rate': 1,  # Simplified
                'dst_host_diff_srv_rate': 0,
                'dst_host_same_src_port_rate': 1,  # Simplified
                'dst_host_srv_diff_host_rate': 0,
                'dst_host_serror_rate': 0,
                'dst_host_srv_serror_rate': 0,
                'dst_host_rerror_rate': 0,
                'dst_host_srv_rerror_rate': 0
            })
            
        # Add zeroes for features we can't extract directly
        for feature in self.feature_names:
            if feature not in features:
                features[feature] = 0
        
        return features

    def preprocess_packet_features(self, features_df):
        """Preprocess the packet features to match what the model expects"""
        if features_df.empty:
            return pd.DataFrame()
            
        # Ensure we have all required features for the model
        for feature in self.feature_names:
            if feature not in features_df:
                features_df[feature] = 0
                
        # Only keep features the model knows about
        processed_df = features_df[self.feature_names]
        
        # Apply scaling if we have a scaler
        if self.scaler:
            # Find which columns were scaled during training
            numeric_cols = [col for col in processed_df.columns 
                           if col not in ['protocol_type_icmp', 'protocol_type_tcp', 'protocol_type_udp', 
                                         'flag_S0', 'flag_SF', 'flag_REJ', 'land', 'logged_in']]
            
            if numeric_cols:
                processed_df[numeric_cols] = self.scaler.transform(processed_df[numeric_cols])
                
        return processed_df

    def process_buffer(self, packet_buffer):
        """Process packets and return a list of malicious source IPs"""
        if not self.model or not packet_buffer:
            return []

        try:
            # Create DataFrame from packet features
            df = pd.DataFrame(packet_buffer)
            if df.empty:
                return []
                
            # Get source IPs for reference
            src_ips = df['src_ip'].tolist() if 'src_ip' in df.columns else []
            
            # Preprocess the data
            df_processed = self.preprocess_packet_features(df)
            if df_processed.empty:
                return []

            # Make predictions
            predictions = self.model.predict(df_processed)
            malicious_ips = set()

            for idx, pred in enumerate(predictions):
                if pred == 1 and idx < len(src_ips):  # 1 = attack, 0 = normal
                    ip = src_ips[idx]
                    if ip:
                        malicious_ips.add(ip)
                        block_logger.info(f"[MLLayer] Detected malicious traffic from {ip} via ML model")
                        logger.warning(f"[MLLayer] Potential attack detected from {ip}")

            return list(malicious_ips)
            
        except Exception as e:
            logger.error(f"[MLLayer] Error in ML processing: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return []

    def add_packet_to_buffer(self, packet):
        """Add a packet to the processing buffer"""
        features = self.extract_features(packet)
        if features:
            with self._lock:
                self.packet_buffer.append(features)

    def start_processing(self, packet_capture=None):
        """Start background thread to process packet buffer continuously"""
        if not self.model:
            logger.warning("[MLLayer] ML model is not loaded. Skipping processing thread.")
            return

        self.running = True

        def worker():
            while self.running:
                # Process our own buffer
                with self._lock:
                    buffer = self.packet_buffer.copy()
                    self.packet_buffer = []
                
                # Also process any buffer from packet capture if provided
                if packet_capture:
                    buffer.extend(packet_capture.get_and_clear_buffer())
                
                # Process the combined buffer
                if buffer:
                    malicious_ips = self.process_buffer(buffer)
                    with self._lock:
                        for ip in malicious_ips:
                            self.suspicious_ips.add(ip)
                            if packet_capture and packet_capture.dpi_layer:
                                packet_capture.dpi_layer.block_ip(ip)
                
                time.sleep(ML_PROCESSING_INTERVAL)

        self.processing_thread = threading.Thread(target=worker, daemon=True)
        self.processing_thread.start()
        logger.info("[MLLayer] ML processing thread started")

    def stop_processing(self):
        self.running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=2)
            logger.info("[MLLayer] ML processing thread stopped")

    def get_suspicious_ips(self):
        """Return and clear the set of detected suspicious IPs"""
        with self._lock:
            ips = list(self.suspicious_ips)
            self.suspicious_ips.clear()
            return ips