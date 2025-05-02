from scapy.all import sniff, IP
import logging
import threading
from config.settings import INTERFACE, PACKET_BUFFER_SIZE

logger = logging.getLogger('ids')
block_logger = logging.getLogger('blocked_traffic')
packet_logger = logging.getLogger('all_packets')  # Get packet logger here too

class PacketCapture:
    def __init__(self, dpi_layer, ml_layer, packet_logger):
        self.dpi_layer = dpi_layer
        self.ml_layer = ml_layer
        self.packet_logger = packet_logger
        self.packet_buffer = []
        self.buffer_lock = threading.Lock()
        self.running = False
        self.capture_thread = None

    def packet_handler(self, packet):
        """Handle a captured packet"""
        try:
            # Log summary of all sniffed packets
            self.packet_logger.info(packet.summary())

            # Process with DPI layer
            is_blocked, reason = self.dpi_layer.process_packet(packet)

            if is_blocked:
                if packet.haslayer(IP):
                    block_logger.info(f"Blocked {packet[IP].src} -> {packet[IP].dst}: {reason}")
                return

            # ML feature extraction
            if packet.haslayer(IP):
                with self.buffer_lock:
                    if len(self.packet_buffer) < PACKET_BUFFER_SIZE:
                        features = self.ml_layer.extract_features(packet)
                        self.packet_buffer.append(features)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def get_and_clear_buffer(self):
        with self.buffer_lock:
            buffer = self.packet_buffer.copy()
            self.packet_buffer = []
        return buffer

    def start(self):
        self.running = True
        logger.info(f"Starting packet capture on interface {INTERFACE}")
        self.capture_thread = threading.Thread(
            target=lambda: sniff(
                iface=INTERFACE,
                prn=self.packet_handler,
                store=0,
                stop_filter=lambda x: not self.running
            )
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop(self):
        logger.info("Stopping packet capture")
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
