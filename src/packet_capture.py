from scapy.all import sniff, IP, conf
from scapy.error import Scapy_Exception
import logging
import threading
import socket
from config.settings import PACKET_BUFFER_SIZE

logger = logging.getLogger('ids')
block_logger = logging.getLogger('blocked_traffic')
packet_logger = logging.getLogger('all_packets')

class PacketCapture:
    def __init__(self, dpi_layer, ml_layer, packet_logger):
        self.dpi_layer = dpi_layer
        self.ml_layer = ml_layer
        self.packet_logger = packet_logger
        self.packet_buffer = []
        self.buffer_lock = threading.Lock()
        self.running = False
        self.capture_thread = None

    def get_primary_interface(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            s.close()
            for name, iface in conf.ifaces.items():
                if iface.ip == primary_ip:
                    logger.info(f"Found primary interface: {name} with IP {primary_ip}")
                    return name
        except Exception as e:
            logger.warning(f"Could not find primary interface: {e}")
        return None

    def select_interface(self):
        iface = self.get_primary_interface()
        if iface:
            return iface

        # Try a non-loopback fallback
        for name, iface in conf.ifaces.items():
            if 'loopback' not in str(name).lower() and 'lo' != str(name).lower():
                logger.info(f"Selected non-loopback interface: {name}")
                return name

        # As a last resort, use loopback
        for name, iface in conf.ifaces.items():
            if 'loopback' in str(name).lower() or 'lo' == str(name).lower():
                logger.info(f"Selected loopback interface: {name}")
                return name

        logger.error("No network interfaces available")
        return None

    def packet_handler(self, packet):
        try:
            if packet is None:
                return
            packet_logger.info(packet.summary())
            if packet.haslayer(IP):
                logger.info(f"Processing packet from {packet[IP].src} to {packet[IP].dst}")
                is_blocked, reason = self.dpi_layer.process_packet(packet)
                if is_blocked:
                    block_logger.info(f"Blocked {packet[IP].src} -> {packet[IP].dst}: {reason}")
                    return
                with self.buffer_lock:
                    if len(self.packet_buffer) < PACKET_BUFFER_SIZE:
                        features = self.ml_layer.extract_features(packet)
                        self.packet_buffer.append(features)
                if len(self.packet_buffer) >= PACKET_BUFFER_SIZE:
                    buffer = self.get_and_clear_buffer()
                    malicious_ips = self.ml_layer.process_buffer(buffer)
                    for ip in malicious_ips:
                        self.dpi_layer.block_ip(ip)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def get_and_clear_buffer(self):
        with self.buffer_lock:
            buffer = self.packet_buffer.copy()
            self.packet_buffer = []
        return buffer

    def start(self):
        self.running = True
        iface = self.select_interface()
        if not iface:
            self.running = False
            return
        logger.info(f"Starting packet capture on interface {iface}")
        self.capture_thread = threading.Thread(
            target=lambda: self._capture_packets(iface),
            daemon=True
        )
        self.capture_thread.start()

    def _capture_packets(self, iface):
        try:
            sniff(
                iface=iface,
                prn=self.packet_handler,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except ValueError as e:
            logger.error(f"Interface error: {e}")
            self._try_fallback_interfaces()
        except Scapy_Exception as e:
            logger.error(f"Scapy error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
        finally:
            logger.info("Packet capture stopped")

    def _try_fallback_interfaces(self):
        for name in conf.ifaces:
            try:
                logger.info(f"Trying fallback interface: {name}")
                sniff(iface=name, prn=self.packet_handler, store=0, count=1, timeout=2)
                sniff(iface=name, prn=self.packet_handler, store=0, stop_filter=lambda x: not self.running)
                return
            except Exception as e:
                logger.debug(f"Fallback interface {name} failed: {e}")
        logger.error("All interfaces failed")

    def stop(self):
        logger.info("Stopping packet capture")
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)

    def start_ml_processing(self):
        self.ml_layer.start_processing(self)

    def stop_ml_processing(self):
        self.ml_layer.stop_processing()
