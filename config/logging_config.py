import logging
import os
from config.settings import LOGS_DIR

def setup_logging():
    """Set up logging configuration"""
    os.makedirs(LOGS_DIR, exist_ok=True)

    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # Main IDS logger — logs to file
    ids_logger = logging.getLogger('ids')
    ids_logger.setLevel(logging.INFO)
    ids_handler = logging.FileHandler(os.path.join(LOGS_DIR, 'ids.log'))
    ids_handler.setFormatter(logging.Formatter(log_format))
    ids_logger.addHandler(ids_handler)

    # Blocked traffic logger — logs to console only
    block_logger = logging.getLogger('blocked_traffic')
    block_logger.setLevel(logging.INFO)
    block_handler = logging.StreamHandler()
    block_handler.setFormatter(logging.Formatter(log_format))
    block_logger.addHandler(block_handler)

    # All packets logger — logs all sniffed packets to a file
    packet_logger = logging.getLogger('all_packets')
    packet_logger.setLevel(logging.INFO)
    packet_handler = logging.FileHandler(os.path.join(LOGS_DIR, 'all_packets.log'))
    packet_handler.setFormatter(logging.Formatter(log_format))
    packet_logger.addHandler(packet_handler)

    return ids_logger, block_logger, packet_logger
