from scapy.all import IP, TCP, UDP, DNS, Raw
import logging
import subprocess
from src.threat_intelligence import ThreatIntelligence

logger = logging.getLogger('ids')

class DPILayer:
    def __init__(self):
        self.threat_intel = ThreatIntelligence()
        
        # TCP flag combinations that are suspicious
        self.suspicious_flags = [
            ('S', 'F'),  # SYN-FIN
            ('S', 'R'),  # SYN-RST
            ('F', 'R'),  # FIN-RST
            # Add more as needed
        ]
    
    def is_suspicious_tcp_flags(self, packet):
        """Check for suspicious TCP flag combinations"""
        if not packet.haslayer(TCP):
            return False
        
        flags = str(packet[TCP].flags)
        for flag_combo in self.suspicious_flags:
            if flag_combo[0] in flags and flag_combo[1] in flags:
                return True
        return False
    
    def is_dns_suspicious(self, packet):
        """Check for DNS-based attacks like overflow"""
        if packet.haslayer(DNS):
            # Check for unusually long DNS queries
            if packet.haslayer(DNS) and packet.qd and len(packet.qd.qname) > 100:
                return True
            # Add more DNS checks here, like domain pattern matching
        return False
    
    def is_suspicious_http_activity(self, packet):
        """Check for suspicious HTTP activity, such as large headers or unusual methods"""
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            if b'GET' in raw_data and len(raw_data) > 2000:  # Large GET request
                return True
            if b'POST' in raw_data and len(raw_data) > 2000:  # Large POST request
                return True
        return False

    def block_ip_windows(self, ip):
        """Block IP using netsh (Windows firewall)"""
        try:
            subprocess.call([ 
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=BlockMaliciousIP", "dir=in", "action=block", f"remoteip={ip}"
            ])
            logger.info(f"Blocked IP {ip} using firewall rule.")
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")

    def process_packet(self, packet):
        """Process a packet and return (is_blocked, reason)"""
        if not packet.haslayer(IP):
            return False, ""
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check against known malicious IPs
        if self.threat_intel.is_malicious(src_ip):
            logger.warning(f"Malicious IP detected: {src_ip}")
            self.block_ip_windows(src_ip)
            return True, f"Known malicious IP: {src_ip}"
        
        # Check TCP flags
        if self.is_suspicious_tcp_flags(packet):
            logger.warning(f"Suspicious TCP flags from {src_ip}")
            self.block_ip_windows(src_ip)
            return True, f"Suspicious TCP flags from {src_ip}"
        
        # Check DNS
        if self.is_dns_suspicious(packet):
            logger.warning(f"Suspicious DNS activity from {src_ip}")
            self.block_ip_windows(src_ip)
            return True, f"Suspicious DNS activity from {src_ip}"
        
        # Check HTTP (new addition)
        if self.is_suspicious_http_activity(packet):
            logger.warning(f"Suspicious HTTP activity from {src_ip}")
            self.block_ip_windows(src_ip)
            return True, f"Suspicious HTTP activity from {src_ip}"
        
        # Add more DPI checks as needed
        
        return False, ""

