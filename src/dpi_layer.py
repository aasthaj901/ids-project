from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw
import logging
import subprocess
import platform

logger = logging.getLogger('ids')

class DPILayer:
    def __init__(self, threat_intel):
        self.threat_intel = threat_intel
        self.suspicious_flags = [
            ('S', 'F'),
            ('S', 'R'),
            ('F', 'R'),
        ]
        self.total_packets_analyzed = 0
        self.suspicious_packet_count = 0
        self.blocked_ips = set()

    def is_suspicious_tcp_flags(self, packet):
        if not packet.haslayer(TCP):
            return False
        flags = str(packet[TCP].flags)
        for flag_combo in self.suspicious_flags:
            if flag_combo[0] in flags and flag_combo[1] in flags:
                return True
        return False

    def is_dns_suspicious(self, packet):
        if packet.haslayer(DNS):
            try:
                if packet.haslayer(DNSQR) and len(packet[DNSQR].qname) > 100:
                    return True
                if hasattr(packet.qd, 'qname') and len(packet.qd.qname) > 100:
                    return True
            except:
                pass
        return False

    def is_suspicious_http_activity(self, packet):
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            if b'GET' in raw_data and len(raw_data) > 2000:
                return True
            if b'POST' in raw_data and len(raw_data) > 2000:
                return True
        return False

    def block_ip(self, ip):
        if ip in self.blocked_ips:
            logger.debug(f"IP {ip} already blocked, skipping")
            return

        self.blocked_ips.add(ip)

        if platform.system() == "Windows":
            self.block_ip_windows(ip)
        else:
            self.block_ip_linux(ip)

    def block_ip_windows(self, ip):
        try:
            subprocess.call([ 
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=BlockMaliciousIP", "dir=in", "action=block", f"remoteip={ip}"
            ])
            logger.info(f"Blocked IP {ip} using firewall rule.")
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")

    def block_ip_linux(self, ip):
        try:
            subprocess.call([
                "sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"
            ])
            logger.info(f"Blocked IP {ip} using iptables.")
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")

    def process_packet(self, packet):
        if not packet.haslayer(IP):
            return False, ""

        self.total_packets_analyzed += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Skip local loopback addresses (127.0.0.1)
        if src_ip == '127.0.0.1' or dst_ip == '127.0.0.1':
            return False, ""

        # Log the processing of the packet (both suspicious and non-suspicious)
        logger.info(f"Processing packet from {src_ip} to {dst_ip}")

        # Check if the source IP is malicious based on threat intelligence
        if self.threat_intel.is_malicious(src_ip) or self.threat_intel.is_malicious(dst_ip):
            self.suspicious_packet_count += 1
            logger.warning(f"Malicious IP detected: {src_ip} -> {dst_ip} (Threat Intelligence Layer)")
            self.block_ip(src_ip)
            return True, f"Known malicious IP: {src_ip} -> {dst_ip} (Threat Intelligence Layer)"

        # Check for suspicious TCP flags
        if self.is_suspicious_tcp_flags(packet):
            self.suspicious_packet_count += 1
            logger.warning(f"Suspicious TCP flags from {src_ip} -> {dst_ip} (DPI Layer)")
            self.block_ip(src_ip)
            return True, f"Suspicious TCP flags from {src_ip} (DPI Layer)"

        # Check for suspicious DNS activity
        if self.is_dns_suspicious(packet):
            self.suspicious_packet_count += 1
            logger.warning(f"Suspicious DNS activity from {src_ip} -> {dst_ip} (DPI Layer)")
            self.block_ip(src_ip)
            return True, f"Suspicious DNS activity from {src_ip} (DPI Layer)"

        # Check for suspicious HTTP activity
        if self.is_suspicious_http_activity(packet):
            self.suspicious_packet_count += 1
            logger.warning(f"Suspicious HTTP activity from {src_ip} -> {dst_ip} (DPI Layer)")
            self.block_ip(src_ip)
            return True, f"Suspicious HTTP activity from {src_ip} (DPI Layer)"

        # Log non-suspicious packets
        logger.info(f"Packet from {src_ip} to {dst_ip} is not suspicious (DPI Layer)")

        return False, ""

    def get_total_packets_analyzed(self):
        return self.total_packets_analyzed

    def get_suspicious_packet_count(self):
        return self.suspicious_packet_count

    def generate_summary(self):
        return {
            'dpiPackets': self.total_packets_analyzed,
            'suspiciousTraffic': self.suspicious_packet_count
        }
