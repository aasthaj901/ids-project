from scapy.all import IP, UDP, DNS, DNSQR, TCP, send, sr1, sniff
import random
import logging
import time
import subprocess
from src.threat_intelligence import ThreatIntelligence

# Setup logger to log to a file
logging.basicConfig(filename="traffic_simulation.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class TrafficSimulator:
    def __init__(self, threat_intel):
        self.threat_intel = threat_intel
        self.firewall_rules = []
        
        # Define benign IP ranges
        self.benign_ip_ranges = [
            "192.168.1.0/24",
            "10.0.0.0/24",
            "172.16.0.0/24"
        ]

    def check_ip_blocked(self, ip):
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2
            )
            if result.returncode == 0:
                return False
            
            iptables_result = subprocess.run(
                ["sudo", "iptables", "-L", "-n"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2
            )
            output = iptables_result.stdout.decode('utf-8')
            return ip in output
        
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            logger.warning(f"Could not check IP {ip}")
            return False

    def get_malicious_test_ips(self, count=3):
        """Fetch test IPs from cached malicious IPs and ranges"""
        # Use custom malicious test IPs instead of using the threat intel database
        # This avoids conflicts with legitimate traffic simulation
        test_ips = [
            "45.134.22.123",  # Example malicious IP that won't interfere with local network
            "185.143.223.45", 
            "91.92.103.137",
            "23.234.25.203",
            "78.128.113.34"
        ]
        
        logger.info(f"Using custom malicious test IPs: {test_ips}")
        random.shuffle(test_ips)
        return test_ips[:count]
    
    def generate_benign_ip(self):
        """Generate a random benign IP from defined ranges"""
        benign_ips = [
            "192.168.1.10", 
            "192.168.1.20",
            "192.168.1.30", 
            "192.168.1.40",
            "10.0.0.10",
            "10.0.0.20",
            "172.16.0.10",
            "172.16.0.20"
        ]
        return random.choice(benign_ips)
    
    def generate_mixed_traffic(self, benign_count=5, malicious_count=3):
        """Generate a mix of benign and normal traffic"""
        self.threat_intel.update_if_needed()
        malicious_ips = self.get_malicious_test_ips(malicious_count)
        
        if not malicious_ips:
            logger.error("No malicious test IPs generated.")
            return
        
        # Common destinations
        destinations = [
            "8.8.8.8",      # Google DNS
            "1.1.1.1",      # Cloudflare DNS
            "208.67.222.222", # OpenDNS
            "192.168.1.1",  # Default gateway
        ]
        
        # Generate benign traffic first
        logger.info("Generating benign traffic...")
        for i in range(benign_count):
            src_ip = self.generate_benign_ip()
            dst_ip = random.choice(destinations)
                
            try:
                # Normal DNS query
                send(IP(src=src_ip, dst=dst_ip) / UDP(dport=53) / DNS(qd=DNSQR(qname="example.com")))
                # Normal HTTP request
                send(IP(src=src_ip, dst=dst_ip) / TCP(dport=80, flags="S"))
                logger.info(f"Sent benign traffic from {src_ip} to {dst_ip}")
                time.sleep(0.2)  # Small delay between packets
            except Exception as e:
                logger.error(f"Error sending benign packets from {src_ip}: {e}")
        
        # Then generate malicious traffic
        logger.info(f"Generating malicious traffic from IPs: {malicious_ips}")
        for ip in malicious_ips:
            logger.info(f"Testing malicious IP: {ip}")
            
            # Multiple destinations for malicious traffic
            for dst in destinations:
                try:
                    # Send various suspicious packets with delays between them
                    send(IP(src=ip, dst=dst) / UDP(dport=53) / DNS(qd=DNSQR(qname="a"*101 + ".com")))
                    time.sleep(0.2)
                    
                    send(IP(src=ip, dst=dst) / TCP(dport=80, flags="SF"))
                    time.sleep(0.2)
                    
                    send(IP(src=ip, dst=dst) / TCP(dport=443, flags="SR"))
                    time.sleep(0.2)
                    
                    send(IP(src=ip, dst=dst) / TCP(dport=22, flags="FR"))
                    logger.info(f"Sent suspicious packets from {ip} to {dst}")
                    time.sleep(0.5)
                except Exception as e:
                    logger.error(f"Error sending packets from {ip} to {dst}: {e}")
            
            # Check if the IP was blocked
            time.sleep(1)
            if self.check_ip_blocked(ip):
                logger.info(f"IP {ip} is BLOCKED after traffic")
            else:
                logger.warning(f"IP {ip} NOT blocked after traffic")
            
            # Add some delay between malicious IPs
            time.sleep(1)
    
    def generate_suspicious_traffic(self):
        """Original method maintained for backward compatibility"""
        # Call the new mixed traffic generator with default values
        self.generate_mixed_traffic(benign_count=5, malicious_count=3)