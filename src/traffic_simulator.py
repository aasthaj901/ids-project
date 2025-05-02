from scapy.all import IP, UDP, DNS, DNSQR, TCP, send
import random
import logging
from src.threat_intelligence import ThreatIntelligence

# Setup logger to log to a file
logging.basicConfig(filename="traffic_simulation.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class TrafficSimulator:
    def __init__(self, threat_intel):
        self.threat_intel = threat_intel

    def generate_suspicious_traffic(self):
        # Get the malicious IPs
        malicious_ips = list(self.threat_intel.malicious_ips)  # Convert the set to a list

        # Log the malicious IPs to a file
        logger.info(f"Malicious IPs fetched: {malicious_ips}")

        if not malicious_ips:
            logger.warning("No malicious IPs found, unable to simulate traffic.")
            return  # Exit if no malicious IPs

        # Generate suspicious DNS overflow traffic
        ip = random.choice(malicious_ips)  # Get a malicious IP
        dns_packet = IP(src=ip, dst="192.168.1.1") / UDP(sport=12345, dport=53) / DNS(qd=DNSQR(qname="a" * 101 + ".com"))
        dns_packet.show()  # Show the DNS packet (for debugging)
        
        # Send the suspicious DNS packet
        send(dns_packet)
        logger.info(f"Sent suspicious DNS query from {ip} to 192.168.1.1")

        # Suspicious TCP SYN-FIN flag
        syn_fin_packet = IP(src=ip, dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="SF")
        syn_fin_packet.show()  # Show the SYN-FIN packet
        send(syn_fin_packet)  # Send the SYN-FIN packet
        logger.info(f"Sent SYN-FIN packet from {ip} to 192.168.1.1")

        # Suspicious TCP SYN-RST flag
        syn_rst_packet = IP(src=ip, dst="192.168.1.1") / TCP(flags="SR", sport=12345, dport=80)
        send(syn_rst_packet)
        logger.info(f"Sent SYN-RST packet from {ip} to 192.168.1.1")

        # Suspicious TCP FIN-RST flag
        fin_rst_packet = IP(src=ip, dst="192.168.1.1") / TCP(flags="FR", sport=12345, dport=80)
        send(fin_rst_packet)
        logger.info(f"Sent FIN-RST packet from {ip} to 192.168.1.1")


# Example usage:
if __name__ == "__main__":
    threat_intel = ThreatIntelligence()  # Create an instance of ThreatIntelligence
    traffic_simulator = TrafficSimulator(threat_intel)
    traffic_simulator.generate_suspicious_traffic()
