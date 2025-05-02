from scapy.all import IP, TCP, UDP, DNS

def packet_summary(packet):
    """Return a human-readable summary of a packet"""
    summary = []
    
    if packet.haslayer(IP):
        summary.append(f"IP: {packet[IP].src} -> {packet[IP].dst}")
        summary.append(f"Protocol: {packet[IP].proto}")
        summary.append(f"TTL: {packet[IP].ttl}")
    
    if packet.haslayer(TCP):
        summary.append(f"TCP: {packet[TCP].sport} -> {packet[TCP].dport}")
        summary.append(f"Flags: {packet[TCP].flags}")
        summary.append(f"Window: {packet[TCP].window}")
    
    if packet.haslayer(UDP):
        summary.append(f"UDP: {packet[UDP].sport} -> {packet[UDP].dport}")
    
    if packet.haslayer(DNS):
        if packet.haslayer(DNS) and packet.qd:
            summary.append(f"DNS Query: {packet.qd.qname}")
    
    return ", ".join(summary)

def print_packet(packet):
    """Print packet details in a readable format"""
    print(packet_summary(packet))
    print("-" * 50)