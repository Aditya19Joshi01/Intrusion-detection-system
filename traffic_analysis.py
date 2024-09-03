from collections import defaultdict
import time
from alerting import log_alert
from reporting import aggregate_data

# A dictionary to track SYN packets from each source IP
syn_packets = defaultdict(list)

# Function to detect SYN flooding
def detect_syn_flood(packet):
    if packet.haslayer("TCP") and packet["TCP"].flags == "S":
        ip_src = packet["IP"].src
        current_time = time.time()

        # Record the timestamp of the SYN packet
        syn_packets[ip_src].append(current_time)

        # Remove old entries
        syn_packets[ip_src] = [t for t in syn_packets[ip_src] if current_time - t < 1]

        # Check if the number of SYN packets exceeds a threshold within a short time
        if len(syn_packets[ip_src]) > 100:
            message = f"SYN flood detected from {ip_src}"
            log_alert("SYN Flood", message)
            aggregate_data(packet, threat_type="SYN Flood")

# Function to detect port scanning
def detect_port_scan(packet):
    if packet.haslayer("TCP"):
        ip_src = packet["IP"].src
        port = packet["TCP"].dport

        # Record the port being scanned
        port_scan[ip_src].add(port)

        # If multiple ports are scanned within a short period, raise an alert
        if len(port_scan[ip_src]) > 10:
            message = f"Port scanning detected from {ip_src}"
            log_alert("Port Scan", message)
            aggregate_data(packet, threat_type="Port Scan")

# Dictionary to track scanned ports
port_scan = defaultdict(set)

def analyze_packet(packet):
    detect_syn_flood(packet)
    detect_port_scan(packet)
