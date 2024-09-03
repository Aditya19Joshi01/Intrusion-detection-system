# packet_capture.py

from scapy.all import sniff, IP, TCP, UDP
from traffic_analysis import analyze_packet
from reporting import aggregate_data

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            proto = "Other"
            sport = None
            dport = None

        print(f"[+] {proto} Packet: {ip_src}:{sport} -> {ip_dst}:{dport}")
        
        # Aggregate data for reporting
        aggregate_data(packet)

        # Analyze the packet for threats
        analyze_packet(packet)

def start_packet_capture(interface=None):
    print("[*] Starting packet capture...")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    start_packet_capture()
