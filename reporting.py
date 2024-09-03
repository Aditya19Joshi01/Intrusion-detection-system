# reporting.py

import matplotlib.pyplot as plt
from collections import defaultdict

# Dictionaries to store analysis data
packet_counts = defaultdict(int)
threat_counts = defaultdict(int)

# Function to aggregate data
def aggregate_data(packet=None, threat_type=None):
    packet_counts["total"] += 1

    if threat_type:
        threat_counts[threat_type] += 1
        print(f"Aggregating threat: {threat_type}, current count: {threat_counts[threat_type]}")

    print(f"Total packets so far: {packet_counts['total']}")


# Function to generate a report
def generate_report():
    print("[*] Generating report...")

    # Display summary
    print(f"Total Packets Captured: {packet_counts['total']}")
    for threat, count in threat_counts.items():
        print(f"{threat}: {count} occurrences")

    # Generate visualizations
    plot_traffic_summary()
    plot_threat_summary()

# Function to plot traffic summary
def plot_traffic_summary():
    labels = ['Packets Captured']
    sizes = [packet_counts['total']]

    plt.figure(figsize=(6, 6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')
    plt.title('Traffic Summary')
    plt.show()

# Function to plot threat summary
def plot_threat_summary():
    labels = threat_counts.keys()
    sizes = threat_counts.values()

    plt.figure(figsize=(10, 6))
    plt.bar(labels, sizes, color='red')
    plt.title('Threat Summary')
    plt.xlabel('Threat Type')
    plt.ylabel('Occurrences')
    plt.show()

generate_report()