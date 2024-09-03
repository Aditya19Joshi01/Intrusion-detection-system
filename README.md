# Intrusion Detection System (IDS)

## Overview

This Intrusion Detection System (IDS) monitors network traffic in real-time and detects potential security threats such as port scans and SYN floods. The system captures packets from the network, analyzes them for suspicious behavior, and generates detailed reports with visual summaries. This project enhances network security by providing early warnings of possible intrusions.

## Features

- **Real-Time Packet Capture**: Monitors live network traffic to detect potential intrusions.
- **Threat Detection**: Identifies common threats like port scanning and SYN flooding.
- **Automated Reporting**: Generates visual reports summarizing detected threats.
- **Modular Design**: Extensible to include additional threat detection mechanisms.

## Modules Used

- **[Scapy](https://scapy.net/)**: For capturing and analyzing network packets.
- **[Matplotlib](https://matplotlib.org/)**: For generating visual reports (pie charts, bar graphs).
- **[Collections](https://docs.python.org/3/library/collections.html)**: Specifically `defaultdict`, for efficient data aggregation.
- **[Socket](https://docs.python.org/3/library/socket.html)**: For managing network connections.
- **[Sys](https://docs.python.org/3/library/sys.html) & [OS](https://docs.python.org/3/library/os.html)**: For handling system-level operations and log management.

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/Aditya19Joshi01/Intrusion-detection-system.git
    ```
    
## Usage

1. **Start Packet Capture**:
    ```bash
    python packet_capture.py
    ```
   This script will begin monitoring network traffic and log any detected threats.

2. **Analyze Traffic**:
    The `traffic_analysis.py` script is automatically called to analyze captured packets and identify potential intrusions.

3. **Generate Report**:
    After capturing and analyzing traffic, generate a visual report:
    ```bash
    python reporting.py
    ```
    This will produce charts summarizing the types and frequency of detected threats.

## Project Structure

- `packet_capture.py`: Captures network packets in real-time.
- `traffic_analysis.py`: Analyzes the captured packets for suspicious behavior.
- `reporting.py`: Aggregates the results and generates visual reports.
- `logs/`: Directory containing log files of detected threats.

## Example Output

Upon running the system, you can expect outputs similar to the following:

- **Log File**: Logs detected threats with details about the source, type, and time of detection.
- **Visual Report**: A graphical summary of the detected threats, showing the frequency of different types of intrusions.

## Customization

You can extend the IDS by adding new detection methods in `traffic_analysis.py` and modifying the `aggregate_data()` function in `reporting.py` to include the new threat types.
