
from scapy.all import rdpcap, IP, TCP
from collections import defaultdict, deque
from pathlib import Path
import json
from datetime import datetime


# Detection settings
TIME_WINDOW = 10
PORT_SCAN_THRESHOLD = 10
SYN_THRESHOLD = 100


def analyze_pcap(file_path):

    print("\nHYBRID NETWORK SECURITY")
    print("NETWORK THREAT DETECTION")
    print("=" * 45)

    packets = rdpcap(file_path)

    # Store recent SYN activity for each source IP
    port_activity = defaultdict(deque)
    syn_activity = defaultdict(int)
    alerts = []
    alerted_sources = set()

    for packet in packets:

        if IP not in packet or TCP not in packet:
            continue

        source = packet[IP].src
        destination_port = packet[TCP].dport
        flags = packet[TCP].flags

        # Detect TCP SYN packets without ACK
        if flags & 0x02 and not flags & 0x10:

            timestamp = float(packet.time)

            syn_activity[source] += 1

            activity = port_activity[source]

            # Add current packet to the time window
            activity.append((timestamp, destination_port))

            # Remove packets older than 10 seconds
            while activity and timestamp - activity[0][0] > TIME_WINDOW:
                activity.popleft()

            # Count unique ports in the current window
            unique_ports = {
                port for _, port in activity
            }

            # Detect possible rapid port scanning
            if (
                len(unique_ports) >= PORT_SCAN_THRESHOLD
                and source not in alerted_sources
            ):

                alerts.append({
                    "type": "POSSIBLE_PORT_SCAN",
                    "source_ip": source,
                    "unique_ports": len(unique_ports),
                    "time_window_seconds": TIME_WINDOW,
                    "severity": "MEDIUM"
                })

                alerted_sources.add(source)

    # Detect high SYN packet volume
    for source, count in syn_activity.items():

        if count >= SYN_THRESHOLD:

            alerts.append({
                "type": "HIGH_SYN_VOLUME",
                "source_ip": source,
                "syn_packets": count,
                "severity": "HIGH"
            })

    # Generate report
    report = {
        "analyzed_at": datetime.now().isoformat(),
        "pcap_file": str(file_path),
        "total_packets": len(packets),
        "alerts_generated": len(alerts),
        "detection_settings": {
            "time_window_seconds": TIME_WINDOW,
            "port_scan_threshold": PORT_SCAN_THRESHOLD,
            "syn_threshold": SYN_THRESHOLD
        },
        "alerts": alerts
    }

    Path("reports").mkdir(exist_ok=True)

    with open("reports/threat_alerts.json", "w") as file:
        json.dump(report, file, indent=4)

    print("Total packets:", len(packets))
    print("Security alerts:", len(alerts))

    for alert in alerts:
        print("\nALERT:", alert)

    print("\nAnalysis completed!")
    print("Report: reports/threat_alerts.json")

    return report


if __name__ == "__main__":

    pcap_file = input("Enter PCAP file path: ").strip().strip('"')

    if Path(pcap_file).is_file():
        analyze_pcap(pcap_file)
    else:
        print("Error: PCAP file not found.")
