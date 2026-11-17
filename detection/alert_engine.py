
import json
from pathlib import Path
from datetime import datetime


def generate_security_summary():

    report_path = Path("reports/threat_alerts.json")

    if not report_path.exists():
        print("Error: Threat report not found.")
        return

    with open(report_path, "r") as file:
        report = json.load(file)

    alerts = report.get("alerts", [])

    # Categorize alerts by severity
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for alert in alerts:
        severity = alert.get("severity", "LOW").upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    # Create security summary
    summary = {
        "generated_at": datetime.now().isoformat(),
        "pcap_file": report.get("pcap_file"),
        "total_packets": report.get("total_packets", 0),
        "total_alerts": len(alerts),
        "severity_summary": severity_counts,
        "alerts": alerts
    }

    # Save security summary
    output_path = Path("reports/security_summary.json")

    with open(output_path, "w") as file:
        json.dump(summary, file, indent=4)

    print("\nHYBRID NETWORK SECURITY")
    print("SECURITY ALERT SUMMARY")
    print("=" * 45)

    print("Packets analyzed:", summary["total_packets"])
    print("Total alerts:", summary["total_alerts"])

    for severity, count in severity_counts.items():
        print(f"{severity} alerts: {count}")

    print("\nSummary saved:", output_path)


if __name__ == "__main__":
    generate_security_summary()
