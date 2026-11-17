
import sqlite3
import json
from pathlib import Path
from datetime import datetime


DATABASE_PATH = Path("database/security.db")
REPORT_PATH = Path("reports/threat_alerts.json")


def store_security_alerts():

    if not REPORT_PATH.exists():
        print("Error: Threat alert report not found.")
        return

    with open(REPORT_PATH, "r", encoding="utf-8") as file:
        report = json.load(file)

    alerts = report.get("alerts", [])

    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    saved_count = 0
    skipped_count = 0

    for alert in alerts:

        alert_type = alert.get("type")
        source_ip = alert.get("source_ip")
        severity = alert.get("severity", "LOW")

        # Avoid duplicate alerts from the same report
        cursor.execute("""
            SELECT id FROM security_alerts
            WHERE alert_type = ?
            AND source_ip = ?
            AND details = ?
        """, (
            alert_type,
            source_ip,
            json.dumps(alert, sort_keys=True)
        ))

        if cursor.fetchone():
            skipped_count += 1
            continue

        cursor.execute("""
            INSERT INTO security_alerts (
                alert_type,
                source_ip,
                severity,
                details,
                detected_at
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            alert_type,
            source_ip,
            severity,
            json.dumps(alert, sort_keys=True),
            report.get("analyzed_at", datetime.now().isoformat())
        ))

        saved_count += 1

    connection.commit()
    connection.close()

    print("\nSECURITY ALERT DATABASE")
    print("=" * 40)
    print("Total alerts:", len(alerts))
    print("Records inserted:", saved_count)
    print("Duplicates skipped:", skipped_count)
    print("Database: database/security.db")


if __name__ == "__main__":
    store_security_alerts()
