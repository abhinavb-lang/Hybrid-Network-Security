
import sqlite3
import json
from pathlib import Path
from datetime import datetime


DATABASE_PATH = Path("database/security.db")
SCAN_REPORT = Path("reports/port_scan_results.json")


def store_scan_results():

    if not SCAN_REPORT.exists():
        print("Error: Port scan report not found.")
        return

    with open(SCAN_REPORT, "r") as file:
        scan_data = json.load(file)

    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    saved_count = 0

    # Support either a list of results or a dictionary report
    if isinstance(scan_data, list):
        results = scan_data
    else:
        results = scan_data.get("results", [])

    for item in results:

        cursor.execute("""
            INSERT INTO scan_results
            (target_ip, port, protocol, state, service, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            item.get("ip"),
            item.get("port"),
            item.get("protocol"),
            item.get("state"),
            item.get("service"),
            datetime.now().isoformat()
        ))

        saved_count += 1

    connection.commit()
    connection.close()

    print("Scan results saved to SQLite!")
    print("Records inserted:", saved_count)


if __name__ == "__main__":
    store_scan_results()
