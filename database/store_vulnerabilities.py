
import sqlite3
import json
from pathlib import Path
from datetime import datetime


DATABASE_PATH = Path("database/security.db")
REPORT_PATH = Path("reports/risk_assessment.json")


def store_vulnerabilities():

    if not REPORT_PATH.exists():
        print("Error: Risk assessment report not found.")
        return

    with open(REPORT_PATH, "r", encoding="utf-8") as file:
        report = json.load(file)

    findings = report.get("results", [])

    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    saved_count = 0
    skipped_count = 0

    for item in findings:

        cve_id = item.get("cve_id")

        if not cve_id:
            continue

        # Avoid inserting the same CVE multiple times
        cursor.execute(
            "SELECT id FROM vulnerabilities WHERE cve_id = ?",
            (cve_id,)
        )

        if cursor.fetchone():
            skipped_count += 1
            continue

        cursor.execute("""
            INSERT INTO vulnerabilities (
                cve_id,
                description,
                cvss_score,
                severity,
                verification,
                detected_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            cve_id,
            item.get("description"),
            item.get("cvss_score"),
            item.get("severity"),
            item.get("verification"),
            datetime.now().isoformat()
        ))

        saved_count += 1

    connection.commit()
    connection.close()

    print("\nVULNERABILITY DATABASE")
    print("=" * 40)
    print("Total findings:", len(findings))
    print("Records inserted:", saved_count)
    print("Duplicates skipped:", skipped_count)
    print("Database: database/security.db")


if __name__ == "__main__":
    store_vulnerabilities()
