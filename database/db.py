
import sqlite3
from pathlib import Path
from datetime import datetime


DATABASE_PATH = Path("database/security.db")


def get_connection():
    DATABASE_PATH.parent.mkdir(exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():

    connection = get_connection()
    cursor = connection.cursor()

    # Store network scan results
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT NOT NULL,
            port INTEGER,
            protocol TEXT,
            state TEXT,
            service TEXT,
            scanned_at TEXT
        )
    """)

    # Store vulnerability findings
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            description TEXT,
            cvss_score REAL,
            severity TEXT,
            verification TEXT,
            detected_at TEXT
        )
    """)

    # Store security alerts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            source_ip TEXT,
            severity TEXT,
            details TEXT,
            detected_at TEXT
        )
    """)

    connection.commit()
    connection.close()

    print("Database initialized successfully!")
    print("Database:", DATABASE_PATH)


if __name__ == "__main__":
    initialize_database()
