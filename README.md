# Hybrid Network Vulnerability Scanner & Threat Detection Dashboard

## Project Overview

The **Hybrid Network Vulnerability Scanner & Threat Detection Dashboard** is a Python-based cybersecurity project designed to discover network devices, scan open ports, retrieve related CVE information, assess potential security risks, and detect suspicious network activity from packet captures.

It combines basic offensive security assessment techniques with defensive security monitoring in a single application.

## Features

- **Network Discovery:** Discover active devices using Nmap.
- **Port Scanning:** Identify open and filtered ports and detect running services.
- **CVE Lookup:** Retrieve related vulnerability information from the NVD API.
- **Risk Assessment:** Classify findings using CVSS severity scores.
- **Packet Analysis:** Analyze PCAP files using Scapy.
- **Threat Detection:** Identify suspicious TCP SYN scanning activity.
- **Alert Engine:** Categorize detected alerts by severity.
- **Database Storage:** Store scan results, vulnerabilities, and alerts in SQLite.
- **Security Dashboard:** Display security information through a Flask web dashboard.
- **Automatic Refresh:** Refresh dashboard data every 10 seconds.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Nmap | Network discovery and port scanning |
| Scapy | Packet capture analysis |
| NVD API | CVE information retrieval |
| Flask | Web dashboard |
| SQLite | Database storage |
| HTML & CSS | Dashboard interface |
| JavaScript & Chart.js | Dashboard charts |

## Project Structure

```text
Hybrid-Network-Security/
│
├── scanner/
│   ├── network_discovery.py
│   └── port_scanner.py
│
├── vulnerability/
│   ├── cve_lookup.py
│   └── risk_scoring.py
│
├── detection/
│   ├── packet_monitor.py
│   └── alert_engine.py
│
├── dashboard/
│   └── app.py
│
├── database/
│   ├── db.py
│   ├── store_scans.py
│   ├── store_vulnerabilities.py
│   └── store_alerts.py
│
├── reports/
├── screenshots/
├── tests/
├── venv/
└── main.py
```

## Requirements

- Windows 10/11 or Linux
- Python 3
- Nmap
- Visual Studio Code (recommended)
- Internet connection for NVD API requests

## Installation

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### 2. Open the project directory

```bash
cd Hybrid-Network-Security
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the virtual environment

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 5. Install dependencies

```bash
python -m pip install flask python-nmap requests pandas scapy
```

### 6. Install Nmap

Download Nmap from:

https://nmap.org/download.html

Make sure Nmap is available in your system PATH.

## Running the Project

Run the main application:

```powershell
.\venv\Scripts\python.exe .\main.py
```

The main menu provides the following options:

1. Network Discovery
2. Port Scanner
3. CVE Lookup
4. Risk Assessment
5. Packet Threat Detection
6. Security Alert Engine
7. Store Scan Results
8. Store Vulnerabilities
9. Store Security Alerts
10. Launch Security Dashboard
0. Exit

## Launching the Dashboard

Select option 10 from the main menu.

Open your browser and visit:

http://127.0.0.1:5000

The dashboard displays network scan records, vulnerability findings, security alerts, and charts.

## Threat Detection Logic

The packet analysis module examines TCP SYN packets in PCAP files.

It identifies:

- A possible port scan when a source IP contacts at least 10 unique destination ports within a 10-second window.
- A high-severity alert when a source IP generates at least 100 TCP SYN packets in the capture.

These are heuristic indicators and do not independently prove malicious activity.

## Important CVE Verification Note

CVE keyword search results are related search matches, not proof that a scanned system is vulnerable.

The project marks these findings as **UNVERIFIED**. Confirming vulnerability requires checking the exact product, version, configuration, and applicable security advisories.

## Project Limitations

- Network discovery and port scanning are currently configured for localhost testing.
- CVE keyword matches require independent verification.
- Packet detection analyzes supplied PCAP files; it is not continuous live network monitoring.
- Detection thresholds are basic heuristics and may produce false positives or miss some attacks.
- The dashboard is configured for local access, not public internet deployment.

## Security and Ethical Use

This project is intended for educational purposes and authorized cybersecurity testing.

Only scan systems and networks that you own or have explicit permission to test. Use packet captures that you are authorized to analyze.

## Future Improvements

- Generate downloadable PDF security reports.
- Add scan-history filtering and duplicate prevention.
- Improve vulnerability verification using product and version matching.
- Add live network monitoring.
- Improve detection rules and alert notifications.
- Add user authentication and dashboard access controls.

## Author

**Cybersecurity Portfolio Project**

Hybrid Network Vulnerability Scanner & Threat Detection Dashboard.

---

*Built with Python, Nmap, Scapy, Flask, SQLite, and the NVD API.*