
from flask import Flask, render_template_string
import sqlite3
from pathlib import Path

app = Flask(__name__)

DATABASE_PATH = (
    Path(__file__).resolve().parent.parent
    / "database" / "security.db"
)


def get_dashboard_data():

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    scans = connection.execute(
        "SELECT * FROM scan_results ORDER BY id DESC"
    ).fetchall()

    vulnerabilities = connection.execute(
        "SELECT * FROM vulnerabilities ORDER BY id DESC"
    ).fetchall()

    alerts = connection.execute(
        "SELECT * FROM security_alerts ORDER BY id DESC"
    ).fetchall()

    connection.close()

    return scans, vulnerabilities, alerts


@app.route("/")
def dashboard():

    scans, vulnerabilities, alerts = get_dashboard_data()

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for item in vulnerabilities:
        severity = item["severity"].upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    alert_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "CRITICAL": 0
    }

    for alert in alerts:
        severity = alert["severity"].upper()

        if severity in alert_counts:
            alert_counts[severity] += 1

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Hybrid Network Security</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

        <style>
            * {
                box-sizing: border-box;
            }

            body {
                margin: 0;
                background: #0b1120;
                color: #e2e8f0;
                font-family: Arial, sans-serif;
            }

            .sidebar {
                width: 230px;
                height: 100vh;
                position: fixed;
                top: 0;
                left: 0;
                background: #111c30;
                padding: 25px 18px;
            }

            .sidebar h2 {
                color: #38bdf8;
                font-size: 19px;
                margin-bottom: 35px;
            }

            .sidebar a {
                display: block;
                color: #cbd5e1;
                text-decoration: none;
                padding: 14px;
                margin-bottom: 8px;
                border-radius: 7px;
            }

            .sidebar a:hover {
                background: #243550;
                color: #38bdf8;
            }

            .main {
                margin-left: 230px;
                padding: 30px;
            }

            .header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 15px;
                flex-wrap: wrap;
            }

            h1 {
                color: #38bdf8;
                margin-bottom: 8px;
            }

            .subtitle {
                color: #94a3b8;
            }

            .refresh {
                background: #0284c7;
                color: white;
                border: none;
                border-radius: 7px;
                padding: 12px 20px;
                cursor: pointer;
                font-size: 14px;
            }

            .refresh:hover {
                background: #0369a1;
            }

            .cards {
                display: grid;
                grid-template-columns:
                    repeat(auto-fit, minmax(180px, 1fr));
                gap: 18px;
                margin: 30px 0;
            }

            .card, .section {
                background: #19263b;
                border: 1px solid #293b55;
                border-radius: 12px;
                padding: 22px;
            }

            .card p {
                color: #94a3b8;
                margin: 0;
            }

            .number {
                font-size: 34px;
                font-weight: bold;
                margin-top: 12px;
                color: #38bdf8;
            }

            .section {
                margin-bottom: 25px;
                overflow-x: auto;
            }

            h2 {
                color: #7dd3fc;
            }

            .charts {
                display: grid;
                grid-template-columns:
                    repeat(auto-fit, minmax(280px, 1fr));
                gap: 20px;
                margin-bottom: 25px;
            }

            .chart-box {
                background: #19263b;
                border: 1px solid #293b55;
                border-radius: 12px;
                padding: 20px;
                min-width: 0;
            }

            .chart-container {
                position: relative;
                height: 280px;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                min-width: 550px;
            }

            th, td {
                text-align: left;
                padding: 14px;
                border-bottom: 1px solid #334155;
            }

            th {
                color: #7dd3fc;
            }

            .CRITICAL {
                color: #f87171;
            }

            .HIGH {
                color: #fb923c;
            }

            .MEDIUM {
                color: #facc15;
            }

            .LOW {
                color: #4ade80;
            }

            .footer {
                color: #64748b;
                text-align: center;
                margin: 35px 0;
            }

            @media (max-width: 750px) {
                .sidebar {
                    width: 100%;
                    height: auto;
                    position: relative;
                }

                .sidebar a {
                    display: inline-block;
                }

                .main {
                    margin-left: 0;
                    padding: 18px;
                }
            }
        </style>
    </head>

    <body>

        <aside class="sidebar">

            <h2>HYBRID SECURITY</h2>

            <a href="#overview">Dashboard</a>
            <a href="#charts">Analytics</a>
            <a href="#scans">Network Scans</a>
            <a href="#vulnerabilities">Vulnerabilities</a>
            <a href="#alerts">Security Alerts</a>

        </aside>

        <main class="main">

            <div class="header">
                <div>
                    <h1>Security Dashboard</h1>
                    <p class="subtitle">
                        Network Vulnerability Scanner & Threat Detection
                    </p>
                </div>

                <button class="refresh"
                        onclick="window.location.reload()">
                    Refresh Dashboard
                </button>
            </div>

            <div id="overview" class="cards">

                <div class="card">
                    <p>Network Scan Records</p>
                    <div class="number">{{ scans|length }}</div>
                </div>

                <div class="card">
                    <p>Vulnerabilities</p>
                    <div class="number">
                        {{ vulnerabilities|length }}
                    </div>
                </div>

                <div class="card">
                    <p>Security Alerts</p>
                    <div class="number">{{ alerts|length }}</div>
                </div>

                <div class="card">
                    <p>High Risk Findings</p>
                    <div class="number">
                        {{ severity_counts["HIGH"] +
                           severity_counts["CRITICAL"] }}
                    </div>
                </div>

            </div>

            <div id="charts" class="charts">

                <div class="chart-box">
                    <h2>Vulnerability Severity</h2>
                    <div class="chart-container">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>

                <div class="chart-box">
                    <h2>Security Alert Severity</h2>
                    <div class="chart-container">
                        <canvas id="alertChart"></canvas>
                    </div>
                </div>

            </div>

            <div id="scans" class="section">

                <h2>Network Scan Results</h2>

                <table>
                    <tr>
                        <th>IP Address</th>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>State</th>
                        <th>Service</th>
                    </tr>

                    {% for scan in scans %}
                    <tr>
                        <td>{{ scan.target_ip }}</td>
                        <td>{{ scan.port }}</td>
                        <td>{{ scan.protocol }}</td>
                        <td>{{ scan.state }}</td>
                        <td>{{ scan.service }}</td>
                    </tr>
                    {% endfor %}
                </table>

            </div>

            <div id="vulnerabilities" class="section">

                <h2>Vulnerability Findings</h2>

                <table>
                    <tr>
                        <th>CVE ID</th>
                        <th>CVSS</th>
                        <th>Severity</th>
                        <th>Verification</th>
                    </tr>

                    {% for item in vulnerabilities %}
                    <tr>
                        <td>{{ item.cve_id }}</td>
                        <td>{{ item.cvss_score }}</td>
                        <td class="{{ item.severity }}">
                            {{ item.severity }}
                        </td>
                        <td>{{ item.verification }}</td>
                    </tr>
                    {% endfor %}
                </table>

            </div>

            <div id="alerts" class="section">

                <h2>Security Alerts</h2>

                <table>
                    <tr>
                        <th>Alert Type</th>
                        <th>Source IP</th>
                        <th>Severity</th>
                        <th>Detected At</th>
                    </tr>

                    {% for alert in alerts %}
                    <tr>
                        <td>{{ alert.alert_type }}</td>
                        <td>{{ alert.source_ip }}</td>
                        <td class="{{ alert.severity }}">
                            {{ alert.severity }}
                        </td>
                        <td>{{ alert.detected_at }}</td>
                    </tr>
                    {% endfor %}
                </table>

            </div>

            <div class="footer">
                Hybrid Network Security | Local Monitoring Dashboard
            </div>

        </main>

        <script>

            const severityData = {{ severity_counts | tojson }};
            const alertData = {{ alert_counts | tojson }};

            new Chart(
                document.getElementById("severityChart"),
                {
                    type: "doughnut",
                    data: {
                        labels: [
                            "Critical", "High", "Medium", "Low"
                        ],
                        datasets: [{
                            data: [
                                severityData.CRITICAL,
                                severityData.HIGH,
                                severityData.MEDIUM,
                                severityData.LOW
                            ],
                            backgroundColor: [
                                "#ef4444",
                                "#f97316",
                                "#eab308",
                                "#22c55e"
                            ],
                            borderWidth: 0
                        }]
                    },
                    options: {
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                labels: { color: "#e2e8f0" }
                            }
                        }
                    }
                }
            );

            new Chart(
                document.getElementById("alertChart"),
                {
                    type: "bar",
                    data: {
                        labels: [
                            "Critical", "High", "Medium", "Low"
                        ],
                        datasets: [{
                            label: "Security Alerts",
                            data: [
                                alertData.CRITICAL,
                                alertData.HIGH,
                                alertData.MEDIUM,
                                alertData.LOW
                            ],
                            backgroundColor: "#38bdf8",
                            borderRadius: 6
                        }]
                    },
                    options: {
                        maintainAspectRatio: false,
                        scales: {
                            x: {
                                ticks: { color: "#e2e8f0" },
                                grid: { color: "#293b55" }
                            },
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    color: "#e2e8f0",
                                    precision: 0
                                },
                                grid: { color: "#293b55" }
                            }
                        },
                        plugins: {
                            legend: {
                                labels: { color: "#e2e8f0" }
                            }
                        }
                    }
                }
            );

        </script>

    </body>
    <script>
    // Automatically refresh dashboard every 10 seconds
    setInterval(function () {
        window.location.reload();
    }, 10000);
</script>
    </html>
    """

    return render_template_string(
        html,
        scans=scans,
        vulnerabilities=vulnerabilities,
        alerts=alerts,
        severity_counts=severity_counts,
        alert_counts=alert_counts
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
