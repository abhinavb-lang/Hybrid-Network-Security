
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

MODULES = {
    "1": ("Network Discovery", "scanner/network_discovery.py"),
    "2": ("Port Scanner", "scanner/port_scanner.py"),
    "3": ("CVE Lookup", "vulnerability/cve_lookup.py"),
    "4": ("Risk Assessment", "vulnerability/risk_scoring.py"),
    "5": ("Packet Threat Detection", "detection/packet_monitor.py"),
    "6": ("Security Alert Engine", "detection/alert_engine.py"),
    "7": ("Store Scan Results", "database/store_scans.py"),
    "8": ("Store Vulnerabilities", "database/store_vulnerabilities.py"),
    "9": ("Store Security Alerts", "database/store_alerts.py"),
    "10": ("Launch Security Dashboard", "dashboard/app.py")
}


def run_module(name, relative_path):

    script_path = BASE_DIR / relative_path

    if not script_path.is_file():
        print("\nError: Module not found:", relative_path)
        return

    print("\nStarting:", name)
    print("=" * 50)

    try:
        subprocess.run(
            [sys.executable, str(script_path)],
            cwd=BASE_DIR,
            check=False
        )

    except KeyboardInterrupt:
        print("\nModule stopped by user.")

    print("\nReturning to main menu...")


def main():

    while True:

        print("\n" + "=" * 55)
        print("       HYBRID NETWORK SECURITY SYSTEM")
        print("=" * 55)

        for number, (name, path) in MODULES.items():
            print(f"{number}. {name}")

        print("0. Exit")

        print("=" * 55)

        choice = input("Select an option: ").strip()

        if choice == "0":
            print("\nExiting Hybrid Network Security System.")
            break

        if choice in MODULES:
            name, path = MODULES[choice]
            run_module(name, path)

        else:
            print("\nInvalid option. Please try again.")


if __name__ == "__main__":
    main()
