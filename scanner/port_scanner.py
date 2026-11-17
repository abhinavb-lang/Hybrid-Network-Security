
import nmap
import json
from pathlib import Path
from datetime import datetime


def scan_ports(target, ports="1-1024"):
    scanner = nmap.PortScanner()

    print("\nStarting Port Scanner...")
    print(f"Target: {target}")

    try:
        scanner.scan(
            hosts=target,
            ports=ports,
            arguments="-sT -sV --version-light -T3"
        )

        results = []

        for host in scanner.all_hosts():

            print(f"\nHost: {host}")

            for protocol in scanner[host].all_protocols():

                port_info = scanner[host][protocol]

                for port, details in port_info.items():

                    service = {
                        "ip": host,
                        "protocol": protocol,
                        "port": port,
                        "state": details.get("state"),
                        "service": details.get("name"),
                        "product": details.get("product"),
                        "version": details.get("version"),
                        "scanned_at": datetime.now().isoformat()
                    }

                    results.append(service)
                    print(service)

        Path("reports").mkdir(exist_ok=True)

        with open("reports/port_scan_results.json", "w") as file:
            json.dump(results, file, indent=4)

        print("\nPort scanning completed!")
        print(f"Results saved: reports/port_scan_results.json")

        return results

    except nmap.PortScannerError as error:
        print(f"Nmap error: {error}")
        return []

    except Exception as error:
        print(f"Unexpected error: {error}")
        return []


if __name__ == "__main__":

    # Initial test: scan only your own computer
    scan_ports("127.0.0.1")
