print("NETWORK SCANNER STARTED")

import nmap
import json
from datetime import datetime


def discover_network(target):
    scanner = nmap.PortScanner()

    print(f"\nStarting network discovery: {target}")

    scanner.scan(hosts=target, arguments="-sn")

    devices = []

    for host in scanner.all_hosts():
        device = {
            "ip": host,
            "hostname": scanner[host].hostname(),
            "status": scanner[host].state(),
            "discovered_at": datetime.now().isoformat()
        }

        devices.append(device)
        print(device)

    return devices


if __name__ == "__main__":
    # Scan only your own machine for this first test
    results = discover_network("127.0.0.1")

    with open("discovered_devices.json", "w") as file:
        json.dump(results, file, indent=4)

    print("\nScan completed!")
