from __future__ import annotations

import argparse
import json
from pathlib import Path

from server import generate_pdf_report, run_scan


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureProbe TCP port scanner with service detection and PDF reporting.")
    parser.add_argument("target", help="Target URL, hostname, IP address, or CIDR range.")
    parser.add_argument("-p", "--ports", default="21,22,23,25,53,80,110,139,143,443,445,587,993,995,1433,3306,3389,5432,5900,6379,8080,8443,27017", help="Ports or ranges, e.g. 22,80,443,8000-8010.")
    parser.add_argument("-t", "--timeout", type=float, default=0.7, help="Socket timeout in seconds.")
    parser.add_argument("-w", "--threads", type=int, default=100, help="Maximum worker threads.")
    parser.add_argument("--json", action="store_true", help="Print the full JSON result.")
    args = parser.parse_args()

    result = run_scan(
        {
            "target": args.target,
            "ports": args.ports,
            "timeout": args.timeout,
            "threads": args.threads,
        }
    )
    result["pdfReport"] = generate_pdf_report(result)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print("SecureProbe scan complete")
    print(f"Target: {result['target']}")
    print(f"Checked sockets: {result['checkedPorts']}")
    print(f"Open ports: {result['openCount']}")
    print(f"Exposure rating: {result['exposureRating']}")
    for row in result["openPorts"]:
        banner = f" | {row['banner']}" if row.get("banner") else ""
        print(f"- {row['host']}:{row['port']} {row['service']} ({row['confidence']}){banner}")
    print(f"PDF report: {Path(result['pdfReport'].lstrip('/')).resolve()}")


if __name__ == "__main__":
    main()
