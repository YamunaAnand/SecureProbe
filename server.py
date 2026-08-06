from __future__ import annotations

import concurrent.futures
import hashlib
import ipaddress
import json
import mimetypes
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


ROOT = Path(__file__).resolve().parent
REPORT_DIR = ROOT / "output" / "pdf"
MAX_PORTS = 5000
MAX_HOSTS = 256
MAX_THREADS = 500
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8017

SERVICE_NAMES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MSRPC",
    139: "NETBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    2049: "NFS",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8000: "HTTP-ALT",
    8080: "HTTP-PROXY",
    8443: "HTTPS-ALT",
    27017: "MONGODB",
}

RISKY_PORTS = {
    21: ("Medium", "FTP service exposed", "FTP often sends credentials in clear text. Use SFTP/FTPS or restrict access."),
    22: ("Low", "SSH service exposed", "Use key-based auth, disable root login, and restrict source IPs where possible."),
    23: ("High", "Telnet service exposed", "Telnet is unencrypted. Disable it and use SSH."),
    25: ("Medium", "SMTP service exposed", "Confirm relay controls, SPF/DKIM/DMARC, and patch level."),
    139: ("Medium", "NetBIOS service exposed", "Restrict legacy Windows file-sharing services to trusted networks."),
    445: ("High", "SMB service exposed", "Never expose SMB publicly. Restrict by firewall/VPN and patch aggressively."),
    1433: ("High", "MSSQL service exposed", "Restrict database access and enforce strong authentication."),
    3306: ("High", "MySQL service exposed", "Restrict database access to application hosts or VPN ranges."),
    3389: ("High", "RDP service exposed", "Restrict RDP, enforce MFA, and monitor brute-force attempts."),
    5432: ("High", "PostgreSQL service exposed", "Restrict database access and enforce TLS/authentication controls."),
    5900: ("High", "VNC service exposed", "Do not expose VNC publicly. Tunnel through VPN or SSH."),
    6379: ("High", "Redis service exposed", "Redis should not be internet-facing. Bind locally or firewall it."),
    27017: ("High", "MongoDB service exposed", "Restrict database access and enforce authentication/TLS."),
}


@dataclass(frozen=True)
class ScanTarget:
    display: str
    host: str


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def clean_target(raw_target: str) -> str:
    target = raw_target.strip()
    if not target:
        raise ValueError("Enter a target host, URL, IP address, or CIDR range.")
    if "://" in target:
        parsed = urlparse(target)
        target = parsed.hostname or ""
    elif "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            target = target.split("/", 1)[0]
    if not target:
        raise ValueError("The target could not be parsed.")
    return target


def expand_targets(raw_target: str) -> list[ScanTarget]:
    target = clean_target(raw_target)
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise ValueError("CIDR ranges must look like 192.168.1.0/24.") from exc
        hosts = list(network.hosts())
        if not hosts and network.num_addresses == 1:
            hosts = [network.network_address]
        if len(hosts) > MAX_HOSTS:
            raise ValueError(f"CIDR range is too large. Scan {MAX_HOSTS} hosts or fewer.")
        return [ScanTarget(str(host), str(host)) for host in hosts]
    return [ScanTarget(target, target)]


def parse_ports(raw_ports: str) -> list[int]:
    ports: set[int] = set()
    try:
        for item in raw_ports.split(","):
            part = item.strip()
            if not part:
                continue
            if "-" in part:
                start_text, end_text = part.split("-", 1)
                start = int(start_text.strip())
                end = int(end_text.strip())
                if start > end:
                    start, end = end, start
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
    except ValueError as exc:
        raise ValueError("Ports must be numbers or ranges like 22,80,443,8000-8010.") from exc

    clean_ports = sorted(port for port in ports if 1 <= port <= 65535)
    if not clean_ports:
        raise ValueError("Enter at least one TCP port from 1 to 65535.")
    if len(clean_ports) > MAX_PORTS:
        raise ValueError(f"Too many ports. Scan {MAX_PORTS} ports or fewer.")
    return clean_ports


def base_service_name(port: int) -> str:
    if port in SERVICE_NAMES:
        return SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "UNKNOWN"


def read_banner(sock: socket.socket, host: str, port: int, timeout: float) -> str:
    sock.settimeout(min(timeout, 1.2))
    try:
        if port in {80, 8000, 8080}:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii", "ignore"))
        data = sock.recv(256)
    except OSError:
        return ""
    return data.decode("utf-8", "replace").strip().replace("\r", " ").replace("\n", " ")[:180]


def detect_service(port: int, banner: str) -> dict[str, str]:
    hint = base_service_name(port)
    banner_lower = banner.lower()
    service = hint
    confidence = "low"
    method = "port_hint"

    if banner.startswith("SSH-"):
        service = "SSH"
        confidence = "high"
        method = "banner"
    elif banner.startswith("220") and port in {21, 25, 587}:
        service = "FTP" if port == 21 else "SMTP"
        confidence = "medium"
        method = "banner"
    elif "http/" in banner_lower or "server:" in banner_lower:
        service = "HTTP" if port not in {443, 8443} else "HTTPS"
        confidence = "medium"
        method = "http_probe"
    elif banner.startswith("TLS "):
        service = "HTTPS" if port in {443, 8443} else hint
        confidence = "medium"
        method = "tls_handshake"

    version = "Unknown"
    match = re.search(r"(OpenSSH[_/ -]?[\w.]+|nginx[/ ][\w.]+|Apache[/ ][\w.]+|Microsoft-IIS[/ ][\w.]+)", banner, re.I)
    if match:
        version = match.group(1)
        confidence = "high"

    return {
        "name": service,
        "version": version,
        "method": method,
        "confidence": confidence,
    }


def scan_one(target: ScanTarget, port: int, timeout: float) -> dict[str, Any]:
    started = time.perf_counter()
    result: dict[str, Any] = {
        "host": target.display,
        "port": port,
        "state": "closed",
        "service": base_service_name(port),
        "serviceVersion": "Unknown",
        "serviceMethod": "port_hint",
        "confidence": "low",
        "banner": "",
        "latencyMs": None,
    }

    try:
        with socket.create_connection((target.host, port), timeout=timeout) as sock:
            result["state"] = "open"
            result["latencyMs"] = round((time.perf_counter() - started) * 1000, 1)
            if port in {443, 465, 993, 995, 8443}:
                result["service"] = "HTTPS" if port in {443, 8443} else result["service"]
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    with context.wrap_socket(sock, server_hostname=target.host) as tls_sock:
                        result["banner"] = f"TLS {tls_sock.version()}"
                except OSError:
                    result["banner"] = ""
            else:
                result["banner"] = read_banner(sock, target.host, port, timeout)
            service = detect_service(port, str(result["banner"]))
            result["service"] = service["name"]
            result["serviceVersion"] = service["version"]
            result["serviceMethod"] = service["method"]
            result["confidence"] = service["confidence"]
    except (ConnectionRefusedError, TimeoutError, socket.timeout, OSError):
        pass
    return result


def build_findings(open_ports: list[dict[str, Any]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for row in open_ports:
        risk = RISKY_PORTS.get(int(row["port"]))
        if risk:
            severity, title, recommendation = risk
            findings.append(
                {
                    "severity": severity,
                    "title": title,
                    "evidence": f'{row["host"]}:{row["port"]} responded as {row["service"]}.',
                    "recommendation": recommendation,
                }
            )

    web_ports = [row for row in open_ports if int(row["port"]) in {80, 443, 8000, 8080, 8443}]
    if web_ports:
        findings.append(
            {
                "severity": "Low",
                "title": "Public web service exposure",
                "evidence": ", ".join(f'{row["host"]}:{row["port"]}/{row["service"]}' for row in web_ports),
                "recommendation": "Keep web stacks patched, force HTTPS, and review TLS/security headers.",
            }
        )

    if not findings:
        findings.append(
            {
                "severity": "Info",
                "title": "No high-risk service pattern detected",
                "evidence": "Open ports were reviewed against the built-in exposure checklist.",
                "recommendation": "Validate business need and repeat scans after any network changes.",
            }
        )
    return findings


def exposure_rating(findings: list[dict[str, str]], open_count: int) -> str:
    severities = {finding["severity"].lower() for finding in findings}
    if "high" in severities:
        return "High"
    if "medium" in severities or open_count > 8:
        return "Medium"
    if open_count:
        return "Low"
    return "Informational"


def run_scan(payload: dict[str, Any]) -> dict[str, Any]:
    target_text = str(payload.get("target", ""))
    ports_text = str(payload.get("ports", ""))
    timeout = max(0.05, min(float(payload.get("timeout", 0.5)), 10.0))
    threads = max(1, min(int(payload.get("threads", 50)), MAX_THREADS))
    targets = expand_targets(target_text)
    ports = parse_ports(ports_text)

    started = time.perf_counter()
    jobs = [(target, port) for target in targets for port in ports]
    results: list[dict[str, Any]] = []
    workers = min(threads, len(jobs))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scan_one, target, port, timeout) for target, port in jobs]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda row: (row["host"], row["port"]))
    open_ports = [row for row in results if row["state"] == "open"]
    findings = build_findings(open_ports)
    duration = time.perf_counter() - started

    return {
        "target": target_text.strip(),
        "resolvedTargets": [target.display for target in targets],
        "checkedPorts": len(results),
        "openCount": len(open_ports),
        "closedCount": len(results) - len(open_ports),
        "duration": f"{duration:.2f}s",
        "results": results,
        "openPorts": open_ports,
        "findings": findings,
        "exposureRating": exposure_rating(findings, len(open_ports)),
        "generatedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
    }


def report_filename(result: dict[str, Any]) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    digest = hashlib.sha1(json.dumps(result, sort_keys=True).encode("utf-8")).hexdigest()[:8]
    return f"secureprobe-report-{stamp}-{digest}.pdf"


def make_paragraph(text: Any, style: ParagraphStyle) -> Paragraph:
    safe = str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return Paragraph(safe, style)


def generate_pdf_report(result: dict[str, Any]) -> str:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    filename = report_filename(result)
    path = REPORT_DIR / filename
    styles = getSampleStyleSheet()
    title = ParagraphStyle("SecureProbeTitle", parent=styles["Title"], fontSize=24, leading=30, textColor=colors.HexColor("#0f2544"))
    heading = ParagraphStyle("SecureProbeHeading", parent=styles["Heading2"], fontSize=14, leading=18, textColor=colors.HexColor("#163f6d"), spaceBefore=10)
    body = ParagraphStyle("SecureProbeBody", parent=styles["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("SecureProbeSmall", parent=styles["BodyText"], fontSize=8, leading=10)
    table_head = ParagraphStyle("SecureProbeTableHead", parent=small, textColor=colors.white)

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.55 * inch,
        bottomMargin=0.55 * inch,
        title="SecureProbe Security Assessment Report",
    )

    elements: list[Any] = [
        make_paragraph("SecureProbe Security Assessment Report", title),
        make_paragraph("Open TCP Port Detection and Service Assessment", styles["Heading3"]),
        Spacer(1, 12),
    ]

    summary_rows = [
        ["Target", result["target"]],
        ["Resolved targets", ", ".join(result["resolvedTargets"])],
        ["Generated", result["generatedAt"]],
        ["Checked sockets", result["checkedPorts"]],
        ["Open ports", result["openCount"]],
        ["Closed or filtered", result["closedCount"]],
        ["Duration", result["duration"]],
        ["Exposure rating", result["exposureRating"]],
    ]
    summary_table = Table([[make_paragraph(a, body), make_paragraph(b, body)] for a, b in summary_rows], colWidths=[1.7 * inch, 5.3 * inch])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e9f1fb")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#b8c9dc")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    elements.extend([summary_table, Spacer(1, 12), make_paragraph("Open Ports", heading)])

    if result["openPorts"]:
        open_rows = [["Host", "Port", "Service", "Confidence", "Evidence"]]
        for row in result["openPorts"]:
            evidence = row.get("banner") or row.get("serviceMethod") or "TCP connect succeeded"
            open_rows.append([row["host"], row["port"], row["service"], row["confidence"], evidence])
        table = Table(
            [
                [make_paragraph(cell, table_head if row_index == 0 else small) for cell in row]
                for row_index, row in enumerate(open_rows)
            ],
            colWidths=[1.35 * inch, 0.55 * inch, 1.0 * inch, 0.8 * inch, 3.3 * inch],
            repeatRows=1,
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#163f6d")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#b8c9dc")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        elements.append(table)
    else:
        elements.append(make_paragraph("No open TCP ports were confirmed in the selected scope.", body))

    elements.extend([Spacer(1, 12), make_paragraph("Security Findings", heading)])
    finding_rows = [["Severity", "Finding", "Evidence", "Recommendation"]]
    for finding in result["findings"]:
        finding_rows.append([finding["severity"], finding["title"], finding["evidence"], finding["recommendation"]])
    finding_table = Table(
        [
            [make_paragraph(cell, table_head if row_index == 0 else small) for cell in row]
            for row_index, row in enumerate(finding_rows)
        ],
        colWidths=[0.75 * inch, 1.45 * inch, 2.1 * inch, 2.7 * inch],
        repeatRows=1,
    )
    finding_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#163f6d")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#b8c9dc")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    elements.append(finding_table)

    elements.extend(
        [
            PageBreak(),
            make_paragraph("Methodology and Accuracy Notes", heading),
            make_paragraph(
                "SecureProbe uses TCP connect scanning from this machine. An open result means the TCP handshake completed from this network location. Closed or filtered means the connection was refused, timed out, reset, or blocked during the timeout window.",
                body,
            ),
            Spacer(1, 8),
            make_paragraph(
                "Service names combine IANA/common port hints, safe banner reads, HTTP probes, and TLS handshake evidence. Confidence is high when a banner/version clearly identifies the service, medium when protocol behavior confirms it, and low when only the port number identifies it.",
                body,
            ),
            Spacer(1, 8),
            make_paragraph(
                "Recommendations: validate every exposed service, disable unused listeners, restrict administrative/database ports with firewall rules, patch service software, and repeat scans after remediation.",
                body,
            ),
        ]
    )

    doc.build(elements)
    return f"/output/pdf/{filename}"


class SecureProbeHandler(BaseHTTPRequestHandler):
    server_version = "SecureProbe/1.0"

    def do_GET(self) -> None:
        request_path = urlparse(self.path).path

        if request_path == "/":
            request_path = "/index.html"

        file_path = (ROOT / request_path.lstrip("/")).resolve()

        if not str(file_path).startswith(str(ROOT)) or not file_path.is_file():
            self.send_error(404)
            return

        body = file_path.read_bytes()
        content_type = (
            mimetypes.guess_type(file_path.name)[0]
            or "application/octet-stream"
        )

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))

        if request_path.startswith("/output/pdf/") and file_path.suffix.lower() == ".pdf":
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="{file_path.name}"'
            )

        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/scan":
            json_response(self, 404, {"error": "Unknown endpoint."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            result = run_scan(payload)
            result["pdfReport"] = generate_pdf_report(result)
            json_response(self, 200, result)
        except ValueError as exc:
            json_response(self, 400, {"error": str(exc)})
        except Exception as exc:
            json_response(self, 500, {"error": f"Scan failed: {exc}"})

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer((DEFAULT_HOST, DEFAULT_PORT), SecureProbeHandler)
    print(f"SecureProbe running at http://{DEFAULT_HOST}:{DEFAULT_PORT}/")
    server.serve_forever()


if __name__ == "__main__":
    main()
