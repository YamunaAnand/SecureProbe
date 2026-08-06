# SecureProbe

SecureProbe is a Python-based security assessment tool for authorized TCP port scanning, conservative service detection, evidence-based risk analysis, and report generation. The current version includes both a command-line workflow and a browser-based dashboard.


## Current stack

- Python: 3.13.7 (tested in the current workspace)
- Flask: 3.1.3
- pytest: 9.1.1

## What the project does

The project can:
- scan a single host or an authorized IPv4 CIDR range,
- identify open TCP ports,
- infer likely services from standard port hints,
- raise evidence-based security findings,
- generate JSON and HTML reports,
- run through a simple web interface at http://127.0.0.1:5000.

## Features

- Single-host and CIDR scanning
- TCP port parsing for single ports, comma-separated values, and ranges
- Multi-threaded scanning with ThreadPoolExecutor
- Open/closed/timeout/error state reporting
- Conservative service detection
- Evidence-based risk analysis
- JSON and HTML reporting
- Web dashboard with export links
- CLI and API-based workflows
- Automated tests

## Project structure

- app.py: Flask web app and scan API
- main.py: CLI entry point
- scanner/: scanning and target parsing logic
- detection/: service detection logic
- security/: risk analysis logic
- reporting/: JSON and HTML report generation
- templates/: web UI templates
- static/: frontend assets
- tests/: automated test suite

## Installation

From the project root:

```powershell
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

If you are using the workspace interpreter, the project is already configured to use the local virtual environment in the repository.

## Running the web app

Start the browser-based interface:

```powershell
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Running the CLI

Example:

```powershell
python main.py --target 127.0.0.1 --ports 80,443 --threads 20 --timeout 0.5 --format both
```

### CLI options

- --target: host, IP address, or CIDR block
- --ports: single port, comma-separated ports, or ranges
- --threads: number of worker threads
- --timeout: connection timeout in seconds
- --output: output directory for reports
- --format: json, html, or both
- --verbose: enable verbose logging
- --max-hosts: maximum hosts for CIDR expansion

## Example commands

```powershell
python main.py --target localhost --ports 80,443
python main.py --target 127.0.0.1 --ports 22,80,443 --threads 100
python main.py --target 192.168.1.0/24 --ports 80,443 --max-hosts 16
```

## Target and port formats

- Targets: localhost, 127.0.0.1, hostname, 192.168.1.0/24
- Ports: 80, 22,80,443, 1-1024, 22,80,443,8000-8080

## Service detection and risk analysis

The tool uses conservative port-based hints and optional banner-based evidence. It does not guess vulnerabilities or claim exploitation without observed signals.

## Reporting

Reports are written to the reports/ directory in JSON and HTML formats. The web app also exposes downloadable links after a scan completes.

## Testing

Run the automated test suite:

```powershell
python -m pytest -q
```

## Ethical and legal usage

Use this tool only against systems you own or are explicitly authorized to assess. The project is intended for learning, lab environments, and authorized security testing.


