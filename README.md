# IDS

This project is a lightweight intrusion detection system built in Python. It captures network traffic, detects common scan and spoofing patterns, logs alerts, and exposes them through a local dashboard.

## What it does

The IDS monitors packets in real time and looks for:

- SYN scans
- FIN scans
- NULL scans
- XMAS scans
- UDP scans
- ARP spoofing

When a detection occurs, the system:

- records an alert in a local JSON file
- sends the alert to a Flask dashboard
- optionally forwards the alert to Elasticsearch for indexing

## Features

- Packet capture using Scapy
- Modular detector classes
- Central alert reporting path
- Local JSON alert storage in alerts.json
- Web dashboard with live alert updates
- Optional Elasticsearch and Kibana stack via Docker Compose

## Project structure

- ids/ - detection engine and detector modules
- frontend/ - Flask dashboard and WebSocket support
- logger.py - shared alert logging/reporting module
- run_ids.py - main entry point for the IDS and dashboard
- docker-compose.yml - Elasticsearch and Kibana services
- alerts.json - generated alert log file

## Requirements

- Python 3.9 or newer
- Windows, Linux, or macOS
- Administrator/root privileges may be required for packet capture

Install dependencies:

```bash
pip install -r requirements.txt
```

## Quick start

### 1. Create and activate a virtual environment

```bash
python -m venv venv
```

On Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

On Linux/macOS:

```bash
source venv/bin/activate
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Start the optional Elasticsearch and Kibana stack

```bash
docker compose up -d
```

This starts:

- Elasticsearch at http://localhost:9200
- Kibana at http://localhost:5601

### 4. Run the IDS dashboard

```bash
python run_ids.py
```

The web dashboard will be available at:

- http://localhost:5000

## Alert output

Alerts are written to the local file:

- alerts.json

The same alert path is also used for dashboard updates and optional Elasticsearch indexing.

## Notes

- The packet interface in run_ids.py may need to be adjusted depending on your machine.
- On Windows, you may need to choose the correct network adapter name for Scapy.
- Elasticsearch integration is optional; the system can still log and display alerts locally if Elasticsearch is unavailable.

## Development notes

If you want to extend the project, the main place to add new detectors is under the ids/detectors directory. New detections should report through the shared alert path in logger.py so they automatically reach the local log, dashboard, and Elasticsearch.
