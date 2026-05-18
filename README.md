# PROBE - Network Forensics & Intrusion Prevention System

PROBE is a hackathon-ready, agentless network forensics and intrusion detection platform built for **CT-DFIR-03 - Network Forensics**. It helps analysts discover devices, inspect traffic metadata, detect suspicious behavior, generate forensic evidence, and demonstrate response actions without installing agents on client devices.

## What It Does

- Captures or simulates packet metadata through a FastAPI backend
- Discovers real devices and open ports using installed Nmap
- Uploads and analyzes `.pcap` / `.pcapng` files from Wireshark
- Maps devices by IP, MAC, hostname, vendor, open ports, and risk score
- Detects port scans, ARP spoofing, DNS tunneling, anonymizer endpoints, beaconing, exposed services, and new devices
- Shows live traffic, devices, topology, alerts, scan history, and forensic evidence in a React dashboard
- Exports JSON, CSV, HTML, PDF, SHA-256 evidence hash, and Ollama AI analysis reports
- Provides dry-run blocking commands for alert sources

## Current Features

### Backend

- FastAPI REST and WebSocket API
- Scapy-based packet parsing and live capture scaffolding
- Built-in `demo0` traffic generator for reliable presentations
- Real Nmap scan ingestion through `/scan/nmap`
- PCAP upload analysis through `/pcap/upload`
- IDS-style detection engine
- Device mapper and risk scoring
- Scan history and new/changed host diffs
- Evidence store with JSON, CSV, HTML, PDF, and hash exports
- Ollama integration at `http://127.0.0.1:11434`

### Frontend

- React + Vite dashboard
- Live Traffic page with charts, packet table, PCAP upload, and attack simulations
- Devices page with Nmap scanner, topology, scan history, and device detail panel
- Alerts page with resolve and dry-run block actions
- Forensics page with reports, CSV exports, evidence hash, AI analysis, and AI PDF export

## Project Structure

```text
backend/
  api/              FastAPI routes
  capture/          Capture controller and demo traffic
  detection/        IDS and anomaly rules
  models/           Pydantic schemas
  parsers/          Packet parsers
  services/         Nmap, PCAP, reports, AI, devices, alerts
  utils/            Vendor lookup helpers
frontend/
  src/              React dashboard
docs/               API, setup, and architecture notes
demo/               Demo alert assets
docker/             Dockerfiles
scripts/            Helper scripts
tests/              Backend unit/API tests
```

## Requirements

- Python 3.12+ recommended
- Node.js 20+
- Nmap installed and available on `PATH`
- Npcap/admin privileges for real live capture on Windows
- Optional: Ollama exposed at `http://127.0.0.1:11434`

## Quick Start

From the repository root:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m backend.cli --host 127.0.0.1 --port 8000
```

In another terminal:

```powershell
cd frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

Open:

```text
http://127.0.0.1:5173
```

API health check:

```text
http://127.0.0.1:8000/health
```

## Presentation Flow

1. Start backend and frontend.
2. Open the dashboard at `http://127.0.0.1:5173`.
3. Click **Stop** if you want to stop demo traffic.
4. Go to **Devices** and run an Nmap scan against `127.0.0.1` or an authorized LAN target such as `192.168.1.0/24`.
5. Show discovered hosts, open ports, risk scores, topology, and scan history.
6. Go to **Live Traffic** and upload a PCAP or use attack simulation buttons if the network is quiet.
7. Go to **Alerts** and show detection output plus dry-run blocking.
8. Go to **Forensics** and export JSON, CSV, HTML, PDF, hash, or AI reports.

Use scans and packet capture only on systems and networks you own or are authorized to assess.

## Main API Endpoints

- `GET /health`
- `GET /interfaces`
- `POST /capture/start`
- `POST /capture/stop`
- `GET /packets/history`
- `WS /packets/live`
- `GET /devices`
- `GET /devices/{id}/context`
- `POST /scan/nmap`
- `GET /scan/history`
- `POST /pcap/upload`
- `POST /simulate/{scenario}`
- `GET /alerts`
- `POST /alerts/{id}/resolve`
- `POST /alerts/{id}/block`
- `GET /topology`
- `GET /forensics/export`
- `GET /forensics/report?format=html`
- `GET /forensics/report?format=pdf`
- `GET /forensics/csv/{kind}`
- `GET /forensics/hash`
- `POST /ai/analyze`
- `GET /ai/report.pdf`

Full API notes are in [docs/api.md](docs/api.md).

## Ollama AI Analysis

The AI analysis features call Ollama at:

```text
http://127.0.0.1:11434
```

If Ollama is running in Docker, publish the port to the host:

```powershell
docker run -d --name ollama -p 11434:11434 ollama/ollama
```

Then use a model name installed in Ollama, for example `llama3.2`, `llama3`, or `mistral`.

## Testing

```powershell
.venv\Scripts\python.exe -m pytest
```

Frontend build:

```powershell
cd frontend
npm run build
```

## Docker

```powershell
docker compose up --build
```

## What Not To Commit

The `.gitignore` excludes local virtual environments, dependency folders, frontend build output, pytest cache, local PCAP evidence, generated exports, logs, and scratch files such as `run.txt`.

Commit the source folders and docs:

- `backend/`
- `frontend/`
- `docs/`
- `demo/`
- `docker/`
- `scripts/`
- `tests/`
- `requirements.txt`
- `docker-compose.yml`
- `.gitignore`
- `README.md`

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
