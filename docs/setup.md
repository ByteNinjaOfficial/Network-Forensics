# Setup Guide

## Backend

```bash
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m backend.cli --reload
```

The API starts at `http://127.0.0.1:8000`. It automatically starts `demo0`, which simulates normal traffic, DNS tunneling, TOR/VPN access, ARP spoofing, and an Nmap-like port scan.

Live capture requires administrator/root privileges and a working packet capture driver. Use `/interfaces` to list available interfaces, then call `/capture/start` with `mode: "live"`.

## Dashboard

```bash
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173`.

## Tests

```bash
.venv\Scripts\python.exe -m pytest
```

## Real Device Discovery With Nmap

The dashboard Devices page can run Nmap against a target you provide, such as `127.0.0.1`, `192.168.1.1`, or `192.168.1.0/24`.

The backend runs:

```bash
nmap -T4 -F -oX - <target>
```

It parses XML output and updates the device inventory with real host state, hostnames, vendors, and open ports. Use scans only on networks you own or are authorized to assess.

Nmap scans also create useful demo evidence:

- Scan history with new-host and changed-port diffs.
- Risk scores based on risky ports, unknown devices, and attack surface size.
- Alerts for exposed SMB, Telnet, RDP, VNC, FTP, and new devices.
- A topology panel that links the scanner to discovered devices.

## PCAP, Reports, and AI

The Live Traffic page accepts `.pcap` and `.pcapng` uploads. Uploaded captures are parsed with Scapy and merged into packets, devices, and alerts.

The Forensics page can export:

- JSON evidence
- CSV tables
- HTML report
- PDF report
- SHA-256 evidence hash
- Ollama AI analysis and AI PDF report

Ollama is expected at `http://127.0.0.1:11434`. Set the model name in the UI to one installed in your Ollama container, for example `llama3.2`, `llama3`, or `mistral`.

## Live Capture

Use the capture selector in the dashboard header to choose `demo0` or a real Scapy/Npcap interface. Real capture on Windows usually needs Npcap and administrator privileges.

## Docker

```bash
docker compose up --build
```
