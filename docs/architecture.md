# PROBE Architecture

PROBE is an agentless network forensics MVP with a FastAPI backend and a React dashboard.

## Data Flow

1. `CaptureController` receives packets from Scapy or the built-in Cyberthon demo stream.
2. `parse_scapy_packet` normalizes packet metadata for TCP, UDP, ICMP, DNS, HTTP, and ARP.
3. `DeviceMapper` updates IP, MAC, vendor, hostname, port, and risk history.
4. `DetectionEngine` applies threshold, signature, and behavior rules.
5. `AlertManager` deduplicates alerts and writes immutable evidence records into `EvidenceStore`.
6. REST and WebSocket endpoints serve live packets, alerts, device inventory, topology, and JSON evidence exports.

## MVP Detection Rules

- Port scan: 50 or more unique destination ports from one source within 10 seconds.
- ARP spoofing: more than one MAC address observed for the same IP.
- DNS tunneling: long DNS query labels or sustained high query length.
- Anonymizer endpoint: TOR/VPN indicators in destination IP, DNS, or TLS metadata.
- Beaconing: repeated external destination hits within a rolling window.

## Production Path

The in-memory `EvidenceStore` is intentionally simple for hackathon demos. Replace it with PostgreSQL plus Elasticsearch for retention, search, and audit controls. Keep the service interfaces stable so capture, detection, and API code do not need large rewrites.
