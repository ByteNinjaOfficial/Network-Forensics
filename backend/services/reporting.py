from __future__ import annotations

import csv
import hashlib
import html
import io
import json
from datetime import UTC, datetime

from backend.services.evidence_store import EvidenceStore


class ReportBuilder:
    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def csv_export(self, kind: str) -> str:
        output = io.StringIO()
        rows = _rows_for(kind, self.store)
        if not rows:
            return ""
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue()

    def html_report(self, ai_summary: str | None = None) -> str:
        evidence = self.store.export_json()
        digest = hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()
        devices = self.store.list_devices()
        alerts = self.store.list_alerts(limit=50)
        generated_at = datetime.now(UTC).isoformat()
        ai_block = f"<section><h2>AI Analysis</h2><pre>{html.escape(ai_summary)}</pre></section>" if ai_summary else ""
        device_rows = "".join(f"<tr><td>{html.escape(d.ip_address)}</td><td>{html.escape(d.hostname or '-')}</td><td>{html.escape(d.vendor or '-')}</td><td>{', '.join(map(str, d.open_ports))}</td><td>{d.risk_score}</td></tr>" for d in devices)
        alert_rows = "".join(f"<tr><td>{html.escape(a.severity)}</td><td>{html.escape(a.alert_type)}</td><td>{html.escape(a.source_ip or '-')}</td><td>{html.escape(a.description)}</td></tr>" for a in alerts)
        return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>PROBE Evidence Report</title>
<style>body{{font-family:Arial,sans-serif;margin:32px;color:#172033}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #d9e2ec;padding:8px;text-align:left}}pre{{white-space:pre-wrap;background:#f4f7f9;padding:12px;border:1px solid #d9e2ec}}.hash{{overflow-wrap:anywhere}}</style></head>
<body><h1>PROBE Network Forensics Evidence Report</h1><p>Generated at: {generated_at}</p><p class="hash"><strong>SHA-256:</strong> {digest}</p>
<section><h2>Summary</h2><ul><li>Packets: {len(evidence["packets"])}</li><li>Devices: {len(evidence["devices"])}</li><li>Alerts: {len(evidence["alerts"])}</li><li>Scans: {len(evidence["scan_history"])}</li></ul></section>
{ai_block}
<section><h2>Devices</h2><table><thead><tr><th>IP</th><th>Host</th><th>Vendor</th><th>Open Ports</th><th>Risk</th></tr></thead><tbody>{device_rows}</tbody></table></section>
<section><h2>Alerts</h2><table><thead><tr><th>Severity</th><th>Type</th><th>Source</th><th>Description</th></tr></thead><tbody>{alert_rows}</tbody></table></section>
</body></html>"""

    def pdf_report(self, title: str, body: str) -> bytes:
        text = f"{title}\n\n{body}"
        return _simple_pdf(text)

    def evidence_hash(self) -> str:
        evidence = self.store.export_json()
        return hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()


def _rows_for(kind: str, store: EvidenceStore) -> list[dict[str, object]]:
    if kind == "devices":
        return [device.model_dump(mode="json") for device in store.list_devices()]
    if kind == "alerts":
        return [alert.model_dump(mode="json") for alert in store.list_alerts(limit=1000)]
    if kind == "scans":
        return [scan.model_dump(mode="json") for scan in store.list_scans(limit=200)]
    return [packet.model_dump(mode="json") for packet in store.list_packets(limit=1000)]


def _simple_pdf(text: str) -> bytes:
    lines = []
    for raw in text.splitlines():
        while len(raw) > 92:
            lines.append(raw[:92])
            raw = raw[92:]
        lines.append(raw)
    escaped = [_pdf_escape(line) for line in lines[:58]]
    stream = "BT /F1 10 Tf 50 780 Td 14 TL " + " T* ".join(f"({line}) Tj" for line in escaped) + " ET"
    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n",
        b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
        f"5 0 obj << /Length {len(stream.encode())} >> stream\n{stream}\nendstream endobj\n".encode(),
    ]
    data = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(data))
        data.extend(obj)
    xref = len(data)
    data.extend(f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        data.extend(f"{offset:010d} 00000 n \n".encode())
    data.extend(f"trailer << /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(data)


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
