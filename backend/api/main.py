from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Annotated

import httpx
from fastapi import FastAPI, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response

from backend.capture.sniffer import CaptureController
from backend.detection.engine import DetectionEngine
from backend.models.schemas import (
    Alert,
    BlockRequest,
    CaptureRequest,
    CaptureStatus,
    Device,
    NmapScanRequest,
    NmapScanResult,
    PacketMetadata,
    ScanHistoryEntry,
)
from backend.services.alert_manager import AlertManager
from backend.services.ai_analyzer import AiAnalyzer
from backend.services.device_mapper import DeviceMapper
from backend.services.evidence_store import EvidenceStore
from backend.services.nmap_scanner import NmapScanner
from backend.services.pcap_analyzer import PcapAnalyzer
from backend.services.reporting import ReportBuilder
from backend.services.simulator import AttackSimulator
from backend.services.threat_blocker import ThreatBlocker

app = FastAPI(
    title="PROBE Network Forensics API",
    version="0.1.0",
    description="Agentless network forensics and IDS/IPS MVP for Cyberthon CT-DFIR-03.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

store = EvidenceStore()
device_mapper = DeviceMapper(store)
alert_manager = AlertManager(store)
detection_engine = DetectionEngine(alert_manager)
blocker = ThreatBlocker(store)
nmap_scanner = NmapScanner(store)
capture = CaptureController(store, device_mapper, detection_engine)
pcap_analyzer = PcapAnalyzer(store, device_mapper, detection_engine)
simulator = AttackSimulator(store, device_mapper, detection_engine)
reporting = ReportBuilder(store)
ai_analyzer = AiAnalyzer(store)


@asynccontextmanager
async def lifespan(app_: FastAPI):
    await capture.start(interface="demo0", mode="demo")
    yield
    await capture.stop()


app.router.lifespan_context = lifespan


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "probe-api"}


@app.get("/interfaces")
async def interfaces() -> list[dict[str, str]]:
    return capture.list_interfaces()


@app.post("/capture/start", response_model=CaptureStatus)
async def start_capture(request: CaptureRequest) -> CaptureStatus:
    return await capture.start(interface=request.interface, bpf_filter=request.bpf_filter, mode=request.mode)


@app.post("/capture/stop", response_model=CaptureStatus)
async def stop_capture() -> CaptureStatus:
    return await capture.stop()


@app.get("/capture/status", response_model=CaptureStatus)
async def capture_status() -> CaptureStatus:
    return capture.status()


@app.get("/packets/history", response_model=list[PacketMetadata])
async def packet_history(
    limit: Annotated[int, Query(ge=1, le=1000)] = 250,
    protocol: str | None = None,
) -> list[PacketMetadata]:
    return store.list_packets(limit=limit, protocol=protocol)


@app.websocket("/packets/live")
async def packet_stream(websocket: WebSocket) -> None:
    await websocket.accept()
    queue = store.subscribe_packets()
    try:
        while True:
            packet = await queue.get()
            await websocket.send_json(packet.model_dump(mode="json"))
    except WebSocketDisconnect:
        store.unsubscribe_packets(queue)


@app.get("/devices", response_model=list[Device])
async def devices() -> list[Device]:
    return store.list_devices()


@app.get("/devices/{device_id}", response_model=Device)
async def device(device_id: str) -> Device:
    item = store.get_device(device_id)
    if item is None:
        raise HTTPException(status_code=404, detail="device not found")
    return item


@app.get("/devices/{device_id}/context")
async def device_context(device_id: str) -> dict[str, object]:
    item = store.get_device(device_id)
    if item is None:
        raise HTTPException(status_code=404, detail="device not found")
    packets = [packet for packet in store.list_packets(limit=500) if packet.src_ip == item.ip_address or packet.dst_ip == item.ip_address]
    alerts = [alert for alert in store.list_alerts(limit=500) if alert.device_id == item.id or alert.source_ip == item.ip_address or alert.source_mac == item.mac_address]
    scans = [scan for scan in store.list_scans(limit=50) if any(host.ip_address == item.ip_address for host in scan.hosts)]
    return {"device": item, "packets": packets[:50], "alerts": alerts[:50], "scans": scans[:20]}


@app.post("/scan/nmap", response_model=NmapScanResult)
async def nmap_scan(request: NmapScanRequest) -> NmapScanResult:
    try:
        return await nmap_scanner.scan(request.target, request.arguments)
    except TimeoutError as exc:
        raise HTTPException(status_code=504, detail="nmap scan timed out") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/scan/history", response_model=list[ScanHistoryEntry])
async def scan_history(limit: Annotated[int, Query(ge=1, le=100)] = 25) -> list[ScanHistoryEntry]:
    return store.list_scans(limit=limit)


@app.post("/pcap/upload")
async def upload_pcap(file: UploadFile = File(...)) -> dict[str, object]:
    suffix = ".pcapng" if file.filename and file.filename.endswith(".pcapng") else ".pcap"
    try:
        return pcap_analyzer.analyze_bytes(await file.read(), suffix=suffix)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/simulate/{scenario}")
async def simulate_attack(scenario: str) -> dict[str, object]:
    if scenario not in {"port_scan", "dns_tunnel", "arp_spoof", "beaconing"}:
        raise HTTPException(status_code=400, detail="unknown simulation scenario")
    return simulator.simulate(scenario)


@app.get("/alerts", response_model=list[Alert])
async def alerts(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    unresolved_only: bool = False,
) -> list[Alert]:
    return store.list_alerts(limit=limit, unresolved_only=unresolved_only)


@app.post("/alerts/{alert_id}/resolve", response_model=Alert)
async def resolve_alert(alert_id: str) -> Alert:
    resolved = store.resolve_alert(alert_id)
    if resolved is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return resolved


@app.post("/alerts/{alert_id}/block")
async def block_alert_source(alert_id: str, dry_run: bool = True) -> dict[str, str]:
    alert = next((item for item in store.list_alerts(limit=1000) if item.id == alert_id), None)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    if not alert.source_ip:
        raise HTTPException(status_code=400, detail="alert has no source IP")
    return blocker.block_ip(alert.source_ip, f"Blocked from alert {alert.alert_type}", dry_run=dry_run)


@app.websocket("/alerts/live")
async def alert_stream(websocket: WebSocket) -> None:
    await websocket.accept()
    queue = store.subscribe_alerts()
    try:
        while True:
            alert = await queue.get()
            await websocket.send_json(alert.model_dump(mode="json"))
    except WebSocketDisconnect:
        store.unsubscribe_alerts(queue)


@app.post("/block/ip")
async def block_ip(request: BlockRequest) -> dict[str, str]:
    return blocker.block_ip(request.value, request.reason, dry_run=request.dry_run)


@app.post("/block/mac")
async def block_mac(request: BlockRequest) -> dict[str, str]:
    return blocker.block_mac(request.value, request.reason, dry_run=request.dry_run)


@app.get("/forensics/export")
async def export_evidence(format: str = "json") -> dict[str, object]:
    if format.lower() != "json":
        raise HTTPException(status_code=400, detail="MVP export currently supports json")
    return store.export_json()


@app.get("/forensics/report", response_model=None)
async def export_report(format: str = "markdown"):
    if format == "html":
        return HTMLResponse(reporting.html_report())
    if format == "pdf":
        return Response(
            reporting.pdf_report("PROBE Network Forensics Evidence Report", store.export_report()),
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="probe-evidence-report.pdf"'},
        )
    return {"format": "markdown", "sha256": reporting.evidence_hash(), "report": store.export_report()}


@app.get("/forensics/csv/{kind}")
async def export_csv(kind: str) -> Response:
    if kind not in {"packets", "devices", "alerts", "scans"}:
        raise HTTPException(status_code=400, detail="kind must be packets, devices, alerts, or scans")
    return Response(
        reporting.csv_export(kind),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="probe-{kind}.csv"'},
    )


@app.get("/forensics/hash")
async def evidence_hash() -> dict[str, str]:
    return {"sha256": reporting.evidence_hash()}


@app.post("/ai/analyze")
async def ai_analyze(model: str = "llama3.2") -> dict[str, str]:
    try:
        return await ai_analyzer.analyze(model=model)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Ollama request failed: {exc}") from exc


@app.get("/ai/report.pdf")
async def ai_report_pdf(model: str = "llama3.2") -> Response:
    try:
        analysis = await ai_analyzer.analyze(model=model)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Ollama request failed: {exc}") from exc
    return Response(
        reporting.pdf_report("PROBE AI Network Forensics Analysis", analysis["analysis"]),
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="probe-ai-analysis.pdf"'},
    )


@app.get("/topology")
async def topology() -> dict[str, list[dict[str, object]]]:
    return store.topology()


@app.get("/stats")
async def stats() -> dict[str, object]:
    return store.stats()


async def run_demo_for(seconds: float = 8.0) -> None:
    await capture.start(interface="demo0", mode="demo")
    await asyncio.sleep(seconds)
    await capture.stop()
