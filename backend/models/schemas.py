from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, Field


class PacketMetadata(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    src_ip: str
    dst_ip: str
    protocol: str
    size: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    src_mac: str | None = None
    dst_mac: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    hostname: str | None = None
    dns_query: str | None = None
    http_host: str | None = None
    http_path: str | None = None
    tls_sni: str | None = None
    tcp_flags: str | None = None
    arp_op: str | None = None
    payload_hash: str | None = None


class Device(BaseModel):
    id: str
    ip_address: str
    mac_address: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    open_ports: list[int] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    risk_score: int = 0
    packet_count: int = 0


class Alert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    alert_type: str
    severity: str
    description: str
    source_ip: str | None = None
    source_mac: str | None = None
    device_id: str | None = None
    evidence_packet_id: str | None = None
    threat_score: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    resolved: bool = False


class CaptureRequest(BaseModel):
    interface: str = "demo0"
    bpf_filter: str | None = None
    mode: str = "demo"


class CaptureStatus(BaseModel):
    running: bool
    interface: str
    bpf_filter: str | None = None
    mode: str
    packets_seen: int


class BlockRequest(BaseModel):
    value: str
    reason: str = "Analyst requested block"
    dry_run: bool = True


class NmapScanRequest(BaseModel):
    target: str = "127.0.0.1"
    arguments: list[str] = Field(default_factory=lambda: ["-T4", "-F"])


class NmapHost(BaseModel):
    ip_address: str
    hostname: str | None = None
    mac_address: str | None = None
    vendor: str | None = None
    state: str = "unknown"
    open_ports: list[int] = Field(default_factory=list)


class NmapScanResult(BaseModel):
    command: list[str]
    hosts: list[NmapHost]
    scan_id: str | None = None
    target: str | None = None
    new_hosts: list[str] = Field(default_factory=list)
    changed_hosts: list[str] = Field(default_factory=list)
    alerts_created: int = 0
    raw_summary: str | None = None


class ScanHistoryEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    target: str
    command: list[str]
    hosts: list[NmapHost]
    new_hosts: list[str] = Field(default_factory=list)
    changed_hosts: list[str] = Field(default_factory=list)
    alerts_created: int = 0
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class BlockedEntity(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    kind: str
    value: str
    reason: str
    blocked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    command: str
    dry_run: bool = True
