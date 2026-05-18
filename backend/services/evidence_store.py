from __future__ import annotations

import asyncio
from collections import Counter, defaultdict, deque
from datetime import UTC, datetime

from backend.models.schemas import Alert, BlockedEntity, Device, PacketMetadata, ScanHistoryEntry


class EvidenceStore:
    def __init__(self, packet_limit: int = 10000) -> None:
        self._packets: deque[PacketMetadata] = deque(maxlen=packet_limit)
        self._devices: dict[str, Device] = {}
        self._alerts: deque[Alert] = deque(maxlen=2000)
        self._blocked: list[BlockedEntity] = []
        self._scan_history: deque[ScanHistoryEntry] = deque(maxlen=200)
        self._packet_subscribers: set[asyncio.Queue[PacketMetadata]] = set()
        self._alert_subscribers: set[asyncio.Queue[Alert]] = set()
        self._ip_macs: dict[str, set[str]] = defaultdict(set)

    @property
    def packet_count(self) -> int:
        return len(self._packets)

    def add_packet(self, packet: PacketMetadata) -> None:
        self._packets.append(packet)
        if packet.src_mac:
            self._ip_macs[packet.src_ip].add(packet.src_mac)
        self._publish(self._packet_subscribers, packet)

    def list_packets(self, limit: int = 250, protocol: str | None = None) -> list[PacketMetadata]:
        packets = list(self._packets)
        if protocol:
            packets = [packet for packet in packets if packet.protocol.lower() == protocol.lower()]
        return packets[-limit:][::-1]

    def upsert_device(self, device: Device) -> None:
        self._devices[device.id] = device

    def get_device(self, device_id: str) -> Device | None:
        return self._devices.get(device_id)

    def list_devices(self) -> list[Device]:
        return sorted(self._devices.values(), key=lambda item: item.last_seen, reverse=True)

    def macs_for_ip(self, ip: str) -> set[str]:
        return set(self._ip_macs.get(ip, set()))

    def add_alert(self, alert: Alert) -> None:
        self._alerts.append(alert)
        if alert.source_mac and alert.source_mac in self._devices:
            device = self._devices[alert.source_mac]
            device.risk_score = max(device.risk_score, alert.threat_score)
            self._devices[alert.source_mac] = device
        self._publish(self._alert_subscribers, alert)

    def list_alerts(self, limit: int = 100, unresolved_only: bool = False) -> list[Alert]:
        alerts = list(self._alerts)
        if unresolved_only:
            alerts = [alert for alert in alerts if not alert.resolved]
        return alerts[-limit:][::-1]

    def resolve_alert(self, alert_id: str) -> Alert | None:
        for alert in self._alerts:
            if alert.id == alert_id:
                alert.resolved = True
                return alert
        return None

    def add_blocked(self, blocked: BlockedEntity) -> None:
        self._blocked.append(blocked)

    def add_scan(self, scan: ScanHistoryEntry) -> None:
        self._scan_history.append(scan)

    def list_scans(self, limit: int = 25) -> list[ScanHistoryEntry]:
        return list(self._scan_history)[-limit:][::-1]

    def subscribe_packets(self) -> asyncio.Queue[PacketMetadata]:
        queue: asyncio.Queue[PacketMetadata] = asyncio.Queue(maxsize=500)
        self._packet_subscribers.add(queue)
        return queue

    def unsubscribe_packets(self, queue: asyncio.Queue[PacketMetadata]) -> None:
        self._packet_subscribers.discard(queue)

    def subscribe_alerts(self) -> asyncio.Queue[Alert]:
        queue: asyncio.Queue[Alert] = asyncio.Queue(maxsize=500)
        self._alert_subscribers.add(queue)
        return queue

    def unsubscribe_alerts(self, queue: asyncio.Queue[Alert]) -> None:
        self._alert_subscribers.discard(queue)

    def stats(self) -> dict[str, object]:
        protocols = Counter(packet.protocol for packet in self._packets)
        talkers = Counter(packet.src_ip for packet in self._packets)
        return {
            "packets": len(self._packets),
            "devices": len(self._devices),
            "alerts": len(self._alerts),
            "blocked": len(self._blocked),
            "scans": len(self._scan_history),
            "high_risk_devices": len([device for device in self._devices.values() if device.risk_score >= 70]),
            "protocols": dict(protocols),
            "top_talkers": talkers.most_common(5),
            "generated_at": datetime.now(UTC).isoformat(),
        }

    def topology(self) -> dict[str, list[dict[str, object]]]:
        nodes = [{"id": device.id, "label": device.hostname or device.ip_address, "risk": device.risk_score, "type": "device", "ip": device.ip_address, "ports": device.open_ports} for device in self._devices.values()]
        edge_counts = Counter((packet.src_ip, packet.dst_ip, packet.protocol) for packet in self._packets)
        edges = [
            {"source": src, "target": dst, "protocol": protocol, "packets": count}
            for (src, dst, protocol), count in edge_counts.items()
        ]
        edges.extend(
            {"source": "nmap-scanner", "target": device.id, "protocol": "NMAP", "packets": len(device.open_ports) or 1}
            for device in self._devices.values()
        )
        nodes.append({"id": "nmap-scanner", "label": "Scanner", "risk": 0, "type": "scanner"})
        for packet in self._packets:
            if not any(node["id"] == packet.dst_ip for node in nodes):
                nodes.append({"id": packet.dst_ip, "label": packet.dst_ip, "risk": 0, "type": "external" if not packet.dst_ip.startswith(("192.168.", "10.", "172.")) else "server"})
        return {"nodes": nodes, "edges": edges}

    def export_json(self) -> dict[str, object]:
        return {
            "packets": [packet.model_dump(mode="json") for packet in self._packets],
            "devices": [device.model_dump(mode="json") for device in self._devices.values()],
            "alerts": [alert.model_dump(mode="json") for alert in self._alerts],
            "blocked_entities": [blocked.model_dump(mode="json") for blocked in self._blocked],
            "scan_history": [scan.model_dump(mode="json") for scan in self._scan_history],
            "exported_at": datetime.now(UTC).isoformat(),
        }

    def export_report(self) -> str:
        generated_at = datetime.now(UTC).isoformat()
        alerts = self.list_alerts(limit=20)
        devices = self.list_devices()
        scans = self.list_scans(limit=10)
        lines = [
            "# PROBE Network Forensics Evidence Report",
            "",
            f"Generated at: {generated_at}",
            "",
            "## Summary",
            "",
            f"- Packets recorded: {len(self._packets)}",
            f"- Devices discovered: {len(devices)}",
            f"- Alerts raised: {len(self._alerts)}",
            f"- Nmap scans: {len(self._scan_history)}",
            "",
            "## High Risk Devices",
            "",
        ]
        high_risk = [device for device in devices if device.risk_score >= 50]
        if high_risk:
            lines.extend(f"- {device.ip_address} risk={device.risk_score} ports={','.join(map(str, device.open_ports)) or 'none'} host={device.hostname or 'unknown'}" for device in high_risk)
        else:
            lines.append("- None recorded")
        lines.extend(["", "## Recent Alerts", ""])
        if alerts:
            lines.extend(f"- [{alert.severity}] {alert.alert_type} {alert.source_ip or ''}: {alert.description}" for alert in alerts)
        else:
            lines.append("- None recorded")
        lines.extend(["", "## Recent Nmap Scans", ""])
        if scans:
            lines.extend(f"- {scan.target}: {len(scan.hosts)} host(s), new={len(scan.new_hosts)}, changed={len(scan.changed_hosts)}" for scan in scans)
        else:
            lines.append("- None recorded")
        return "\n".join(lines)

    @staticmethod
    def _publish(subscribers: set[asyncio.Queue], item: object) -> None:
        stale: list[asyncio.Queue] = []
        for queue in subscribers:
            try:
                queue.put_nowait(item)
            except asyncio.QueueFull:
                stale.append(queue)
        for queue in stale:
            subscribers.discard(queue)
