from __future__ import annotations

from backend.models.schemas import Device, PacketMetadata
from backend.services.evidence_store import EvidenceStore
from backend.utils.vendor_lookup import lookup_vendor


class DeviceMapper:
    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def observe(self, packet: PacketMetadata) -> Device:
        device_id = packet.src_mac or packet.src_ip
        existing = self.store.get_device(device_id)
        ports = set(existing.open_ports if existing else [])
        if packet.src_port:
            ports.add(packet.src_port)
        if packet.dst_port and packet.dst_ip.startswith(("192.168.", "10.", "172.")):
            ports.add(packet.dst_port)

        device = Device(
            id=device_id,
            ip_address=packet.src_ip,
            mac_address=packet.src_mac,
            vendor=lookup_vendor(packet.src_mac),
            hostname=packet.hostname or (existing.hostname if existing else None),
            open_ports=sorted(ports)[:100],
            first_seen=existing.first_seen if existing else packet.timestamp,
            last_seen=packet.timestamp,
            risk_score=existing.risk_score if existing else 0,
            packet_count=(existing.packet_count if existing else 0) + 1,
        )
        self.store.upsert_device(device)
        return device
