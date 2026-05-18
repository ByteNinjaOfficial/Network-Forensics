from __future__ import annotations

from datetime import UTC, datetime

from backend.detection.engine import DetectionEngine
from backend.models.schemas import PacketMetadata
from backend.services.device_mapper import DeviceMapper
from backend.services.evidence_store import EvidenceStore


class AttackSimulator:
    def __init__(self, store: EvidenceStore, mapper: DeviceMapper, detector: DetectionEngine) -> None:
        self.store = store
        self.mapper = mapper
        self.detector = detector

    def simulate(self, scenario: str) -> dict[str, object]:
        packets = _scenario_packets(scenario)
        for packet in packets:
            self.store.add_packet(packet)
            self.mapper.observe(packet)
            self.detector.inspect(packet, self.store)
        return {"scenario": scenario, "packets_added": len(packets), "alerts": len(self.store.list_alerts(limit=500))}


def _scenario_packets(scenario: str) -> list[PacketMetadata]:
    now = datetime.now(UTC)
    if scenario == "dns_tunnel":
        return [
            PacketMetadata(
                src_ip="192.168.56.44",
                dst_ip="1.1.1.1",
                src_mac="d8:3a:dd:99:44:01",
                protocol="DNS",
                size=210,
                timestamp=now,
                dns_query="chunk-4f9a8c2e7d1b0a9e8d7c6b5a4f3e2d1c.exfil.demo.local",
                hostname="sim-finance-host",
            )
        ]
    if scenario == "arp_spoof":
        return [
            PacketMetadata(src_ip="192.168.56.1", dst_ip="192.168.56.10", src_mac="08:00:27:aa:aa:01", protocol="ARP", size=60, timestamp=now, arp_op="is-at", hostname="gateway"),
            PacketMetadata(src_ip="192.168.56.1", dst_ip="192.168.56.10", src_mac="08:00:27:bb:bb:02", protocol="ARP", size=60, timestamp=now, arp_op="is-at", hostname="spoofed-gateway"),
        ]
    if scenario == "beaconing":
        return [
            PacketMetadata(src_ip="192.168.56.77", dst_ip="198.98.51.42", src_mac="44:65:0d:56:77:01", protocol="TLS", size=430, timestamp=now, tls_sni="c2.demo.local", hostname="sim-workstation")
            for _ in range(12)
        ]
    return [
        PacketMetadata(src_ip="192.168.56.66", dst_ip="192.168.56.20", src_mac="02:42:ac:56:00:66", protocol="TCP", size=64, timestamp=now, dst_port=port, tcp_flags="S", hostname="sim-kali")
        for port in range(1, 62)
    ]
