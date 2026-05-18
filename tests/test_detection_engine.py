from datetime import UTC, datetime

from backend.detection.engine import DetectionEngine
from backend.models.schemas import PacketMetadata
from backend.services.alert_manager import AlertManager
from backend.services.device_mapper import DeviceMapper
from backend.services.evidence_store import EvidenceStore


def test_port_scan_alert_after_unique_ports():
    store = EvidenceStore()
    mapper = DeviceMapper(store)
    detector = DetectionEngine(AlertManager(store))

    for port in range(1, 52):
        packet = PacketMetadata(
            src_ip="192.168.1.99",
            dst_ip="192.168.1.10",
            src_mac="02:42:ac:11:00:99",
            protocol="TCP",
            size=60,
            dst_port=port,
            timestamp=datetime.now(UTC),
        )
        store.add_packet(packet)
        mapper.observe(packet)
        detector.inspect(packet, store)

    alerts = store.list_alerts()
    assert any(alert.alert_type == "PORT_SCAN" for alert in alerts)


def test_arp_spoof_alert_on_multiple_macs_for_ip():
    store = EvidenceStore()
    detector = DetectionEngine(AlertManager(store))
    first = PacketMetadata(src_ip="192.168.1.50", dst_ip="192.168.1.1", src_mac="08:00:27:aa:aa:aa", protocol="ARP", size=60)
    second = PacketMetadata(src_ip="192.168.1.50", dst_ip="192.168.1.1", src_mac="08:00:27:bb:bb:bb", protocol="ARP", size=60)

    store.add_packet(first)
    detector.inspect(first, store)
    store.add_packet(second)
    detector.inspect(second, store)

    assert store.list_alerts()[0].alert_type == "ARP_SPOOFING"


def test_long_dns_query_flags_tunneling():
    store = EvidenceStore()
    detector = DetectionEngine(AlertManager(store))
    packet = PacketMetadata(
        src_ip="192.168.1.44",
        dst_ip="1.1.1.1",
        src_mac="d8:3a:dd:5c:01:9a",
        protocol="DNS",
        size=180,
        dns_query="a" * 64 + ".example.net",
    )

    store.add_packet(packet)
    detector.inspect(packet, store)

    assert store.list_alerts()[0].alert_type == "DNS_TUNNELING"
