from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta

from backend.models.schemas import Alert, PacketMetadata
from backend.services.alert_manager import AlertManager
from backend.services.evidence_store import EvidenceStore


class DetectionEngine:
    def __init__(self, alerts: AlertManager) -> None:
        self.alerts = alerts
        self._ports_by_src: dict[str, deque[tuple[datetime, int]]] = defaultdict(deque)
        self._dns_lengths: dict[str, deque[tuple[datetime, int]]] = defaultdict(deque)
        self._external_hits: dict[str, deque[datetime]] = defaultdict(deque)

    def inspect(self, packet: PacketMetadata, store: EvidenceStore) -> None:
        self._detect_port_scan(packet)
        self._detect_dns_tunnel(packet)
        self._detect_tor_or_proxy(packet)
        self._detect_arp_spoof(packet, store)
        self._detect_beaconing(packet)

    def _detect_port_scan(self, packet: PacketMetadata) -> None:
        if packet.protocol != "TCP" or packet.dst_port is None:
            return
        window = self._ports_by_src[packet.src_ip]
        window.append((packet.timestamp, packet.dst_port))
        _trim_pairs(window, packet.timestamp, seconds=10)
        unique_ports = {port for _, port in window}
        if len(unique_ports) >= 50:
            self.alerts.raise_alert(
                Alert(
                    alert_type="PORT_SCAN",
                    severity="high",
                    source_ip=packet.src_ip,
                    source_mac=packet.src_mac,
                    description=f"{packet.src_ip} touched {len(unique_ports)} unique ports in 10 seconds",
                    evidence_packet_id=packet.id,
                    threat_score=86,
                )
            )

    def _detect_dns_tunnel(self, packet: PacketMetadata) -> None:
        if packet.protocol != "DNS" or not packet.dns_query:
            return
        window = self._dns_lengths[packet.src_ip]
        window.append((packet.timestamp, len(packet.dns_query)))
        _trim_pairs(window, packet.timestamp, seconds=60)
        if len(packet.dns_query) > 55 or sum(length for _, length in window) / len(window) > 45:
            self.alerts.raise_alert(
                Alert(
                    alert_type="DNS_TUNNELING",
                    severity="medium",
                    source_ip=packet.src_ip,
                    source_mac=packet.src_mac,
                    description=f"Suspicious DNS query length from {packet.src_ip}: {packet.dns_query}",
                    evidence_packet_id=packet.id,
                    threat_score=67,
                )
            )

    def _detect_tor_or_proxy(self, packet: PacketMetadata) -> None:
        tor_indicators = ("torproject", "185.220.101.", "198.98.51.")
        haystack = " ".join(filter(None, [packet.dst_ip, packet.tls_sni, packet.dns_query]))
        if any(indicator in haystack for indicator in tor_indicators):
            self.alerts.raise_alert(
                Alert(
                    alert_type="ANONYMIZER_ENDPOINT",
                    severity="medium",
                    source_ip=packet.src_ip,
                    source_mac=packet.src_mac,
                    description=f"Traffic from {packet.src_ip} matched TOR/VPN endpoint indicators",
                    evidence_packet_id=packet.id,
                    threat_score=62,
                )
            )

    def _detect_arp_spoof(self, packet: PacketMetadata, store: EvidenceStore) -> None:
        if not packet.src_mac:
            return
        macs = store.macs_for_ip(packet.src_ip)
        if len(macs | {packet.src_mac}) > 1:
            self.alerts.raise_alert(
                Alert(
                    alert_type="ARP_SPOOFING",
                    severity="critical",
                    source_ip=packet.src_ip,
                    source_mac=packet.src_mac,
                    description=f"Multiple MAC addresses observed for {packet.src_ip}: {', '.join(sorted(macs | {packet.src_mac}))}",
                    evidence_packet_id=packet.id,
                    threat_score=94,
                )
            )

    def _detect_beaconing(self, packet: PacketMetadata) -> None:
        if _is_private(packet.dst_ip):
            return
        hits = self._external_hits[f"{packet.src_ip}->{packet.dst_ip}"]
        hits.append(packet.timestamp)
        _trim_datetimes(hits, packet.timestamp, seconds=120)
        if len(hits) >= 10:
            self.alerts.raise_alert(
                Alert(
                    alert_type="BEACONING",
                    severity="medium",
                    source_ip=packet.src_ip,
                    source_mac=packet.src_mac,
                    description=f"Repeated external connections from {packet.src_ip} to {packet.dst_ip}",
                    evidence_packet_id=packet.id,
                    threat_score=58,
                )
            )


def _trim_pairs(values: deque[tuple[datetime, int]], now: datetime, seconds: int) -> None:
    cutoff = now - timedelta(seconds=seconds)
    while values and values[0][0] < cutoff:
        values.popleft()


def _trim_datetimes(values: deque[datetime], now: datetime, seconds: int) -> None:
    cutoff = now - timedelta(seconds=seconds)
    while values and values[0] < cutoff:
        values.popleft()


def _is_private(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31."))
