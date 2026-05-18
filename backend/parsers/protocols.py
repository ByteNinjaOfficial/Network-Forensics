from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from backend.models.schemas import PacketMetadata


def parse_scapy_packet(raw: Any) -> PacketMetadata | None:
    try:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.http import HTTPRequest
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.l2 import ARP, Ether
    except Exception:
        return None

    src_mac = dst_mac = src_ip = dst_ip = None
    protocol = "OTHER"
    src_port = dst_port = None
    dns_query = http_host = http_path = tls_sni = arp_op = None

    if raw.haslayer(Ether):
        src_mac = raw[Ether].src
        dst_mac = raw[Ether].dst
    if raw.haslayer(IP):
        src_ip = raw[IP].src
        dst_ip = raw[IP].dst
    if raw.haslayer(TCP):
        protocol = "TCP"
        src_port = int(raw[TCP].sport)
        dst_port = int(raw[TCP].dport)
    elif raw.haslayer(UDP):
        protocol = "UDP"
        src_port = int(raw[UDP].sport)
        dst_port = int(raw[UDP].dport)
    elif raw.haslayer(ICMP):
        protocol = "ICMP"
    elif raw.haslayer(ARP):
        protocol = "ARP"
        src_ip = raw[ARP].psrc
        dst_ip = raw[ARP].pdst
        src_mac = raw[ARP].hwsrc
        dst_mac = raw[ARP].hwdst
        arp_op = "who-has" if int(raw[ARP].op) == 1 else "is-at"

    if raw.haslayer(DNS) and raw.haslayer(DNSQR):
        protocol = "DNS"
        dns_query = raw[DNSQR].qname.decode(errors="ignore").rstrip(".")
    if raw.haslayer(HTTPRequest):
        protocol = "HTTP"
        http_host = raw[HTTPRequest].Host.decode(errors="ignore") if raw[HTTPRequest].Host else None
        http_path = raw[HTTPRequest].Path.decode(errors="ignore") if raw[HTTPRequest].Path else None

    if not src_ip and not src_mac:
        return None

    return PacketMetadata(
        src_ip=src_ip or "0.0.0.0",
        dst_ip=dst_ip or "0.0.0.0",
        src_mac=src_mac,
        dst_mac=dst_mac,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        size=len(raw),
        timestamp=datetime.now(UTC),
        dns_query=dns_query,
        http_host=http_host,
        http_path=http_path,
        tls_sni=tls_sni,
        arp_op=arp_op,
    )
