from __future__ import annotations

import asyncio
import itertools
import random
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from backend.detection.engine import DetectionEngine
from backend.models.schemas import CaptureStatus, PacketMetadata
from backend.parsers.protocols import parse_scapy_packet
from backend.services.device_mapper import DeviceMapper
from backend.services.evidence_store import EvidenceStore


class CaptureController:
    """Coordinates live packet capture or deterministic demo traffic."""

    def __init__(self, store: EvidenceStore, mapper: DeviceMapper, detector: DetectionEngine) -> None:
        self.store = store
        self.mapper = mapper
        self.detector = detector
        self._task: asyncio.Task[None] | None = None
        self._running = False
        self._interface = "demo0"
        self._filter: str | None = None
        self._mode = "demo"

    def list_interfaces(self) -> list[dict[str, str]]:
        interfaces = [{"name": "demo0", "description": "Built-in Cyberthon demo traffic"}]
        try:
            from scapy.all import get_if_list

            interfaces.extend({"name": item, "description": "Local capture interface"} for item in get_if_list())
        except Exception:
            pass
        return interfaces

    async def start(self, interface: str, bpf_filter: str | None = None, mode: str = "demo") -> CaptureStatus:
        if self._running:
            return self.status()
        self._interface = interface
        self._filter = bpf_filter
        self._mode = mode
        self._running = True
        target = self._demo_loop if mode == "demo" or interface == "demo0" else self._scapy_loop
        self._task = asyncio.create_task(target())
        return self.status()

    async def stop(self) -> CaptureStatus:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        return self.status()

    def status(self) -> CaptureStatus:
        return CaptureStatus(
            running=self._running,
            interface=self._interface,
            bpf_filter=self._filter,
            mode=self._mode,
            packets_seen=self.store.packet_count,
        )

    async def _handle_packet(self, packet: PacketMetadata) -> None:
        self.store.add_packet(packet)
        self.mapper.observe(packet)
        self.detector.inspect(packet, self.store)

    async def _demo_loop(self) -> None:
        for packet in itertools.cycle(_demo_packets()):
            if not self._running:
                return
            packet.id = str(uuid4())
            packet.timestamp = datetime.now(UTC)
            await self._handle_packet(packet)
            await asyncio.sleep(0.12 if packet.protocol != "TCP" else 0.03)

    async def _scapy_loop(self) -> None:
        try:
            from scapy.all import AsyncSniffer
        except Exception:
            self._mode = "demo"
            await self._demo_loop()
            return

        queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=5000)

        def enqueue(raw: Any) -> None:
            try:
                queue.put_nowait(raw)
            except asyncio.QueueFull:
                pass

        sniffer = AsyncSniffer(iface=self._interface, filter=self._filter, prn=enqueue, store=False)
        sniffer.start()
        try:
            while self._running:
                raw = await queue.get()
                parsed = parse_scapy_packet(raw)
                if parsed:
                    await self._handle_packet(parsed)
        finally:
            sniffer.stop()


def _demo_packets() -> list[PacketMetadata]:
    base = datetime.now(UTC)
    attacker_mac = "02:42:ac:11:00:66"
    victim = "192.168.10.25"
    ports = list(range(20, 86))
    packets: list[PacketMetadata] = [
        PacketMetadata(src_ip="192.168.10.12", dst_ip="8.8.8.8", src_mac="58:ef:68:21:44:10", dst_mac="aa:bb:cc:00:00:01", protocol="DNS", size=92, timestamp=base, dns_query="updates.microsoft.com", hostname="analyst-laptop"),
        PacketMetadata(src_ip="192.168.10.44", dst_ip="1.1.1.1", src_mac="d8:3a:dd:5c:01:9a", dst_mac="aa:bb:cc:00:00:01", protocol="DNS", size=228, timestamp=base, dns_query="very-long-subdomain-exfiltration-marker-4d2f9b7a91c0.example.net", hostname="finance-pc"),
        PacketMetadata(src_ip="192.168.10.77", dst_ip="185.220.101.18", src_mac="44:65:0d:99:aa:01", dst_mac="aa:bb:cc:00:00:01", protocol="TLS", size=642, timestamp=base, tls_sni="relay.torproject.org", hostname="unknown-android"),
        PacketMetadata(src_ip="192.168.10.50", dst_ip="192.168.10.1", src_mac="08:00:27:aa:10:50", dst_mac="aa:bb:cc:00:00:01", protocol="ARP", size=60, timestamp=base, arp_op="is-at", hostname="lab-vm"),
        PacketMetadata(src_ip="192.168.10.50", dst_ip="192.168.10.1", src_mac="08:00:27:bb:99:50", dst_mac="aa:bb:cc:00:00:01", protocol="ARP", size=60, timestamp=base, arp_op="is-at", hostname="lab-vm-clone"),
    ]
    packets.extend(
        PacketMetadata(
            src_ip="192.168.10.66",
            dst_ip=victim,
            src_mac=attacker_mac,
            dst_mac="58:ef:68:21:44:25",
            protocol="TCP",
            size=random.randint(54, 80),
            timestamp=base,
            dst_port=port,
            tcp_flags="S",
            hostname="kali-attacker",
        )
        for port in ports
    )
    return packets
