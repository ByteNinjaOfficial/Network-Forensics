from __future__ import annotations

import asyncio
import shutil
import xml.etree.ElementTree as ET
from datetime import UTC, datetime

from backend.models.schemas import Alert, Device, NmapHost, NmapScanResult, ScanHistoryEntry
from backend.services.evidence_store import EvidenceStore
from backend.utils.vendor_lookup import lookup_vendor


class NmapScanner:
    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    async def scan(self, target: str, arguments: list[str] | None = None) -> NmapScanResult:
        nmap_path = shutil.which("nmap")
        if not nmap_path:
            raise RuntimeError("nmap executable was not found on PATH")

        safe_arguments = _sanitize_arguments(arguments or ["-T4", "-F"])
        command = [nmap_path, *safe_arguments, "-oX", "-", target]
        started_at = datetime.now(UTC)
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
        if process.returncode not in (0, None):
            raise RuntimeError(stderr.decode(errors="ignore") or "nmap scan failed")

        hosts = _parse_nmap_xml(stdout.decode(errors="ignore"))
        new_hosts: list[str] = []
        changed_hosts: list[str] = []
        alerts_created = 0
        for host in hosts:
            device_id = host.mac_address or host.ip_address
            existing = self.store.get_device(device_id)
            if existing is None:
                new_hosts.append(host.ip_address)
            elif sorted(existing.open_ports) != sorted(host.open_ports):
                changed_hosts.append(host.ip_address)
            risk_score = _risk_score(host, is_new=existing is None)
            device = Device(
                id=device_id,
                ip_address=host.ip_address,
                mac_address=host.mac_address,
                vendor=host.vendor or lookup_vendor(host.mac_address),
                hostname=host.hostname,
                open_ports=host.open_ports,
                first_seen=existing.first_seen if existing else datetime.now(UTC),
                last_seen=datetime.now(UTC),
                risk_score=max(existing.risk_score if existing else 0, risk_score),
                packet_count=existing.packet_count if existing else 0,
            )
            self.store.upsert_device(device)
            for alert in _alerts_for_host(host, device.id, is_new=existing is None):
                self.store.add_alert(alert)
                alerts_created += 1

        result_command = ["nmap", *safe_arguments, "-oX", "-", target]
        scan = ScanHistoryEntry(
            target=target,
            command=result_command,
            hosts=hosts,
            new_hosts=new_hosts,
            changed_hosts=changed_hosts,
            alerts_created=alerts_created,
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )
        self.store.add_scan(scan)
        return NmapScanResult(
            scan_id=scan.id,
            target=target,
            command=result_command,
            hosts=hosts,
            new_hosts=new_hosts,
            changed_hosts=changed_hosts,
            alerts_created=alerts_created,
            raw_summary=f"{len(hosts)} host(s) parsed",
        )


def _sanitize_arguments(arguments: list[str]) -> list[str]:
    blocked = {"-oX", "-oA", "-oG", "-oN", "-iL", "--script", "--script-args"}
    clean: list[str] = []
    for item in arguments:
        if item in blocked or item.startswith("-o"):
            continue
        clean.append(item)
    return clean[:12]


def _parse_nmap_xml(xml_text: str) -> list[NmapHost]:
    root = ET.fromstring(xml_text)
    hosts: list[NmapHost] = []
    for host in root.findall("host"):
        status = host.find("status")
        state = status.attrib.get("state", "unknown") if status is not None else "unknown"
        addresses = host.findall("address")
        ip_address = None
        mac_address = None
        vendor = None
        for address in addresses:
            addr_type = address.attrib.get("addrtype")
            if addr_type in {"ipv4", "ipv6"} and not ip_address:
                ip_address = address.attrib.get("addr")
            if addr_type == "mac":
                mac_address = address.attrib.get("addr")
                vendor = address.attrib.get("vendor")
        if not ip_address:
            continue

        hostname = None
        hostname_node = host.find("hostnames/hostname")
        if hostname_node is not None:
            hostname = hostname_node.attrib.get("name")

        open_ports: list[int] = []
        for port in host.findall("ports/port"):
            port_state = port.find("state")
            if port_state is not None and port_state.attrib.get("state") == "open":
                open_ports.append(int(port.attrib["portid"]))

        hosts.append(
            NmapHost(
                ip_address=ip_address,
                hostname=hostname,
                mac_address=mac_address,
                vendor=vendor,
                state=state,
                open_ports=sorted(open_ports),
            )
        )
    return hosts


RISKY_PORTS = {
    21: ("FTP_OPEN", "FTP service is exposed"),
    23: ("TELNET_OPEN", "Telnet service is exposed"),
    445: ("SMB_EXPOSED", "SMB service is exposed"),
    3389: ("RDP_EXPOSED", "Remote Desktop service is exposed"),
    5900: ("VNC_EXPOSED", "VNC service is exposed"),
}


def _risk_score(host: NmapHost, is_new: bool) -> int:
    score = 10 if host.state == "up" else 0
    if is_new:
        score += 20
    if not host.vendor and not host.mac_address:
        score += 10
    score += min(len(host.open_ports) * 6, 35)
    score += sum(18 for port in host.open_ports if port in RISKY_PORTS)
    return min(score, 100)


def _alerts_for_host(host: NmapHost, device_id: str, is_new: bool) -> list[Alert]:
    alerts: list[Alert] = []
    if is_new:
        alerts.append(
            Alert(
                alert_type="NEW_DEVICE",
                severity="low",
                source_ip=host.ip_address,
                source_mac=host.mac_address,
                device_id=device_id,
                description=f"Nmap discovered a new host at {host.ip_address}",
                threat_score=30,
            )
        )
    if len(host.open_ports) >= 10:
        alerts.append(
            Alert(
                alert_type="LARGE_ATTACK_SURFACE",
                severity="medium",
                source_ip=host.ip_address,
                source_mac=host.mac_address,
                device_id=device_id,
                description=f"{host.ip_address} exposes {len(host.open_ports)} open ports",
                threat_score=60,
            )
        )
    for port in host.open_ports:
        if port in RISKY_PORTS:
            alert_type, description = RISKY_PORTS[port]
            alerts.append(
                Alert(
                    alert_type=alert_type,
                    severity="high" if port in {23, 3389, 5900} else "medium",
                    source_ip=host.ip_address,
                    source_mac=host.mac_address,
                    device_id=device_id,
                    description=f"{description} on {host.ip_address}:{port}",
                    threat_score=75 if port in {23, 3389, 5900} else 62,
                )
            )
    return alerts
