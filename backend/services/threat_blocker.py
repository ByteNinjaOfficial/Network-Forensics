from __future__ import annotations

import platform
import subprocess

from backend.models.schemas import BlockedEntity
from backend.services.evidence_store import EvidenceStore


class ThreatBlocker:
    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def block_ip(self, ip: str, reason: str, dry_run: bool = True) -> dict[str, str]:
        command = _ip_block_command(ip)
        blocked = BlockedEntity(kind="ip", value=ip, reason=reason, command=command, dry_run=dry_run)
        self.store.add_blocked(blocked)
        if not dry_run:
            subprocess.run(command, shell=True, check=False)
        return {"status": "recorded" if dry_run else "executed", "command": command}

    def block_mac(self, mac: str, reason: str, dry_run: bool = True) -> dict[str, str]:
        command = f"router-api deny-mac {mac}"
        blocked = BlockedEntity(kind="mac", value=mac, reason=reason, command=command, dry_run=dry_run)
        self.store.add_blocked(blocked)
        return {"status": "recorded", "command": command}


def _ip_block_command(ip: str) -> str:
    if platform.system().lower().startswith("win"):
        return f'netsh advfirewall firewall add rule name="PROBE Block {ip}" dir=in action=block remoteip={ip}'
    return f"iptables -A INPUT -s {ip} -j DROP"
