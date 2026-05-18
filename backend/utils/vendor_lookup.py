from __future__ import annotations

OUI_PREFIXES = {
    "58:ef:68": "Belkin / Linksys",
    "d8:3a:dd": "Apple",
    "44:65:0d": "Amazon",
    "08:00:27": "Oracle VirtualBox",
    "02:42:ac": "Docker / Lab Host",
}


def lookup_vendor(mac: str | None) -> str | None:
    if not mac:
        return None
    return OUI_PREFIXES.get(mac.lower()[:8])
