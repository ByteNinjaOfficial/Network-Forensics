from __future__ import annotations

from backend.models.schemas import Alert
from backend.services.evidence_store import EvidenceStore


class AlertManager:
    def __init__(self, store: EvidenceStore) -> None:
        self.store = store
        self._recent_keys: set[tuple[str, str | None]] = set()

    def raise_alert(self, alert: Alert) -> Alert:
        key = (alert.alert_type, alert.source_ip)
        if key in self._recent_keys:
            return alert
        self._recent_keys.add(key)
        self.store.add_alert(alert)
        return alert
