from __future__ import annotations

import httpx

from backend.services.evidence_store import EvidenceStore


class AiAnalyzer:
    def __init__(self, store: EvidenceStore, base_url: str = "http://127.0.0.1:11434") -> None:
        self.store = store
        self.base_url = base_url.rstrip("/")

    async def analyze(self, model: str = "llama3.2") -> dict[str, str]:
        stats = self.store.stats()
        alerts = self.store.list_alerts(limit=10)
        devices = self.store.list_devices()[:10]
        prompt = (
            "You are a DFIR analyst. Produce a concise network forensics assessment with: "
            "executive summary, highest risk devices, likely attack patterns, and next actions.\n\n"
            f"Stats: {stats}\n"
            f"Alerts: {[a.model_dump(mode='json') for a in alerts]}\n"
            f"Devices: {[d.model_dump(mode='json') for d in devices]}\n"
        )
        async with httpx.AsyncClient(timeout=90) as client:
            response = await client.post(
                f"{self.base_url}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
            )
            response.raise_for_status()
            payload = response.json()
        return {"model": model, "analysis": payload.get("response", "").strip()}
