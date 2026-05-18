from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

from backend.detection.engine import DetectionEngine
from backend.parsers.protocols import parse_scapy_packet
from backend.services.device_mapper import DeviceMapper
from backend.services.evidence_store import EvidenceStore


class PcapAnalyzer:
    def __init__(self, store: EvidenceStore, mapper: DeviceMapper, detector: DetectionEngine) -> None:
        self.store = store
        self.mapper = mapper
        self.detector = detector

    def analyze_bytes(self, content: bytes, suffix: str = ".pcap") -> dict[str, object]:
        try:
            from scapy.all import rdpcap
        except Exception as exc:
            raise RuntimeError("Scapy PCAP support is unavailable") from exc

        with NamedTemporaryFile(delete=False, suffix=suffix) as handle:
            handle.write(content)
            temp_path = Path(handle.name)

        parsed = 0
        try:
            for raw in rdpcap(str(temp_path)):
                packet = parse_scapy_packet(raw)
                if not packet:
                    continue
                self.store.add_packet(packet)
                self.mapper.observe(packet)
                self.detector.inspect(packet, self.store)
                parsed += 1
        finally:
            temp_path.unlink(missing_ok=True)
        return {"packets_imported": parsed, "alerts": len(self.store.list_alerts(limit=500))}
