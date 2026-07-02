import json
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


class EventLogger:
    def __init__(self, log_path: Optional[str | Path] = None):
        self.log_path = Path(log_path or Path(__file__).resolve().parent / "alerts.json")
        self.lock = threading.Lock()
        self._ensure_file()

    def _ensure_file(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.write_text("[]", encoding="utf-8")

    def log_event(
        self,
        event_type: str,
        src_ip: str,
        message: str,
        severity: str = "medium",
        destination_ip: Optional[str] = None,
        detection_reason: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        event = {
            "timestamp": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "event_type": event_type,
            "attack_type": event_type,
            "src_ip": src_ip,
            "destination_ip": destination_ip,
            "severity": severity,
            "message": message,
            "detection_reason": detection_reason,
            "metadata": metadata or {},
        }

        with self.lock:
            self._ensure_file()
            try:
                existing = json.loads(self.log_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                existing = []

            if not isinstance(existing, list):
                existing = []

            existing.append(event)
            self.log_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")

        return event

    def read_events(self) -> list[dict[str, Any]]:
        with self.lock:
            self._ensure_file()
            try:
                data = json.loads(self.log_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return []
            return data if isinstance(data, list) else []


logger = EventLogger()


def log_event(
    event_type: str,
    src_ip: str,
    message: str,
    severity: str = "medium",
    destination_ip: Optional[str] = None,
    detection_reason: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    return logger.log_event(
        event_type=event_type,
        src_ip=src_ip,
        message=message,
        severity=severity,
        destination_ip=destination_ip,
        detection_reason=detection_reason,
        metadata=metadata,
    )


def report_alert(
    event_type: str,
    src_ip: str,
    message: str,
    severity: str = "medium",
    destination_ip: Optional[str] = None,
    detection_reason: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    alert = logger.log_event(
        event_type=event_type,
        src_ip=src_ip,
        message=message,
        severity=severity,
        destination_ip=destination_ip,
        detection_reason=detection_reason,
        metadata=metadata,
    )

    print(f"[{alert['timestamp']}] [{severity.upper()}] {message}")

    try:
        from frontend.app import alert_store

        alert_store.add_alert(alert)
    except Exception:
        pass

    try:
        from elasticsearch import Elasticsearch

        es = Elasticsearch(os.getenv("ELASTICSEARCH_URL", "http://localhost:9200"), request_timeout=5)
        es.index(index="ids-alerts", document=alert)
    except Exception as exc:
        print(f"Elasticsearch unavailable: {exc}")

    return alert


def read_events() -> list[dict[str, Any]]:
    return logger.read_events()
