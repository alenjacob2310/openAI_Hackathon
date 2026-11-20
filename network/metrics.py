"""In-memory detection metrics and structured incident logging."""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG_DIR = Path(__file__).resolve().parent.parent / "logs" / "network"


@dataclass
class DetectionEvent:
    scenario: str
    severity: str
    message: str
    metrics: dict[str, Any]
    remediated: bool = False
    remediation: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class NodeMetrics:
    """Sliding-window counters used by detectors."""

    def __init__(self, port: int, window_seconds: int = 60) -> None:
        self.port = port
        self.window = window_seconds
        self._lock = threading.Lock()
        self.request_times: deque[float] = deque()
        self.auth_failures: deque[float] = deque()
        self.auth_attempts_by_user: dict[str, deque[float]] = defaultdict(deque)
        self.phishing_hits: deque[float] = deque()
        self.ransomware_signals: deque[float] = deque()
        self.blocked_ips: set[str] = set()
        self.quarantined_urls: set[str] = set()
        self.isolated: bool = False
        self.rate_limit_rps: float = 40.0
        self.incidents: list[DetectionEvent] = []
        self.total_requests: int = 0
        self.mesh_messages: int = 0
        self.remediations: int = 0
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._log_path = LOG_DIR / f"node_{port}.jsonl"

    def _prune(self, q: deque[float], now: float | None = None) -> None:
        now = now or time.time()
        while q and now - q[0] > self.window:
            q.popleft()

    def record_request(self, client_ip: str = "127.0.0.1") -> None:
        with self._lock:
            now = time.time()
            self.request_times.append(now)
            self._prune(self.request_times, now)
            self.total_requests += 1
            self._write_log(
                {
                    "event": "request",
                    "ip": client_ip,
                    "rps_estimate": self.current_rps_unlocked(),
                }
            )

    def record_mesh(self) -> None:
        with self._lock:
            self.mesh_messages += 1

    def record_auth_failure(self, username: str) -> None:
        with self._lock:
            now = time.time()
            self.auth_failures.append(now)
            self._prune(self.auth_failures, now)
            q = self.auth_attempts_by_user[username]
            q.append(now)
            self._prune(q, now)
            self._write_log({"event": "auth_failure", "user": username})

    def record_auth_success(self, username: str) -> None:
        with self._lock:
            self._write_log({"event": "auth_success", "user": username})

    def record_phishing(self, url: str) -> None:
        with self._lock:
            now = time.time()
            self.phishing_hits.append(now)
            self._prune(self.phishing_hits, now)
            self._write_log({"event": "phishing_indicator", "url": url})

    def record_ransomware(self, detail: str) -> None:
        with self._lock:
            now = time.time()
            self.ransomware_signals.append(now)
            self._prune(self.ransomware_signals, now)
            self._write_log({"event": "ransomware_signal", "detail": detail})

    def current_rps_unlocked(self) -> float:
        self._prune(self.request_times)
        if len(self.request_times) < 2:
            return float(len(self.request_times))
        span = max(self.request_times[-1] - self.request_times[0], 1.0)
        return len(self.request_times) / span

    def current_rps(self) -> float:
        with self._lock:
            return self.current_rps_unlocked()

    def auth_failure_rate(self) -> float:
        with self._lock:
            self._prune(self.auth_failures)
            return len(self.auth_failures) / max(self.window, 1)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            self._prune(self.request_times)
            self._prune(self.auth_failures)
            self._prune(self.phishing_hits)
            self._prune(self.ransomware_signals)
            return {
                "port": self.port,
                "total_requests": self.total_requests,
                "mesh_messages": self.mesh_messages,
                "requests_in_window": len(self.request_times),
                "rps_estimate": round(self.current_rps_unlocked(), 2),
                "auth_failures_in_window": len(self.auth_failures),
                "phishing_hits_in_window": len(self.phishing_hits),
                "ransomware_signals_in_window": len(self.ransomware_signals),
                "blocked_ips": sorted(self.blocked_ips),
                "quarantined_urls": sorted(self.quarantined_urls),
                "isolated": self.isolated,
                "rate_limit_rps": self.rate_limit_rps,
                "remediations": self.remediations,
                "incidents": [e.__dict__ for e in self.incidents[-20:]],
            }

    def raise_incident(
        self,
        scenario: str,
        severity: str,
        message: str,
        metrics: dict[str, Any],
        remediated: bool = False,
        remediation: str = "",
    ) -> DetectionEvent:
        event = DetectionEvent(
            scenario=scenario,
            severity=severity,
            message=message,
            metrics=metrics,
            remediated=remediated,
            remediation=remediation,
        )
        with self._lock:
            self.incidents.append(event)
            if remediated:
                self.remediations += 1
            self._write_log({"event": "incident", **event.__dict__})
        return event

    def _write_log(self, payload: dict[str, Any]) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "port": self.port,
            **payload,
        }
        with self._log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
