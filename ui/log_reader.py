"""Read JSONL node logs and scenario reports from logs/network."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from network import NODE_PORTS

LOG_DIR = Path(__file__).resolve().parent.parent / "logs" / "network"


def read_node_logs(port: int | None = None, limit: int = 80) -> list[dict[str, Any]]:
    paths: list[Path]
    if port is None:
        paths = [LOG_DIR / f"node_{p}.jsonl" for p in NODE_PORTS]
    else:
        paths = [LOG_DIR / f"node_{port}.jsonl"]

    rows: list[dict[str, Any]] = []
    for path in paths:
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    rows.sort(key=lambda r: r.get("ts", ""))
    return rows[-limit:]


def read_incidents(limit: int = 50) -> list[dict[str, Any]]:
    rows = read_node_logs(limit=500)
    incidents = [r for r in rows if r.get("event") == "incident"]
    return incidents[-limit:]


def read_remediations(limit: int = 50) -> list[dict[str, Any]]:
    incidents = read_incidents(limit=200)
    return [i for i in incidents if i.get("remediated")][-limit:]


def latest_scenario_report() -> dict[str, Any] | list[Any] | None:
    if not LOG_DIR.exists():
        return None
    reports = sorted(LOG_DIR.glob("scenario_report_*.json"), reverse=True)
    if not reports:
        return None
    try:
        return json.loads(reports[0].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def list_scenario_reports() -> list[Path]:
    if not LOG_DIR.exists():
        return []
    return sorted(LOG_DIR.glob("scenario_report_*.json"), reverse=True)


def read_agent_logs(limit: int = 80) -> list[dict[str, Any]]:
    path = LOG_DIR / "agent.jsonl"
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    rows: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows
