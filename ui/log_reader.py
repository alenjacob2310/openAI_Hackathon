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
    """Remediated incident rows from node JSONL (scan newest lines first)."""
    rows: list[dict[str, Any]] = []
    # Mesh traffic makes these files huge — walk backwards until we have enough.
    per_file_budget = 50_000
    for port in NODE_PORTS:
        path = LOG_DIR / f"node_{port}.jsonl"
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        found = 0
        for line in reversed(lines[-per_file_budget:]):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("event") == "incident" and row.get("remediated"):
                rows.append(row)
                found += 1
                if found >= limit:
                    break
    rows.sort(key=lambda r: r.get("ts", ""))
    return rows[-limit:]


def read_executed_actions(limit: int = 40) -> list[dict[str, Any]]:
    """Executed remediation actions from agent.jsonl (+ node remediated incidents)."""
    actions: list[dict[str, Any]] = []

    for row in read_agent_logs(limit=300):
        event = row.get("event")
        if event == "execute":
            req = row.get("request") or {}
            resp = row.get("response") or {}
            action = req.get("action") or "unknown"
            ok = row.get("http_status") == 200 and resp.get("status") == "ok"
            detail_parts: list[str] = []
            if req.get("ips"):
                detail_parts.append("ips=" + ",".join(str(i) for i in req["ips"][:4]))
            if req.get("urls"):
                detail_parts.append("urls=" + ",".join(str(u) for u in req["urls"][:3]))
            if req.get("rate_limit_rps") is not None:
                detail_parts.append(f"rps={req.get('rate_limit_rps')}")
            if req.get("reason"):
                detail_parts.append(f"reason={req.get('reason')}")
            actions.append(
                {
                    "ts": row.get("ts", ""),
                    "source": "agent",
                    "scenario": req.get("scenario") or "unknown",
                    "port": resp.get("port"),
                    "action": action,
                    "status": "ok" if ok else f"fail:{row.get('http_status')}",
                    "detail": "; ".join(detail_parts) or (resp.get("detail") or ""),
                    "message": f"Executed {action}",
                }
            )
        elif event == "execute_summary" and row.get("detail"):
            actions.append(
                {
                    "ts": row.get("ts", ""),
                    "source": "agent",
                    "scenario": "summary",
                    "port": None,
                    "action": "execute_summary",
                    "status": "ok",
                    "detail": str(row.get("detail")),
                    "message": "Execution summary",
                }
            )

    # Fall back to node-side remediated incidents when agent.jsonl has no executes
    if not any(a.get("action") not in {None, "execute_summary"} and a.get("source") == "agent" for a in actions):
        for row in read_remediations(limit=limit):
            rem = str(row.get("remediation") or "")
            msg = str(row.get("message") or "")
            action = "remediate"
            lower = f"{msg} {rem}".lower()
            if "block" in lower and "ip" in lower:
                action = "block_ip"
            elif "quarantine" in lower or "url" in lower:
                action = "quarantine_url"
            elif "isolat" in lower:
                action = "isolate"
            elif "jwt" in lower or "rotat" in lower:
                action = "rotate_jwt"
            elif "rate" in lower:
                action = "set_rate_limit"
            actions.append(
                {
                    "ts": row.get("ts", ""),
                    "source": "node",
                    "scenario": row.get("scenario") or "unknown",
                    "port": row.get("port"),
                    "action": action,
                    "status": "ok",
                    "detail": rem or msg,
                    "message": msg or rem,
                }
            )

    actions.sort(key=lambda r: r.get("ts", ""))
    # Prefer concrete execute rows; keep summaries but de-dupe identical details
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for a in actions:
        key = f"{a.get('ts')}|{a.get('action')}|{a.get('port')}|{a.get('detail')}"
        if key in seen:
            continue
        seen.add(key)
        deduped.append(a)
    return deduped[-limit:]


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
