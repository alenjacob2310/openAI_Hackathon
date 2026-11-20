"""HTTP client helpers for the three FastAPI mesh nodes."""

from __future__ import annotations

from typing import Any

import httpx

from network import NODE_PORTS, NODE_URLS
from network.secrets_store import mesh_credentials

TIMEOUT = 8.0


def fetch_health(port: int) -> dict[str, Any]:
    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            r = client.post(f"{NODE_URLS[port]}/health")
            if r.status_code >= 400:
                return {"online": False, "port": port, "error": r.text}
            data = r.json()
            data["online"] = True
            return data
    except Exception as exc:  # noqa: BLE001
        return {"online": False, "port": port, "error": str(exc)}


def fetch_metrics(port: int) -> dict[str, Any]:
    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            r = client.get(f"{NODE_URLS[port]}/metrics")
            if r.status_code >= 400:
                return {"online": False, "port": port, "error": r.text}
            data = r.json()
            data["online"] = True
            return data
    except Exception as exc:  # noqa: BLE001
        return {"online": False, "port": port, "error": str(exc)}


def fetch_all_metrics() -> dict[int, dict[str, Any]]:
    return {p: fetch_metrics(p) for p in NODE_PORTS}


def fetch_all_health() -> dict[int, dict[str, Any]]:
    return {p: fetch_health(p) for p in NODE_PORTS}


def _token(client: httpx.Client, port: int) -> str:
    user, password = mesh_credentials()
    r = client.post(
        f"{NODE_URLS[port]}/auth/token",
        json={"username": user, "password": password},
    )
    r.raise_for_status()
    return r.json()["access_token"]


def send_mesh_heartbeat(src: int, dst: int, payload: str = "ui-heartbeat") -> dict[str, Any]:
    with httpx.Client(timeout=TIMEOUT) as client:
        token = _token(client, dst)
        r = client.post(
            f"{NODE_URLS[dst]}/mesh/message",
            json={"from_port": src, "payload": payload, "scenario_tag": None},
            headers={"Authorization": f"Bearer {token}"},
        )
        try:
            data = r.json()
        except Exception:  # noqa: BLE001
            data = {"raw": r.text}
        data["_http_status"] = r.status_code
        data["_src"] = src
        data["_dst"] = dst
        return data


def run_scenario_api(name: str) -> dict[str, Any]:
    """Inject scenario signals then LangGraph monitor remediates."""
    import asyncio

    from network.scenarios.runner import run_scenario

    return asyncio.run(run_scenario(name))


def run_all_scenarios_api() -> list[dict[str, Any]]:
    import asyncio

    from network.scenarios.runner import run_all_scenarios

    return asyncio.run(run_all_scenarios(pause_between=1.0))


def run_monitor_agent_api(
    hint_scenario: str | None = None,
    focus_port: int | None = None,
    hint_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from src.monitor_agent import run_monitor_agent

    return run_monitor_agent(
        hint_scenario=hint_scenario,
        focus_port=focus_port,
        hint_context=hint_context,
    )


def lift_isolation(port: int) -> dict[str, Any]:
    with httpx.Client(timeout=TIMEOUT) as client:
        token = _token(client, port)
        r = client.post(f"{NODE_URLS[port]}/admin/lift-isolation", headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        return r.json() if r.content else {"status": r.status_code}
