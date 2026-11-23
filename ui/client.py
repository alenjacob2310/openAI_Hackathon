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


def _require_local_controls(port: int) -> None:
    from network.secrets_store import simulation_actions_enabled, simulator_config_status
    if port not in NODE_PORTS:
        raise ValueError('Select one of the configured localhost simulator ports.')
    if not simulator_config_status()['configured'] or not simulation_actions_enabled():
        raise RuntimeError('Local node controls require configured credentials and explicit simulator execution opt-in.')


def _operator_action(port: int, route: str) -> dict[str, Any]:
    _require_local_controls(port)
    with httpx.Client(timeout=TIMEOUT) as client:
        token = _token(client, port)
        response = client.post(f'{NODE_URLS[port]}/admin/{route}', headers={'Authorization': f'Bearer {token}'})
        response.raise_for_status()
        return response.json()


def isolate_node(port: int) -> dict[str, Any]:
    return _operator_action(port, 'isolate')


def bring_node_online(port: int) -> dict[str, Any]:
    return _operator_action(port, 'online')


def shutdown_node(port: int) -> dict[str, Any]:
    return _operator_action(port, 'shutdown')


def start_node(port: int) -> dict[str, Any]:
    import os
    import subprocess
    import sys
    import time
    from pathlib import Path
    _require_local_controls(port)
    if fetch_health(port).get('online'):
        bring_node_online(port)
        return {'status':'already_online','port':port}
    root = Path(__file__).resolve().parents[1]
    environment = {**os.environ, 'MESH_NODE_PORT': str(port)}
    options = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform == 'win32' else {'start_new_session': True}
    process = subprocess.Popen([sys.executable, '-m', 'network.node'], cwd=root, env=environment,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **options)
    for _ in range(30):
        if process.poll() is not None:
            raise RuntimeError(f'Node {port} exited before becoming healthy. Check simulator setup.')
        if fetch_health(port).get('online'):
            return {'status':'started','port':port,'pid':process.pid}
        time.sleep(.2)
    return {'status':'start_timeout','port':port,'pid':process.pid}


def run_scenario_live(name: str, on_step=None) -> dict[str, Any]:
    import asyncio
    from network.scenarios.runner import inject_scenario, finalize_scenario_result
    from src.monitor_agent import iter_monitor_agent
    from network.secrets_store import simulation_actions_enabled
    if not simulation_actions_enabled():
        raise RuntimeError('Live scenario execution requires explicit local demo opt-in.')
    injected = asyncio.run(inject_scenario(name))
    result = {}
    for state in iter_monitor_agent(hint_scenario=name, focus_port=injected.get('focus_port'), hint_context=injected.get('hint_context') or {}):
        result = state
        if on_step:
            on_step(state)
    return asyncio.run(finalize_scenario_result(injected, result))
