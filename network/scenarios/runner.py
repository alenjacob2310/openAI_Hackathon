"""Inject attack signals, then let the LangGraph monitor agent remediate."""

from __future__ import annotations

import asyncio
import json
import logging
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from network import NODE_PORTS, NODE_URLS
from network.mesh import MeshClient

logger = logging.getLogger("scenarios")
REPORT_DIR = Path(__file__).resolve().parent.parent.parent / "logs" / "network"


async def _metrics(client: httpx.AsyncClient, port: int) -> dict[str, Any]:
    r = await client.get(f"{NODE_URLS[port]}/metrics")
    r.raise_for_status()
    return r.json()


def _run_agent(hint_scenario: str, focus_port: int | None, hint_context: dict[str, Any]) -> dict[str, Any]:
    from src.monitor_agent import run_monitor_agent

    return run_monitor_agent(
        hint_scenario=hint_scenario,
        focus_port=focus_port,
        hint_context=hint_context,
    )


def _agent_summary(agent_result: dict[str, Any]) -> dict[str, Any]:
    return {
        "detection": agent_result.get("detection"),
        "remediation_plan": agent_result.get("remediation_plan"),
        "execution_results": agent_result.get("execution_results"),
        "summary": agent_result.get("summary"),
        "agent_trace": agent_result.get("agent_trace"),
        "error": agent_result.get("error"),
    }


async def scenario_ddos(client: httpx.AsyncClient, mesh: MeshClient) -> dict[str, Any]:
    target = random.choice(list(NODE_PORTS))
    attacker_ip = f"198.51.100.{random.randint(10, 200)}"
    logger.info("SCENARIO DDoS inject → node %s from %s", target, attacker_ip)
    before = await _metrics(client, target)

    signal = False
    for burst in range(8):
        r = await client.post(
            f"{NODE_URLS[target]}/scenario/ddos",
            json={"client_ip": attacker_ip, "burst_size": 20},
        )
        data = r.json()
        logger.info("DDoS burst %s signal=%s", burst, data.get("signal"))
        if data.get("signal"):
            signal = True
            break
        await asyncio.sleep(0.05)

    logger.info("LangGraph monitor agent remediating ddos…")
    agent = await asyncio.to_thread(
        _run_agent,
        "ddos",
        target,
        {"attacker_ip": attacker_ip},
    )
    after = await _metrics(client, target)
    contained = attacker_ip in (after.get("blocked_ips") or [])
    return {
        "scenario": "ddos",
        "target": target,
        "attacker_ip": attacker_ip,
        "signal_raised": signal,
        "before": {"rps": before.get("rps_estimate"), "blocked": before.get("blocked_ips")},
        "after": {"rps": after.get("rps_estimate"), "blocked": after.get("blocked_ips")},
        "langgraph": _agent_summary(agent),
        "contained": contained,
    }


async def scenario_phishing(client: httpx.AsyncClient, mesh: MeshClient) -> dict[str, Any]:
    src, dst = random.sample(list(NODE_PORTS), 2)
    logger.info("SCENARIO phishing inject → %s -> %s", src, dst)
    before = await _metrics(client, dst)
    before_kv = before.get("key_version")
    urls = ["https://evil-secure-login.net/owa/auth"]

    token = await mesh.get_token(client, dst)
    headers = {"Authorization": f"Bearer {token}"}
    body = {
        "subject": "Urgent: Password Expiry",
        "body": "Reset now at https://evil-secure-login.net/owa/auth or lose access.",
        "urls": urls,
    }
    r = await client.post(f"{NODE_URLS[dst]}/scenario/phishing", json=body, headers=headers)
    inject = r.json() if r.status_code < 500 else {"error": r.text}
    mesh.invalidate_token(dst)

    logger.info("LangGraph monitor agent remediating phishing…")
    agent = await asyncio.to_thread(
        _run_agent,
        "phishing",
        dst,
        {"urls": urls, "jwt_compromise_suspected": True},
    )
    after = await _metrics(client, dst)
    return {
        "scenario": "phishing",
        "src": src,
        "dst": dst,
        "inject": inject,
        "before_key_version": before_kv,
        "after_key_version": after.get("key_version"),
        "quarantined_urls": after.get("quarantined_urls"),
        "langgraph": _agent_summary(agent),
        "contained": (after.get("key_version") or 0) > (before_kv or 0)
        or any(u in (after.get("quarantined_urls") or []) for u in urls),
    }


async def scenario_ransomware(client: httpx.AsyncClient, mesh: MeshClient) -> dict[str, Any]:
    target = random.choice(list(NODE_PORTS))
    logger.info("SCENARIO ransomware inject → node %s", target)
    before = await _metrics(client, target)
    token = await mesh.get_token(client, target)
    headers = {"Authorization": f"Bearer {token}"}
    body = {
        "host": "FIN-WS-042",
        "actions": ["encrypt_files", "delete_shadow_copies", "vssadmin Delete Shadows"],
        "note": "README_LOCKED.txt drop detected",
    }
    r = await client.post(f"{NODE_URLS[target]}/scenario/ransomware", json=body, headers=headers)
    inject = r.json() if r.content else {"status": r.status_code}
    mesh.invalidate_token(target)

    logger.info("LangGraph monitor agent remediating ransomware…")
    agent = await asyncio.to_thread(_run_agent, "ransomware", target, {"host": "FIN-WS-042"})
    after = await _metrics(client, target)

    # Lift isolation so remaining scenarios/mesh can continue
    await client.post(f"{NODE_URLS[target]}/admin/lift-isolation")

    return {
        "scenario": "ransomware",
        "target": target,
        "inject": inject,
        "isolated_observed": after.get("isolated") is True,
        "before_key_version": before.get("key_version"),
        "after_key_version": after.get("key_version"),
        "langgraph": _agent_summary(agent),
        "contained": after.get("isolated") is True
        or (after.get("key_version") or 0) > (before.get("key_version") or 0),
    }


async def scenario_credential_stuffing(client: httpx.AsyncClient, mesh: MeshClient) -> dict[str, Any]:
    target = random.choice(list(NODE_PORTS))
    attacker_ip = f"203.0.113.{random.randint(10, 200)}"
    logger.info("SCENARIO credential_stuffing inject → node %s from %s", target, attacker_ip)
    before = await _metrics(client, target)

    signal = False
    for i in range(35):
        r = await client.post(
            f"{NODE_URLS[target]}/scenario/credential_stuffing",
            json={
                "username": f"user{i}@example.com",
                "password": "leaked-password",
                "client_ip": attacker_ip,
            },
        )
        data = r.json()
        if data.get("signal"):
            signal = True
            logger.info("Stuffing signal after %s attempts", i + 1)
            break
        await asyncio.sleep(0.02)

    logger.info("LangGraph monitor agent remediating credential_stuffing…")
    agent = await asyncio.to_thread(
        _run_agent,
        "credential_stuffing",
        target,
        {"attacker_ip": attacker_ip},
    )
    mesh.invalidate_token(target)
    after = await _metrics(client, target)
    return {
        "scenario": "credential_stuffing",
        "target": target,
        "attacker_ip": attacker_ip,
        "signal_raised": signal,
        "before_key_version": before.get("key_version"),
        "after_key_version": after.get("key_version"),
        "blocked_ips": after.get("blocked_ips"),
        "langgraph": _agent_summary(agent),
        "contained": attacker_ip in (after.get("blocked_ips") or []),
    }


SCENARIO_FUNCS = {
    "ddos": scenario_ddos,
    "phishing": scenario_phishing,
    "ransomware": scenario_ransomware,
    "credential_stuffing": scenario_credential_stuffing,
}


async def run_scenario(name: str) -> dict[str, Any]:
    mesh = MeshClient()
    await mesh.wait_until_healthy()
    async with httpx.AsyncClient(timeout=60.0) as client:
        result = await SCENARIO_FUNCS[name](client, mesh)
    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    return result


async def run_all_scenarios(pause_between: float = 2.0) -> list[dict[str, Any]]:
    order = ["ddos", "phishing", "credential_stuffing", "ransomware"]
    random.shuffle(order)
    results: list[dict[str, Any]] = []
    mesh = MeshClient()
    await mesh.wait_until_healthy()
    async with httpx.AsyncClient(timeout=60.0) as client:
        for name in order:
            logger.info("=== Running scenario (LangGraph remediate): %s ===", name)
            result = await SCENARIO_FUNCS[name](client, mesh)
            result["finished_at"] = datetime.now(timezone.utc).isoformat()
            results.append(result)
            await asyncio.sleep(pause_between)

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORT_DIR / f"scenario_report_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    logger.info("Wrote scenario report to %s", path)
    return results
