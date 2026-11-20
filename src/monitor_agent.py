"""
LangGraph monitoring & remediation agent.

Pipeline:
  collect_telemetry → detect_incident → retrieve_sop → plan_remediation
  → execute_remediation → summarize
"""

from __future__ import annotations

import json
import re
import os

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict

import httpx
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph

from network import NODE_PORTS, NODE_URLS
from network.secrets_store import mesh_credentials
from src.agent import get_llm
from src.config import RETRIEVER_K
from src.vector_store import similarity_search

AGENT_LOG = Path(__file__).resolve().parent.parent / "logs" / "network" / "agent.jsonl"


class MonitorState(TypedDict, total=False):
    focus_port: int | None
    hint_scenario: str | None
    hint_context: dict[str, Any]
    telemetry: dict[str, Any]
    recent_logs: list[dict[str, Any]]
    detection: dict[str, Any]
    retrieval_query: str
    retrieved_docs: list[dict[str, Any]]
    remediation_plan: dict[str, Any]
    execution_results: list[dict[str, Any]]
    summary: str
    agent_trace: list[dict[str, Any]]
    error: str


def _trace(state: MonitorState, step: str, detail: str = "", data: dict | None = None) -> list[dict[str, Any]]:
    items = list(state.get("agent_trace") or [])
    items.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "step": step,
            "detail": detail,
            "data": data or {},
        }
    )
    return items


def _append_agent_log(record: dict[str, Any]) -> None:
    AGENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with AGENT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), **record}) + "\n")


def _read_recent_logs(limit: int = 40) -> list[dict[str, Any]]:
    log_dir = AGENT_LOG.parent
    rows: list[dict[str, Any]] = []
    for port in NODE_PORTS:
        path = log_dir / f"node_{port}.jsonl"
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    rows.sort(key=lambda r: r.get("ts", ""))
    return rows[-limit:]


def _mesh_token(client: httpx.Client, port: int) -> str:
    user, password = mesh_credentials()
    r = client.post(
        f"{NODE_URLS[port]}/auth/token",
        json={"username": user, "password": password},
    )
    r.raise_for_status()
    return r.json()["access_token"]


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise


def node_collect_telemetry(state: MonitorState) -> MonitorState:
    """Gather metrics + open incidents from all mesh nodes."""
    telemetry: dict[str, Any] = {}
    try:
        with httpx.Client(timeout=8.0) as client:
            for port in NODE_PORTS:
                try:
                    r = client.get(f"{NODE_URLS[port]}/metrics")
                    if r.status_code < 400:
                        data = r.json()
                        data["online"] = True
                        telemetry[str(port)] = data
                    else:
                        telemetry[str(port)] = {"online": False, "error": r.text, "port": port}
                except Exception as exc:  # noqa: BLE001
                    telemetry[str(port)] = {"online": False, "error": str(exc), "port": port}
    except Exception as exc:  # noqa: BLE001
        return {
            **state,
            "error": f"Telemetry collection failed: {exc}",
            "agent_trace": _trace(state, "collect_telemetry", str(exc)),
        }

    # Flatten open incidents
    open_incidents = []
    for port, m in telemetry.items():
        for inc in m.get("open_incidents") or []:
            open_incidents.append({"port": int(port), **inc})

    recent_logs = _read_recent_logs(limit=40)

    return {
        **state,
        "telemetry": {
            "nodes": telemetry,
            "open_incidents": open_incidents,
            "hint_scenario": state.get("hint_scenario"),
            "hint_context": state.get("hint_context") or {},
        },
        "recent_logs": recent_logs,
        "error": "",
        "agent_trace": _trace(
            state,
            "collect_telemetry",
            f"online={sum(1 for v in telemetry.values() if v.get('online'))}/3 "
            f"open_incidents={len(open_incidents)}",
            {"ports": list(telemetry.keys())},
        ),
    }


def node_detect_incident(state: MonitorState) -> MonitorState:
    """LLM classifies the active incident from telemetry signals."""
    if state.get("error"):
        return state

    telemetry = state.get("telemetry") or {}
    hint = state.get("hint_scenario")
    system = SystemMessage(
        content=(
            "You are a SOC monitoring agent. Given mesh node telemetry and open signals, "
            "decide if an incident is active. Reply with JSON only:\n"
            "{\n"
            '  "incident_detected": true/false,\n'
            '  "scenario": "ddos|phishing|ransomware|credential_stuffing|none|unknown",\n'
            '  "severity": "low|medium|high|critical",\n'
            '  "target_port": 8001|8002|8003|null,\n'
            '  "attacker_ips": ["..."],\n'
            '  "malicious_urls": ["..."],\n'
            '  "usernames": ["..."],\n'
            '  "evidence": ["short bullet", "..."],\n'
            '  "jwt_compromise_suspected": true/false,\n'
            '  "confidence": 0.0-1.0\n'
            "}\n"
            "Prefer hint_scenario when telemetry supports it. "
            "Use open_incidents, rps_estimate, auth_failures, phishing_hits, ransomware_signals."
        )
    )
    human = HumanMessage(
        content=json.dumps(
            {
                "hint_scenario": hint,
                "hint_context": state.get("hint_context") or {},
                "focus_port": state.get("focus_port"),
                "telemetry": telemetry,
                "recent_log_tail": (state.get("recent_logs") or [])[-15:],
            },
            default=str,
        )
    )
    try:
        llm = get_llm(temperature=0)
        raw = llm.invoke([system, human]).content
        text = raw if isinstance(raw, str) else str(raw)
        detection = _extract_json(text)
    except Exception as exc:  # noqa: BLE001
        # Deterministic fallback from open incidents / hint
        detection = _fallback_detect(state)
        detection["fallback_reason"] = str(exc)

    if hint and detection.get("scenario") in {None, "none", "unknown"}:
        detection["scenario"] = hint
        detection["incident_detected"] = True

    _append_agent_log({"event": "detect", "detection": detection})
    return {
        **state,
        "detection": detection,
        "agent_trace": _trace(
            state,
            "detect_incident",
            f"{detection.get('scenario')} conf={detection.get('confidence')}",
            detection,
        ),
    }


def _fallback_detect(state: MonitorState) -> dict[str, Any]:
    hint = state.get("hint_scenario")
    ctx = state.get("hint_context") or {}
    telemetry = (state.get("telemetry") or {}).get("nodes") or {}
    open_inc = (state.get("telemetry") or {}).get("open_incidents") or []

    scenario = hint or "none"
    target = state.get("focus_port")
    ips: list[str] = []
    urls: list[str] = []
    if open_inc:
        last = open_inc[-1]
        scenario = last.get("scenario") or scenario
        target = last.get("port") or target
        m = last.get("metrics") or {}
        if m.get("ip"):
            ips.append(str(m["ip"]))
        ips.extend(str(x) for x in (m.get("ips") or []))
        urls.extend(str(x) for x in (m.get("urls") or []))

    if ctx.get("attacker_ip"):
        ips.append(str(ctx["attacker_ip"]))
    urls.extend(str(x) for x in (ctx.get("urls") or []))

    # Pick busiest node if no target
    if target is None and telemetry:
        target = max(
            (int(p) for p in telemetry.keys()),
            key=lambda p: float((telemetry.get(str(p)) or {}).get("rps_estimate") or 0),
            default=8001,
        )

    return {
        "incident_detected": scenario not in {"none", None, ""},
        "scenario": scenario or "unknown",
        "severity": "high",
        "target_port": target,
        "attacker_ips": list(dict.fromkeys(ips)),
        "malicious_urls": list(dict.fromkeys(urls)),
        "usernames": list(ctx.get("usernames") or []),
        "evidence": ["fallback detector used"],
        "jwt_compromise_suspected": scenario in {"phishing", "credential_stuffing", "ransomware"},
        "confidence": 0.55 if hint else 0.4,
    }


def node_retrieve_sop(state: MonitorState) -> MonitorState:
    """RAG over playbooks/CVEs to ground the remediation plan."""
    if state.get("error"):
        return state
    detection = state.get("detection") or {}
    if not detection.get("incident_detected"):
        return {
            **state,
            "retrieved_docs": [],
            "retrieval_query": "",
            "agent_trace": _trace(state, "retrieve_sop", "skipped — no incident"),
        }

    scenario = detection.get("scenario", "unknown")
    query = (
        f"Incident response containment SOP for {scenario}. "
        f"Immediate actions, JWT rotation, isolation, IP block, URL quarantine. "
        f"Evidence: {', '.join(detection.get('evidence') or [])}"
    )
    docs: list[dict[str, Any]] = []
    try:
        from src.config import OPENAI_API_KEY

        if OPENAI_API_KEY:
            for d in similarity_search(query, k=RETRIEVER_K):
                docs.append(
                    {
                        "content": d.page_content[:1200],
                        "metadata": dict(d.metadata or {}),
                    }
                )
    except Exception as exc:  # noqa: BLE001
        return {
            **state,
            "retrieval_query": query,
            "retrieved_docs": [],
            "agent_trace": _trace(state, "retrieve_sop", f"RAG failed: {exc}"),
        }

    return {
        **state,
        "retrieval_query": query,
        "retrieved_docs": docs,
        "agent_trace": _trace(state, "retrieve_sop", f"{len(docs)} chunks", {"query": query}),
    }


def node_plan_remediation(state: MonitorState) -> MonitorState:
    """LLM produces structured remediation actions for the target node."""
    if state.get("error"):
        return state
    detection = state.get("detection") or {}
    if not detection.get("incident_detected"):
        plan = {
            "actions": [],
            "rationale": "No active incident detected.",
            "scenario": "none",
        }
        return {
            **state,
            "remediation_plan": plan,
            "agent_trace": _trace(state, "plan_remediation", "no actions"),
        }

    citations = []
    context_blocks = []
    for i, doc in enumerate(state.get("retrieved_docs") or [], start=1):
        meta = doc.get("metadata") or {}
        label = f"[{i}] {meta.get('doc_type')} {meta.get('source')}"
        citations.append(label)
        context_blocks.append(f"{label}\n{doc.get('content', '')}")

    system = SystemMessage(
        content=(
            "You are a SOC remediation planner. Using detection + SOP context, "
            "output JSON only:\n"
            "{\n"
            '  "scenario": "...",\n'
            '  "target_port": 8001,\n'
            '  "rationale": "short",\n'
            '  "actions": [\n'
            '    {"action": "block_ip|quarantine_url|isolate|rotate_jwt|set_rate_limit",'
            ' "ips": [], "urls": [], "rate_limit_rps": null, "reason": "..."}\n'
            "  ],\n"
            '  "sop_citations": ["[1]", "[2]"]\n'
            "}\n"
            "Rules:\n"
            "- ddos: block_ip + set_rate_limit\n"
            "- phishing: quarantine_url + rotate_jwt (JWT may be harvested)\n"
            "- ransomware: isolate + rotate_jwt\n"
            "- credential_stuffing: block_ip + rotate_jwt\n"
            "- Only use actions listed. Prefer exact SOP policy IDs in reason when present."
        )
    )
    human = HumanMessage(
        content=json.dumps(
            {
                "detection": detection,
                "hint_context": state.get("hint_context") or {},
                "sop_context": "\n\n".join(context_blocks)[:8000],
            },
            default=str,
        )
    )
    try:
        llm = get_llm(temperature=0)
        raw = llm.invoke([system, human]).content
        text = raw if isinstance(raw, str) else str(raw)
        plan = _extract_json(text)
    except Exception as exc:  # noqa: BLE001
        plan = _fallback_plan(detection, state.get("hint_context") or {})
        plan["fallback_reason"] = str(exc)

    if not plan.get("target_port"):
        plan["target_port"] = detection.get("target_port") or state.get("focus_port") or 8001
    plan.setdefault("sop_citations", citations[:4])

    _append_agent_log({"event": "plan", "plan": plan})
    return {
        **state,
        "remediation_plan": plan,
        "agent_trace": _trace(
            state,
            "plan_remediation",
            f"{len(plan.get('actions') or [])} actions → :{plan.get('target_port')}",
            plan,
        ),
    }


def _fallback_plan(detection: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    scenario = detection.get("scenario") or "unknown"
    port = detection.get("target_port") or 8001
    ips = list(detection.get("attacker_ips") or [])
    if ctx.get("attacker_ip"):
        ips.append(str(ctx["attacker_ip"]))
    urls = list(detection.get("malicious_urls") or [])
    urls.extend(str(u) for u in (ctx.get("urls") or []))
    ips = list(dict.fromkeys(ips))
    urls = list(dict.fromkeys(urls))

    actions: list[dict[str, Any]] = []
    if scenario == "ddos":
        actions = [
            {"action": "block_ip", "ips": ips, "urls": [], "reason": "DDoS source containment"},
            {"action": "set_rate_limit", "ips": [], "urls": [], "rate_limit_rps": 10.0, "reason": "NET-DDOS-SCRUB-01"},
        ]
    elif scenario == "phishing":
        actions = [
            {"action": "quarantine_url", "ips": [], "urls": urls or ["https://evil-secure-login.net/owa/auth"], "reason": "NET-URL-BLOCK-01"},
            {"action": "rotate_jwt", "ips": [], "urls": [], "reason": "JWT harvest suspected"},
        ]
    elif scenario == "ransomware":
        actions = [
            {"action": "isolate", "ips": [], "urls": [], "reason": "EDR-ISO-01"},
            {"action": "rotate_jwt", "ips": [], "urls": [], "reason": "Credential/session compromise risk"},
        ]
    elif scenario == "credential_stuffing":
        actions = [
            {"action": "block_ip", "ips": ips, "urls": [], "reason": "WAF-IP-RATE-02"},
            {"action": "rotate_jwt", "ips": [], "urls": [], "reason": "Auth plane hardening / IAM-STEPUP-01"},
        ]
    return {
        "scenario": scenario,
        "target_port": port,
        "rationale": "Deterministic fallback plan from detection",
        "actions": actions,
        "sop_citations": [],
    }


def node_execute_remediation(state: MonitorState) -> MonitorState:
    """Call node /admin/remediate for each planned action."""
    if os.getenv("SOC_ENABLE_SIMULATION_ACTIONS", "false").lower() != "true":
        return {**state, "error": "Simulation actions disabled. Set SOC_ENABLE_SIMULATION_ACTIONS=true only for the local demo mesh."}

    if state.get("error"):
        return state
    plan = state.get("remediation_plan") or {}
    actions = plan.get("actions") or []
    port = int(plan.get("target_port") or state.get("focus_port") or 8001)
    scenario = plan.get("scenario") or (state.get("detection") or {}).get("scenario") or "unknown"
    results: list[dict[str, Any]] = []

    if not actions:
        return {
            **state,
            "execution_results": [],
            "agent_trace": _trace(state, "execute_remediation", "nothing to execute"),
        }

    try:
        with httpx.Client(timeout=15.0) as client:
            token = _mesh_token(client, port)
            headers = {"Authorization": f"Bearer {token}"}
            for act in actions:
                body = {
                    "action": act.get("action"),
                    "ips": act.get("ips") or [],
                    "urls": act.get("urls") or [],
                    "rate_limit_rps": act.get("rate_limit_rps"),
                    "scenario": scenario,
                    "reason": act.get("reason") or "langgraph_agent",
                }
                # rotate_jwt may invalidate token — refresh after
                r = client.post(
                    f"{NODE_URLS[port]}/admin/remediate",
                    json=body,
                    headers=headers,
                )
                try:
                    payload = r.json()
                except Exception:  # noqa: BLE001
                    payload = {"raw": r.text}
                entry = {
                    "http_status": r.status_code,
                    "request": body,
                    "response": payload,
                }
                results.append(entry)
                _append_agent_log({"event": "execute", **entry})
                if body["action"] == "rotate_jwt" or r.status_code == 401:
                    try:
                        token = _mesh_token(client, port)
                        headers = {"Authorization": f"Bearer {token}"}
                    except Exception:  # noqa: BLE001
                        pass
    except Exception as exc:  # noqa: BLE001
        return {
            **state,
            "execution_results": results,
            "error": f"Execution failed: {exc}",
            "agent_trace": _trace(state, "execute_remediation", str(exc), {"partial": results}),
        }

    return {
        **state,
        "execution_results": results,
        "agent_trace": _trace(
            state,
            "execute_remediation",
            f"executed {len(results)} actions on :{port}",
            {"results": results},
        ),
    }


def node_summarize(state: MonitorState) -> MonitorState:
    """Produce analyst-facing summary of monitor → remediate cycle."""
    detection = state.get("detection") or {}
    plan = state.get("remediation_plan") or {}
    results = state.get("execution_results") or []
    ok = sum(1 for r in results if r.get("http_status") == 200 and (r.get("response") or {}).get("status") == "ok")

    if not detection.get("incident_detected"):
        summary = "LangGraph monitor: no active incident requiring remediation."
    else:
        summary = (
            f"LangGraph monitor detected **{detection.get('scenario')}** "
            f"(severity={detection.get('severity')}, confidence={detection.get('confidence')}) "
            f"on node :{plan.get('target_port')}. "
            f"Planned {len(plan.get('actions') or [])} actions; "
            f"executed OK={ok}/{len(results)}. "
            f"Rationale: {plan.get('rationale', '')}"
        )

    _append_agent_log({"event": "summary", "summary": summary, "ok": ok})
    return {
        **state,
        "summary": summary,
        "agent_trace": _trace(state, "summarize", summary[:240]),
    }


def build_monitor_graph():
    graph = StateGraph(MonitorState)
    graph.add_node("collect_telemetry", node_collect_telemetry)
    graph.add_node("detect_incident", node_detect_incident)
    graph.add_node("retrieve_sop", node_retrieve_sop)
    graph.add_node("plan_remediation", node_plan_remediation)
    graph.add_node("execute_remediation", node_execute_remediation)
    graph.add_node("summarize", node_summarize)

    graph.set_entry_point("collect_telemetry")
    graph.add_edge("collect_telemetry", "detect_incident")
    graph.add_edge("detect_incident", "retrieve_sop")
    graph.add_edge("retrieve_sop", "plan_remediation")
    graph.add_edge("plan_remediation", "execute_remediation")
    graph.add_edge("execute_remediation", "summarize")
    graph.add_edge("summarize", END)
    return graph.compile()


_MONITOR = None


def get_monitor_agent():
    global _MONITOR
    if _MONITOR is None:
        _MONITOR = build_monitor_graph()
    return _MONITOR


def run_monitor_agent(
    *,
    hint_scenario: str | None = None,
    focus_port: int | None = None,
    hint_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one full monitor → remediate cycle."""
    agent = get_monitor_agent()
    result = agent.invoke(
        {
            "hint_scenario": hint_scenario,
            "focus_port": focus_port,
            "hint_context": hint_context or {},
            "agent_trace": [],
        }
    )
    return result
