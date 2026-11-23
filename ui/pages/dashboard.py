"""Main SOC dashboard matching the wireframe sketch."""

from __future__ import annotations

import time

import pandas as pd
import streamlit as st

from network import NODE_PORTS
from network.secrets_store import simulator_config_status, simulation_actions_enabled
from ui.simulator import simulator_controls
from ui.client import (
    bring_node_online,
    fetch_all_metrics,
    isolate_node,
    run_scenario_live,
    shutdown_node,
    start_node,
)
from ui.log_reader import (
    latest_scenario_report,
    read_agent_logs,
    read_executed_actions,
    read_incidents,
    read_remediations,
)
from ui.styles import banner, inject_styles
from ui.viz import (
    AGENT_STEP_ORDER,
    agent_architecture_svg,
    completed_steps_before,
    mesh_svg,
    normalize_agent_step,
)

SCENARIOS = {
    "ddos": "DDoS",
    "phishing": "Phishing",
    "ransomware": "Ransomware",
    "credential_stuffing": "Credential stuffing",
}

# Metrics & thresholds used by nodes (signals) + Agent monitor (confirm/remediate)
DETECTION_CRITERIA = {
    "ddos": {
        "metrics": "rps_estimate · requests_in_window (60s) · open ddos incidents",
        "thresholds": "RPS ≥ 25  OR  ≥ 30 requests in sliding window",
    },
    "phishing": {
        "metrics": "phishing_hits · malicious URL match · jwt_compromise_suspected",
        "thresholds": "≥ 1 evil/phish URL hit  OR  scenario_tag=phishing",
    },
    "ransomware": {
        "metrics": "ransomware_signals · payload markers · open ransomware incidents",
        "thresholds": "≥ 1 marker: encrypt_files · vssadmin · .locked · ransom_note",
    },
    "credential_stuffing": {
        "metrics": "auth_failures_in_window · unique usernames · source IP",
        "thresholds": "≥ 20 failed logins in 60s window (many users, few tries each)",
    },
}


def _ensure_state() -> None:
    st.session_state.setdefault("mesh_history", [])
    st.session_state.setdefault("rps_history", {p: [] for p in NODE_PORTS})
    st.session_state.setdefault("activity_feed", [])
    st.session_state.setdefault("scenario_results", [])


def _live_agent_view() -> tuple[str | None, set[str], str]:
    """Return (active_step, completed_steps, status_label) for architecture SVG."""
    live = st.session_state.get("agent_live") or {}
    if live.get("active"):
        active = normalize_agent_step(live.get("active"))
        completed = set(live.get("completed") or [])
        label = live.get("label") or (f"running · {active}" if active else "running")
        # After a finished run we park on Collect with no completed steps
        if live.get("label", "").startswith("ready"):
            return "collect", set(), label
        return active, completed, label

    # Idle / between runs: default highlight to Collect (not last summarize step)
    if st.session_state.get("monitor_result"):
        return "collect", set(), "ready — waiting for next run"

    logs = read_agent_logs(limit=5)
    if logs:
        return "collect", set(), "ready — waiting for next run"
    return "collect", set(), "idle — waiting for agent"


def _render_architecture(slot) -> None:
    active, completed, label = _live_agent_view()
    slot.markdown(
        agent_architecture_svg(active, completed, status_label=label),
        unsafe_allow_html=True,
    )


def _append_activity(kind: str, message: str, meta: dict | None = None) -> None:
    feed = st.session_state.setdefault("activity_feed", [])
    feed.append({"kind": kind, "message": message, "meta": meta or {}})
    st.session_state.activity_feed = feed[-100:]


def _scenario_status_map() -> dict[str, dict]:
    """Merge latest scenario runs into a per-scenario status dict."""
    status = {
        k: {"contained": None, "summary": "No run yet", "detail": {}}
        for k in SCENARIOS
    }
    results = list(st.session_state.get("scenario_results") or [])
    report = latest_scenario_report()
    if isinstance(report, list):
        results = report + results
    for r in results:
        name = r.get("scenario")
        if name not in status:
            continue
        lg = r.get("agent") or {}
        status[name] = {
            "contained": r.get("contained"),
            "summary": lg.get("summary")
            or ("Detected" if r.get("contained") else "Signal injected"),
            "detail": r,
        }
    return status


def page() -> None:
    inject_styles()
    _ensure_state()
    banner(
        "SOC Command Center",
        "Agent architecture · live mesh · attack monitoring & Agent remediation",
    )

    readiness = fetch_all_metrics()
    can_run = simulator_controls(readiness, require_execution=True)
    can_control = bool(simulator_config_status()['configured']) and simulation_actions_enabled()

    # Toolbar
    t1, t2, t3, t4 = st.columns([1.1, 1.4, 1.4, 1])
    with t1:
        auto = st.toggle("Live refresh", value=True)
    with t2:
        scenario_key = st.selectbox(
            "Scenario",
            options=list(SCENARIOS.keys()),
            format_func=lambda k: SCENARIOS[k],
            label_visibility="collapsed",
        )
    run_clicked = False
    with t3:
        run_clicked = st.button(
            "Run scenario + agent", type="primary", width="stretch", disabled=not can_run
        )
    with t4:
        if st.button("Refresh", width="stretch"):
            st.rerun()

    with st.container(key="dashboard_panels"):
        left, right = st.columns([0.42, 0.58], gap="medium")

    # ===================== LEFT COLUMN =====================
    with left:
        # --- Agent Architecture ---
        with st.container(border=True):
            st.markdown("**Agent architecture** · VDB")
            arch_slot = st.empty()
            _render_architecture(arch_slot)
            st.caption(
                "Live highlight: collect → detect → retrieve (VDB) → plan → execute → summarize"
            )

        # --- Agent Logs (collapsible) ---
        logs_expanded = bool(run_clicked) or bool(
            (st.session_state.get("agent_live") or {}).get("active")
        )
        with st.expander("Agent logs", expanded=logs_expanded):
            agent_log_slot = st.empty()

            def _escape(text: str) -> str:
                return (
                    str(text)
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                )

            def _agent_log_detail(step_name: str, detail: str, data: dict | None = None) -> str:
                """Prefer rich detail; fall back to structured fields for key steps."""
                data = data or {}
                text = (detail or "").strip()
                if text:
                    return text
                if step_name == "detect_incident" and data:
                    scen = data.get("scenario") or "unknown"
                    conf = data.get("confidence")
                    try:
                        conf_s = f"{float(conf):.0%}" if conf is not None else "n/a"
                    except (TypeError, ValueError):
                        conf_s = str(conf)
                    return (
                        f"Detected {str(scen).replace('_', ' ').title()} attack "
                        f"(confidence={conf_s}, severity={data.get('severity', 'n/a')})"
                    )
                if step_name == "execute_remediation":
                    results = data.get("results") or data.get("partial") or []
                    acts = []
                    for r in results:
                        req = r.get("request") or {}
                        acts.append(str(req.get("action") or "?"))
                    return "Executed: " + (", ".join(acts) if acts else "no actions")
                if step_name == "retrieve_sop":
                    n = data.get("n_docs")
                    return f"Retrieved {n} SOP chunks" if n is not None else "SOP retrieval"
                return ""

            def _format_agent_jsonl_row(row: dict) -> tuple[str, str]:
                event = str(row.get("event") or "agent")
                if row.get("detail"):
                    return event, str(row["detail"])
                if event == "detect" and row.get("detection"):
                    d = row["detection"]
                    scen = str(d.get("scenario") or "unknown").replace("_", " ").title()
                    conf = d.get("confidence")
                    try:
                        conf_s = f"{float(conf):.0%}" if conf is not None else "n/a"
                    except (TypeError, ValueError):
                        conf_s = str(conf)
                    return (
                        "detect_incident",
                        f"Detected {scen} attack (confidence={conf_s}, "
                        f"severity={d.get('severity', 'n/a')})",
                    )
                if event == "execute":
                    req = row.get("request") or {}
                    action = req.get("action") or "action"
                    ips = req.get("ips") or []
                    urls = req.get("urls") or []
                    bits = [str(action)]
                    if ips:
                        bits.append("ips=" + ",".join(str(i) for i in ips[:3]))
                    if urls:
                        bits.append("urls=" + ",".join(str(u) for u in urls[:2]))
                    if req.get("rate_limit_rps") is not None:
                        bits.append(f"rps={req.get('rate_limit_rps')}")
                    status = (row.get("response") or {}).get("status") or row.get("http_status")
                    return "execute_remediation", f"{' · '.join(bits)} → {status}"
                if event in {"execute_summary", "retrieve_sop", "summary", "plan"}:
                    if event == "plan" and row.get("plan"):
                        plan = row["plan"]
                        acts = [a.get("action") for a in (plan.get("actions") or []) if a.get("action")]
                        return "plan_remediation", f"{len(acts)} actions: {', '.join(acts)}"
                    if event == "summary":
                        return "summarize", str(row.get("summary") or "")[:320]
                    return event, str(row.get("detail") or row.get("summary") or "")[:320]
                return event, str(row.get("ts", ""))[-12:]

            def _paint_agent_logs(trace: list | None = None) -> None:
                trace = trace or (st.session_state.get("monitor_result") or {}).get("agent_trace") or []
                agent_logs = read_agent_logs(limit=12)
                if trace:
                    html = []
                    for step in trace[-10:]:
                        name = str(step.get("step") or "step")
                        detail = _agent_log_detail(name, str(step.get("detail") or ""), step.get("data") or {})
                        html.append(
                            f'<div class="timeline-item agent">'
                            f'<span class="pill pill-info">{_escape(name)}</span> '
                            f'<span class="mono">{_escape(detail[:420])}</span></div>'
                        )
                    agent_log_slot.markdown("".join(html), unsafe_allow_html=True)
                elif agent_logs:
                    html = []
                    for row in reversed(agent_logs[-10:]):
                        name, detail = _format_agent_jsonl_row(row)
                        html.append(
                            f'<div class="timeline-item agent">'
                            f'<span class="pill pill-info">{_escape(name)}</span> '
                            f'<span class="mono">{_escape(detail[:420])}</span></div>'
                        )
                    agent_log_slot.markdown("".join(html), unsafe_allow_html=True)
                else:
                    agent_log_slot.caption("No agent activity yet — run a scenario.")

            _paint_agent_logs()

        # Live agent run (updates architecture highlights per Agent node)
        if run_clicked:
            status = st.status(f"Running {scenario_key}: inject → Agent…", expanded=True)
            completed: set[str] = set()
            try:
                st.session_state["agent_live"] = {
                    "active": "collect",
                    "completed": [],
                    "label": f"injecting {scenario_key}",
                }
                _render_architecture(arch_slot)

                def on_step(state: dict) -> None:
                    trace = state.get("agent_trace") or []
                    active = None
                    if trace:
                        active = normalize_agent_step(str(trace[-1].get("step") or ""))
                    if active:
                        completed.add(active)
                        # mark prior steps completed too
                        completed.update(completed_steps_before(active))
                    st.session_state["agent_live"] = {
                        "active": active,
                        "completed": sorted(completed, key=lambda s: AGENT_STEP_ORDER.index(s) if s in AGENT_STEP_ORDER else 99),
                        "label": f"running · {active or '…'}",
                    }
                    st.session_state["monitor_result"] = {
                        **{k: state.get(k) for k in (
                            "detection",
                            "remediation_plan",
                            "execution_results",
                            "summary",
                            "agent_trace",
                            "error",
                            "retrieved_docs",
                        )},
                        "from_scenario": scenario_key,
                    }
                    _render_architecture(arch_slot)
                    _paint_agent_logs(trace)
                    status.write(f"Step: **{active or '…'}** — {(trace[-1].get('detail') if trace else '')[:280]}")

                result = run_scenario_live(scenario_key, on_step=on_step)
                st.session_state.setdefault("scenario_results", []).append(result)
                st.session_state["monitor_result"] = {
                    **(result.get("agent") or {}),
                    "from_scenario": scenario_key,
                }
                # Reset highlight to Collect after the analysis finishes
                st.session_state["agent_live"] = {
                    "active": "collect",
                    "completed": [],
                    "label": "ready — waiting for next run",
                }
                _render_architecture(arch_slot)
                _paint_agent_logs((result.get("agent") or {}).get("agent_trace"))
                _append_activity("attack", f"Injected {scenario_key}", result)
                _append_activity(
                    "agent",
                    (result.get("agent") or {}).get("summary")
                    or f"Agent handled {scenario_key}",
                    result.get("agent"),
                )
                if result.get("contained"):
                    _append_activity("remediation", f"Detected {scenario_key}", result)
                status.update(
                    label=f"{scenario_key}: {'detected' if result.get('contained') else 'not detected'}",
                    state="complete",
                )
                st.toast(
                    f"{scenario_key}: {'detected' if result.get('contained') else 'not detected'}"
                )
            except Exception as exc:  # noqa: BLE001
                status.update(label="Agent run failed", state="error")
                st.error(str(exc))
                st.session_state.pop("agent_live", None)

        # --- Monitoring Dashboard (collapsible; detected attacks only) ---
        statuses = _scenario_status_map()
        remediations = read_remediations(limit=20)
        incidents = read_incidents(limit=20)
        detected = {
            key: s
            for key, s in statuses.items()
            if s.get("contained") is True
        }
        monitor_expanded = bool(detected) or bool(run_clicked)
        with st.expander(
            f"Incidents · {len(detected)} detected",
            expanded=monitor_expanded,
        ):
            m1, m2, m3 = st.columns(3)
            executed_count = len(
                [a for a in read_executed_actions(limit=50) if a.get("action") != "execute_summary"]
            )
            m1.metric("Open signals", sum(1 for i in incidents if not i.get("remediated")))
            m2.metric("Remediations", max(executed_count, len(remediations)))
            m3.metric("Detected", len(detected))

            if not detected:
                st.caption("No detected attacks yet — run a scenario.")
            else:
                for key, s in detected.items():
                    title = SCENARIOS.get(key, key)
                    detail = s.get("detail") or {}
                    target = detail.get("target") or detail.get("dst") or "—"
                    summary = (s.get("summary") or "")[:160]
                    criteria = DETECTION_CRITERIA.get(key) or {}
                    st.markdown(
                        f'<div class="attack-row">'
                        f'<h4><span class="pill pill-ok">detected</span> {title}</h4>'
                        f'<p class="mono">target={target}</p>'
                        f'<p><b>Detect via:</b> {criteria.get("metrics", "—")}</p>'
                        f'<p class="mono"><b>Threshold:</b> {criteria.get("thresholds", "—")}</p>'
                        f'<p>{summary}</p>'
                        f"</div>",
                        unsafe_allow_html=True,
                    )

            with st.expander("Latest remediations", expanded=bool(run_clicked) or bool(remediations)):
                executed = list(read_executed_actions(limit=24))
                # Prefer live run execution_results when available
                live = st.session_state.get("monitor_result") or {}
                live_results = live.get("execution_results") or []
                live_rows: list[dict] = []
                for er in live_results:
                    req = er.get("request") or {}
                    resp = er.get("response") or {}
                    ok = er.get("http_status") == 200 and resp.get("status") == "ok"
                    bits = []
                    if req.get("ips"):
                        bits.append("ips=" + ",".join(str(i) for i in req["ips"][:4]))
                    if req.get("urls"):
                        bits.append("urls=" + ",".join(str(u) for u in req["urls"][:3]))
                    if req.get("rate_limit_rps") is not None:
                        bits.append(f"rps={req.get('rate_limit_rps')}")
                    if req.get("reason"):
                        bits.append(str(req.get("reason")))
                    live_rows.append(
                        {
                            "ts": "live",
                            "scenario": req.get("scenario")
                            or live.get("from_scenario")
                            or (live.get("detection") or {}).get("scenario")
                            or "unknown",
                            "port": resp.get("port")
                            or (live.get("remediation_plan") or {}).get("target_port"),
                            "action": req.get("action") or "unknown",
                            "status": "ok" if ok else f"fail:{er.get('http_status')}",
                            "detail": "; ".join(bits) or str(resp.get("detail") or ""),
                        }
                    )
                rows = live_rows + [
                    a
                    for a in executed
                    if a.get("action") != "execute_summary"
                ]
                if not rows and not remediations:
                    st.caption("None yet — run a scenario to execute remediation actions.")
                elif not rows:
                    for r in reversed(remediations[-8:]):
                        st.markdown(
                            f'<div class="timeline-item remediated">'
                            f'<span class="pill pill-ok">{r.get("scenario")}</span> '
                            f'<span class="mono">:{r.get("port")} · {r.get("remediation", "")[:160]}</span>'
                            f"</div>",
                            unsafe_allow_html=True,
                        )
                else:
                    # Deduplicate while preferring live rows first
                    seen: set[str] = set()
                    shown = 0
                    for r in reversed(rows[-20:]):
                        key = f"{r.get('action')}|{r.get('port')}|{r.get('detail')}|{r.get('ts')}"
                        if key in seen:
                            continue
                        seen.add(key)
                        action = r.get("action") or "action"
                        scenario = r.get("scenario") or "unknown"
                        port = r.get("port")
                        port_s = f":{port}" if port is not None else ""
                        status = r.get("status") or "ok"
                        pill = "pill-ok" if status == "ok" else "pill-crit"
                        detail = str(r.get("detail") or "")[:200]
                        st.markdown(
                            f'<div class="timeline-item remediated">'
                            f'<span class="pill {pill}">{action}</span> '
                            f'<span class="pill pill-info">{scenario}</span> '
                            f'<span class="mono">{port_s} · {status}'
                            f'{" · " + detail if detail else ""}</span>'
                            f"</div>",
                            unsafe_allow_html=True,
                        )
                        shown += 1
                        if shown >= 12:
                            break

    # ===================== RIGHT COLUMN =====================
    with right:
        # --- Network Mesh ---
        with st.container(border=True):
            st.markdown("**Network mesh** · click a node to control it")

            @st.fragment(run_every=3 if auto else None)
            def mesh_panel() -> None:
                metrics = fetch_all_metrics()
                for port, m in metrics.items():
                    if m.get("online"):
                        hist = st.session_state.rps_history.setdefault(port, [])
                        hist.append(float(m.get("rps_estimate") or 0))
                        st.session_state.rps_history[port] = hist[-40:]

                selected = st.session_state.get("selected_mesh_node")
                st.markdown(
                    mesh_svg(metrics, last_hop=st.session_state.get("last_mesh_hop")),
                    unsafe_allow_html=True,
                )

                cols = st.columns(3)
                for col, port in zip(cols, NODE_PORTS):
                    m = metrics.get(port) or {}
                    online = m.get("online")
                    status = (
                        "isolated"
                        if m.get("isolated")
                        else ("online" if online else "offline")
                    )
                    with col:
                        is_sel = selected == port
                        label = f"{'● ' if is_sel else ''}{port}"
                        if st.button(
                            label,
                            key=f"mesh_select_{port}",
                            width="stretch",
                            type="primary" if is_sel else "secondary",
                            help=f"Select node :{port} ({status})",
                        ):
                            st.session_state.selected_mesh_node = port
                            st.rerun()
                        st.caption(
                            f"{status} · {m.get('rps_estimate', 0)} rps · kv{m.get('key_version', '—')}"
                        )

                selected = st.session_state.get("selected_mesh_node")
                if selected:
                    m = metrics.get(selected) or {}
                    online = bool(m.get("online"))
                    isolated = bool(m.get("isolated"))
                    st.markdown(f"**Node :{selected}** controls")
                    a1, a2, a3 = st.columns(3)
                    with a1:
                        start_label = "Online" if (online and isolated) else "Start"
                        if st.button(
                            start_label,
                            key=f"mesh_online_{selected}",
                            width="stretch",
                            disabled=(online and not isolated) or not can_control,
                            help="Start the process if offline, or clear isolation if isolated",
                        ):
                            try:
                                if not online:
                                    result = start_node(int(selected))
                                else:
                                    result = bring_node_online(int(selected))
                                st.toast(f":{selected} → {result.get('status')}")
                                st.rerun()
                            except Exception as exc:  # noqa: BLE001
                                st.error(str(exc))
                    with a2:
                        if st.button(
                            "Isolate",
                            key=f"mesh_isolate_{selected}",
                            width="stretch",
                            disabled=not online or isolated or not can_control,
                            help="Isolate node (refuse mesh traffic)",
                        ):
                            try:
                                result = isolate_node(int(selected))
                                st.toast(f":{selected} isolated · {result.get('status')}")
                                st.rerun()
                            except Exception as exc:  # noqa: BLE001
                                st.error(str(exc))
                    with a3:
                        if st.button(
                            "Shutdown",
                            key=f"mesh_shutdown_{selected}",
                            width="stretch",
                            disabled=not online or not can_control,
                            help="Stop this node process",
                        ):
                            try:
                                result = shutdown_node(int(selected))
                                st.toast(f":{selected} → {result.get('status')}")
                                time.sleep(0.5)
                                st.rerun()
                            except Exception as exc:  # noqa: BLE001
                                st.error(str(exc))
                else:
                    st.caption("Select a node button under the mesh to start, isolate, or shut down.")

                if not any((metrics.get(p) or {}).get("online") for p in NODE_PORTS):
                    st.warning("All nodes offline — select a node and click **Start**.")

            mesh_panel()

        # --- Network Traffic ---
        with st.container(border=True):
            st.markdown("**Network traffic** · usual mesh activity")

            @st.fragment(run_every=3 if auto else None)
            def traffic_panel() -> None:
                max_len = max(
                    (len(st.session_state.rps_history.get(p, [])) for p in NODE_PORTS),
                    default=0,
                )
                if max_len:
                    frame = pd.DataFrame(
                        {
                            str(p): (
                                st.session_state.rps_history.get(p, [])
                                + [None]
                                * (max_len - len(st.session_state.rps_history.get(p, [])))
                            )[-max_len:]
                            for p in NODE_PORTS
                        }
                    )
                    st.line_chart(frame, height=180)
                else:
                    st.caption("Waiting for traffic samples… send a mesh heartbeat.")

                hist = st.session_state.get("mesh_history") or []
                st.caption("Recent hops")
                if not hist:
                    st.caption("No UI heartbeats yet.")
                else:
                    for item in reversed(hist[-8:]):
                        ok = item.get("accepted") is True or item.get("status") == 200
                        pill = "pill-ok" if ok else "pill-warn"
                        st.markdown(
                            f'<div class="timeline-item">'
                            f'<span class="pill {pill}">{item.get("ts")}</span> '
                            f'<span class="mono">{item.get("src")} → {item.get("dst")} · '
                            f'HTTP {item.get("status")}</span></div>',
                            unsafe_allow_html=True,
                        )

            traffic_panel()


page()
