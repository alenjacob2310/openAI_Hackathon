"""Remediation — driven by the LangGraph monitor agent."""

from __future__ import annotations

import streamlit as st

from network import NODE_PORTS
from ui.client import fetch_all_metrics, lift_isolation, run_monitor_agent_api
from ui.log_reader import read_remediations
from ui.styles import banner, inject_styles
from ui.viz import mesh_svg, node_card_html
from ui.simulator import simulator_controls


def page() -> None:
    inject_styles()
    banner(
        "Remediation",
        "LangGraph agent owns detect → retrieve SOP → plan → execute containment on the mesh",
    )

    metrics = fetch_all_metrics()
    can_monitor = simulator_controls(metrics, require_execution=False)
    st.markdown(mesh_svg(metrics), unsafe_allow_html=True)

    cols = st.columns(3)
    for col, port in zip(cols, NODE_PORTS):
        with col:
            m = metrics.get(port) or {}
            st.markdown(node_card_html(port, m), unsafe_allow_html=True)
            if m.get("isolated"):
                if st.button(f"Lift isolation :{port}", key=f"lift_{port}", disabled=not can_monitor):
                    try:
                        lift_isolation(port)
                        st.success(f"Isolation lifted on {port}")
                        st.rerun()
                    except Exception as exc:  # noqa: BLE001
                        st.error(str(exc))

    st.subheader("Run LangGraph monitor / remediate cycle")
    c1, c2, c3 = st.columns([1.2, 1, 1])
    with c1:
        hint = st.selectbox(
            "Hint scenario (optional)",
            options=["(auto-detect)", "ddos", "phishing", "ransomware", "credential_stuffing"],
        )
    with c2:
        focus = st.selectbox("Focus port", options=["(any)", *NODE_PORTS])
    with c3:
        st.write("")
        st.write("")
        run = st.button("Run monitor agent", type="primary", width="stretch", disabled=not can_monitor)

    if run:
        with st.spinner("collect → detect → retrieve SOP → plan → execute…"):
            try:
                result = run_monitor_agent_api(
                    hint_scenario=None if hint == "(auto-detect)" else hint,
                    focus_port=None if focus == "(any)" else int(focus),
                )
                st.session_state["monitor_result"] = result
                feed = st.session_state.setdefault("activity_feed", [])
                feed.append(
                    {
                        "kind": "agent",
                        "message": f"Monitor agent: {result.get('summary', '')[:160]}",
                        "meta": result.get("detection") or {},
                    }
                )
                if (result.get("execution_results") or []):
                    feed.append(
                        {
                            "kind": "remediation",
                            "message": f"Executed {len(result['execution_results'])} containment actions",
                            "meta": result.get("remediation_plan") or {},
                        }
                    )
                st.session_state.activity_feed = feed[-100:]
                if result.get("error"):
                    st.error(result["error"])
                elif result.get("execution_status") == "preview":
                    st.info("Preview complete. No containment actions were executed.")
                else:
                    st.success("Monitor cycle complete")
            except Exception as exc:  # noqa: BLE001
                st.error(str(exc))

    result = st.session_state.get("monitor_result")
    if result:
        st.subheader("Agent summary")
        st.markdown(result.get("summary") or "_No summary_")
        if result.get("error"):
            st.error(result["error"])

        t1, t2, t3 = st.tabs(["Trace", "Detection / Plan", "Execution"])
        with t1:
            for step in result.get("agent_trace") or []:
                st.markdown(
                    f'<div class="timeline-item agent">'
                    f'<span class="pill pill-info">{step.get("step")}</span> '
                    f'<span class="mono">{step.get("detail", "")}</span></div>',
                    unsafe_allow_html=True,
                )
        with t2:
            st.markdown("**Detection**")
            st.json(result.get("detection") or {})
            st.markdown("**Remediation plan**")
            st.json(result.get("remediation_plan") or {})
            docs = result.get("retrieved_docs") or []
            if docs:
                with st.expander(f"SOP chunks ({len(docs)})"):
                    for i, doc in enumerate(docs, 1):
                        meta = doc.get("metadata") or {}
                        st.markdown(f"**[{i}] {meta.get('source')}**")
                        st.code(doc.get("content", "")[:800], language="markdown")
        with t3:
            st.json(result.get("execution_results") or [])

    st.subheader("LangGraph remediation model")
    st.markdown(
        """
        | Graph node | Responsibility |
        |---|---|
        | `collect_telemetry` | Pull `/metrics` + open incidents from 8001–8003 |
        | `detect_incident` | Classify scenario / IoCs from signals |
        | `retrieve_sop` | ChromaDB RAG over playbooks + CVEs |
        | `plan_remediation` | Grounded action list (block / quarantine / isolate / rotate JWT) |
        | `execute_remediation` | POST `/admin/remediate` on the target node |
        | `summarize` | Analyst-facing outcome |
        """
    )

    st.subheader("Logged remediations")
    remediations = read_remediations(limit=80)
    if not remediations:
        st.info("No remediations logged yet — run a scenario or the monitor agent.")
    else:
        for r in reversed(remediations):
            st.markdown(
                f'<div class="timeline-item remediated">'
                f'<span class="pill pill-ok">{r.get("scenario", "incident")}</span> '
                f'<span class="mono">:{r.get("port")} · {r.get("ts", "")}</span>'
                f'<div>{r.get("message", "")}</div>'
                f'<div class="mono">{r.get("remediation", "")}</div>'
                f"</div>",
                unsafe_allow_html=True,
            )

    st.subheader("Combined activity feed")
    feed = st.session_state.get("activity_feed") or []
    if not feed:
        st.caption("UI activity feed is empty.")
    else:
        for item in reversed(feed[-40:]):
            kind = item.get("kind", "info")
            css = {
                "attack": "timeline-item attack",
                "remediation": "timeline-item remediated",
                "agent": "timeline-item agent",
            }.get(kind, "timeline-item")
            pill = {
                "attack": "pill-crit",
                "remediation": "pill-ok",
                "agent": "pill-info",
            }.get(kind, "pill-info")
            st.markdown(
                f'<div class="{css}">'
                f'<span class="pill {pill}">{kind}</span> '
                f'{item.get("message", "")}'
                f"</div>",
                unsafe_allow_html=True,
            )


page()
