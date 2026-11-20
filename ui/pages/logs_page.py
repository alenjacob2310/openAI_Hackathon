"""Node JSONL logs and incident stream."""

from __future__ import annotations

import streamlit as st

from network import NODE_PORTS
from ui.log_reader import (
    list_scenario_reports,
    read_agent_logs,
    read_incidents,
    read_node_logs,
)
from ui.styles import banner, inject_styles


def page() -> None:
    inject_styles()
    banner(
        "Logs",
        "Node JSONL signals + LangGraph agent.jsonl (detect / plan / execute)",
    )

    c1, c2, c3 = st.columns([1, 1, 2])
    with c1:
        port_filter = st.selectbox("Node", options=["all", *NODE_PORTS])
    with c2:
        event_filter = st.selectbox(
            "Event type",
            options=["all", "request", "auth_failure", "auth_success", "phishing_indicator",
                     "ransomware_signal", "incident", "mesh"],
        )
    with c3:
        limit = st.slider("Entries", min_value=20, max_value=300, value=100, step=20)

    if st.button("Refresh logs"):
        st.rerun()

    port = None if port_filter == "all" else int(port_filter)
    rows = read_node_logs(port=port, limit=limit)
    if event_filter != "all":
        rows = [r for r in rows if r.get("event") == event_filter]

    st.subheader("Event stream")
    if not rows:
        st.info("No log lines yet. Run mesh traffic or scenarios to generate events.")
    else:
        for r in reversed(rows[-limit:]):
            event = r.get("event", "?")
            if event == "incident":
                css = "timeline-item remediated" if r.get("remediated") else "timeline-item attack"
                pill = "pill-ok" if r.get("remediated") else "pill-crit"
            elif event in {"phishing_indicator", "ransomware_signal", "auth_failure"}:
                css = "timeline-item attack"
                pill = "pill-warn"
            else:
                css = "timeline-item"
                pill = "pill-info"
            msg = r.get("message") or r.get("detail") or r.get("url") or r.get("user") or ""
            st.markdown(
                f'<div class="{css}">'
                f'<span class="pill {pill}">{event}</span> '
                f'<span class="mono">:{r.get("port")} · {r.get("ts", "")}</span>'
                f'<div class="mono">{msg}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    with st.expander("Raw table", expanded=False):
        st.dataframe(rows, use_container_width=True)

    st.subheader("Incidents")
    incidents = read_incidents(limit=50)
    if not incidents:
        st.caption("No incident events recorded yet.")
    else:
        st.dataframe(incidents, use_container_width=True)

    st.subheader("LangGraph agent log")
    agent_rows = read_agent_logs(limit=60)
    if not agent_rows:
        st.caption("No agent.jsonl entries yet.")
    else:
        for r in reversed(agent_rows[-40:]):
            st.markdown(
                f'<div class="timeline-item agent">'
                f'<span class="pill pill-info">{r.get("event", "agent")}</span> '
                f'<span class="mono">{r.get("ts", "")}</span></div>',
                unsafe_allow_html=True,
            )
        with st.expander("Agent log raw"):
            st.dataframe(agent_rows, use_container_width=True)

    st.subheader("Scenario reports on disk")
    reports = list_scenario_reports()
    if not reports:
        st.caption("No scenario_report_*.json files yet.")
    else:
        for path in reports[:8]:
            st.code(str(path), language="text")


page()
