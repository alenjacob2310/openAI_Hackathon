"""SOC Command Center overview."""

from __future__ import annotations

import streamlit as st

from ui.client import fetch_all_metrics
from ui.log_reader import latest_scenario_report, read_incidents, read_remediations
from ui.styles import banner, inject_styles
from ui.viz import mesh_svg, node_card_html


def page() -> None:
    inject_styles()
    banner(
        "SOC Command Center",
        "Live mesh · attack scenarios · logs · LangGraph agent · automated remediation",
    )

    metrics = fetch_all_metrics()
    online = sum(1 for m in metrics.values() if m.get("online"))
    incidents = read_incidents(limit=100)
    remediations = read_remediations(limit=100)
    report = latest_scenario_report()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Nodes online", f"{online}/3")
    c2.metric("Incidents logged", len(incidents))
    c3.metric("Remediations", len(remediations))
    c4.metric(
        "Last scenario run",
        f"{len(report)} scenarios" if isinstance(report, list) else "—",
    )

    st.markdown(
        mesh_svg(metrics, last_hop=st.session_state.get("last_mesh_hop")),
        unsafe_allow_html=True,
    )

    cols = st.columns(3)
    for col, port in zip(cols, (8001, 8002, 8003)):
        with col:
            st.markdown(node_card_html(port, metrics.get(port) or {}), unsafe_allow_html=True)

    st.subheader("Quick navigation")
    st.markdown(
        """
        Use the sidebar pages:

        1. **Network Activity** — usual mesh heartbeats and live metrics  
        2. **Attack Scenarios** — inject signals; **LangGraph** detects & remediates  
        3. **Logs** — JSONL event stream from all nodes  
        4. **AI Agent** — LangGraph RAG runbooks + incident tickets  
        5. **Remediation** — run the LangGraph monitor cycle (detect → plan → execute)  
        """
    )

    if not online:
        st.warning(
            "Mesh nodes are offline. Start them with `python -m network.run_nodes` "
            "in a separate terminal."
        )


page()
