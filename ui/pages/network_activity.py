"""Usual network activity — live metrics + mesh heartbeats."""

from __future__ import annotations

import random
import time

import streamlit as st

from network import NODE_PORTS
from ui.client import fetch_all_metrics, send_mesh_heartbeat
from ui.styles import banner, inject_styles
from ui.viz import mesh_svg, node_card_html


def _ensure_history() -> None:
    if "mesh_history" not in st.session_state:
        st.session_state.mesh_history = []
    if "rps_history" not in st.session_state:
        st.session_state.rps_history = {p: [] for p in NODE_PORTS}


def page() -> None:
    inject_styles()
    banner(
        "Network Activity",
        "Normal JWT-authenticated POST traffic between nodes 8001 · 8002 · 8003",
    )
    _ensure_history()

    top = st.columns([1, 1, 1, 1])
    with top[0]:
        auto = st.toggle("Auto-refresh (3s)", value=True)
    with top[1]:
        if st.button("Refresh now", use_container_width=True):
            st.rerun()
    with top[2]:
        send = st.button("Send mesh heartbeat", type="primary", use_container_width=True)
    with top[3]:
        clear = st.button("Clear history", use_container_width=True)

    if clear:
        st.session_state.mesh_history = []
        st.session_state.rps_history = {p: [] for p in NODE_PORTS}
        st.session_state.pop("last_mesh_hop", None)

    if send:
        src, dst = random.sample(list(NODE_PORTS), 2)
        try:
            result = send_mesh_heartbeat(src, dst)
            st.session_state.last_mesh_hop = (src, dst)
            st.session_state.mesh_history.append(
                {
                    "ts": time.strftime("%H:%M:%S"),
                    "src": src,
                    "dst": dst,
                    "status": result.get("_http_status"),
                    "accepted": result.get("accepted"),
                    "detail": result.get("echo") or result.get("detected") or result.get("detail"),
                }
            )
            st.session_state.mesh_history = st.session_state.mesh_history[-30:]
        except Exception as exc:  # noqa: BLE001
            st.error(f"Heartbeat failed: {exc}")

    @st.fragment(run_every=3 if auto else None)
    def live_panel() -> None:
        metrics = fetch_all_metrics()
        for port, m in metrics.items():
            if m.get("online"):
                hist = st.session_state.rps_history.setdefault(port, [])
                hist.append(float(m.get("rps_estimate") or 0))
                st.session_state.rps_history[port] = hist[-40:]

        st.markdown(
            mesh_svg(metrics, last_hop=st.session_state.get("last_mesh_hop")),
            unsafe_allow_html=True,
        )
        cols = st.columns(3)
        for col, port in zip(cols, NODE_PORTS):
            with col:
                st.markdown(
                    node_card_html(port, metrics.get(port) or {}),
                    unsafe_allow_html=True,
                )

        st.subheader("RPS trend (live)")
        chart_data = {
            str(p): st.session_state.rps_history.get(p, []) for p in NODE_PORTS
        }
        # Align lengths for Streamlit chart
        max_len = max((len(v) for v in chart_data.values()), default=0)
        if max_len:
            import pandas as pd

            frame = pd.DataFrame(
                {
                    k: (v + [None] * (max_len - len(v)))[-max_len:]
                    for k, v in chart_data.items()
                }
            )
            st.line_chart(frame)
        else:
            st.caption("Waiting for metric samples…")

        online = all((metrics.get(p) or {}).get("online") for p in NODE_PORTS)
        if not online:
            st.warning("One or more nodes offline — start with `python -m network.run_nodes`")

    live_panel()

    st.subheader("Recent mesh hops")
    hist = st.session_state.get("mesh_history") or []
    if not hist:
        st.info("No UI-triggered heartbeats yet. Click **Send mesh heartbeat** or run the mesh simulator.")
    else:
        for item in reversed(hist):
            ok = item.get("accepted") is True or item.get("status") == 200
            pill = "pill-ok" if ok else "pill-warn"
            st.markdown(
                f'<div class="timeline-item">'
                f'<span class="pill {pill}">{item.get("ts")}</span> '
                f'<span class="mono">{item.get("src")} → {item.get("dst")} · '
                f'HTTP {item.get("status")} · accepted={item.get("accepted")}</span>'
                f'<div class="mono">{item.get("detail") or ""}</div>'
                f"</div>",
                unsafe_allow_html=True,
            )


page()
