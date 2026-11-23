"""Run attack signal injection + LangGraph remediation."""

from __future__ import annotations

import streamlit as st

from ui.client import fetch_all_metrics, run_all_scenarios_api, run_scenario_api
from ui.log_reader import latest_scenario_report
from ui.styles import banner, inject_styles
from ui.viz import mesh_svg
from ui.simulator import simulator_controls

SCENARIO_COPY = {
    "ddos": {
        "title": "DDoS",
        "blurb": "Inject request flood signals, then LangGraph blocks IPs / rate-limits.",
        "detect": "Agent reads RPS + open ddos incidents",
        "remediate": "block_ip + set_rate_limit via /admin/remediate",
    },
    "phishing": {
        "title": "Phishing",
        "blurb": "Inject malicious URL / JWT-harvest signal; agent quarantines + rotates JWT.",
        "detect": "Agent classifies phishing URLs from telemetry",
        "remediate": "quarantine_url + rotate_jwt",
    },
    "ransomware": {
        "title": "Ransomware",
        "blurb": "Inject encrypt/vssadmin signals; agent isolates node + rotates JWT.",
        "detect": "Agent sees ransomware_signals / open incidents",
        "remediate": "isolate + rotate_jwt",
    },
    "credential_stuffing": {
        "title": "Credential stuffing",
        "blurb": "Inject auth-failure flood; agent blocks IP + rotates JWT.",
        "detect": "Agent reads auth_failures window",
        "remediate": "block_ip + rotate_jwt",
    },
}


def _append_activity(kind: str, message: str, meta: dict | None = None) -> None:
    feed = st.session_state.setdefault("activity_feed", [])
    feed.append({"kind": kind, "message": message, "meta": meta or {}})
    st.session_state.activity_feed = feed[-100:]


def _show_langgraph(result: dict) -> None:
    lg = result.get("langgraph") or {}
    if not lg:
        return
    st.markdown(lg.get("summary") or "")
    with st.expander("LangGraph trace", expanded=False):
        for step in lg.get("agent_trace") or []:
            st.markdown(
                f'<div class="timeline-item agent">'
                f'<span class="pill pill-info">{step.get("step")}</span> '
                f'<span class="mono">{step.get("detail","")}</span></div>',
                unsafe_allow_html=True,
            )
        st.json(
            {
                "detection": lg.get("detection"),
                "plan": lg.get("remediation_plan"),
                "execution": lg.get("execution_results"),
            }
        )


def page() -> None:
    inject_styles()
    banner(
        "Attack Scenarios",
        "Nodes only raise signals — LangGraph monitor agent plans and executes remediation",
    )

    metrics = fetch_all_metrics()
    can_execute = simulator_controls(metrics, require_execution=True)
    online = sum(1 for m in metrics.values() if m.get("online"))
    if online < 3:
        st.warning(
            f"Only {online}/3 nodes online. Start mesh with `python -m network.run_nodes` "
            "and restart nodes after code updates."
        )

    st.markdown(mesh_svg(metrics), unsafe_allow_html=True)

    cols = st.columns(4)
    for col, key in zip(cols, SCENARIO_COPY):
        info = SCENARIO_COPY[key]
        with col:
            st.markdown(f"### {info['title']}")
            st.caption(info["blurb"])
            st.markdown(f"**Detect:** {info['detect']}")
            st.markdown(f"**Remediate:** {info['remediate']}")
            if st.button(f"Run {info['title']}", key=f"run_{key}", width="stretch", disabled=not can_execute):
                with st.spinner(f"Inject {key} → LangGraph remediate…"):
                    try:
                        result = run_scenario_api(key)
                        st.session_state.setdefault("scenario_results", []).append(result)
                        st.session_state["monitor_result"] = {
                            **(result.get("langgraph") or {}),
                            "from_scenario": key,
                        }
                        _append_activity("attack", f"Injected {key}", result)
                        _append_activity(
                            "agent",
                            (result.get("langgraph") or {}).get("summary") or f"Agent handled {key}",
                            result.get("langgraph"),
                        )
                        if result.get("contained"):
                            _append_activity("remediation", f"Contained {key}", result)
                        st.success(f"{key} finished · contained={result.get('contained')}")
                        _show_langgraph(result)
                    except Exception as exc:  # noqa: BLE001
                        st.error(str(exc))

    st.divider()
    if st.button("Run all 4 scenarios (ransomware last)", type="primary", disabled=not can_execute):
        with st.spinner("Full suite: inject → LangGraph remediate…"):
            try:
                results = run_all_scenarios_api()
                st.session_state.scenario_results = results
                for r in results:
                    _append_activity("attack", f"Injected {r.get('scenario')}", r)
                    _append_activity(
                        "agent",
                        (r.get("langgraph") or {}).get("summary") or f"Agent handled {r.get('scenario')}",
                        r.get("langgraph"),
                    )
                    if r.get("contained"):
                        _append_activity("remediation", f"Contained {r.get('scenario')}", r)
                st.success(f"Completed {len(results)} scenarios")
            except Exception as exc:  # noqa: BLE001
                st.error(str(exc))

    results = st.session_state.get("scenario_results") or latest_scenario_report() or []
    st.subheader("Scenario results")
    if not results:
        st.info("No scenario runs yet.")
    else:
        for r in results:
            name = r.get("scenario", "?")
            contained = r.get("contained")
            pill = "pill-ok" if contained else "pill-crit"
            st.markdown(
                f'<div class="timeline-item {"remediated" if contained else "attack"}">'
                f'<span class="pill {pill}">{name}</span> '
                f'<span class="mono">contained={contained} · '
                f'target={r.get("target") or r.get("dst")}</span>'
                f"</div>",
                unsafe_allow_html=True,
            )
            with st.expander(f"Details · {name}", expanded=False):
                _show_langgraph(r)
                st.json(r)


page()
