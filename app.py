"""
SOC Copilot — Streamlit entrypoint.

Pages:
  Overview · Network Activity · Attack Scenarios · Logs · AI Agent · Remediation
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

st.set_page_config(
    page_title="SOC Copilot | Incident workspace",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="auto",
)

st.logo(str(ROOT / "ui" / "assets" / "logo.svg"), size="large", icon_image=str(ROOT / "ui" / "assets" / "mark.svg"))

overview = st.Page("ui/pages/overview.py", title="Overview", icon="🛡️", default=False)
network = st.Page("ui/pages/network_activity.py", title="Network Activity", icon="📡")
scenarios = st.Page("ui/pages/scenarios.py", title="Attack Scenarios", icon="⚡")
logs = st.Page("ui/pages/logs_page.py", title="Logs", icon="📋")
agent = st.Page("ui/pages/ai_agent.py", title="Incident workspace", icon="🤖", default=True)
remediation = st.Page("ui/pages/remediation.py", title="Remediation", icon="🛠️")

nav = st.navigation(
    {
        "Investigate": [agent, logs],
        "Local simulation": [overview, network, scenarios, remediation],
    }
)
nav.run()
