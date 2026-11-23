"""
SOC Copilot — Streamlit entrypoint.

Left-hand navigation:
  Main · Investigate
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

st.logo(
    str(ROOT / "ui" / "assets" / "logo.svg"),
    size="large",
    icon_image=str(ROOT / "ui" / "assets" / "mark.svg"),
)

# Top of sidebar (dashboard.py is not modified)
dashboard = st.Page("ui/pages/dashboard.py", title="Dashboard", icon="🛡️", default=True)

# Investigate
agent = st.Page(
    "ui/pages/ai_agent.py",
    title="Incident workspace",
    icon="🤖",
)
knowledge = st.Page(
    "ui/pages/knowledge_base.py",
    title="Knowledge Base",
    icon="📚",
)
logs = st.Page("ui/pages/logs_page.py", title="Logs", icon="📋")

network = st.Page("ui/pages/network_activity.py", title="Network Activity", icon="📡")
scenarios = st.Page("ui/pages/scenarios.py", title="Attack Scenarios", icon="⚡")
remediation = st.Page("ui/pages/remediation.py", title="Remediation", icon="🛠️")

nav = st.navigation(
    {
        "Main": [dashboard],
        "Investigate": [agent, knowledge, logs],
        "Local simulation": [network, scenarios, remediation],
    }
)
nav.run()
