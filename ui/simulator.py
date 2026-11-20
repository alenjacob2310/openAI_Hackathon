"""Readiness messaging shared by simulator control pages."""
from __future__ import annotations

import streamlit as st
from network import NODE_PORTS
from network.secrets_store import simulator_config_status, simulation_actions_enabled


def simulator_controls(metrics: dict, *, require_execution: bool) -> bool:
    configured = bool(simulator_config_status()['configured'])
    online = all((metrics.get(port) or {}).get('online') for port in NODE_PORTS)
    execution = simulation_actions_enabled()
    if not configured or not online:
        st.info('This page requires the three localhost demo nodes. The cloud incident workspace works independently.')
        st.code('python scripts/setup_simulator.py --enable-actions\npython -m network.run_nodes', language='bash')
        st.caption('Run these commands on your local machine, then restart the local Streamlit app. Setting a cloud secret alone does not start simulator node services.')
        return False
    if not execution:
        st.info('Preview mode: proposed actions can be inspected, but no containment will be executed.')
        st.code('python scripts/setup_simulator.py --enable-actions', language='bash')
        st.caption('Restart the local Streamlit app after opting in. This enables actions only against the configured demo mesh.')
        return not require_execution
    st.caption('Local simulator execution enabled · demo nodes 8001–8003')
    return True
