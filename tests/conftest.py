"""Keep test telemetry and ticket writes out of the running demo workspace."""
import pytest


@pytest.fixture(autouse=True)
def isolate_runtime_artifacts(tmp_path, monkeypatch):
    import network.metrics
    import src.monitor_agent
    import src.ticket_generator
    import ui.log_reader
    logs = tmp_path / 'logs' / 'network'
    monkeypatch.setattr(network.metrics, 'LOG_DIR', logs)
    monkeypatch.setattr(src.monitor_agent, 'AGENT_LOG', logs / 'agent.jsonl')
    monkeypatch.setattr(src.ticket_generator, 'TICKETS_DIR', tmp_path / 'tickets')
    monkeypatch.setattr(ui.log_reader, 'LOG_DIR', logs)
