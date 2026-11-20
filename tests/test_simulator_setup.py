from pathlib import Path
from unittest.mock import patch

from dotenv import dotenv_values
from streamlit.testing.v1 import AppTest

from scripts.setup_simulator import SECRET_KEYS, configure_simulator

ROOT = Path(__file__).resolve().parents[1]


def test_setup_generates_unique_secrets_and_is_idempotent(tmp_path, monkeypatch):
    for key in SECRET_KEYS:
        monkeypatch.delenv(key, raising=False)
    env = tmp_path / '.env'
    assert set(configure_simulator(env)) == set(SECRET_KEYS)
    values = dotenv_values(env)
    assert len(set(values.values())) == len(SECRET_KEYS)
    assert all(len(values[key]) >= 40 for key in SECRET_KEYS)
    before = env.read_bytes()
    assert configure_simulator(env) == []
    assert env.read_bytes() == before
    assert env.stat().st_mode & 0o777 == 0o600


def test_setup_preserves_existing_configuration(tmp_path, monkeypatch):
    for key in SECRET_KEYS:
        monkeypatch.delenv(key, raising=False)
    env = tmp_path / '.env'
    env.write_text('OPENAI_API_KEY=unit-test-only\nMESH_SERVICE_PASSWORD=existing-demo-password\n')
    configured = configure_simulator(env)
    assert 'MESH_SERVICE_PASSWORD' not in configured
    assert dotenv_values(env)['MESH_SERVICE_PASSWORD'] == 'existing-demo-password'
    assert dotenv_values(env)['OPENAI_API_KEY'] == 'unit-test-only'


def test_network_ui_disables_heartbeat_until_configured():
    with patch('network.secrets_store.simulator_config_status', return_value={'configured':False,'missing':['MESH_SERVICE_PASSWORD']}), patch('ui.client.fetch_all_metrics',return_value={}):
        at = AppTest.from_file(str(ROOT / 'ui/pages/network_activity.py'),default_timeout=30).run()
        assert not at.exception
        assert next(b for b in at.button if b.label == 'Send mesh heartbeat').disabled
        assert any('setup_simulator.py' in code.value for code in at.code)


def test_network_ui_sends_heartbeat_when_ready():
    metrics = {port: {'online':True,'port':port,'rps_estimate':0} for port in (8001,8002,8003)}
    with patch('network.secrets_store.simulator_config_status', return_value={'configured':True,'missing':[]}), patch('ui.client.fetch_all_metrics',return_value=metrics), patch('ui.client.send_mesh_heartbeat',return_value={'_http_status':200,'accepted':True,'echo':'ui-heartbeat'}) as send:
        at = AppTest.from_file(str(ROOT / 'ui/pages/network_activity.py'),default_timeout=30).run()
        next(b for b in at.button if b.label == 'Send mesh heartbeat').click().run()
        assert not at.exception
        send.assert_called_once()
        assert any('Heartbeat accepted' in success.value for success in at.success)
        assert len(at.session_state['mesh_history']) == 1


def test_setup_explicit_action_opt_in_preserves_secrets(tmp_path, monkeypatch):
    for key in SECRET_KEYS:
        monkeypatch.delenv(key, raising=False)
    env = tmp_path / '.env'
    configure_simulator(env)
    before = dotenv_values(env)
    configure_simulator(env, enable_actions=True)
    after = dotenv_values(env)
    assert after['SOC_ENABLE_SIMULATION_ACTIONS'] == 'true'
    assert all(after[key] == before[key] for key in SECRET_KEYS)
    snapshot = env.read_bytes()
    configure_simulator(env, enable_actions=True)
    assert env.read_bytes() == snapshot


def test_cloud_scenarios_disabled_without_nodes():
    with patch('ui.client.fetch_all_metrics',return_value={}), patch('ui.simulator.simulator_config_status',return_value={'configured':False}), patch('ui.simulator.simulation_actions_enabled',return_value=False):
        at = AppTest.from_file(str(ROOT / 'ui/pages/scenarios.py'), default_timeout=30).run()
        assert not at.exception
        assert all(button.disabled for button in at.button if button.label.startswith('Run '))


def test_cloud_monitor_disabled_without_nodes():
    with patch('ui.client.fetch_all_metrics',return_value={}), patch('ui.simulator.simulator_config_status',return_value={'configured':False}), patch('ui.simulator.simulation_actions_enabled',return_value=False):
        at = AppTest.from_file(str(ROOT / 'ui/pages/remediation.py'),default_timeout=30).run()
        assert not at.exception
        assert next(b for b in at.button if b.label=='Run monitor agent').disabled
