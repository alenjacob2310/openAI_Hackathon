import pytest
import jwt
from fastapi.testclient import TestClient
from network.auth import NodeAuthState, create_token, decode_token
from network.node import create_app

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv('JWT_SECRET_8001', 'unit-test-secret-with-at-least-32-bytes')
    monkeypatch.setenv('MESH_SERVICE_PASSWORD', 'test-service-password')
    monkeypatch.setenv('SOC_ENABLE_DEMO_LOGIN', 'false')
    monkeypatch.setattr('network.auth.load_secret', lambda port: 'unit-test-secret-with-at-least-32-bytes')
    monkeypatch.setattr('network.node.mesh_credentials', lambda: ('mesh-service','test-service-password'))
    return TestClient(create_app(8001))


def test_admin_auth_and_roles(client):
    assert client.post('/admin/lift-isolation').status_code == 401
    assert client.post('/auth/token',json={'username':'attacker','password':'attacker-correct'}).status_code == 401
    state = client.app.state.auth
    token = create_token(state,'ordinary-user',{'role':'user'})
    headers = {'Authorization':f'Bearer {token}'}
    for route, body in [('/admin/lift-isolation',None),('/admin/rotate-jwt',None),('/admin/remediate',{'action':'isolate'})]:
        assert client.post(route, json=body, headers=headers).status_code == 403
    response = client.post('/auth/token',json={'username':'mesh-service','password':'test-service-password'})
    headers = {'Authorization':'Bearer ' + response.json()['access_token']}
    assert client.post('/admin/remediate',json={'action':'isolate'},headers=headers).status_code == 200
    assert client.post('/admin/lift-isolation',headers=headers).status_code == 200


def test_jwt_claims_and_rotation():
    state = NodeAuthState(port=8001,secret='unit-test-secret-with-at-least-32-bytes')
    with pytest.raises(ValueError): create_token(state,'user',{'exp':9999999999})
    token = create_token(state,'user')
    assert decode_token(state,token)['sub'] == 'user'
    state.refresh_secret('new-unit-test-secret-with-at-least-32-bytes')
    with pytest.raises(Exception): decode_token(state,token)
    incomplete = jwt.encode({'kv':state.key_version},state.secret,algorithm='HS256')
    with pytest.raises(Exception): decode_token(state,incomplete)


def test_monitor_disabled_actions_are_preview_only(monkeypatch):
    from src.monitor_agent import node_execute_remediation, node_summarize
    from unittest.mock import patch
    monkeypatch.setattr('src.monitor_agent.simulation_actions_enabled', lambda: False)
    state = {'detection': {'incident_detected':True,'scenario':'ddos'},
             'remediation_plan': {'target_port':8001,'actions':[{'action':'set_rate_limit','rate_limit_rps':10}]}}
    with patch('src.monitor_agent.httpx.Client', side_effect=AssertionError('Preview must not use admin APIs')):
        result = node_execute_remediation(state)
    assert result['execution_status'] == 'preview'
    assert result['execution_results'] == []
    assert not result.get('error')
    assert 'No containment actions were executed' in node_summarize(result)['summary']


def test_monitor_no_actions_does_not_raise_opt_in_error(monkeypatch):
    from src.monitor_agent import node_execute_remediation
    monkeypatch.setattr('src.monitor_agent.simulation_actions_enabled', lambda: False)
    result = node_execute_remediation({})
    assert result['execution_status'] == 'not_needed'
    assert not result.get('error')


def test_monitor_rejects_non_demo_target(monkeypatch):
    from src.monitor_agent import node_execute_remediation
    from unittest.mock import patch
    monkeypatch.setattr('src.monitor_agent.simulation_actions_enabled', lambda: True)
    with patch('src.monitor_agent.httpx.Client', side_effect=AssertionError('No outbound call for an invalid target')):
        result = node_execute_remediation({'remediation_plan':{'target_port':9000,'actions':[{'action':'isolate'}]}})
    assert 'local demo nodes' in result['error']
