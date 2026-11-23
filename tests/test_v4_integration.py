from pathlib import Path
from unittest.mock import patch
import asyncio
import json

import pytest
from langchain_core.documents import Document
from streamlit.testing.v1 import AppTest

from src import vector_store as vs
from src.knowledge import numbered_steps
from tests.test_soc import TestEmbeddings

ROOT = Path(__file__).resolve().parents[1]

@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(vs, 'CHROMA_DIR', tmp_path/'chroma')
    monkeypatch.setattr(vs, 'UPLOADS_DIR', tmp_path/'uploads')
    monkeypatch.setattr(vs, 'get_embeddings', lambda:TestEmbeddings())
    return vs.build_vector_store()


def test_multiline_conditions_and_fenced_examples_preserved():
    text = '## Containment Checklist\n1. Reset passwords\n   only if submission is confirmed.\n\n```text\n1. This is an example, not a step\n```\n2. Revoke sessions'
    records = numbered_steps(text)
    assert len(records)==2
    assert 'only if submission is confirmed.' in records[0]['content']
    assert records[0]['line_start']==2 and records[0]['line_end']==3
    chunks=vs.split_documents([Document(page_content=text, metadata={'doc_type':'upload'})], strategy='sop_steps')
    assert len(chunks)==2 and 'only if' in chunks[0].page_content


def test_plain_uploads_do_not_disappear_with_step_strategy():
    chunks=vs.split_documents([Document(page_content='plain supplementary advisory text',metadata={'doc_type':'upload'})],strategy='sop_steps')
    assert len(chunks)==1 and 'supplementary' in chunks[0].page_content


def test_editing_requires_explicit_server_opt_in(tmp_path, monkeypatch):
    monkeypatch.setenv('SOC_ENABLE_KB_EDITING','false')
    with pytest.raises(PermissionError):vs.save_uploaded_file('guide.md',b'body')
    with pytest.raises(PermissionError):vs.save_chunk_config({'chunk_size':1000})


def test_upload_collisions_and_symlinks_never_replace_files(tmp_path, monkeypatch):
    monkeypatch.setenv('SOC_ENABLE_KB_EDITING','true')
    monkeypatch.setattr(vs,'PLAYBOOKS_DIR',tmp_path)
    target=tmp_path/'phishing.md';target.write_text('approved content')
    with pytest.raises(FileExistsError):vs.save_uploaded_file('phishing.md',b'unapproved replacement',destination='playbooks')
    assert target.read_text()=='approved content'
    (tmp_path/'alias.md').symlink_to(target)
    with pytest.raises(FileExistsError):vs.save_uploaded_file('alias.md',b'replacement',destination='playbooks')
    assert target.read_text()=='approved content'


def test_upload_validation_and_config_bounds(tmp_path,monkeypatch):
    monkeypatch.setenv('SOC_ENABLE_KB_EDITING','true')
    monkeypatch.setattr(vs,'UPLOADS_DIR',tmp_path/'uploads')
    monkeypatch.setattr(vs,'CHROMA_DIR',tmp_path/'db')
    for filename, body in [('bad.json',b'{invalid'),('bad.txt',b'\xff'),('script.py',b'print(1)'),('big.txt',b'x'*1_000_001)]:
        with pytest.raises(ValueError):vs.save_uploaded_file(filename,body)
    with pytest.raises(ValueError):vs.save_chunk_config({'chunk_size':200,'chunk_overlap':250})
    path=vs.save_uploaded_file('../guide.txt',b'context')
    assert path.parent==tmp_path/'uploads' and path.name=='guide.txt'


def test_failed_staged_upsert_keeps_live_index(store):
    old_marker=(vs.CHROMA_DIR/'.indexed').read_bytes()
    old_count=store._collection.count()
    from chromadb.api.models.Collection import Collection
    with patch.object(Collection,'upsert',side_effect=RuntimeError('simulated disk failure')):
        with pytest.raises(RuntimeError):vs.build_vector_store(force_rebuild=True)
    assert (vs.CHROMA_DIR/'.indexed').read_bytes()==old_marker
    assert store._collection.count()==old_count
    assert vs.index_stats()['indexed']


def test_upload_invalidates_index_and_stays_supplementary(store,monkeypatch):
    monkeypatch.setenv('SOC_ENABLE_KB_EDITING','true')
    vs.save_uploaded_file('guide.txt',b'Unapproved context must not become an organizational containment step.')
    assert not vs.index_stats()['indexed']
    current=vs.build_vector_store()
    assert current.get(where={'doc_type':'upload'})['documents']
    assert vs.index_stats()['indexed']
    assert store._collection.count()>0


def test_step_strategy_keeps_all_approved_sop_records(store,monkeypatch):
    monkeypatch.setenv('SOC_ENABLE_KB_EDITING','true')
    original=store.get(where={'doc_type':'playbook'})['documents']
    rebuilt=vs.build_vector_store(force_rebuild=True,strategy='fixed',chunk_size=300,chunk_overlap=50)
    assert set(original)==set(rebuilt.get(where={'doc_type':'playbook'})['documents'])


def test_dashboard_gates_actions_with_no_local_services(monkeypatch):
    with patch('ui.client.fetch_all_metrics',return_value={}),patch('network.secrets_store.simulator_config_status',return_value={'configured':False}),patch('network.secrets_store.simulation_actions_enabled',return_value=False),patch('ui.simulator.simulator_config_status',return_value={'configured':False}),patch('ui.simulator.simulation_actions_enabled',return_value=False):
        app=AppTest.from_file(str(ROOT/'app.py'),default_timeout=30).run()
        assert not app.exception
        assert next(b for b in app.button if b.label=='Run scenario + agent').disabled
        next(b for b in app.button if b.key=='mesh_select_8001').click().run()
        assert next(b for b in app.button if b.key=='mesh_online_8001').disabled


def test_kb_readonly_ui_and_preview(monkeypatch,tmp_path):
    monkeypatch.setenv('SOC_ENABLE_KB_EDITING','false')
    monkeypatch.setattr(vs,'CHROMA_DIR',tmp_path/'db')
    app=AppTest.from_file(str(ROOT/'ui/pages/knowledge_base.py'),default_timeout=30).run()
    assert not app.exception
    assert next(b for b in app.button if b.label=='Save chunking settings').disabled
    next(b for b in app.button if b.label=='Preview chunks').click().run()
    assert not app.exception and app.code


def test_local_client_rejects_non_demo_ports_and_disabled_mode(monkeypatch):
    import ui.client as client
    monkeypatch.setattr('network.secrets_store.simulation_actions_enabled',lambda:False)
    with patch('subprocess.Popen',side_effect=AssertionError('No process should be spawned')):
        with pytest.raises(ValueError):client.start_node(9000)
        with pytest.raises(RuntimeError):client.start_node(8001)


def test_streamed_runner_preserves_backend_opt_in(monkeypatch):
    from network.scenarios import runner
    monkeypatch.setattr(runner,'simulation_actions_enabled',lambda:False)
    with patch.object(runner,'MeshClient',side_effect=AssertionError('No traffic should be injected')):
        with pytest.raises(RuntimeError):asyncio.run(runner.inject_scenario('ddos'))


def test_dashboard_streams_agent_steps_and_records_result(monkeypatch,tmp_path):
    import ui.log_reader as logs
    monkeypatch.setattr(logs,'LOG_DIR',tmp_path)
    metrics={p:{'online':True,'port':p,'rps_estimate':0} for p in (8001,8002,8003)}
    def scenario(name,on_step=None):
        state={'detection':{'incident_detected':True,'scenario':name,'severity':'high','confidence':.9},
               'remediation_plan':{'target_port':8001,'actions':[{'action':'set_rate_limit'}]},
               'execution_results':[{'http_status':200,'response':{'status':'ok'},'request':{'action':'set_rate_limit'}}],
               'summary':'Demo incident contained.', 'agent_trace':[]}
        for step in ('collect_telemetry','detect_incident','retrieve_sop','plan_remediation','execute_remediation','summarize'):
            state['agent_trace'].append({'step':step,'detail':'verified demo state','data':{}})
            on_step(dict(state))
        return {'scenario':name,'target':8001,'contained':True,'agent':state}
    with patch('ui.client.fetch_all_metrics',return_value=metrics),patch('ui.client.run_scenario_live',side_effect=scenario),patch('network.secrets_store.simulator_config_status',return_value={'configured':True}),patch('network.secrets_store.simulation_actions_enabled',return_value=True),patch('ui.simulator.simulator_config_status',return_value={'configured':True}),patch('ui.simulator.simulation_actions_enabled',return_value=True):
        app=AppTest.from_file(str(ROOT/'ui/pages/dashboard.py'),default_timeout=30).run()
        next(b for b in app.button if b.label=='Run scenario + agent').click().run()
        assert not app.exception
        assert app.session_state['scenario_results'][-1]['contained'] is True
        assert len(app.session_state['monitor_result']['agent_trace'])==6


def test_new_admin_routes_require_operator_authentication(monkeypatch):
    from network.node import create_app
    from network.auth import NodeAuthState,create_token
    from fastapi.testclient import TestClient
    with patch('network.node.bootstrap_auth_state',return_value=NodeAuthState(8001,'local-test-secret-at-least-32-bytes')),patch('network.node.mesh_credentials',return_value=('operator','test-password')):
        client=TestClient(create_app(8001))
        for route in ('/admin/online','/admin/isolate','/admin/shutdown'):
            assert client.post(route).status_code==401
        token=create_token(client.app.state.auth,'ordinary-user',{'role':'user'})
        for route in ('/admin/online','/admin/isolate','/admin/shutdown'):
            assert client.post(route,headers={'Authorization':f'Bearer {token}'}).status_code==403
        token=client.post('/auth/token',json={'username':'operator','password':'test-password'}).json()['access_token']
        headers={'Authorization':f'Bearer {token}'}
        assert client.post('/admin/isolate',headers=headers).status_code==200
        # Recovery can authenticate after isolation, even when key rotation invalidated a cached token.
        refreshed=client.post('/auth/token',json={'username':'operator','password':'test-password'})
        assert refreshed.status_code==200
        headers={'Authorization':'Bearer '+refreshed.json()['access_token']}
        assert client.post('/admin/online',headers=headers).status_code==200


def test_live_finalizer_keeps_isolation_applied():
    from network.scenarios import runner
    from unittest.mock import AsyncMock,MagicMock
    client=MagicMock()
    manager=MagicMock();manager.__aenter__=AsyncMock(return_value=client);manager.__aexit__=AsyncMock(return_value=None)
    with patch.object(runner.httpx,'AsyncClient',return_value=manager),patch.object(runner,'_metrics',new=AsyncMock(return_value={'isolated':True,'key_version':2})):
        result=asyncio.run(runner.finalize_scenario_result({'scenario':'ransomware','focus_port':8001,'before_key_version':1},{}))
    assert result['contained'] is True and result['isolated_observed'] is True
    client.post.assert_not_called()
    assert result['langgraph']==result['agent']
