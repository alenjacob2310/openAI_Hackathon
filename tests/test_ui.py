from pathlib import Path
from unittest.mock import patch
from streamlit.testing.v1 import AppTest
ROOT = Path(__file__).resolve().parents[1]


def test_ui_parse_sample_change_and_error_clear_stale_results():
    at = AppTest.from_file(str(ROOT / 'ui/pages/ai_agent.py'), default_timeout=30).run()
    assert not at.exception
    at.selectbox[0].select('alert_phishing.json').run()
    next(b for b in at.button if b.label == "Parse alert").click().run()
    assert at.session_state['parsed']['attack_classification'] == 'Phishing'
    at.selectbox[0].select('alert_public_s3_bucket.json').run()
    assert 'Public S3 Bucket' in at.text_area[0].value
    assert 'parsed' not in at.session_state
    at.text_area[0].set_value('[]').run()
    next(b for b in at.button if b.label == "Parse alert").click().run()
    assert at.error
    assert 'parsed' not in at.session_state
    assert not at.exception


def test_ui_ticket_button_without_api_calls(tmp_path):
    import src.ticket_generator as tg
    parsed = {'alert_id':'UI-001','attack_classification':'Phishing','iocs':{},'severity':'High'}
    result = {'parsed_alert':parsed,'containment_checklist':'- [ ] Approved step [1]', 'citations':['[1] SOP-IR-001'], 'retrieved_docs':[]}
    with patch('src.config.OPENAI_API_KEY','unit-test-key'), patch('src.vector_store.index_stats',return_value={'indexed':True}), patch('src.agent.run_incident_assistant',return_value=result), patch.object(tg,'TICKETS_DIR',tmp_path):
        at = AppTest.from_file(str(ROOT / 'ui/pages/ai_agent.py'),default_timeout=30).run()
        next(r for r in at.radio if r.label == 'Analysis mode').set_value('Vector retrieval').run()
        next(b for b in at.button if b.label == "Analyze alert").click().run()
        assert not at.exception
        button = next(b for b in at.button if b.label == 'Generate Incident Ticket')
        button.click().run()
        assert not at.exception
        assert 'No completed actions' in at.session_state['ticket']
        assert Path(at.session_state['ticket_path']).exists()


def test_local_demo_review_ticket_and_incident_isolation(tmp_path):
    import src.ticket_generator as tg
    with patch('src.config.OPENAI_API_KEY', ''), patch.object(tg, 'TICKETS_DIR', tmp_path):
        at = AppTest.from_file(str(ROOT / 'ui/pages/ai_agent.py'), default_timeout=30).run()
        next(b for b in at.button if b.label == 'Analyze alert').click().run()
        assert not at.exception
        result = at.session_state['agent_result']
        assert result['analysis_mode'] == 'Local demo'
        assert len(at.checkbox) == 14
        at.checkbox[0].check().run()
        next(t for t in at.text_input if t.label == 'Prepared by').set_value('SOC Tier 2').run()
        next(t for t in at.text_area if t.label == 'Analyst notes').set_value('Validate impacted mailboxes.').run()
        next(b for b in at.button if b.label == 'Generate Incident Ticket').click().run()
        assert not at.exception
        assert 'Steps reviewed for applicability: 1/14' in at.session_state['ticket']
        assert 'Validate impacted mailboxes.' in at.session_state['ticket']
        assert 'No completed actions' in at.session_state['ticket']
        at.selectbox[0].select('alert_public_s3_bucket.json').run()
        assert 'ticket' not in at.session_state
        assert 'agent_result' not in at.session_state
        next(b for b in at.button if b.label == 'Analyze alert').click().run()
        assert not at.exception
        assert at.session_state['agent_result']['parsed_alert']['attack_classification'] == 'Public S3 Bucket'
        assert not any(c.value for c in at.checkbox)
        assert next(t for t in at.text_area if t.label == 'Analyst notes').value == ''


def test_unknown_alert_and_mode_change_clear_response():
    with patch('src.config.OPENAI_API_KEY', ''):
        at = AppTest.from_file(str(ROOT / 'ui/pages/ai_agent.py'), default_timeout=30).run()
        next(b for b in at.button if b.label == 'Analyze alert').click().run()
        assert 'agent_result' in at.session_state
        next(r for r in at.radio if r.label == 'Analysis mode').set_value('Vector retrieval').run()
        assert 'agent_result' not in at.session_state
        assert next(b for b in at.button if b.label == 'Analyze alert').disabled
        next(r for r in at.radio if r.label == 'Analysis mode').set_value('Local demo').run()
        at.text_area[0].set_value('{"rule_name":"Unrecognized event"}').run()
        next(b for b in at.button if b.label == 'Analyze alert').click().run()
        assert at.error
        assert 'agent_result' not in at.session_state
        assert not at.exception


def test_evidence_search_filters_actual_sources():
    with patch('src.config.OPENAI_API_KEY', ''):
        at = AppTest.from_file(str(ROOT / 'ui/pages/ai_agent.py'), default_timeout=30).run()
        next(b for b in at.button if b.label == 'Analyze alert').click().run()
        next(t for t in at.text_input if t.label == 'Search evidence').set_value('MG-PHISH-03').run()
        matches = [e for e in at.expander if 'SOP-IR-001' in e.label]
        assert len(matches) == 1
        next(r for r in at.radio if r.label == 'Source type').set_value('CVE advisories').run()
        assert any('No sources match' in info.value for info in at.info)
        assert not at.exception
