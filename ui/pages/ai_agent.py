"""Interactive incident workspace connected to the SOC parser, retrieval and tickets."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from html import escape
from pathlib import Path

import streamlit as st

from src.alert_parser import list_sample_alerts, parse_alert_json_string
from src.agent import run_incident_assistant
from src.config import ALERTS_DIR, CVES_PATH, OPENAI_API_KEY, PLAYBOOKS_DIR
from src.ticket_generator import generate_incident_ticket, save_ticket
from src.vector_store import build_vector_store, index_stats
from ui.styles import inject_styles, stat_card
from ui.workspace import (checklist_sections, clear_investigation, review_key, review_snapshot,
                          run_local_demo, source_for_citation)

SCENARIO_ALERT_MAP = {name: f'alert_{name}.json' for name in
                      ('ddos', 'phishing', 'ransomware', 'credential_stuffing', 'public_s3_bucket')}


def _log_agent(step: str, detail: str = '') -> None:
    feed = st.session_state.setdefault('agent_activity', [])
    feed.append(dict(step=step, detail=detail, at=datetime.now(timezone.utc).strftime('%H:%M:%S UTC')))
    st.session_state.agent_activity = feed[-30:]


def _friendly(name: str) -> str:
    if name == '(paste custom JSON)':
        return 'Custom alert'
    return name.removeprefix('alert_').removesuffix('.json').replace('_', ' ').title().replace('Ddos', 'DDoS').replace('S3', 'S3')


def _context(parsed: dict) -> None:
    severity = str(parsed.get('severity', 'Unknown'))
    tag = severity.lower() if severity.lower() in ('high', 'critical') else ''
    st.markdown(f'''<div class="soc-context"><span class="soc-tag {tag}">{escape(severity.upper())}</span><span class="soc-tag">{escape(parsed.get('attack_classification', 'Unknown'))}</span><div class="soc-context-title">{escape(parsed.get('rule_name') or 'Unclassified security signal')}</div><div class="soc-context-meta">{escape(parsed.get('alert_id', 'UNKNOWN'))} · {escape(parsed.get('timestamp') or 'No event timestamp')}</div></div>''', unsafe_allow_html=True)


def _indicators(parsed: dict) -> None:
    st.caption('Extracted candidates include affected internal assets. Validate maliciousness before blocking.')
    rows = [dict(Type=kind.replace('_', ' ').title(), Indicator=value)
            for kind, values in parsed.get('iocs', {}).items() for value in values]
    if rows:
        st.dataframe(rows, hide_index=True, width='stretch')
        st.download_button('Export indicators', json.dumps(parsed.get('iocs', {}), indent=2),
                           file_name='indicators.json', mime='application/json', key='export_iocs')
    else:
        st.info('No indicators extracted. Add alert evidence and parse again.')
    st.markdown('**MITRE ATT&CK techniques**')
    st.write(' · '.join(parsed.get('mitre_techniques', [])) or 'None explicitly identified')
    with st.expander('Parsed alert details'):
        st.json(parsed)


def _evidence(result: dict) -> None:
    st.caption('Exact organizational source text and mock vulnerability intelligence behind this response.')
    search = st.text_input('Search evidence', placeholder='Policy ID, source file, or keyword', key='evidence_search')
    source_type = st.radio('Source type', ['All sources', 'Playbooks', 'CVE advisories'], horizontal=True, key='source_filter')
    shown = 0
    for doc in result.get('retrieved_docs', []):
        meta = doc.get('metadata', {})
        if source_type == 'Playbooks' and meta.get('doc_type') != 'playbook':
            continue
        if source_type == 'CVE advisories' and meta.get('doc_type') != 'cve':
            continue
        if search.lower() not in (doc.get('content', '') + json.dumps(meta)).lower():
            continue
        shown += 1
        label = f"{meta.get('sop_id', meta.get('cve_id', 'Source'))} · {meta.get('source', '')}"
        if meta.get('line_start'):
            label += f" : {meta['line_start']} · {meta.get('section', '')}"
        with st.expander(label):
            st.code(doc.get('content', ''), language='markdown')
            st.caption('Mock advisory — verify current vendor guidance.' if meta.get('mock') else 'Bundled organizational SOP · exact source text')
    if not shown:
        st.info('No sources match this filter.')


def _containment(result: dict, fingerprint: str) -> None:
    sections = checklist_sections(result.get('containment_checklist', ''))
    st.caption('Check a step after reviewing its applicability. Review does not execute or confirm containment.')
    progress = st.empty()
    for number, (section, steps) in enumerate(sections, 1):
        with st.container(border=True):
            st.markdown(f'**{number:02d} / {section}**')
            for step in steps:
                main, source = st.columns([.86, .14])
                label, doc = source_for_citation(result, step['citation'])
                with main:
                    st.checkbox(step['text'], key=review_key(fingerprint, step['citation']), help=label, wrap=True, width='stretch')
                with source:
                    with st.popover(f"[{step['citation']}]", width='stretch'):
                        st.caption(label)
                        st.code(doc['content'] if doc else step['text'], language='markdown')
    snapshot = review_snapshot(result, st.session_state, fingerprint)
    reviewed = sum(item['reviewed'] for item in snapshot)
    with progress.container():
        st.progress(reviewed / len(snapshot) if snapshot else 0, text=f'{reviewed} of {len(snapshot)} steps reviewed')
    if not sections:
        st.markdown(result.get('containment_checklist', ''))
    st.markdown('**Related vulnerability intelligence**')
    cves = [d for d in result.get('retrieved_docs', []) if d.get('metadata', {}).get('doc_type') == 'cve']
    for doc in cves:
        with st.expander(doc['metadata'].get('cve_id', 'CVE advisory')):
            st.code(doc['content'], language='json')
    requested = result.get('parsed_alert', {}).get('related_cves', [])
    missing = set(requested) - {d['metadata'].get('cve_id') for d in cves}
    if missing:
        st.warning('Not found in the mock feed: ' + ', '.join(sorted(missing)))
    if not requested:
        st.caption('No CVE explicitly identified in this alert. No vulnerability is inferred from attack category.')
    st.caption('Bundled CVE feed is mocked. An ID match does not confirm exploitation.')
    with st.expander('Full cited checklist / Markdown'):
        st.code(result.get('containment_checklist', ''), language='markdown')


def _ticket(result: dict, fingerprint: str) -> None:
    st.markdown('### A clear handoff, with the evidence attached.')
    st.caption('Create a local Markdown ticket. Root cause remains unconfirmed; recommendations are not recorded as completed actions.')
    analyst = st.text_input('Prepared by', placeholder='Analyst name or team', key='ticket_analyst')
    notes = st.text_area('Analyst notes', placeholder='Record scope, open questions, and handoff context…', height=100, key='ticket_notes')
    if st.button('Generate Incident Ticket', type='primary', width='stretch'):
        try:
            snapshot = review_snapshot(result, st.session_state, fingerprint)
            count = sum(item['reviewed'] for item in snapshot)
            ticket = generate_incident_ticket(result['parsed_alert'], result['containment_checklist'], result.get('citations', []))
            ticket += f"\n\n## Analyst Review\n- Analysis mode: {result.get('analysis_mode', 'Vector retrieval')}\n- Steps reviewed for applicability: {count}/{len(snapshot)}\n- Review checkmarks do not confirm execution.\n"
            if analyst.strip():
                ticket += '\nPrepared by (analyst supplied):\n' + '\n'.join('> ' + line for line in analyst.splitlines()) + '\n'
            if notes.strip():
                ticket += '\nAnalyst notes (analyst supplied):\n' + '\n'.join('> ' + line for line in notes.splitlines()) + '\n'
            path = save_ticket(ticket, result['parsed_alert'].get('alert_id', 'UNKNOWN'))
            st.session_state.update(ticket=ticket, ticket_path=str(path), ticket_review_count=count)
            _log_agent('Ticket created', path.name)
        except Exception as exc:
            st.error(f'Ticket could not be saved: {exc}')
    if st.session_state.get('ticket'):
        st.success('Ticket ready to download')
        st.caption(f"Draft includes {st.session_state.get('ticket_review_count', 0)} reviewed steps at generation. Regenerate after changing review selections or notes.")
        safe_id = re.sub(r'[^A-Za-z0-9_-]', '_', str(result['parsed_alert'].get('alert_id', 'incident')))[:100]
        st.download_button('Download ticket (.md)', st.session_state['ticket'], file_name=f'ticket_{safe_id}.md', mime='text/markdown', width='stretch')
        with st.expander('Preview incident ticket', expanded=True):
            st.markdown(st.session_state['ticket'])


def page() -> None:
    inject_styles()
    choices = {p.name: p for p in list_sample_alerts(ALERTS_DIR)}
    samples = [json.loads(p.read_text(encoding='utf-8')) for p in choices.values()]
    feed = json.loads(CVES_PATH.read_text(encoding='utf-8'))
    with st.sidebar:
        mode = st.radio('Analysis mode', ['Local demo', 'Vector retrieval'],
                        index=1 if OPENAI_API_KEY else 0, key='analysis_mode')
        st.caption('Local demo uses bundled SOPs directly. Vector retrieval uses OpenAI embeddings and Chroma.')
        st.divider()
        st.markdown('**Knowledge library**')
        st.caption(f"{len(list(PLAYBOOKS_DIR.glob('*.md')))} playbooks · {len(feed.get('cves', []))} mock advisories")
        stats = index_stats()
        st.caption('Vector index · current' if stats.get('indexed') else 'Vector index · not built or out of date')
        if st.button('Build / Rebuild Index', width='stretch', disabled=not bool(OPENAI_API_KEY)):
            try:
                with st.spinner('Building knowledge index…'):
                    build_vector_store(force_rebuild=True)
                _log_agent('Index rebuilt')
                st.rerun()
            except Exception as exc:
                st.error(f'Index build failed: {exc}')
        if not OPENAI_API_KEY:
            st.caption('Add OPENAI_API_KEY to .env to enable vector retrieval.')
        st.divider()
        with st.expander('Activity log'):
            for event in reversed(st.session_state.get('agent_activity', [])):
                st.caption(f"{event.get('at', '')} · {event['step']}")
                if event.get('detail'):
                    st.text(event['detail'])
            if not st.session_state.get('agent_activity'):
                st.caption('Your investigation activity will appear here.')

    title, status = st.columns([.76, .24], vertical_alignment='center')
    with title:
        st.markdown('<div class="soc-eyebrow">Security operations / Investigate</div><div class="soc-title">Incident workspace</div><div class="soc-subtitle">From the first signal to your next approved action.</div>', unsafe_allow_html=True)
    with status:
        label = 'LOCAL DEMO' if mode == 'Local demo' else 'VECTOR RETRIEVAL'
        st.markdown(f'<div class="soc-status"><span class="soc-status-dot"></span>{label} · MOCK CVE FEED</div>', unsafe_allow_html=True)
    metrics = st.columns(4)
    cards = [('Sample alerts', len(samples), 'Synthetic scenarios ready to investigate'),
             ('High / critical', sum(str(a.get('severity', '')).lower() in ('high', 'critical') for a in samples), 'Reported severity in the sample inbox'),
             ('Response playbooks', len(list(PLAYBOOKS_DIR.glob('*.md'))), 'Exact organizational SOP steps'),
             ('CVE advisories', len(feed.get('cves', [])), 'Bundled mock intelligence')]
    for column, (label, value, foot) in zip(metrics, cards):
        with column:
            stat_card(label, str(value).zfill(2), foot)

    left, right = st.columns([.37, .63], gap='large')
    with left:
        with st.container(border=True):
            st.markdown('### Alert inbox')
            st.caption('Choose a scenario or bring your own alert.')
            options = list(choices) + ['(paste custom JSON)']
            default = 'alert_phishing.json' if 'alert_phishing.json' in choices else options[0]
            scenarios = st.session_state.get('scenario_results') or []
            if scenarios:
                mapped = SCENARIO_ALERT_MAP.get(scenarios[-1].get('scenario'))
                if mapped in choices:
                    default = mapped
            sample = st.selectbox('Select alert', options, index=options.index(default), format_func=_friendly, key='selected_alert')
            controls = st.container()
            with st.expander('Import JSON alert'):
                upload = st.file_uploader('Upload a JSON alert', type=['json'], key='alert_upload')
            if upload is not None:
                st.caption('Uploaded JSON is selected. Remove it to return to sample alerts.')
            if upload is not None:
                raw_bytes = upload.getvalue()
                input_id = 'upload_' + hashlib.sha256(raw_bytes).hexdigest()
                try:
                    if len(raw_bytes) > 1_000_000:
                        raise ValueError('Alert exceeds 1 MB limit')
                    initial = raw_bytes.decode('utf-8-sig')
                except (UnicodeError, ValueError) as exc:
                    st.error(str(exc))
                    initial = ''
            else:
                input_id = sample
                initial = choices[sample].read_text(encoding='utf-8') if sample in choices else '{\n  "alert_id": "CUSTOM-001",\n  "severity": "High",\n  "rule_name": "",\n  "raw_event": {}\n}'
            text = st.text_area('Raw security alert (JSON)', value=initial, height=240, key=f'alert_input_{input_id}')
            fingerprint = hashlib.sha256((mode + '\0' + text).encode()).hexdigest()
            if st.session_state.get('alert_fingerprint') != fingerprint:
                clear_investigation(st.session_state)
                st.session_state['alert_fingerprint'] = fingerprint
            preview = None
            try:
                preview = parse_alert_json_string(text).model_dump()
            except (ValueError, TypeError, RecursionError):
                pass
            if preview:
                _context(preview)
            with controls:
                parse_col, reset_col = st.columns(2)
                with parse_col:
                    parse = st.button('Parse alert', width='stretch')
                with reset_col:
                    reset = st.button('Reset investigation', width='stretch')
                analyze = st.button('Analyze alert', type='primary', width='stretch',
                                    disabled=mode == 'Vector retrieval' and not OPENAI_API_KEY)
                if mode == 'Local demo':
                    st.caption('Demo analysis · direct source lookup · no API calls')
            if reset:
                clear_investigation(st.session_state)
                st.rerun()
            if parse:
                clear_investigation(st.session_state)
                try:
                    parsed = parse_alert_json_string(text)
                    st.session_state['parsed'] = parsed.model_dump()
                    _log_agent('Alert parsed', parsed.attack_classification)
                except Exception as exc:
                    st.session_state['analysis_error'] = str(exc)
            if analyze:
                clear_investigation(st.session_state)
                try:
                    with st.spinner('Matching alert evidence to approved procedures…'):
                        result = run_local_demo(text) if mode == 'Local demo' else run_incident_assistant(text)
                    if result.get('error'):
                        raise ValueError(result['error'])
                    result['analysis_mode'] = mode
                    result.setdefault('analyzed_at', datetime.now(timezone.utc).isoformat())
                    st.session_state['parsed'] = result['parsed_alert']
                    st.session_state['agent_result'] = result
                    _log_agent('Response plan ready', result['parsed_alert']['attack_classification'])
                except Exception as exc:
                    st.session_state['analysis_error'] = str(exc)
                    _log_agent('Analysis needs attention', str(exc))

    with right:
        result = st.session_state.get('agent_result')
        parsed = st.session_state.get('parsed') or preview
        st.markdown('### Investigation')
        if st.session_state.get('analysis_error'):
            st.error(st.session_state['analysis_error'])
        if result:
            st.caption(f"{result['parsed_alert'].get('alert_id', 'Incident')} · {result.get('analysis_mode', mode)} · recommendations ready")
        else:
            st.caption('Evidence first. Approved procedures next.')
        containment, indicators, evidence, ticket = st.tabs(['Containment', 'Indicators', 'Evidence', 'Incident ticket'])
        with containment:
            if result:
                _containment(result, fingerprint)
            else:
                st.markdown('<div class="soc-empty"><div class="soc-empty-icon">⌁</div><h3>Find the next approved action.</h3><p>Select an alert, inspect its evidence, and analyze it to reveal the matching response playbook.</p></div>', unsafe_allow_html=True)
                st.markdown('**01** Parse the signal &nbsp; → &nbsp; **02** Match approved steps &nbsp; → &nbsp; **03** Prepare the handoff')
                if parsed:
                    st.caption(f"Preview: {parsed.get('attack_classification', 'Unknown')} · {sum(len(v) for v in parsed.get('iocs', {}).values())} indicator candidates · analysis not run")
        with indicators:
            if parsed:
                _indicators(parsed)
            else:
                st.info('Choose a valid JSON alert to inspect its indicators.')
        with evidence:
            if result:
                _evidence(result)
            else:
                st.info('Analyze an alert to inspect the organizational steps and advisories supporting its response.')
        with ticket:
            if result:
                _ticket(result, fingerprint)
            else:
                st.info('Generate a response plan first. Your incident ticket will include its evidence and citations.')
        if result:
            snapshot = review_snapshot(result, st.session_state, fingerprint)
            payload = {**result, 'step_reviews': snapshot,
                       'analyst_notes': st.session_state.get('ticket_notes', ''),
                       'prepared_by': st.session_state.get('ticket_analyst', '')}
            st.download_button('Export investigation (.json)', json.dumps(payload, indent=2),
                               file_name='investigation.json', mime='application/json', key='export_case')
    st.markdown('<div class="soc-footer">SOC COPILOT &nbsp; / &nbsp; Analyst decision support · Exact SOP citations · Mock vulnerability intelligence</div>', unsafe_allow_html=True)


page()
