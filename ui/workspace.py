"""Presentation helpers and explicit offline demo adapter for the incident workspace."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from src.alert_parser import parse_alert_json_string
from src.config import CVES_PATH, PLAYBOOKS_DIR
from src.knowledge import cve_records, playbook_records, render_grounded_checklist

RESULT_KEYS = ('parsed', 'agent_result', 'ticket', 'ticket_path', 'ticket_review_count', 'analysis_error', 'ticket_notes')


def clear_investigation(state) -> None:
    for key in RESULT_KEYS:
        state.pop(key, None)
    for key in list(state):
        if key.startswith('review_'):
            state.pop(key, None)


def run_local_demo(text: str) -> dict:
    """Use bundled sources directly. Never represent this as vector/AI retrieval."""
    parsed = parse_alert_json_string(text).model_dump()
    docs = [d for d in playbook_records(PLAYBOOKS_DIR)
            if d['metadata']['classification'] == parsed['attack_classification']]
    docs += [d for d in cve_records(CVES_PATH)
             if d['metadata']['cve_id'] in parsed['related_cves']]
    checklist, citations = render_grounded_checklist(parsed, docs)
    return dict(parsed_alert=parsed, retrieved_docs=docs, containment_checklist=checklist,
                citations=citations, analysis_mode='Local demo',
                analyzed_at=datetime.now(timezone.utc).isoformat())


def checklist_sections(checklist: str) -> list[tuple[str, list[dict]]]:
    """Keep the exact cited item text while exposing native checkbox controls."""
    sections = []
    title, steps = '', []
    for line in checklist.splitlines():
        if line.startswith('## '):
            if steps:
                sections.append((title, steps))
            title, steps = line[3:], []
        match = re.match(r'^- \[ \] (.+) \[(\d+)\]$', line)
        if match:
            steps.append(dict(text=match.group(1), citation=int(match.group(2))))
    if steps:
        sections.append((title, steps))
    return sections


def review_key(fingerprint: str, citation: int) -> str:
    return f'review_{fingerprint}_{citation}'


def review_snapshot(result: dict, state, fingerprint: str) -> list[dict]:
    return [dict(section=section, **step,
                 reviewed=bool(state.get(review_key(fingerprint, step['citation']), False)))
            for section, steps in checklist_sections(result.get('containment_checklist', '')) for step in steps]


def source_for_citation(result: dict, number: int) -> tuple[str, dict | None]:
    citations = result.get('citations', [])
    label = next((c for c in citations if c.startswith(f'[{number}] ')), 'Source unavailable')
    for doc in result.get('retrieved_docs', []):
        meta = doc.get('metadata', {})
        if f"{meta.get('source')}:{meta.get('line_start')} ·" in label:
            return label, doc
    return label, None
