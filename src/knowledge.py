"""Source-preserving knowledge records. No model-generated SOP text."""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path

CATEGORIES = {
    'phishing': 'Phishing', 'ransomware': 'Ransomware',
    'credential_stuffing': 'Credential Stuffing', 'ddos': 'DDoS',
    'public_s3_bucket': 'Public S3 Bucket',
}

def numbered_steps(text: str) -> list[dict]:
    """Extract complete Markdown list items, retaining indented conditions and source spans."""
    lines = text.splitlines()
    records = []
    section = ''
    in_fence = False
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.lstrip().startswith(('```', '~~~')):
            in_fence = not in_fence
        if in_fence:
            index += 1
            continue
        if line.startswith('## '):
            section = line[3:]
        match = re.match(r'^(\d+)\.\s+(.+)$', line)
        escalation = section == 'Escalation Criteria' and line.startswith('- ')
        if not match and not escalation:
            index += 1
            continue
        first = index
        body = [match.group(2) if match else line[2:]]
        index += 1
        while index < len(lines):
            following = lines[index]
            if following.startswith(('  ', '\t')):
                body.append(following)
                index += 1
            elif not following.strip() and index + 1 < len(lines) and lines[index + 1].startswith(('  ', '\t')):
                body.append(following)
                index += 1
            else:
                break
        records.append(dict(content='\n'.join(body), section=section,
                            step=match.group(1) if match else str(first + 1),
                            line_start=first + 1, line_end=index))
    return records


def playbook_records(directory: Path) -> list[dict]:
    records = []
    for path in sorted(directory.glob('*.md')):
        text = path.read_text(encoding='utf-8')
        if not text.strip():
            continue
        sop_id = text.splitlines()[0].split(':', 1)[0].lstrip('# ')
        for step in numbered_steps(text):
            meta = dict(source=path.name, doc_type='playbook', title=path.stem.replace('_', ' ').title(),
                        classification=CATEGORIES.get(path.stem, 'Unknown'), sop_id=sop_id,
                        **{key: value for key, value in step.items() if key != 'content'})
            records.append(dict(content=step['content'], metadata=meta))
    return records

def cve_records(path: Path) -> list[dict]:
    feed = json.loads(path.read_text(encoding='utf-8'))
    records = []
    for item in feed.get('cves', []):
        cve_id = item['cve_id']
        # Preserve the entire advisory, including its original references and mock-feed provenance.
        content = 'MOCK INTELLIGENCE — not a verified live advisory\n' + json.dumps(item, indent=2)
        records.append(dict(content=content, metadata=dict(
            source=cve_id, cve_id=cve_id, doc_type='cve', title=item.get('title', ''),
            feed_name=feed.get('feed_name', ''), generated_at=feed.get('generated_at', ''),
            mock=True)))
    return records

def corpus_fingerprint(playbooks: Path, cves: Path, model: str) -> str:
    digest = hashlib.sha256(('step-index-v2:' + model).encode())
    for path in sorted(playbooks.glob('*.md')) + [cves]:
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()

def render_grounded_checklist(parsed: dict, docs: list[dict]) -> tuple[str, list[str]]:
    """Render only exact indexed steps from the matching organizational SOP."""
    classification = parsed.get('attack_classification', 'Unknown')
    triage_sections = sorted({d['metadata'].get('section', '') for d in docs if d['metadata'].get('classification') == classification and d['metadata'].get('section', '').startswith('Immediate Triage')})
    approved_sections = (*triage_sections, 'Containment Checklist', 'Escalation Criteria')
    selected = [d for d in docs if d['metadata'].get('doc_type') == 'playbook'
                and d['metadata'].get('classification') == classification
                and d['metadata'].get('section') in approved_sections]
    # A partial retrieval must not masquerade as a complete containment checklist.
    if not any(d['metadata']['section'] == 'Containment Checklist' for d in selected):
        raise ValueError('No matching organizational containment SOP found; analyst review required.')
    citations, blocks = [], []
    for section in approved_sections:
        rows = sorted((d for d in selected if d['metadata']['section'] == section),
                      key=lambda d: d['metadata']['line_start'])
        blocks.append('## ' + section)
        for doc in rows:
            meta = doc['metadata']; idx = len(citations) + 1
            citations.append(f"[{idx}] {meta['sop_id']} · {meta['source']}:{meta['line_start']} · {section} · step {meta['step']}")
            blocks.append(f"- [ ] {doc['content']} [{idx}]")
    blocks.append('## Related CVE Intelligence\nMock feed; verify applicability and current vendor guidance. A CVE mentioned in an alert is not proof of exploitation.')
    cves = [d for d in docs if d['metadata'].get('doc_type') == 'cve'
            and d['metadata'].get('cve_id') in parsed.get('related_cves', [])]
    for doc in cves:
        idx = len(citations) + 1
        citations.append(f"[{idx}] {doc['metadata']['source']} · mock CVE feed")
        blocks.append(f"### {doc['metadata']['source']} [{idx}]\n```json\n{doc['content'].split(chr(10), 1)[-1]}\n```")
    available = {d['metadata']['cve_id'] for d in cves}
    missing = sorted(set(parsed.get('related_cves', [])) - available)
    if missing:
        blocks.append('Not found in indexed mock feed: ' + ', '.join(missing))
    if not parsed.get('related_cves'):
        blocks.append('No CVE explicitly identified in this alert; no vulnerability is inferred from attack category alone.')
    prefix = f"## Attack Classification\n{classification}\n\nAll actions below are recommendations; execution is not recorded by this assistant. Preserve SOP conditions before acting.\n\n## Key IoCs\n```json\n{json.dumps(parsed.get('iocs', {}), indent=2)}\n```\n"
    return prefix + '\n\n'.join(blocks), citations
