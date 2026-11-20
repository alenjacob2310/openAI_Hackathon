"""Evidence-only incident ticket export; does not claim recommended actions were executed."""
from __future__ import annotations
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4
from src.config import TICKETS_DIR


def _timeline(raw: Any, path='alert') -> list[tuple[datetime, str, str]]:
    events = []
    if isinstance(raw, dict):
        for key, value in raw.items():
            location = f'{path}.{key}'
            if isinstance(value, str) and (key == 'timestamp' or key.endswith(('_time', '_at', '_seen'))):
                try:
                    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                    if dt.tzinfo is not None:
                        events.append((dt, location, value))
                except ValueError:
                    pass
            events.extend(_timeline(value, location))
    elif isinstance(raw, list):
        for idx, value in enumerate(raw):
            events.extend(_timeline(value, f'{path}[{idx}]'))
    return sorted(events)


def generate_incident_ticket(parsed_alert: dict[str, Any], containment_checklist: str,
                             citations: list[str] | None = None) -> str:
    events = _timeline(parsed_alert.get('raw') or {})
    if not events and parsed_alert.get('timestamp'):
        events = _timeline({'timestamp': parsed_alert['timestamp']})
    timeline = '\n'.join(f'- {value} — observed field `{path}`' for _, path, value in events) or '- No timestamped events supplied.'
    return '\n\n'.join([
        '# Incident Ticket',
        '## Summary\n' + str(parsed_alert.get('summary', 'No summary supplied.')),
        'Alert ID: ' + str(parsed_alert.get('alert_id', 'UNKNOWN')),
        '## Timeline\n' + timeline,
        '## Root Cause (Hypothesized)\nUnconfirmed. Attack classification is a triage hypothesis, not a verified root cause. Investigate the evidence in the cited SOP.',
        '## Key IoCs\n```json\n' + json.dumps(parsed_alert.get('iocs', {}), indent=2) + '\n```',
        '## Containment Actions Taken\nNo completed actions have been recorded by this assistant.',
        '## Containment Actions Recommended\n' + containment_checklist,
        '## Related CVEs\n' + (', '.join(parsed_alert.get('related_cves', [])) or 'None explicitly identified in the alert.') + '\nMock intelligence; applicability is unconfirmed.',
        '## Severity & Priority Recommendation\nReported severity: ' + str(parsed_alert.get('severity', 'Unknown')) + '. Priority requires analyst assessment of impact and scope.',
        '## Next Steps / Owners\nSOC analyst: validate classification, assign an incident owner, execute applicable approved steps, and record outcomes and timestamps.',
        '## Sources\n' + ('\n'.join(citations or []) or 'No citations supplied.'),
    ])


def save_ticket(ticket_markdown: str, alert_id: str = 'UNKNOWN') -> Path:
    TICKETS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    safe_id = re.sub(r'[^A-Za-z0-9_-]', '_', str(alert_id))[:100] or 'UNKNOWN'
    path = TICKETS_DIR / f'ticket_{safe_id}_{ts}_{uuid4().hex[:8]}.md'
    path.write_text(f'<!-- generated_at={ts} -->\n\n' + ticket_markdown, encoding='utf-8')
    return path
