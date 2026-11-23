# SOP-IR-001: Phishing Incident Response Playbook

**Classification:** Internal  
**Owner:** SOC Tier 2  
**Last Updated:** 2026-03-20  
**Severity Mapping:** Low–Critical depending on credential compromise and lateral movement  

## Purpose
Provide step-by-step containment and eradication procedures when a phishing email, malicious link, or credential-harvesting page is detected. Include mesh metrics the monitoring agent uses and remediations it can execute.

## Detection Metrics & Thresholds
| Metric | Source | Threshold / condition |
|---|---|---|
| `phishing_hits` | Mesh `/metrics` | ≥ **1** malicious / evil URL hit |
| Malicious URL match | Mesh message / scenario payload | URL contains phish/evil patterns (e.g. `evil-secure-login`, credential-harvest paths) |
| `scenario_tag=phishing` | Mesh `/mesh/message` or `/scenario/phishing` | Any tagged phishing pulse raises a signal |
| `jwt_compromise_suspected` | Detection / planner | `true` when users may have submitted credentials on a fake login page |
| Open `phishing` incidents | Mesh open incidents | ≥ 1 unremediated phishing incident on `:8001`–`:8003` |
| Mail gateway / IdP | Enterprise telemetry | Quarantine hits, URL rewrite clicks, impossible-travel after phish |

**Detect when:** `phishing_hits ≥ 1` **OR** `scenario_tag=phishing` **OR** an open phishing incident exists.

## Detection Triggers
- User-reported suspicious email
- Email gateway quarantine / URL rewrite hits
- Identity provider impossible-travel or MFA fatigue alerts linked to a phish
- EDR detection of payload dropped from email attachment
- Mesh node phishing signal (URL hit or scenario tag)

## Immediate Triage (0–15 minutes)
1. **Confirm the alert** — Open the reported message in a sandbox viewer; do not open attachments on analyst workstations.
2. **Extract Indicators of Compromise (IoCs)** — Capture sender address, reply-to, subject, message-ID, URLs, attachment hashes (SHA256), and any credential-harvest domains.
3. **Classify attack type** — Credential harvesting, malware delivery, BEC (business email compromise), or spear-phishing.
4. **Identify impacted users** — Search mail logs for recipients who received the same message-ID or identical subject/sender within the last 72 hours.
5. **Check mesh telemetry** — Note `phishing_hits`, malicious URLs, and target port from `/metrics`.

## Containment Checklist
1. **Quarantine the message** across the enterprise mail system using the message-ID or exact subject+sender pair (MG-PHISH-03).
2. **Block malicious URLs/domains** at the secure web gateway and DNS firewall (NET-URL-BLOCK-01) — mesh action: `quarantine_url`.
3. **Rotate JWT / revoke sessions** when credential harvest is suspected (IAM-RESET-02) — mesh action: `rotate_jwt`.
4. **Reset credentials** for any user who clicked the link or submitted credentials; force MFA re-enrollment.
5. **Disable forwarding rules** created by attackers on compromised mailboxes.
6. **Isolate endpoints** that executed attachments via EDR network isolation (EDR-ISO-01).

## Remediations (execute on target mesh node)
Use these actions in order for an active phishing incident. The Agent maps them to `/admin/remediate`.

| Priority | Action | Parameters | Policy ID | When to use |
|---|---|---|---|---|
| 1 | `quarantine_url` | `urls`: malicious / harvest URLs from detection | NET-URL-BLOCK-01 | Always when URLs are known |
| 2 | `rotate_jwt` | (node JWT key rotation) | IAM-RESET-02 / JWT harvest | Credential harvest suspected |
| 3 | Mail quarantine + IdP session revoke | message-ID / user list | MG-PHISH-03 | Parallel enterprise containment |
| 4 | `isolate` | (endpoint / host) | EDR-ISO-01 | Only if malware execution confirmed |

### Standard remediation sequence
1. **Quarantine malicious URLs** — Execute `quarantine_url` with all IoC URLs (`malicious_urls` from detection). Reason: `Phishing URL block (NET-URL-BLOCK-01)`.
2. **Rotate JWT / revoke sessions** — Execute `rotate_jwt` on the impacted node so harvested tokens fail. Reason: `JWT harvest suspected`.
3. **Reset affected user passwords + MFA** — Force IdP reset for clickers / submitters (IAM-RESET-02).
4. **Verify containment** — Confirm URLs are blocked, `phishing_hits` stop increasing, and new tokens use the rotated key version.
5. **Do not** prefer `block_ip` or `set_rate_limit` for pure phishing unless the same source is also flooding auth.

### Example remediation payload (mesh)
```json
{
  "scenario": "phishing",
  "target_port": 8002,
  "rationale": "Credential-harvest URL observed — quarantine URL and rotate JWT",
  "actions": [
    {
      "action": "quarantine_url",
      "ips": [],
      "urls": ["https://evil-secure-login.net/owa/auth"],
      "reason": "Phishing URL block (NET-URL-BLOCK-01)"
    },
    {
      "action": "rotate_jwt",
      "ips": [],
      "urls": [],
      "reason": "JWT harvest suspected (IAM-RESET-02)"
    }
  ]
}
```

## Investigation Steps
1. Review mail authentication results (SPF/DKIM/DMARC) for the sender domain.
2. Correlate click telemetry from URL rewrite / proxy logs with identity sign-in logs.
3. Search EDR for process trees spawned from Office macros or archive extractors.
4. Check for new OAuth app grants or mailbox rules on impacted accounts.
5. Map any harvested credentials to privileged / privileged-adjacent accounts.

## Eradication & Recovery
1. Remove malware artifacts from isolated hosts and reimage if persistence is confirmed.
2. Confirm URL/domain blocks remain active for at least 30 days.
3. Restore mailbox access only after password reset + MFA verification.
4. Notify affected users with approved communications template COMM-PHISH-01.

## Escalation Criteria
- Executive or VIP mailbox targeted → escalate to CIRT Lead
- Evidence of successful credential use against production systems → raise severity to Critical
- Confirmed BEC wire-fraud attempt → notify Fraud & Legal immediately

## Evidence Retention
Retain original .eml, IoC list, mail search results, IdP session revoke logs, mesh remediation responses, and EDR isolation tickets for 365 days.
