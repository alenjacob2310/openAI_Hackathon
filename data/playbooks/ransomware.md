# SOP-IR-002: Ransomware Incident Response Playbook

**Classification:** Internal – Restricted  
**Owner:** CIRT / SOC Tier 3  
**Last Updated:** 2026-03-20  
**Severity Mapping:** High–Critical  

## Purpose
Define rapid containment, evidence preservation, and recovery steps when ransomware encryption, ransom notes, or known ransomware TTPs are observed. Include mesh detection metrics and remediations the monitoring agent can execute.

## Detection Metrics & Thresholds
| Metric | Source | Threshold / condition |
|---|---|---|
| `ransomware_signals` | Mesh `/metrics` | ≥ **1** ransomware signal |
| Payload markers | Mesh message / scenario payload | Any of: `encrypt_files`, `vssadmin`, `.locked`, `ransom_note`, `wbadmin`, wipe/shadow-copy language |
| `scenario_tag=ransomware` | Mesh `/mesh/message` or `/scenario/ransomware` | Tagged ransomware pulse raises a signal |
| Open `ransomware` incidents | Mesh open incidents | ≥ 1 unremediated ransomware incident |
| EDR behavior rules | Endpoint telemetry | Mass file rename/encrypt, canary file changes |
| Shadow copy deletion | Host logs | `vssadmin` / `wbadmin` delete events |

**Detect when:** `ransomware_signals ≥ 1` **OR** ≥ 1 marker (`encrypt_files` · `vssadmin` · `.locked` · `ransom_note`) **OR** an open ransomware incident exists.

## Detection Triggers
- EDR ransomware behavior rules (mass file rename/encrypt)
- Canary file modifications
- Shadow copy deletion events (vssadmin / wbadmin)
- User reports of .locked / .encrypted files or ransom notes
- Threat intel match on known ransomware C2 domains
- Mesh ransomware signal / marker match

## Immediate Triage (0–10 minutes)
1. **Declare a ransomware event** — Notify CIRT Lead and Incident Commander; open a Priority-1 bridge.
2. **Do not power off hosts** unless directed; prefer network isolation to preserve volatile evidence.
3. **Identify patient zero and blast radius** — List hosts with encryption activity in the last 2 hours from EDR; check mesh target port.
4. **Capture IoCs** — Ransom note hashes, encrypted file extensions, C2 IPs/domains, attacker email/Tor payment address, ransomware family name if identifiable.
5. **Confirm mesh signal** — Review `ransomware_signals` and open incidents on `/metrics`.

## Containment Checklist
1. **Network-isolate all actively encrypting hosts** via EDR / mesh — action: `isolate` (EDR-ISO-01); if EDR fails, disable switch ports (NET-PORT-KILL-02).
2. **Rotate JWT / revoke sessions** — action: `rotate_jwt` to cut off session reuse and lateral API abuse.
3. **Disable SMB / remote admin shares** for affected VLANs temporarily (NET-SMB-LOCK-01).
4. **Block identified C2 domains/IPs** at perimeter firewall and DNS (NET-IOC-BLOCK-01) — optional mesh `block_ip` / `quarantine_url` when IoCs exist.
5. **Disable compromised domain accounts** used for lateral movement; reset KRBTGT if Golden Ticket is suspected (IAM-AD-EMERGENCY-04).
6. **Preserve forensic images** of 2–3 representative hosts before reimaging (FOR-ACQ-01).

## Remediations (execute on target mesh node)
Use these actions immediately for an active ransomware incident.

| Priority | Action | Parameters | Policy ID | When to use |
|---|---|---|---|---|
| 1 | `isolate` | (node-level network isolation) | EDR-ISO-01 | Always for active encryption / ransomware signal |
| 2 | `rotate_jwt` | (invalidate tokens / sessions) | Credential/session compromise risk | Always after isolation |
| 3 | `block_ip` / `quarantine_url` | C2 IPs / domains if known | NET-IOC-BLOCK-01 | When C2 IoCs are available |
| 4 | AD account disable + backup lockdown | enterprise controls | IAM-AD-EMERGENCY-04 | Parallel CIRT actions |

### Standard remediation sequence
1. **Isolate the impacted node** — Execute `isolate` so the host cannot reach peers or exfiltrate. Reason: `EDR-ISO-01 ransomware containment`.
2. **Rotate JWT** — Execute `rotate_jwt` to invalidate potentially stolen sessions. Reason: `Credential/session compromise risk`.
3. **Block C2 IoCs** — If attacker IPs/URLs are known, execute `block_ip` / `quarantine_url`.
4. **Verify containment** — Node returns isolated status; non-admin mesh traffic receives 503; encryption activity stops spreading.
5. **Do not** rely on rate limits alone — ransomware requires isolation first, not `set_rate_limit`.

### Example remediation payload (mesh)
```json
{
  "scenario": "ransomware",
  "target_port": 8003,
  "rationale": "Ransomware markers observed — isolate node and rotate JWT",
  "actions": [
    {
      "action": "isolate",
      "ips": [],
      "urls": [],
      "reason": "EDR-ISO-01 ransomware containment"
    },
    {
      "action": "rotate_jwt",
      "ips": [],
      "urls": [],
      "reason": "Credential/session compromise risk"
    }
  ]
}
```

## Investigation Steps
1. Determine initial access vector: phishing, RDP brute force, vulnerable public service, or supply-chain.
2. Timeline lateral movement using Windows Event 4624/4648, RDP logs, and EDR process graphs.
3. Identify deleted shadow copies and backup integrity status with Backup Ops.
4. Attribute ransomware family using note text, extension, and sandbox detonation.
5. Cross-reference CVE intelligence for any exploited public-facing service.

## Eradication & Recovery
1. Rebuild compromised hosts from known-good golden images; do not trust “decryptors” unless validated by CIRT malware analysts.
2. Rotate all privileged credentials and service account secrets.
3. Restore data from immutable / offline backups after integrity verification.
4. Reintroduce systems to production in waves with enhanced monitoring (`lift-isolation` / `online` only after clean rebuild).
5. Maintain C2 blocks for a minimum of 90 days.

## Escalation Criteria
- Encryption of domain controllers or backup servers → Critical / Executive notification
- Evidence of data exfiltration before encryption → engage Legal & Privacy (extortion risk)
- OT / life-safety systems impacted → activate Business Continuity Plan

## Communication & Legal
Do not negotiate ransom without Legal and Executive approval. Use template COMM-RANSOM-01 for internal status updates only.

## Evidence Retention
Retain EDR timelines, ransom notes, mesh remediation responses (`isolate`, `rotate_jwt`), forensic images, and backup integrity reports for 365 days or per legal hold.
