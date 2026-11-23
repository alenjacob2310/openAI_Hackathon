# SOP-IR-003: Credential Stuffing Incident Response Playbook

**Classification:** Internal  
**Owner:** SOC Tier 2 / Identity Security  
**Last Updated:** 2026-03-20  
**Severity Mapping:** Medium–High  

## Purpose
Contain automated login attacks that reuse breached username/password pairs against customer or employee authentication endpoints. Define mesh detection metrics and remediations the monitoring agent can execute.

## Detection Metrics & Thresholds
| Metric | Source | Threshold / condition |
|---|---|---|
| `auth_failures_in_window` | Mesh `/metrics` (60s window) | ≥ **20** failed logins |
| Unique usernames in failures | Auth failure buffer | Many distinct users, **1–2 tries each** (stuffing vs brute force) |
| Source IP / ASN clustering | Mesh auth + WAF | Repeated failures from same IP, proxy pool, or ASN |
| Open `credential_stuffing` incidents | Mesh open incidents | Raised when failure threshold is crossed on `:8001`–`:8003` |
| Successful logins in attack window | IdP / mesh auth | Medium if mostly failures; **High** if >50 successes or any admin success |
| WAF / bot-management | Enterprise edge | Spike in failed logins from distributed IPs |

**Detect when:** `auth_failures_in_window ≥ 20` in 60 seconds (many users, few tries each) **OR** an open `credential_stuffing` incident exists.

## Detection Triggers
- WAF / bot-management spikes in failed logins from distributed IPs
- IdP risk engine: impossible travel + high failure rate for many accounts
- Credential stuffing signature on `/login` or `/auth/token` endpoints
- Mesh auth-failure flood signal (`STUFFING_FAIL_THRESHOLD = 20`)
- Dark-web combo-list mentions of our domains (threat intel)

## Immediate Triage (0–20 minutes)
1. **Confirm stuffing vs. brute force** — High volume of unique usernames with 1–2 attempts each indicates stuffing; repeated attempts on few accounts indicates brute force.
2. **Extract IoCs** — Source IP ranges, User-Agent clusters, JA3/JA4 TLS fingerprints, targeted endpoints, ASN/geolocation patterns, and sample usernames (hashed for privacy).
3. **Measure impact** — Count successful authentications during the attack window; flag privileged or VIP accounts first.
4. **Classify severity** — Medium if mostly failures; High if >50 successful logins or any admin success.
5. **Identify target node** — Prefer the mesh port with the highest `auth_failures_in_window`.

## Containment Checklist
1. **Enable aggressive bot challenges** (CAPTCHA / JS challenge) on login endpoints via WAF policy WAF-BOT-CS-01.
2. **Block or rate-limit attacking IP ranges / ASNs** at WAF, CDN, and mesh — action: `block_ip` (WAF-IP-RATE-02).
3. **Force step-up MFA** for all successful logins from new devices during the attack window (IAM-STEPUP-01).
4. **Invalidate sessions / rotate JWT** for accounts that authenticated successfully during the stuffing window — action: `rotate_jwt` (IAM-SESSION-KILL-03).
5. **Temporarily enforce password reset** for successfully stuffed accounts; prioritize admins (IAM-RESET-02).
6. **Disable legacy auth protocols** (IMAP/POP/basic auth) if they are being abused (IAM-LEGACY-OFF-01).

## Remediations (execute on target mesh node)
Use these actions in order for an active credential-stuffing incident.

| Priority | Action | Parameters | Policy ID | When to use |
|---|---|---|---|---|
| 1 | `block_ip` | `ips`: attacker / proxy source IPs | WAF-IP-RATE-02 | Confirmed stuffing sources |
| 2 | `rotate_jwt` | (invalidate sessions / tokens) | IAM-STEPUP-01 / IAM-SESSION-KILL-03 | Always after successful or suspected stuffing |
| 3 | WAF bot challenge + step-up MFA | login endpoints | WAF-BOT-CS-01 / IAM-STEPUP-01 | Parallel enterprise hardening |
| 4 | `set_rate_limit` | `rate_limit_rps`: 10 on auth plane if needed | WAF-IP-RATE-02 | Optional if flood continues after IP blocks |

### Standard remediation sequence
1. **Block attacker source IPs** — Execute `block_ip` with IoC IPs from detection (`attacker_ips`). Reason: `Credential stuffing source block (WAF-IP-RATE-02)`.
2. **Rotate JWT / kill sessions** — Execute `rotate_jwt` so any stuffed successful tokens die. Reason: `Auth plane hardening (IAM-STEPUP-01)`.
3. **Force password reset + MFA** for accounts that authenticated during the window (IAM-RESET-02).
4. **Verify containment** — Confirm `auth_failures_in_window` drops below 20 and blocked IPs receive 403.
5. **Do not isolate the whole node** for stuffing alone — prefer IP block + JWT rotation unless the host is compromised.

### Example remediation payload (mesh)
```json
{
  "scenario": "credential_stuffing",
  "target_port": 8001,
  "rationale": "Auth failure flood ≥20/60s — block sources and rotate JWT",
  "actions": [
    {
      "action": "block_ip",
      "ips": ["203.0.113.50", "198.51.100.12"],
      "urls": [],
      "reason": "Credential stuffing source block (WAF-IP-RATE-02)"
    },
    {
      "action": "rotate_jwt",
      "ips": [],
      "urls": [],
      "reason": "Auth plane hardening / IAM-STEPUP-01"
    }
  ]
}
```

## Investigation Steps
1. Correlate successful logins with subsequent sensitive actions (password change, MFA disable, data export).
2. Identify whether attackers used residential proxies, cloud VPS, or botnet IPs.
3. Check if leaked credentials match known breach dumps for our email domains.
4. Review API tokens issued during the window.
5. Map attack to MITRE ATT&CK T1110.004 (Credential Stuffing).

## Eradication & Recovery
1. Keep elevated bot protections for 14 days post-incident.
2. Notify affected users using template COMM-CREDSTUFF-01; require password change.
3. Add stolen-password detection (haveibeenpwned-style check) if not already enabled.
4. Tune detection thresholds with Identity Security to reduce false positives.

## Escalation Criteria
- Admin / break-glass account compromise → Critical
- Customer PII accessed after successful stuffing → Privacy & Legal notification
- Sustained attack >1 hour despite blocks → escalate to Network & CDN vendors

## Evidence Retention
Export WAF logs, IdP authentication logs, mesh `/metrics` snapshots, blocked IP lists, remediation API responses, and account impact CSV for 180 days.
