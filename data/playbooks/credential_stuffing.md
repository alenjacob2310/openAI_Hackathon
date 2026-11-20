# SOP-IR-003: Credential Stuffing Incident Response Playbook

**Classification:** Internal  
**Owner:** SOC Tier 2 / Identity Security  
**Last Updated:** 2026-01-20  
**Severity Mapping:** Medium–High  

## Purpose
Contain automated login attacks that reuse breached username/password pairs against customer or employee authentication endpoints.

## Detection Triggers
- WAF / bot-management spikes in failed logins from distributed IPs
- IdP risk engine: impossible travel + high failure rate for many accounts
- Credential stuffing signature on `/login` or token endpoints
- Dark-web combo-list mentions of our domains (threat intel)

## Immediate Triage (0–20 minutes)
1. **Confirm stuffing vs. brute force** — High volume of unique usernames with 1–2 attempts each indicates stuffing; repeated attempts on few accounts indicates brute force.
2. **Extract IoCs** — Source IP ranges, User-Agent clusters, JA3/JA4 TLS fingerprints, targeted endpoints, ASN/geolocation patterns, and sample usernames (hashed for privacy).
3. **Measure impact** — Count successful authentications during the attack window; flag privileged or VIP accounts first.
4. **Classify severity** — Medium if mostly failures; High if >50 successful logins or any admin success.

## Containment Checklist
1. **Enable aggressive bot challenges** (CAPTCHA / JS challenge) on login endpoints via WAF policy WAF-BOT-CS-01.
2. **Block or rate-limit attacking IP ranges / ASNs** at WAF and CDN edge (WAF-IP-RATE-02).
3. **Force step-up MFA** for all successful logins from new devices during the attack window (IAM-STEPUP-01).
4. **Invalidate sessions** for accounts that authenticated successfully during the stuffing window (IAM-SESSION-KILL-03).
5. **Temporarily enforce password reset** for successfully stuffed accounts; prioritize admins (IAM-RESET-02).
6. **Disable legacy auth protocols** (IMAP/POP/basic auth) if they are being abused (IAM-LEGACY-OFF-01).

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
Export WAF logs, IdP authentication logs, blocked IP lists, and account impact CSV for 180 days.
