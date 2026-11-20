# SOP-IR-001: Phishing Incident Response Playbook

**Classification:** Internal  
**Owner:** SOC Tier 2  
**Last Updated:** 2026-01-15  
**Severity Mapping:** Low–Critical depending on credential compromise and lateral movement  

## Purpose
Provide step-by-step containment and eradication procedures when a phishing email, malicious link, or credential-harvesting page is detected.

## Detection Triggers
- User-reported suspicious email
- Email gateway quarantine / URL rewrite hits
- Identity provider impossible-travel or MFA fatigue alerts linked to a phish
- EDR detection of payload dropped from email attachment

## Immediate Triage (0–15 minutes)
1. **Confirm the alert** — Open the reported message in a sandbox viewer; do not open attachments on analyst workstations.
2. **Extract Indicators of Compromise (IoCs)** — Capture sender address, reply-to, subject, message-ID, URLs, attachment hashes (SHA256), and any credential-harvest domains.
3. **Classify attack type** — Credential harvesting, malware delivery, BEC (business email compromise), or spear-phishing.
4. **Identify impacted users** — Search mail logs for recipients who received the same message-ID or identical subject/sender within the last 72 hours.

## Containment Checklist
1. **Quarantine the message** across the enterprise mail system using the message-ID or exact subject+sender pair (cite mail gateway policy MG-PHISH-03).
2. **Block malicious URLs/domains** at the secure web gateway and DNS firewall (policy NET-URL-BLOCK-01).
3. **Reset credentials** for any user who clicked the link or submitted credentials; force MFA re-enrollment if MFA tokens may be compromised (IAM-RESET-02).
4. **Revoke active sessions** for affected identities in the IdP (Okta/Azure AD) immediately.
5. **Disable forwarding rules** created by attackers on compromised mailboxes.
6. **Isolate endpoints** that executed attachments via EDR network isolation (EDR-ISO-01).

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
Retain original .eml, IoC list, mail search results, IdP session revoke logs, and EDR isolation tickets for 365 days.
