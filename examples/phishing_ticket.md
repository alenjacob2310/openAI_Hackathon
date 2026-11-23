> Offline example from bundled sample files; no live OpenAI retrieval is claimed.

# Incident Ticket

## Summary
Alert ALT-2026-0312-0041 (High): classified as Phishing. Rule: Phishing Credential Harvest with Successful Click. IoCs: ips=185.220.101.45, 10.20.55.18; domains=evil-secure-login.net, mail.evil-secure-login.net, j.martinez; urls=https://evil-secure-login.net/owa/auth, https://evil-secure-login.net/static/login.js; emails=it-support@evil-secure-login.net, phish.88219@mail.evil-secure-login.net, helpdesk@evil-secure-login.net. Notes: User reported email after clicking. Possible credential harvest.

Alert ID: ALT-2026-0312-0041

## Timeline
- 2026-03-12T14:18:44Z — observed field `alert.raw_event.click_telemetry.click_time`
- 2026-03-12T14:22:07Z — observed field `alert.timestamp`

## Root Cause (Hypothesized)
Unconfirmed. Attack classification is a triage hypothesis, not a verified root cause. Investigate the evidence in the cited SOP.

## Key IoCs
```json
{
  "ips": [
    "185.220.101.45",
    "10.20.55.18"
  ],
  "domains": [
    "evil-secure-login.net",
    "mail.evil-secure-login.net",
    "j.martinez",
    "a.chen"
  ],
  "urls": [
    "https://evil-secure-login.net/owa/auth",
    "https://evil-secure-login.net/static/login.js"
  ],
  "emails": [
    "it-support@evil-secure-login.net",
    "phish.88219@mail.evil-secure-login.net",
    "helpdesk@evil-secure-login.net",
    "j.martinez@acme-corp.com",
    "a.chen@acme-corp.com"
  ]
}
```

## Containment Actions Taken
No completed actions have been recorded by this assistant.

## Containment Actions Recommended
## Attack Classification
Phishing

All actions below are recommendations; execution is not recorded by this assistant. Preserve SOP conditions before acting.

## Key IoCs
```json
{
  "ips": [
    "185.220.101.45",
    "10.20.55.18"
  ],
  "domains": [
    "evil-secure-login.net",
    "mail.evil-secure-login.net",
    "j.martinez",
    "a.chen"
  ],
  "urls": [
    "https://evil-secure-login.net/owa/auth",
    "https://evil-secure-login.net/static/login.js"
  ],
  "emails": [
    "it-support@evil-secure-login.net",
    "phish.88219@mail.evil-secure-login.net",
    "helpdesk@evil-secure-login.net",
    "j.martinez@acme-corp.com",
    "a.chen@acme-corp.com"
  ]
}
```
## Immediate Triage (0–15 minutes)

- [ ] **Confirm the alert** — Open the reported message in a sandbox viewer; do not open attachments on analyst workstations. [1]

- [ ] **Extract Indicators of Compromise (IoCs)** — Capture sender address, reply-to, subject, message-ID, URLs, attachment hashes (SHA256), and any credential-harvest domains. [2]

- [ ] **Classify attack type** — Credential harvesting, malware delivery, BEC (business email compromise), or spear-phishing. [3]

- [ ] **Identify impacted users** — Search mail logs for recipients who received the same message-ID or identical subject/sender within the last 72 hours. [4]

- [ ] **Check mesh telemetry** — Note `phishing_hits`, malicious URLs, and target port from `/metrics`. [5]

## Containment Checklist

- [ ] **Quarantine the message** across the enterprise mail system using the message-ID or exact subject+sender pair (MG-PHISH-03). [6]

- [ ] **Block malicious URLs/domains** at the secure web gateway and DNS firewall (NET-URL-BLOCK-01) — mesh action: `quarantine_url`. [7]

- [ ] **Rotate JWT / revoke sessions** when credential harvest is suspected (IAM-RESET-02) — mesh action: `rotate_jwt`. [8]

- [ ] **Reset credentials** for any user who clicked the link or submitted credentials; force MFA re-enrollment. [9]

- [ ] **Disable forwarding rules** created by attackers on compromised mailboxes. [10]

- [ ] **Isolate endpoints** that executed attachments via EDR network isolation (EDR-ISO-01). [11]

## Escalation Criteria

- [ ] Executive or VIP mailbox targeted → escalate to CIRT Lead [12]

- [ ] Evidence of successful credential use against production systems → raise severity to Critical [13]

- [ ] Confirmed BEC wire-fraud attempt → notify Fraud & Legal immediately [14]

## Related CVE Intelligence
Mock feed; verify applicability and current vendor guidance. A CVE mentioned in an alert is not proof of exploitation.

No CVE explicitly identified in this alert; no vulnerability is inferred from attack category alone.

## Related CVEs
None explicitly identified in the alert.
Mock intelligence; applicability is unconfirmed.

## Severity & Priority Recommendation
Reported severity: High. Priority requires analyst assessment of impact and scope.

## Next Steps / Owners
SOC analyst: validate classification, assign an incident owner, execute applicable approved steps, and record outcomes and timestamps.

## Sources
[1] SOP-IR-001 · phishing.md:31 · Immediate Triage (0–15 minutes) · step 1
[2] SOP-IR-001 · phishing.md:32 · Immediate Triage (0–15 minutes) · step 2
[3] SOP-IR-001 · phishing.md:33 · Immediate Triage (0–15 minutes) · step 3
[4] SOP-IR-001 · phishing.md:34 · Immediate Triage (0–15 minutes) · step 4
[5] SOP-IR-001 · phishing.md:35 · Immediate Triage (0–15 minutes) · step 5
[6] SOP-IR-001 · phishing.md:38 · Containment Checklist · step 1
[7] SOP-IR-001 · phishing.md:39 · Containment Checklist · step 2
[8] SOP-IR-001 · phishing.md:40 · Containment Checklist · step 3
[9] SOP-IR-001 · phishing.md:41 · Containment Checklist · step 4
[10] SOP-IR-001 · phishing.md:42 · Containment Checklist · step 5
[11] SOP-IR-001 · phishing.md:43 · Containment Checklist · step 6
[12] SOP-IR-001 · phishing.md:99 · Escalation Criteria · step 99
[13] SOP-IR-001 · phishing.md:100 · Escalation Criteria · step 100
[14] SOP-IR-001 · phishing.md:101 · Escalation Criteria · step 101
