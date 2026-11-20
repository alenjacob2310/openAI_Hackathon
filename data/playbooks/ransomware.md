# SOP-IR-002: Ransomware Incident Response Playbook

**Classification:** Internal – Restricted  
**Owner:** CIRT / SOC Tier 3  
**Last Updated:** 2026-02-01  
**Severity Mapping:** High–Critical  

## Purpose
Define rapid containment, evidence preservation, and recovery steps when ransomware encryption, ransom notes, or known ransomware TTPs are observed.

## Detection Triggers
- EDR ransomware behavior rules (mass file rename/encrypt)
- Canary file modifications
- Shadow copy deletion events (vssadmin / wbadmin)
- User reports of .locked / .encrypted files or ransom notes
- Threat intel match on known ransomware C2 domains

## Immediate Triage (0–10 minutes)
1. **Declare a ransomware event** — Notify CIRT Lead and Incident Commander; open a Priority-1 bridge.
2. **Do not power off hosts** unless directed; prefer network isolation to preserve volatile evidence.
3. **Identify patient zero and blast radius** — List hosts with encryption activity in the last 2 hours from EDR.
4. **Capture IoCs** — Ransom note hashes, encrypted file extensions, C2 IPs/domains, attacker email/Tor payment address, ransomware family name if identifiable.

## Containment Checklist
1. **Network-isolate all actively encrypting hosts** via EDR (EDR-ISO-01); if EDR fails, disable switch ports (NET-PORT-KILL-02).
2. **Disable SMB / remote admin shares** for affected VLANs temporarily (NET-SMB-LOCK-01).
3. **Block identified C2 domains/IPs** at perimeter firewall and DNS (NET-IOC-BLOCK-01).
4. **Disable compromised domain accounts** used for lateral movement; reset KRBTGT if Golden Ticket is suspected (IAM-AD-EMERGENCY-04).
5. **Pause non-essential scheduled backups** only if backup infrastructure is under attack; otherwise protect backup consoles with MFA lockdown.
6. **Preserve forensic images** of 2–3 representative hosts before reimaging (FOR-ACQ-01).

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
4. Reintroduce systems to production in waves with enhanced monitoring.
5. Maintain C2 blocks for a minimum of 90 days.

## Escalation Criteria
- Encryption of domain controllers or backup servers → Critical / Executive notification
- Evidence of data exfiltration before encryption → engage Legal & Privacy (extortion risk)
- OT / life-safety systems impacted → activate Business Continuity Plan

## Communication & Legal
Do not negotiate ransom without Legal and Executive approval. Use template COMM-RANSOM-01 for internal status updates only.
