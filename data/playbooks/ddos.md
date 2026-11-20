# SOP-IR-004: DDoS Incident Response Playbook

**Classification:** Internal  
**Owner:** SOC Tier 2 / Network Security  
**Last Updated:** 2026-02-10  
**Severity Mapping:** Medium–Critical based on service impact  

## Purpose
Restore availability of customer-facing and internal services under volumetric, protocol, or application-layer denial-of-service attacks.

## Detection Triggers
- CDN / scrubbing center anomaly alerts (Gbps / Mpps spikes)
- Synthetic monitoring failures or elevated latency/error rates
- Firewall connection-table exhaustion
- Upstream ISP blackhole / flowspec notifications
- WAF Layer-7 request flood on specific URLs

## Immediate Triage (0–15 minutes)
1. **Confirm outage scope** — Distinguish DDoS from application bug, bad deploy, or upstream ISP failure using NOC dashboards.
2. **Classify attack type** — Volumetric (L3/L4), protocol (SYN/ACK/UDP amplification), or application (HTTP GET/POST floods).
3. **Extract IoCs / attack metadata** — Source ASNs, top source countries, target IPs/hostnames, protocols/ports, request URIs, User-Agents, and peak bandwidth/PPS.
4. **Declare severity** — Critical if revenue-impacting production APIs or auth services are unavailable.

## Containment Checklist
1. **Engage CDN / DDoS scrubbing provider** and enable “Under Attack” / always-on scrubbing mode (NET-DDOS-SCRUB-01).
2. **Apply rate limits and geo/IP reputation blocks** at CDN edge for abusive ASNs (CDN-RATE-02).
3. **Enable WAF emergency rules** for Layer-7 floods (challenge JS, block empty User-Agents, URI-specific limits) (WAF-L7-EMERGENCY-01).
4. **Blackhole or sinkhole** only as last resort for single-target IPs with ISP approval (NET-RTBH-01).
5. **Scale critical services** horizontally if autoscaling is healthy and attack is partially mitigated.
6. **Protect origin** — Lock origin IP allowlists to CDN only; block direct-to-origin traffic (NET-ORIGIN-LOCK-01).

## Investigation Steps
1. Capture NetFlow/sFlow samples and CDN analytics for post-incident analysis.
2. Identify whether attack coincides with ransom email, protest, or competitor events.
3. Check for concurrent intrusion attempts hidden inside the noise.
4. Validate that monitoring/alerting thresholds did not delay detection.
5. Map to MITRE ATT&CK T1498 (Network Denial of Service) / T1499 (Endpoint DoS) as applicable.

## Eradication & Recovery
1. Gradually relax emergency rules once traffic normalizes for 60+ minutes.
2. Keep elevated scrubbing for 48 hours after attack ends.
3. Patch any application endpoints that were specifically targeted and inexpensive to flood.
4. Update runbooks with new signatures and ASN blocklists.

## Escalation Criteria
- Attack exceeds on-contract scrubbing capacity → executive + vendor emergency bridge
- Auth / payments down >15 minutes → Critical business incident
- Attack paired with intrusion or ransomware → dual-track CIRT response

## Communications
Use COMM-DDOS-01 for status page updates. Do not disclose scrubbing capacity or origin IPs publicly.
