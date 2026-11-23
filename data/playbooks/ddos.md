# SOP-IR-004: DDoS Incident Response Playbook

**Classification:** Internal  
**Owner:** SOC Tier 2 / Network Security  
**Last Updated:** 2026-03-20  
**Severity Mapping:** Medium–Critical based on service impact  

## Purpose
Restore availability of customer-facing and internal services under volumetric, protocol, or application-layer denial-of-service attacks. Provide concrete remediation actions the monitoring agent and on-call responders can execute on the mesh.

## Detection Triggers
- CDN / scrubbing center anomaly alerts (Gbps / Mpps spikes)
- Synthetic monitoring failures or elevated latency/error rates
- Firewall connection-table exhaustion
- Upstream ISP blackhole / flowspec notifications
- WAF Layer-7 request flood on specific URLs
- Mesh node `rps_estimate` ≥ 25 **or** ≥ 30 requests in a 60-second sliding window
- Open `ddos` incident signals on nodes `:8001` / `:8002` / `:8003`

## Immediate Triage (0–15 minutes)
1. **Confirm outage scope** — Distinguish DDoS from application bug, bad deploy, or upstream ISP failure using NOC dashboards and mesh `/metrics`.
2. **Classify attack type** — Volumetric (L3/L4), protocol (SYN/ACK/UDP amplification), or application (HTTP GET/POST floods).
3. **Extract IoCs / attack metadata** — Source IPs/ASNs, top source countries, target ports/hostnames, protocols, request URIs, User-Agents, peak RPS/PPS/bandwidth.
4. **Declare severity** — Critical if revenue-impacting production APIs or auth services are unavailable.
5. **Identify primary target node** — Prefer the mesh node with the highest `rps_estimate` and open DDoS incidents.

## Containment Checklist
1. **Engage CDN / DDoS scrubbing provider** and enable “Under Attack” / always-on scrubbing mode (NET-DDOS-SCRUB-01).
2. **Block attacker source IPs** at the edge / mesh node using `block_ip` for confirmed flood sources (NET-IP-BLOCK-01).
3. **Apply rate limits** on the target service — set emergency rate limit to **10 rps** (or lower if still saturated) via `set_rate_limit` (CDN-RATE-02 / NET-DDOS-SCRUB-01).
4. **Apply geo/IP reputation blocks** at CDN edge for abusive ASNs (CDN-RATE-02).
5. **Enable WAF emergency rules** for Layer-7 floods (challenge JS, block empty User-Agents, URI-specific limits) (WAF-L7-EMERGENCY-01).
6. **Protect origin** — Lock origin IP allowlists to CDN only; block direct-to-origin traffic (NET-ORIGIN-LOCK-01).
7. **Blackhole or sinkhole** only as last resort for single-target IPs with ISP approval (NET-RTBH-01).
8. **Scale critical services** horizontally if autoscaling is healthy and attack is partially mitigated.
9. **Isolate the node** (`isolate`) only if the host itself is compromised or acting as a reflector — prefer IP block + rate limit first for pure volumetric floods.

## Remediations (execute on target mesh node)
Use these actions in order for an active DDoS incident. The Agent should map them to `/admin/remediate` calls on the target port.

| Priority | Action | Parameters | Policy ID | When to use |
|---|---|---|---|---|
| 1 | `block_ip` | `ips`: attacker source IPs from detection / NetFlow | NET-IP-BLOCK-01 | Confirmed flood sources or top talkers |
| 2 | `set_rate_limit` | `rate_limit_rps`: **10.0** (tighten to 5.0 if needed) | NET-DDOS-SCRUB-01 / CDN-RATE-02 | Target node still above RPS threshold after blocks |
| 3 | `isolate` | (node-level) | EDR-ISO-01 / NET-ORIGIN-LOCK-01 | Only if node integrity is suspect or attack is amplified from the host |
| 4 | CDN scrubbing / WAF emergency mode | vendor console | NET-DDOS-SCRUB-01 / WAF-L7-EMERGENCY-01 | Parallel to mesh actions for internet-facing fronts |

### Standard remediation sequence
1. **Block attacker source IPs** — Execute `block_ip` with all IoC IPs from the detection (`attacker_ips`, NetFlow top talkers). Reason: `DDoS source containment (NET-IP-BLOCK-01)`.
2. **Rate-limit the target service** — Execute `set_rate_limit` with `rate_limit_rps=10` on the impacted node. Reason: `Emergency scrub / NET-DDOS-SCRUB-01`.
3. **Verify containment** — Confirm `rps_estimate` drops below threshold, open DDoS incidents clear or mark remediated, and legitimate health checks still succeed.
4. **Escalate scrubbing** — If RPS remains elevated after block + rate limit, enable CDN “Under Attack” mode and WAF L7 emergency rules.
5. **Do not rotate JWT** for pure DDoS unless there is concurrent credential abuse — JWT rotation is for phishing / credential stuffing / ransomware paths.

### Example remediation payload (mesh)
```json
{
  "scenario": "ddos",
  "target_port": 8001,
  "rationale": "Volumetric/application flood — block sources then throttle target",
  "actions": [
    {
      "action": "block_ip",
      "ips": ["203.0.113.10", "198.51.100.44"],
      "urls": [],
      "reason": "DDoS source containment (NET-IP-BLOCK-01)"
    },
    {
      "action": "set_rate_limit",
      "ips": [],
      "urls": [],
      "rate_limit_rps": 10.0,
      "reason": "Emergency rate limit (NET-DDOS-SCRUB-01)"
    }
  ]
}
```

## Investigation Steps
1. Capture NetFlow/sFlow samples and CDN analytics for post-incident analysis.
2. Identify whether attack coincides with ransom email, protest, or competitor events.
3. Check for concurrent intrusion attempts hidden inside the noise.
4. Validate that monitoring/alerting thresholds did not delay detection.
5. Map to MITRE ATT&CK T1498 (Network Denial of Service) / T1499 (Endpoint DoS) as applicable.

## Eradication & Recovery
1. Gradually relax emergency rules once traffic normalizes for 60+ minutes.
2. Keep elevated scrubbing for 48 hours after attack ends.
3. Remove temporary IP blocks that are no longer active attackers after review.
4. Restore `rate_limit_rps` to steady-state values only after sustained normal RPS.
5. Patch any application endpoints that were specifically targeted and inexpensive to flood.
6. Update runbooks with new signatures and ASN blocklists.

## Escalation Criteria
- Attack exceeds on-contract scrubbing capacity → executive + vendor emergency bridge
- Auth / payments down >15 minutes → Critical business incident
- Attack paired with intrusion or ransomware → dual-track CIRT response
- Mesh remediation (`block_ip` + `set_rate_limit`) fails to reduce RPS within 5 minutes → escalate to Network Security on-call

## Communications
Use COMM-DDOS-01 for status page updates. Do not disclose scrubbing capacity or origin IPs publicly.

## Evidence Retention
Retain NetFlow samples, CDN analytics exports, mesh `/metrics` snapshots, remediation API responses (`block_ip`, `set_rate_limit`), and incident timeline for 365 days.
