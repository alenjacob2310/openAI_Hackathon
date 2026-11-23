# SOP-IR-005: Public S3 Bucket Exposure Playbook

**Classification:** Internal  
**Owner:** Cloud Security / SOC Tier 2  
**Last Updated:** 2026-03-20  
**Severity Mapping:** Medium–Critical based on data sensitivity  

## Purpose
Rapidly contain and remediate Amazon S3 (or equivalent object storage) buckets that are unintentionally public or overly permissive, preventing data leakage. Define detection metrics/thresholds and step-by-step remediations for cloud responders (this scenario is cloud-control-plane driven; mesh `/admin/remediate` actions apply only if related JWT/IP abuse is observed on API nodes).

## Detection Metrics & Thresholds
| Metric | Source | Threshold / condition |
|---|---|---|
| Public ACL / policy grant | CSPM / Config | Bucket ACL or policy grants `AllUsers` or `AuthenticatedUsers` → **detect immediately** |
| Public Access Block | Account / bucket setting | Block Public Access **disabled** on bucket or account → **detect immediately** |
| External `GetObject` volume | CloudTrail / access logs | ≥ **100** external GETs in 15 minutes **OR** ≥ **10** unique external ASNs since policy change |
| Sensitive object exposure | DLP / Macie | ≥ **1** PII/secret/credential object publicly readable → **Critical** |
| Policy change events | CloudTrail | `PutBucketPolicy`, `PutBucketAcl`, or `PutPublicAccessBlock` disabling BPA → investigate within 15 minutes |
| Unexpected ASN downloads | Threat intel / CDN | External researcher or scanner ASN pulling object inventory |

**Detect when:** public principal (`*` / `AllUsers`) is present **OR** Public Access Block is off **OR** DLP flags sensitive public objects **OR** external `GetObject` spike exceeds thresholds above.

## Detection Triggers
- CSPM finding: bucket ACL/policy grants `AllUsers` or `AuthenticatedUsers`
- Public access block disabled on account or bucket
- Threat intel / external scan reports of exposed bucket names
- DLP alert on sensitive objects downloaded from public URLs
- CloudTrail `GetObject` spikes from unexpected ASNs

## Immediate Triage (0–15 minutes)
1. **Validate exposure** — Confirm bucket policy, ACLs, and Public Access Block settings in the cloud console / IaC state; do not download entire contents to analyst laptops.
2. **Classify data sensitivity** — Determine if objects contain PII, credentials, source code, backups, or public marketing assets.
3. **Extract IoCs / context** — Bucket name, AWS account ID, region, public URLs, principal that changed the policy, CloudTrail event IDs, and external IPs that accessed objects.
4. **Estimate blast radius** — Use CloudTrail and access logs to count unique external getters since the policy change.
5. **Severity** — Medium for non-sensitive public assets; High/Critical if PII, secrets, or regulated data were readable.

## Containment Checklist
1. **Enable S3 Block Public Access** at the bucket and account level immediately (CLOUD-S3-BPA-01).
2. **Remove public ACLs and wildcard principals** (`*` / `AllUsers`) from bucket policy (CLOUD-S3-POLICY-LOCK-01).
3. **Rotate any secrets** found in exposed objects (API keys, DB passwords, certificates) (IAM-SECRET-ROTATE-01).
4. **Invalidate CDN caches** if the bucket was fronted by CloudFront and sensitive objects may be cached (CDN-INVALIDATE-01).
5. **Restrict bucket policy** to least-privilege IAM roles and known VPC endpoints.
6. **Snapshot access logs** and freeze the bucket (object lock / legal hold) if regulated data may have been exfiltrated (FOR-CLOUD-HOLD-01).

## Remediations (step-by-step)
Execute in order. Cloud APIs are primary; mesh actions are optional follow-ons if API credentials were exposed.

| Priority | Action | Parameters / target | Policy ID | When to use |
|---|---|---|---|---|
| 1 | Enable Block Public Access | Bucket + account | CLOUD-S3-BPA-01 | Always first |
| 2 | Remove public ACL / wildcard policy | Delete `AllUsers` / `*` grants | CLOUD-S3-POLICY-LOCK-01 | Always |
| 3 | Rotate exposed secrets | Keys, DB passwords, certs in objects | IAM-SECRET-ROTATE-01 | If secrets were public |
| 4 | Invalidate CDN cache | CloudFront distribution IDs | CDN-INVALIDATE-01 | If CDN fronted the bucket |
| 5 | Legal hold / object lock | Affected prefixes | FOR-CLOUD-HOLD-01 | Suspected exfiltration / regulated data |
| 6 | Mesh `rotate_jwt` / `block_ip` | API nodes if stolen keys used against mesh | IAM-SECRET-ROTATE-01 | Only if related API abuse observed |

### Standard remediation sequence
1. **Enable Block Public Access** on the bucket and confirm account-level BPA is on (CLOUD-S3-BPA-01).
2. **Lock the policy** — Remove `Principal: "*"` / `AllUsers` / `AuthenticatedUsers` grants; replace with least-privilege roles and VPC endpoints (CLOUD-S3-POLICY-LOCK-01).
3. **Inventory & classify** — List publicly readable object keys; tag PII/secrets; do not bulk-download to analyst workstations.
4. **Rotate secrets** found in exposed objects (IAM-SECRET-ROTATE-01). If cloud access keys were public and used against mesh APIs, execute mesh `rotate_jwt` and `block_ip` for abusing ASNs.
5. **Invalidate CDN caches** for sensitive object paths (CDN-INVALIDATE-01).
6. **Preserve evidence** — Export CloudTrail, access logs, and prior policy versions; apply object lock / legal hold if required (FOR-CLOUD-HOLD-01).
7. **Verify** — CSPM re-scan shows no public ACL/policy; public URL GETs return AccessDenied; BPA remains enabled.

### Example remediation checklist (cloud)
```text
1. aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
2. Remove public ACL grants and rewrite bucket policy without "*" principals
3. Rotate any AKIA*/secrets discovered in objects; revoke old keys
4. Create CloudFront invalidation for exposed object paths
5. Export CloudTrail + access logs; enable object lock / legal hold if PII may have leaked
6. If stolen keys hit mesh APIs: rotate_jwt on impacted nodes; block_ip abusing sources
```

## Investigation Steps
1. Identify who/what changed the bucket policy (human IAM user, CI role, compromised key).
2. Review CloudTrail for `PutBucketPolicy`, `PutBucketAcl`, `PutPublicAccessBlock`, and high-volume `GetObject`.
3. Cross-check exposed object keys against DLP classifications.
4. Determine if this was misconfiguration, malicious insider, or credential compromise.
5. Map to MITRE ATT&CK T1530 (Data from Cloud Storage) if exfiltration is confirmed.

## Eradication & Recovery
1. Remediate IaC templates so the misconfiguration cannot redeploy.
2. Enforce organization SCP denying public S3 policies where business-approved exceptions do not exist.
3. Notify Privacy/Legal if PII or regulated data was publicly accessible (COMM-DATAEXPOSE-01).
4. Re-scan account with CSPM to confirm no sibling exposures.

## Escalation Criteria
- Customer PII / PHI / cardholder data exposed → Critical + Legal/Privacy
- Root cause is compromised CI/CD or cloud keys → invoke credential compromise playbook in parallel
- Media or external researcher disclosure → Communications Lead owns external response

## Evidence Retention
Retain CloudTrail exports, bucket policy versions, access logs, object inventory, and any related mesh remediation responses for 365 days or per legal hold.
