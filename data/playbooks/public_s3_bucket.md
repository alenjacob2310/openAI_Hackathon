# SOP-IR-005: Public S3 Bucket Exposure Playbook

**Classification:** Internal  
**Owner:** Cloud Security / SOC Tier 2  
**Last Updated:** 2026-01-28  
**Severity Mapping:** Medium–Critical based on data sensitivity  

## Purpose
Rapidly contain and remediate Amazon S3 (or equivalent object storage) buckets that are unintentionally public or overly permissive, preventing data leakage.

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

## Containment Checklist
1. **Enable S3 Block Public Access** at the bucket and account level immediately (CLOUD-S3-BPA-01).
2. **Remove public ACLs and wildcard principals** (`*` / `AllUsers`) from bucket policy (CLOUD-S3-POLICY-LOCK-01).
3. **Rotate any secrets** found in exposed objects (API keys, DB passwords, certificates) (IAM-SECRET-ROTATE-01).
4. **Invalidate CDN caches** if the bucket was fronted by CloudFront and sensitive objects may be cached (CDN-INVALIDATE-01).
5. **Restrict bucket policy** to least-privilege IAM roles and known VPC endpoints.
6. **Snapshot access logs** and freeze the bucket (object lock / legal hold) if regulated data may have been exfiltrated (FOR-CLOUD-HOLD-01).

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
Retain CloudTrail exports, bucket policy versions, access logs, and object inventory for 365 days or per legal hold.
