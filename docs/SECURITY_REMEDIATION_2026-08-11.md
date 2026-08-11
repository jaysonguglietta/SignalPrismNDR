# Security Remediation Record - 2026-08-11

## Executive Summary

This change set closes the confirmed authorization, identity, queue-integrity, data-retention, denial-of-service, and production-default findings from the August 2026 adversarial review. No remote-code-execution or direct authentication-bypass path was confirmed. The most important risk was horizontal disclosure inside a tenant when a principal was restricted to selected managed sources: downstream analytics previously enforced tenant boundaries but did not consistently preserve and enforce source provenance.

Repository remediation is complete and covered by automated tests. Production acceptance still requires a staging deployment, IdP/SCIM exercise, AWS policy review, restore drill, and live penetration test.

## Closed Findings

| Finding | Severity | Resolution |
| --- | --- | --- |
| Source ownership stopped at ingest | High | Source provenance and authorization now cover telemetry, analytics, hunts, cases, evidence, workspaces, packet data, response, AI, jobs, stream deliveries, and exports. Mixed or unscoped records fail closed for restricted principals. |
| Mutable actor labels used for separation of duties | High | Governance records store normalized issuer/subject identity keys. Legacy labels remain display-only. Requesters, approvers, verifiers, rule authors, scanners, and packet creators are compared using stable identity. |
| Tenant directory could fail open or match mutable email | High | Production OIDC requires active directory membership bound to issuer/subject. Email matching is an explicit non-production migration option only. |
| Queue worker trusted embedded job and principal | Medium | Queue contract v2 carries only tenant, job, and run identifiers. Workers reload current job/source state and create their own system principal. |
| Response verification was analyst-attested | Medium | Verification is a step-up admin action, must be independent from requester and approver, and can be restricted to configured verifier subjects. |
| Session authorization could remain stale | Medium | Session requests reapply current directory status, roles, permissions, and source scope. Production OIDC sessions expire after 15 minutes by default. |
| Expensive endpoints shared a flat request limit | Medium | Mutation cost is weighted by endpoint, daily tenant telemetry quotas are atomic in DynamoDB, normalized records receive TTL, and gzip decompression is asynchronous and output-bounded. |
| Export approval payloads were stored in DynamoDB | Medium | Production payloads use KMS-encrypted short-lived S3 objects. DynamoDB holds bounded metadata and hashes. Consumption verifies SHA-256, is one-time, and deletes the object. |
| Request logs included secret-bearing query strings | Medium | Structured access and error logs record pathname only. OIDC codes, state, packet grant IDs, and other query data are excluded. |
| Agent evaluation accepted client-authored runs | Medium | Evaluation requires a persisted, authorized AI run ID and records the evaluated run SHA-256 digest. |
| Production could start with local persistence or mutable audit | Medium | Production startup requires DynamoDB, table configuration, S3 audit storage, and fail-closed immutable audit writes. |
| Enterprise artifacts allowed identifier overwrite | Low | Artifacts have immutable type and creator, stable creator identity, revision tokens, conditional create/update, and owner-or-admin update authorization. |

## Trust-Boundary Changes

1. Tenant isolation remains the outer boundary; managed-source authorization is now the inner data boundary.
2. OIDC issuer/subject is the authorization identity. Email and name are presentation attributes.
3. SQS is an untrusted transport. Workers execute only authoritative state loaded from DynamoDB/local storage.
4. Browser and API clients may request privileged work but cannot attest approval, verification, scan, or evaluation evidence for another trust role.
5. DynamoDB stores approval state; S3 stores short-lived approval content; immutable S3 stores audit and retained evidence.

## Validation Evidence

- `npm run check`: passed all syntax, model, telemetry, stitching, heatmap, reporting, platform, advanced-operations, API integration, UI-flow, and 23 enterprise-readiness checks.
- Integration coverage proves assigned-source isolation, empty-by-default service accounts, cross-tenant denial, stable dual-control behavior, persisted-run-only AI evaluation, weighted rate limiting, request-size limits, and production startup failures.
- `npm audit --json`: no known dependency vulnerabilities at review time.
- Terraform formatting is enforced. Validate/plan still requires Terraform `>= 1.6`, provider access, and target-account variables.

## Deployment Actions

1. Provision every OIDC user with exact issuer and subject before enabling `NDR_TENANT_DIRECTORY_REQUIRED=true`.
2. Set independent `response_verifier_subjects` before enabling response execution.
3. Confirm the evidence-staging bucket KMS key, three-day lifecycle, CloudTrail data events, and delete permissions.
4. Set daily telemetry quota and retention values from measured ingest volume and cost budgets.
5. Run source-scope migration checks. Existing derived records without source provenance are intentionally invisible to restricted users and should be regenerated from retained evidence.
6. Exercise role disablement, source reassignment, session expiry, queue redrive, export approval expiry, and response rollback in staging.

## Residual Risk

- Identity changes at an upstream IdP are not visible until directory synchronization or the bounded OIDC session expires. Configure frequent SCIM sync and IdP session revocation where supported.
- Local JSON mode remains a trusted single-node development mode and is rejected by production hardening.
- The staging-bucket lifecycle is a recovery control for abandoned approval objects; immediate deletion is best effort and must be monitored through S3/CloudTrail.
- Existing records created before source provenance was required may need migration or deterministic recomputation.
- A live cloud configuration review and penetration test are still required before high-risk production exposure.
