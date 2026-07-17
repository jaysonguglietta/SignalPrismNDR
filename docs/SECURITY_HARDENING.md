# Security Hardening

This document is the production security baseline for SignalPrism NDR. It records the controls implemented after the adversarial review and the deployment conditions that must remain true.

## Trust Boundaries And Assets

Primary assets are tenant flow evidence, source definitions, investigation cases, detection rules, user assignments, export packages, Bedrock context, credentials, sessions, and audit records.

Untrusted inputs include browser uploads, compressed files, pasted JSON/JSONL, API JSON, OIDC tokens, source names/scopes, AWS responses, flow-log fields, AI questions, and evidence content sent to Bedrock. The principal boundaries are browser to API, API to tenant storage, API to AWS services, OIDC provider to session registry, tenant to tenant, analyst to admin approval, and mutable metadata to immutable S3 evidence/audit storage.

## Implemented Controls

### Identity And Sessions

- RS256 OIDC verification requires discovery-issuer equality, token issuer, audience/authorized party, subject, issued-at, expiration, optional not-before/token-use, eligible JWKS signature key, and a tenant claim by default. Unknown key IDs trigger one bounded JWKS refresh.
- Browser cookies contain only an opaque UUID and HMAC. Principal, CSRF, expiration, tenant scope, and revocation state are server-side; sessions remain HttpOnly, SameSite Strict, TTL-backed, and revocable at logout or roster change.
- Production packet access, controlled export approval, and response approval require recent OIDC MFA evidence from `amr`/`acr` and `auth_time`.
- Tenant roster status and role override OIDC claims when a matching user exists. Revoked, disabled, or suspended users are denied.
- API keys use constant-time comparison. Production hardening requires at least 24 characters.
- Test identity injection is rejected in `NODE_ENV=production` and cannot bind beyond loopback.
- Production requires distinct 32+ character session and evidence-attestation keys and secure cookies.

### Authorization And Governance

- Every persisted object uses a tenant partition. DynamoDB keys use `TENANT#<tenant>#<kind>`; browser localStorage and IndexedDB use tenant-plus-subject scopes.
- Analysts cannot rewrite, ingest, schedule, or run jobs for sources owned by another analyst. Client-supplied ownership is ignored for analyst-created sources.
- Custom tenant roles are restrictive permission sets, not additive labels over their base role. Attribute conditions must match the directory identity, and service accounts with an empty source scope receive no source access.
- Tenant identifiers that require normalization include a namespace-bound digest so distinct external tenant names cannot collapse into one storage partition.
- Direct arbitrary AWS ingest is disabled by default; managed-source inventory is the authority for region, bucket, prefix, and log group.
- Non-admin source access defaults to explicit `assigned` mode; an empty assignment denies access. `all` and `group` modes are deliberate directory/admin policy decisions.
- Detection production promotion and retirement are server-admin actions. Production approval requires a passing test, ATT&CK mapping, substantive description, and a separate approver by default.
- Controlled investigation and Security Lake exports create tenant-scoped, expiring approval requests. The requester cannot self-approve by default; approval state changes are atomic, pending queues are bounded, and approvals are one-time. Security Lake consumption must present the approved SHA-256 content hash.
- Final active tenant admins cannot revoke or demote themselves without another active admin.

### Input, File, AI, And Network Safety

- API JSON has a byte limit, requires `application/json`, rejects arrays/malformed input, and returns stable `400`, `413`, or `415` responses.
- Browser files have compressed and decompressed limits. Gzip is streamed with a hard stop. Structured log recursion has depth and message budgets.
- Direct evidence uploads are size- and tenant-quota-bound, checksum/version-bound, written to a versioned quarantine bucket, and cannot enter the immutable vault until an allowlisted scanner submits a fresh signed clean attestation. The copy pins the exact source version and is reverified before completion. Production startup rejects missing staging, scanner subjects, checksum, retention, or scan-attestation enforcement.
- S3/CloudWatch regions, buckets, prefixes, log groups, AWS hosts, ECS credential URIs, returned credential shapes, response sizes, redirects, and request timeouts are validated.
- AWS SigV4 requests only target exact supported AWS service hosts. ECS credentials are limited to link-local or loopback endpoints.
- Bedrock receives a depth-, node-, string-, and total-context-bounded object. System instructions explicitly classify evidence as attacker-controlled data and prohibit following embedded instructions, disclosing secrets, or claiming tool execution.
- Server error responses suppress upstream bodies, credentials, local paths, and internal stack information.
- Public `/api/health` returns only liveness and time. Detailed runtime posture is isolated behind authenticated `/api/status`; readiness and metrics remain admin-only.

### Integrity, Retention, And Availability

- Evidence manifests use SHA-256 over all included records and detections. Server-side evidence artifacts receive a separate HMAC-SHA256 attestation.
- Redacted exports use a random session-scoped HMAC-SHA256 key instead of reversible or low-entropy hashes.
- Raw evidence packages use exclusive local creation with `0600` permissions or S3 Object Lock. Local JSON updates are atomic and serialized; corruption fails closed.
- Managed/direct ingest cannot report success or advance an S3 checkpoint unless required evidence retention succeeds. Valid records surrounding a malformed JSONL line remain available while the failed line is quarantined.
- Event IDs are canonical SHA-256 digests. Detection production promotion requires an immutable, exact-version, non-stale server backtest and an atomic version condition.
- Audit records are tenant-scoped. Production writes each event to Object Lock COMPLIANCE storage and can fail protected mutations closed when immutable audit storage is unavailable.
- Job intervals are finite integers within configured bounds. Per-tenant scheduled-job and active-import quotas are enforced. Production schedules are durable EventBridge Scheduler resources that send a fixed message contract to SQS. DynamoDB conditional run slots prevent multi-replica races; TTL recovers slots after task failure. Production async work uses SQS with bounded URL/region validation, worker-only processing, visibility heartbeats, retries, DLQ, and queue metrics.
- Every response carries `x-request-id` and W3C `traceparent`; structured request/error logs include those identifiers for incident correlation without logging raw identity values.
- CloudTrail, Route 53 DNS, GuardDuty, Zeek, and Suricata payloads normalize into a bounded schema. Correlation findings retain evidence IDs and do not directly execute response.
- Response actions require a separate tenant admin and emit only to a configured EventBridge bus. Events include an idempotency key; analyst requests cannot supply webhooks or AWS roles.
- Detection content requires a trusted Ed25519 signature and SHA-256 rules digest. Admin imports enter test status and cannot overwrite production rules.
- API rate limits apply by client address and authenticated principal, have bounded identity memory, and honor forwarded addresses only when `NDR_TRUST_PROXY=true` behind a trusted proxy.
- Shared DynamoDB deployments use atomic distributed rate windows and daily tenant counters for agent runs, Bedrock calls, and reserved output tokens.
- Continuous delivery uses a tenant outbox created before telemetry persistence. Individual acknowledgements, leases, bounded exponential retries, terminal dead-letter state, and controlled replay prevent partial batch loss.
- Packet evidence is restricted to allowlisted buckets/prefixes, exact object versions, verified checksum/length, and a completed retained upload or trusted capture-sensor identity.

## Production Gate

Do not approve production deployment until all are true:

- `NDR_PRODUCTION_HARDENING=true`, `NODE_ENV=production`, `NDR_SESSION_COOKIE_SECURE=true`.
- OIDC is configured with an HTTPS issuer, exact audience, tenant claim, and reviewed group mappings. Any API key is randomly generated and rotated.
- Session and evidence attestation secrets are separate Secrets Manager values with rotation ownership.
- `NDR_STORE=dynamodb`; PITR, SSE, TTL, `kind-createdAt-index`, and tenant-bounded `tenant-kind-createdAt-index` are enabled.
- `NDR_DDB_GSI_MIGRATION_MODE=dual-read` remains in place until schema-v2 backfill completeness is proven; conditional case/rule transitions have passed race tests.
- `NDR_QUEUE_URL` is configured, API and worker process roles are separate, queue-age/DLQ alarms notify an owned SNS topic, and a DLQ redrive drill has passed.
- `NDR_DETECTION_CONTENT_PUBLIC_KEY_B64` contains the approved public key; private signing keys are absent from runtime and Terraform state.
- Response execution remains disabled until EventBridge targets have scope validation, least-privilege roles, rollback behavior, and action-ID deduplication.
- Audit Object Lock is COMPLIANCE, evidence retention mode is approved, and `NDR_AUDIT_OBJECT_STORAGE_REQUIRED=true`.
- The ALB has ACM HTTPS, WAF, restricted ingress CIDRs, access logs, deletion protection, and alarm destinations.
- The ECS image is pinned by digest, scan results are accepted, the task is non-root/read-only, and task-role permissions are scoped to approved flow-log, model, and storage ARNs.
- Private subnets have controlled HTTPS egress and the selected VPC resolver. Production plans reject `0.0.0.0/0` HTTPS egress unless the operator explicitly records that risk acceptance. Prefer VPC endpoints for S3, DynamoDB, CloudWatch Logs, ECR, Secrets Manager, SQS, KMS, and EventBridge.
- An allowlisted scanner service identity and runbook own `POST /api/evidence-uploads/{id}/scan`; signed-attestation replay is rejected, infected or failed objects remain outside the immutable evidence vault, and quarantine lifecycle expiry is monitored.
- `npm ci`, `npm audit`, `npm run check`, `npm run visual:test`, CodeQL, dependency review, Terraform validation, image scanning, and a staging smoke test pass.

## Security Validation

Automated tests cover unauthenticated denial, static-file allowlisting, API-key auth, opaque cookie/CSRF sessions, logout revocation, tenant isolation and normalization collisions, restrictive custom permissions, explicit empty source scope, viewer denial, source-ownership bypass attempts, concurrent case revisions, immutable-manifest races, invalid regions, invalid job intervals, MFA step-up, two-person export/response approval, cross-tenant denial, one-time consumption, Security Lake hash mismatch, forged versus server-backed rule promotion, canonical SHA-256 telemetry identity, malformed-line isolation, stream outbox idempotency/retry, OCSF timestamp quarantine, CSV formula neutralization, signed-content tamper rejection/import, SQS contracts, body limits, content type, distributed/local rate limiting, request/trace propagation, startup fail-closed controls, and SigV4 canonical signing.

Playwright covers upload, guided demo, tuning, Bedrock summary UI, approval-queue export, topology replay, admin screens, and sealed IndexedDB cache behavior in Chromium/WebKit with desktop/mobile visual baselines.

## Residual Risks

- The repository defines the evidence quarantine and attestation contract but does not ship a malware engine. Production must integrate a separately operated scanner or sandbox and protect its admin/service identity.
- EventBridge provides at-least-once delivery. Downstream response targets must enforce action-ID idempotency and independently revalidate tenant/target scope.
- Zeek and Suricata event ingestion enriches detection context but is not full packet capture, decryption, or packet reconstruction.
- Browser parsing remains synchronous after bounded file loading. Large evidence should use managed asynchronous ingest; move parsing into Web Workers before increasing browser limits.
- Bedrock prompt-injection controls reduce risk but do not make model output authoritative. Human validation and downstream action authorization remain mandatory.
- Local JSON mode is for trusted single-node development. It does not provide database-grade availability, cross-host locking, or immutable retention.
- Terraform creates strong defaults but cannot prove IdP policy, subnet routing, KMS key governance, image provenance, backup restoration, or organizational SCPs. Review those controls in the target AWS organization.
- The Terraform stack is single-region per invocation. Multi-region cells, data replication, failover routing, and residency policy require separate state and an exercised recovery design.

See [Security Remediation Record](SECURITY_REMEDIATION_2026-07-17.md) for closure evidence covering the twelve deep-dive findings.

## Incident Checks

On suspected compromise: disable the tenant user at the IdP and tenant roster, rotate API/session/OIDC/attestation secrets, stop affected ECS tasks, preserve ALB/CloudWatch/Object Lock evidence, export tenant audit events, inspect unusual approval and AI actions, review source-owner changes and jobs, invalidate WAF/IP allowlists as needed, and rebuild from a reviewed digest. Do not delete retained evidence during containment.
