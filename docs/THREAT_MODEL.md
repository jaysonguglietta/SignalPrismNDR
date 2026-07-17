# SignalPrism NDR Threat Model

This model covers the browser application, Node API, AWS ingest workers, tenant storage, evidence pipeline, AI integration, analytics delivery, response bus, and deployment stack. It assumes internet exposure, malicious tenants, compromised analyst browsers, hostile evidence, compromised cloud sources, and repeated attempts to cross tenant or approval boundaries.

## Security Objectives

1. One tenant cannot read, influence, or infer another tenant's evidence, sources, cases, identities, AI context, exports, jobs, or audit history.
2. Untrusted evidence cannot execute code, alter instructions, select outbound destinations, or bypass response/export approval.
3. Credentials, signing keys, session material, scanner authority, and response-adapter authority remain server-side and least privileged.
4. Raw evidence and audit records retain verifiable integrity, retention, legal-hold, and chain-of-custody metadata.
5. Detection, AI, and response decisions remain evidence-linked, reviewable, reversible where possible, and independently approved for high-impact actions.
6. Ingest, search, AI, export, and upload workloads remain bounded under malicious volume and malformed inputs.

## Assets And Trust Boundaries

| Asset | Boundary | Primary controls |
| --- | --- | --- |
| Browser session | Browser to API | OIDC PKCE or API-key exchange, HttpOnly SameSite cookie, CSRF, server-side revocation, short request IDs |
| Tenant identity | IdP/directory to API | Issuer/audience/signature/time validation, required tenant claim, roster status, restrictive custom permissions |
| Managed source | Tenant control plane to AWS | Server-owned source configuration, owner/source scope, exact AWS hosts, validated region/resource names, task role |
| Raw evidence | Browser/AWS to quarantine/vault | Size/quota/checksum binding, scan gate, immutable vault, retention/legal hold, separate scanner authority |
| Normalized telemetry | Worker/API to DynamoDB/search/stream | Bounded parser, stable event IDs, tenant partitions/filters, deduplication, source allowlist |
| Cases and tasks | Analyst to tenant store | Tenant keys, permission checks, optimistic revision, enum/length validation, audit trail |
| AI context/output | Tenant store to Bedrock | Feature flag, quota, context limits, prompt-injection boundary, citations, no direct mutating tools |
| Export/response intent | Analyst to admin/adapters | Expiring two-person approval, payload hash/idempotency key, tenant lookup, EventBridge boundary, rollback/kill switch |
| Audit history | API to S3 Object Lock | Fail-closed protected mutations, COMPLIANCE retention, tenant-scoped review/export |
| Deployment control | CI/Terraform to AWS | Pinned actions, dependency review, CodeQL, digest-pinned production image, least-privilege roles, WAF, restricted egress |

## Attacker Personas

- **Unauthenticated internet attacker:** probes static paths, auth endpoints, parsers, rate limits, headers, and error behavior.
- **Malicious viewer or analyst:** attempts role escalation, ownership rewrite, export/AI abuse, response self-approval, evidence tampering, or access to another source.
- **Cross-tenant attacker:** manipulates tenant names, object IDs, query filters, service-account scope, or approvals to cross storage partitions.
- **Compromised browser:** replays cookies, submits CSRF, modifies client state, invokes hidden APIs, or uploads hostile evidence. The browser is never an authorization authority.
- **Hostile evidence producer:** embeds prompt injection, malformed JSON/gzip, duplicate IDs, extreme nesting, formula content, suspicious files, or records intended to poison behavior models.
- **Compromised cloud account/source:** returns unexpected volume/content, changes object versions, or attempts to redirect signed requests.
- **Compromised integration or scanner:** abuses EventBridge, connector metadata, packet grants, or clean-scan authority.
- **Supply-chain attacker:** targets dependencies, GitHub Actions, container base images, detection bundles, or build/release credentials.

## Primary Abuse Cases

### Authentication And Session Theft

Attack path: steal/replay a browser cookie or substitute an OIDC token. Controls: secure HttpOnly SameSite cookie in production, CSRF on every cookie mutation, JWT issuer/audience/signature/time checks, server session registry, logout/roster revocation, rate limits, and no local admin beyond loopback. Residual control owner: IdP MFA, device policy, session duration, and incident revocation.

### Cross-Tenant Object Access

Attack path: guess an object ID, normalize two tenant names to one partition, omit a source scope, or supply another tenant in JSON. Controls: tenant comes only from the authenticated principal, every read/write key contains tenant and kind, unsafe external tenant names include a namespace digest, custom roles are deny-by-default, service-account empty scope denies all sources, and OpenSearch adds a server-owned tenant filter.

### Source Ownership And Cloud SSRF

Attack path: rewrite source ownership or supply an AWS-like hostname/region/bucket that targets an attacker service or metadata endpoint. Controls: analysts cannot assign/clear owner fields, managed-source inventory is authoritative, source scope is resolved server-side, AWS service hosts are exact allowlists, regions and names are validated, redirects are disabled, credential endpoints are link-local constrained, and air-gapped mode blocks outbound integrations.

### Evidence Upload And Parser Exploitation

Attack path: oversized/decompression-bomb input, malformed records, path names, checksum substitution, malware, or quota exhaustion. Controls: compressed/decompressed/body/event limits, recursion budgets, file-name/content-type validation, byte and active-session quotas, presigned checksum headers, completion `HEAD`, quarantine, separate scan attestation, Object Lock copy only after clean status, and short staging lifecycle. The production operator must supply the actual malware engine and protect its identity.

### Query And Search Abuse

Attack path: inject OpenSearch query syntax, wildcard/regex expansion, unbounded result sets, or tenant-filter override. Controls: field allowlist, strict port parsing, disallowed wildcard/path operators, bounded terms/results, fixed source fields, fixed timeout/termination, and server-owned tenant filter/index prefix. ClickHouse requires a separately governed query bridge.

### AI Prompt Injection And Data Exfiltration

Attack path: place instructions or secrets in logs, request cross-tenant context, drive excessive model spend, or treat generated text as a response command. Controls: tenant-scoped evidence collection, bounded sanitized context, explicit untrusted-evidence system instruction, daily quotas, feature flag, sanctioned Bedrock host/model scope, citations/evaluation, audit, and no direct execution of model output. Human review remains mandatory.

### Approval And Response Bypass

Attack path: self-approve, replay, race two approvals, change payload after approval, target another tenant, or emit arbitrary webhooks. Controls: separate actor checks, conditional atomic state transition, expiration/one-time consumption, approved payload/hash binding, tenant lookup, allowed response types/adapters, EventBridge-only intent, action idempotency key, global/tenant kill switches, verification, and rollback records.

### Scheduling, Queue, And Availability Abuse

Attack path: create excessive schedules, duplicate runs across replicas, poison SQS messages, stall workers, or replay completed imports. Controls: interval and per-tenant quotas, EventBridge Scheduler fixed target payload, conditional run slots, tenant/source lookup by worker, visibility heartbeat, bounded retries, DLQ, queue-age alarms, pagination caps, checkpoints, stable event deduplication, and async status notifications.

### Supply Chain And Release Compromise

Attack path: malicious package/action/detection content/container. Controls: minimal runtime dependencies, lockfile, `npm ci --ignore-scripts`, audit, Dependabot, dependency review, SHA-pinned GitHub Actions, CodeQL, Ed25519-signed detection bundles, production image digest requirement, non-root/read-only container, and deployment-time image scanning/attestation gate. Base-image digest refresh remains a release responsibility.

## Combined-Risk Scenarios

1. **Compromised analyst plus prompt-injected evidence:** the analyst can invoke AI but receives only bounded tenant context; model output cannot execute a response. Containment still requires a separate approver and adapter validation.
2. **Malicious upload plus scanner compromise:** a forged clean result could move hostile content into the vault. Protect scanner credentials with a dedicated custom service identity restricted to `evidence:scan`, alert on scan engine/version changes, and sandbox all later consumers even for clean objects.
3. **Stolen admin session plus response adapter:** the attacker still cannot approve their own request, but two compromised identities can. IdP phishing-resistant MFA, privileged access workstations, approval anomaly alerts, and EventBridge target-side scope checks are required.
4. **Cloud source compromise plus model poisoning:** checkpoints and dedupe bound reprocessing, but valid hostile telemetry can affect seasonal models. Promotion is approval-gated; maintain poisoning exclusions, rollback snapshots, drift alerts, and known-good evaluation datasets.
5. **Queue replay plus at-least-once response delivery:** ingest uses stable IDs and run slots; response targets must additionally persist and reject previously processed action IDs.

## Validation Matrix

| Control | Automated validation | Production validation |
| --- | --- | --- |
| Auth/session/CSRF | Integration tests | IdP MFA and revocation exercise |
| Tenant/custom RBAC/source scope | Integration adversarial tests | Quarterly access review |
| Parser and query bounds | Unit/integration tests | Fuzzing and load test |
| Immutable evidence | Manifest race/checksum tests | S3 Object Lock and legal-hold drill |
| Upload quarantine | Startup/contract tests | EICAR or approved benign test-file scanner drill |
| Scheduler/worker | Queue contracts/readiness | DLQ redrive and long-import exercise |
| Approval races/replay | Integration tests | Two-person tabletop exercise |
| UI workflows | Chromium/WebKit tests | Staging accessibility and operator UAT |
| Dependencies/release | npm audit, CodeQL, dependency review | Image/SBOM/signature policy gate |
| Backup/DR | Terraform posture only | Restore and regional failover exercise |

## Open Production Decisions

- IdP, MFA, conditional access, privileged-admin lifecycle, and SCIM token rotation.
- Evidence scanner/sandbox product, service identity, signature policy, and infected-object response.
- Approved egress proxy or PrivateLink endpoint set and public OIDC route.
- Tenant data residency, true BYOK key ownership, KMS grant lifecycle, and key-loss procedure.
- Regional replication, recovery point/recovery time objectives, DNS failover, and restore frequency.
- EventBridge response targets, per-action IAM, target-side idempotency, verification, and rollback.
- Packet broker/PCAP system, packet authorization scope, and capture retention.
- SIEM/SOC alert routing for queue, WAF, approval, scanner, audit, model drift, and source-health events.

Review this threat model before every new parser, connector, response adapter, AI tool, storage backend, or cross-region data path.
