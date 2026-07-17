# Security Remediation Record

Date: 2026-07-17

This record closes the twelve production-blocking findings in the 2026-07-17 deep-dive review and documents the adjacent hardening completed in the same change set. Status means the repository implementation and automated contracts are complete; operators must still satisfy the production gate in [Security Hardening](SECURITY_HARDENING.md) for each deployed environment.

## Remediation Matrix

| ID | Finding | Status | Implemented control | Primary validation |
| --- | --- | --- | --- | --- |
| P0-1 | Managed ingest bypassed pipeline policy | Remediated | Every managed, direct, and stream event passes through the same normalization, masking, deduplication, routing, and tiering policy before tenant persistence. | Integration telemetry policy and managed-ingest contracts. |
| P0-2 | S3 checkpointing could skip objects | Remediated | Pagination requests use the exact remaining key count; checkpoints advance only after every selected object is retained and processed successfully. | Bounded S3 pagination and retention failure tests. |
| P0-3 | One malformed line aborted a batch | Remediated | JSONL parsing isolates line failures, reports bounded parser errors, and preserves valid records before and after malformed lines. | Malformed-middle-line unit contract. |
| P0-4 | Event identity used collision-prone hashes | Remediated | Canonical event identity is a 64-character SHA-256 digest; canonical JSON ordering makes equivalent records stable. Browser source discovery uses Web Crypto SHA-256. | SHA length, canonical-order, and deduplication tests. |
| P0-5 | Detection promotion trusted client test state | Remediated | Backtests are immutable server records bound to rule version, digest, dataset, engine, quality gate, and age. Content edits invalidate prior evidence; promotion uses an atomic version condition. | Forged-promotion rejection and real backtest/promotion integration tests. |
| P0-6 | Response approval validation was incomplete | Remediated | The server validates case tenancy, adapter/action compatibility, target schema, expiration, policy snapshot/digest, approval separation, verification, rollback, and production MFA step-up. | Negative response lifecycle and approval tests. |
| P0-7 | Managed evidence retention failed open | Remediated | Production retention, checksum, and scan requirements fail closed. An ingest checkpoint cannot advance and a run cannot succeed when the raw package is not durably retained. | Production startup and retention failure contracts. |
| P0-8 | Browser persistence could not hold allowed uploads | Remediated | Raw uploads use direct multipart-safe S3 transfer metadata rather than JSON persistence. The browser refuses oversized JSON fallback and waits for durable evidence completion. | Direct-upload browser/API contracts and size-limit checks. |
| P0-9 | Browser evidence cache defaulted open | Remediated | IndexedDB evidence caching is opt-in, tenant/principal/session scoped, AES-GCM sealed, and purged when disabled or migrated. No usable session key means no cache write. | Chromium/WebKit encrypted-cache tests, including wrong-session denial. |
| P0-10 | Packet API could become an S3 confused deputy | Remediated | Packet access is limited to approved buckets/prefixes and exact versions, with S3 size/checksum verification and trusted evidence-upload or sensor provenance. Production authorization requires MFA step-up. | Arbitrary bucket, prefix, provenance, version, and identity denial tests. |
| P0-11 | Evidence scan/checksum attestations were weak | Remediated | Production requires S3 checksum and version identity plus a fresh HMAC-signed scanner attestation bound to tenant, upload, bucket, key, version, hash, outcome, engine, time, and nonce. Vault copy is version-pinned and reverified. | Missing checksum, replay, wrong identity/version, and post-copy verification checks. |
| P0-12 | Partial stream delivery could lose events | Remediated | A deterministic tenant outbox is created before event persistence. Per-record acknowledgements, leases, bounded exponential retry, terminal dead-letter state, idempotent replay, and delivery metrics preserve downstream delivery. | Partial failure, retry, duplicate-batch, and replay integration tests. |

## Additional Hardening

- Session cookies contain only a random UUID plus HMAC. Principal, CSRF, expiration, and revocation state are held in the server-side registry; production cannot disable that registry.
- OIDC discovery must report the configured issuer. JWT verification is RS256-only, validates issuer/audience/authorized party/time/token use, refreshes JWKS on an unknown key ID, and rejects ineligible keys.
- ECS and environment AWS credentials are shape-validated. Credential URLs remain limited to approved link-local or loopback endpoints and redirects are denied.
- Non-admin source access is explicit: `all`, `assigned`, or `group`. Empty analyst assignments deny access, and service accounts remain least-privilege.
- Case revisions and detection promotion use conditional writes. Local development emulates compare-and-swap under a file lock.
- DynamoDB records carry `schemaVersion=2`. `dual-read` migration mode merges legacy and tenant-index results until backfill is complete.
- Rate limits and AI daily budgets use atomic DynamoDB counters in shared deployments. Bedrock calls, agent runs, and reserved output tokens have independent tenant quotas.
- CSV exports neutralize spreadsheet formulas, normalize carriage returns, and retain proper CSV quoting.
- Invalid OCSF timestamps are rejected or quarantined instead of being silently replaced with the current time. Native OCSF 1.8 and Security Lake 1.3 remain separate profiles.
- The Docker base image is pinned by multi-architecture digest. CI pins actions, runs dependency review and CodeQL, and Dependabot covers npm, Actions, and Docker.
- CodeQL follow-up removed polynomial regex paths from authorization and tenant parsing, converted S3 to fixed allowlisted regional hosts with encoded bucket paths, made the AWS HTTPS/hostname boundary explicit immediately before `fetch`, converted XML entity decoding to one pass, and requires an exact structured GCP audit-log service identifier.

## Validation Commands

```bash
npm ci
npm audit --audit-level=high
npm run check
npm run build
npm run visual:test
terraform -chdir=infra/aws/terraform fmt -check -recursive
terraform -chdir=infra/aws/terraform init -backend=false
terraform -chdir=infra/aws/terraform validate
```

Terraform validation requires Terraform 1.6 or newer. AWS contract tests that exercise Object Lock, KMS, SQS, Kinesis, Firehose, EventBridge, and IAM must run in an isolated staging account before production approval.

## Residual Deployment Responsibilities

Repository remediation cannot prove the target identity-provider policy, scanner isolation, KMS administration, network egress, AWS Organizations controls, downstream response-adapter idempotency, or recovery procedures. Production owners must complete the gate, retain plan and test evidence, run restore/DLQ/stream-replay drills, and document any accepted exceptions.
