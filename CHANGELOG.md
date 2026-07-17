# Changelog

All notable changes to SignalPrism NDR are tracked here.

## Unreleased

### Security

- Closed all twelve findings from the 2026-07-17 adversarial review: unified ingest policy, lossless S3 checkpoints, line-isolated parsing, SHA-256 event IDs, immutable detection backtests, governed response targets, fail-closed retention, direct evidence uploads, sealed browser caching, packet provenance, signed scan attestations, and durable stream outbox/replay.
- Replaced principal-bearing browser cookies with opaque server-side sessions; added OIDC discovery issuer binding, JWKS refresh, strict key eligibility, production MFA step-up, and AWS credential response validation.
- Added explicit least-privilege source access modes, atomic case/rule transitions, dual-read DynamoDB migration, distributed rate/AI quotas, CSV formula neutralization, and strict invalid-timestamp quarantine.
- Closed CodeQL findings for authorization-header and tenant-ID regex complexity, dynamic AWS request target validation, one-pass XML entity decoding, and exact GCP audit-log name classification.

- Added server-side session registration and revocation, strict production startup validation, OIDC claim/time validation, CSRF-protected logout, constant-time API-key checks, and bounded per-IP/per-principal rate limiting.
- Enforced tenant and source ownership for managed ingest, tenant-scoped DynamoDB keys, conditional scheduler/run leases, per-tenant quotas, and fail-closed local persistence.
- Added two-person, expiring, one-time export approvals with conditional state changes, pending-request quotas, and Security Lake SHA-256 evidence binding.
- Restricted production detection-rule changes to tenant admins with passing tests, ATT&CK metadata, substantive descriptions, and separate author/approver enforcement.
- Bounded JSON, upload, decompression, AWS response, and Bedrock context inputs; constrained AWS/OIDC endpoints and credential-provider URLs; labeled AI evidence as untrusted data.
- Added SHA-256 evidence digests, HMAC-SHA256 evidence-vault attestations, session-scoped export pseudonyms, immutable local package creation, and S3 Object Lock/TLS enforcement.
- Hardened Fargate, ALB, WAF, EFS, IAM, network egress, secrets injection, logging, alarms, image-digest deployment, Docker runtime controls, and CI supply-chain checks.
- Expanded integration and Playwright coverage for auth, isolation, ownership, approvals, body/rate limits, AWS signing, upload, tuning, AI summary, export, topology, and tenant administration.

### Added

- Added an in-product analyst learning center with an NDR lifecycle, telemetry limitations, severity-versus-urgency guidance, live workflow links, an investigation playbook, a glossary, guided-demo practice, and desktop/mobile regression coverage.

- Added multi-cloud, Kubernetes, Cilium, Gigamon/IPFIX/CEF, and ExtraHop normalization.
- Added explainable behavior profiles, attack campaigns, retrospective hunts, and detection backtests.
- Added deterministic and optional Bedrock investigation runs with evidence citations, feedback, AI service posture, and cryptography posture.
- Added native OCSF 1.8 and Security Lake OCSF 1.3 validation profiles, Firehose batching, dynamic partitions, Zstandard Parquet conversion, Glue catalog, and KMS-backed analytics storage. OCSF 1.4 remains migration-only.
- Added Organizations discovery, cross-account source onboarding, and a StackSets-ready member-account role.
- Added governed connector records, EventBridge adapter tests, advanced response intents, dry runs, verification, and rollback.
- Added SCIM user lifecycle provisioning, custom roles, expiring service accounts, rotation, revocation, and source scoping.
- Added direct-to-S3 immutable evidence uploads with browser hashing and completion verification.
- Added the responsive Platform operator workspace plus unit, API, UI contract, and visual regression coverage.

- Durable SQS ingest queue and DLQ, separate API/worker process roles, Fargate worker autoscaling, queue metrics, and age/dead-letter alarms.
- Normalized CloudTrail, Route 53 DNS, GuardDuty, Zeek, and Suricata telemetry ingestion with evidence-linked cross-source correlation.
- Two-person response actions with approval-only defaults and optional EventBridge execution/archive.
- Ed25519-signed detection content verification and admin-only import into governed test status.
- Enterprise readiness API/UI, signal-fusion dashboard, governed response console, signed-content review, contract tests, and deployment posture checks.

- Local investigation workspaces with evidence snapshot restore.
- Guided demo mode with sample evidence, managed sources, prompt preset, and starter case.
- Detection explainability blocks for why it fired, evidence basis, and confidence interpretation.
- Detection policy profiles for strict, balanced, and focused triage.
- Managed source inventory fields for source type, account/owner, region, ENIs, CIDRs, log groups, and prefixes.
- Bedrock assistant prompt presets.
- Portable investigation package export.
- Demo script documentation.
- Tenant-scoped backend persistence for workspaces, cases, evidence runs, and managed sources with DynamoDB/local adapters.
- Tenant-aware RBAC for cases, investigation package exports, and Bedrock AI actions.
- Managed source inventory actions for direct CloudWatch/S3 ingest and scheduled job creation.
- Playable topology replay with step controls and a recent-event trail.
- Automated UI workflow checks for upload/demo, rule tuning, AI context, export, and replay flows.
- Full raw evidence package storage with local fallback and S3 Object Lock retention configuration.
- Tenant admin screen and APIs for users, roles, and managed source ownership.
- Async CloudWatch/S3 import execution with status polling and completion/failure notifications.
- Optional Playwright visual regression configuration and desktop/mobile snapshot specs.
- Enterprise command center with readiness scoring, source discovery, detection rule lifecycle, asset context, policy exposure review, quality metrics, and governance controls.
- Tenant-scoped enterprise settings and detection-rule APIs with RBAC and audit coverage.
- Tenant-scoped enterprise artifact API for copilot notes, threat-intel imports, playbook runs, evidence vault bundles, and generated reports.
- Evidence-cited investigator copilot, threat-intelligence enrichment, source-health drift checks, and explainable entity risk scoring.
- Detection-as-code export, rule quality scoring, clone/promote lifecycle actions, approval metadata, and version increments.
- Response playbooks, evidence vault bundle manifests, replay timeline export, stakeholder report modes, and tenant admin readiness checks.
- Security Lake/SIEM OCSF NDJSON export with backend manifest auditing.
- Investigation graph JSON export and enriched asset ownership posture.
- Documentation refresh across user, operator, deployment, architecture, API, data model, and Terraform guides for advanced enterprise workflows.

## 0.2.0 - 2026-05-05

### Added

- SignalPrism NDR product identity and logo.
- Browser-based VPC Flow Log upload, paste, parsing, and analysis.
- AWS, Azure NSG, GCP VPC, CloudWatch JSON, CSV, and gzipped input support.
- NDR overview, detections, entities, records, hunt, coverage, pipeline, cases, topology, and reports views.
- Entity risk scoring, topology replay, saved hunts, coverage baselines, enrichment, and traffic optimization simulator.
- Case management with status, assignee, severity override, notes, and local audit trail.
- S3 and CloudWatch backend ingest with SigV4 signing.
- Scheduled ingest jobs.
- API key auth, OIDC/SSO, RBAC, rate limiting, security headers, metrics, health, and readiness endpoints.
- DynamoDB-backed persistence option for backend jobs, runs, and audit records.
- Append-only audit export and retention metadata.
- Feature-flagged AWS Bedrock AI assistant for natural-language questions and summaries.
- ECS/Fargate Terraform with ALB, EFS, Secrets Manager, DynamoDB, autoscaling, and S3 Object Lock audit bucket.
- Smoke and integration checks.
- Comprehensive documentation set under `docs/`.

### Notes

- Bedrock is disabled by default.
- Local backend storage defaults to `.ndr-data/`.
- Generated `dist/` output is intentionally ignored by Git.
