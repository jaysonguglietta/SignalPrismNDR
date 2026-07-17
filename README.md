# SignalPrism NDR

SignalPrism NDR is a local and cloud-ready Network Detection and Response console for uploading or continuously ingesting cloud network evidence, correlating identity/DNS/threat/sensor telemetry, investigating entity paths, and governing containment actions. It supports AWS VPC Flow Logs plus CloudTrail, Route 53 resolver DNS, GuardDuty, Zeek JSON, and Suricata EVE JSON.

The detection-operations command center prioritizes attacks by breadth, velocity, privilege, impact, confidence, and blast radius; monitors source and sensor health; resolves time-aware entity relationships; governs seasonal behavior models; analyzes encrypted-traffic metadata; and forecasts telemetry cost. Native exports use OCSF 1.8, while Amazon Security Lake delivery uses a separate OCSF 1.3 compatibility profile with one event class per source, time ordering, five-minute delivery, assigned prefixes, provider identity, and Zstandard Parquet.

An in-product `Learn` workspace explains NDR concepts, analytical boundaries, urgency scoring, each operational screen, a practical signal-investigation playbook, and core terminology. It links learners directly into the live workflows and can load the guided demo for hands-on practice.

## Documentation

- [Documentation Index](docs/README.md)
- [Product Brief](docs/PRODUCT_BRIEF.md)
- [User Guide](docs/USER_GUIDE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [API Reference](docs/API.md)
- [Configuration](docs/CONFIGURATION.md)
- [Data And Detections](docs/DATA_AND_DETECTIONS.md)
- [Bedrock AI Assistant](docs/BEDROCK_AI.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Operations Runbook](docs/OPERATIONS_RUNBOOK.md)
- [Developer Guide](docs/DEVELOPER_GUIDE.md)
- [Demo Script](docs/DEMO_SCRIPT.md)
- [Security Notes](SECURITY.md)
- [Security Hardening](docs/SECURITY_HARDENING.md)
- [Security Remediation Record](docs/SECURITY_REMEDIATION_2026-07-17.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## Open

Open `index.html` in a browser for local file-only analysis.

Run the backend-enabled version with:

```bash
npm start
```

Then open `http://localhost:4173`. With no `NDR_API_KEY` or OIDC issuer configured, backend admin APIs are available only to loopback requests; shared or containerized deployments should set an API key or OIDC.

Cloud ingest uses environment credentials:

```bash
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... npm start
```

The backend stores tenant workspaces, cases, evidence-run metadata, managed sources, job metadata, async job runs, tenant users, enterprise settings, detection rules, enterprise artifacts, ingest runs, and audit records under `.ndr-data/` by default. Set `NDR_STORE=dynamodb` and `NDR_DDB_TABLE` to use DynamoDB for the tenant store.

Full raw evidence packages are written to local object-package storage under `.ndr-data/evidence-packages/` by default. Set `NDR_EVIDENCE_BUCKET` to write packages to S3 with Object Lock retention headers controlled by `NDR_EVIDENCE_RETENTION_DAYS` and `NDR_EVIDENCE_OBJECT_LOCK_MODE`.

For shared environments, set `NDR_API_KEY` or configure OIDC/SSO with `NDR_OIDC_ISSUER`, `NDR_OIDC_CLIENT_ID`, `NDR_OIDC_AUDIENCE`, `NDR_TENANT_CLAIM`, and the role group mappings. Browser sign-in uses an opaque, HMAC-protected HttpOnly SameSite session identifier plus CSRF token; principal and revocation state remain server-side. API clients can still send `x-ndr-api-key` directly. OIDC deployments require exact discovery issuer, audience, and tenant-claim validation by default.

Direct S3/CloudWatch ingest is disabled by default for tenant safety. Create managed sources first, then ingest or schedule jobs from those sources. Set `NDR_ALLOW_DIRECT_INGEST=true` only in trusted single-tenant development environments.

Enable AWS Bedrock AI assistance with:

```bash
NDR_BEDROCK_ENABLED=true \
NDR_BEDROCK_REGION=us-east-1 \
NDR_BEDROCK_MODEL_ID=anthropic.claude-3-haiku-20240307-v1:0 \
npm start
```

The AI assistant uses backend role checks, signs Bedrock Runtime requests server-side, sends a bounded and sanitized investigation context, treats evidence as untrusted data, and is disabled by default.

Backend operational endpoints:

- `GET /api/health`
- `GET /api/ready` (admin)
- `GET /api/metrics` (admin)
- `GET /api/auth/config`
- `GET /api/auth/me`
- `GET /api/ai/config`
- `POST /api/ai/ask`
- `GET /api/audit/events`
- `GET /api/audit/export`

Run smoke checks with:

```bash
node smoke-test.js
```

Run backend integration checks with:

```bash
npm run integration
```

Run the enterprise telemetry/queue contracts and deployment posture checks with:

```bash
npm run enterprise:test
npm run readiness:check
```

Run automated UI workflow checks with:

```bash
npm run ui:test
```

Optional visual regression specs are available for Playwright/browser-driver runs:

```bash
npm ci
npx playwright install chromium webkit
npm run visual:test
```

The locked Playwright dependency, functional browser flows, and desktop/mobile visual baselines are included in the repository. Use `npm run browser:test` for cross-platform functional CI; pixel comparison uses `npm run visual:test` on the designated baseline platform to avoid operating-system font rasterization noise.

Build the dependency-free distributable with:

```bash
npm run build
```

Container run:

```bash
cp .env.example .env
docker compose up --build
```

AWS deployment scaffolding lives in `infra/aws/terraform`.

## Product workflow

1. Upload, drag/drop, paste, or load the sample flow evidence.
2. Create or load an investigation workspace, or use the guided demo.
3. Validate import quality and review parser issues.
4. Triage the NDR overview for risk, detections, observations, entities, rejects, and data volume.
5. Investigate detection cards by severity, confidence, tactic, technique, response guidance, linked evidence, and explainability.
6. Tune the detection profile for strict, balanced, or focused review.
7. Pivot into entity risk, entity timeline, internal paths, external paths, or filtered raw records.
8. Run advanced hunts with fielded queries and save reusable hunts.
9. Track managed sources, coverage, ingest history, async job status, and saved baselines, then ingest or schedule CloudWatch/S3 imports directly from source inventory.
10. Paste DNS/TLS/HTTP/application enrichment and review application intelligence.
11. Manage tenant users, roles, source ownership, access-review exports, and audit-review evidence from the Admin screen.
12. Use the Enterprise workspace for cited answers, detection operations, production hardening, threat intel, detection-as-code, playbooks, vault bundles, reports, and governance readiness.
13. Simulate traffic reduction policies and export detections, records, and full investigation packages.
14. Submit controlled investigation or Security Lake exports for tenant-admin approval, then consume the time-limited approval once. Security Lake approvals are bound to the OCSF payload SHA-256.

## Supported input

- Default AWS VPC Flow Logs field order.
- Logs with a `#Fields:` header.
- CSV exports with recognized VPC Flow Log column names.
- Gzipped log files in browsers that support `DecompressionStream`.
- CloudWatch-style JSON or JSONL records with a `message` field.
- Azure NSG Flow Log JSON.
- GCP VPC Flow Log JSON.

Core parsing and detection run in the browser. When the backend is enabled, workspaces, cases, evidence-run samples, raw evidence package references, managed source definitions, enterprise settings, detection rules, enterprise artifacts, tenant admin records, async job runs, and controlled investigation exports are persisted through tenant-scoped APIs.

## NDR detections

- Rejected sensitive-port probing.
- High rejection-rate windows.
- Internal remote-service access that may indicate lateral movement.
- Periodic outbound connection patterns that may indicate beaconing.
- Suspicious DNS volume.
- Large private-to-public accepted transfers.
- Accepted public access to sensitive services.
- Unusual accepted protocols.
- Log delivery and parser coverage gaps.
- Saved-baseline drift for new entities, ports, apps, and paths.
- AI service traffic candidates when enrichment contains AI-domain hints.

## Gigamon-inspired workbench features

- Coverage and blind spot scoring for expected versus observed ENIs.
- Ingest history and saved baseline comparison.
- Entity timeline and peer summary.
- Detection/observation split.
- Advanced hunt query language.
- Saved hunt run/delete/clear workflows.
- Application intelligence from ports and optional enrichment.
- DNS/TLS/HTTP metadata enrichment import.
- Traffic reduction simulator for filtering, dedupe, and sampling.
- Policy recommendations for security groups, egress review, and lateral access.
- Analyst summary generator.
- SIEM-ready JSON, OCSF-like JSON, CEF, CSV, and redacted JSON exports.
- Local source watchlist for planned continuous ingest.
- Confirmation dialogs for destructive local actions.
- Sortable evidence tables and toast feedback.
- Backend S3 and CloudWatch ingest with AWS SigV4 signing.
- Scheduled local ingest jobs.
- API key protection, OIDC/SSO login with RBAC, rate limiting, request-size limits, security headers, structured logs, health/readiness, and Prometheus-style metrics.
- DynamoDB persistence option for tenant workspaces, cases, evidence runs, managed sources, enterprise artifacts, jobs, runs, and audit records.
- Append-only audit export with retention metadata and Terraform Object Lock retention.
- Feature-flagged AWS Bedrock assistant for natural-language investigation questions and AI-generated summaries.
- Bedrock prompt presets for top risk, executive summary, attack path, containment, evidence gaps, and SIEM query ideas.
- Opt-in, AES-GCM-sealed IndexedDB evidence caching scoped to the authenticated tenant, principal, and browser session; case fallback remains scoped local data.
- Tenant-backed investigation workspaces with guided demo mode.
- Case queue with status, severity override, assignee, notes, and audit log.
- Detection explainability, confidence interpretation, and tunable rule profiles.
- Managed AWS source inventory with account, region, source type, ENIs, CIDRs, log groups, prefixes, direct ingest, and schedule creation.
- Tenant admin screen for users, roles, and managed source ownership.
- Enterprise command center for readiness scoring, detection operations dashboards, production hardening review, source discovery, detection rule lifecycle, asset context, policy exposure review, quality metrics, and governance controls.
- Evidence-cited investigator copilot, source-health drift checks, threat-intelligence enrichment, and explainable entity risk scoring.
- Seasonal peer-group behavior models with drift state, model approval guardrails, and rollback snapshots.
- Source and sensor command center, Kinesis replay controls, hot/cold hunt jobs, temporal entity graph, Community ID, TLS/QUIC metadata analytics, and protocol findings.
- Smart PCAP manifests with immutable hashes and separately approved, expiring access grants.
- Threat-intelligence feed lifecycle with automatic historical retromatching and sightings.
- Response-policy modes, case requirement, independent approval, verification windows, rollback enforcement, and tenant/deployment kill switches.
- Case tasks, watchers, due dates, SLA breach posture, notification policy resources, regional cells, provider workspaces, data-residency/BYOK posture, and governed agent evaluations.
- Detection-as-code bundle export with rule quality scoring, draft/test/production promotion, cloning, approval metadata, and rollback-ready versions.
- Response playbook runs, evidence vault bundle manifests, stakeholder report modes, tenant admin readiness, access review, audit review, and replay timeline exports.
- Security Lake/SIEM OCSF NDJSON export with backend audit manifest support.
- Full raw evidence packages in local package storage or S3 Object Lock storage with retention metadata.
- Async CloudWatch/S3 import runs with polling status and completion/failure notifications.
- Durable SQS ingestion with separate API/worker roles, autoscaled Fargate workers, retries, queue-age monitoring, and a dead-letter queue.
- CloudTrail, Route 53 DNS, GuardDuty, Zeek, and Suricata normalization with explainable cross-source correlation and ATT&CK mappings.
- Two-person response action workflow with EventBridge-only execution, retained event archive, idempotency keys, and no analyst-controlled webhooks.
- Ed25519-signed detection content verification, admin-only import to test status, and preserved independent production promotion.
- Server-backed enterprise readiness score covering identity, storage, queueing, retention, source ownership, response, and detection governance.
- RBAC-controlled portable investigation package export.
- Visual topology map with playable time replay, scrubbing, step controls, and recent-event trail.
- Automated UI flow tests for upload/demo analysis, rule tuning, AI context, investigation export, and topology replay.
- Optional Playwright visual regression specs for desktop and mobile browser snapshots.

## Data model

- `FlowRecord`: normalized source, destination, ports, protocol, bytes, packets, time, action, interface, status, and raw fields.
- `Detection`: severity, confidence, tactic, technique, entity, summary, tags, response guidance, and linked evidence records.
- `EntityRisk`: IP/entity key, risk score, peers, ports, traffic volume, detection count, reject count, and tags.
- `Path`: ranked internal or external source-to-destination traffic path.
- `ParserIssue`: skipped-line quality signal with line number and message.
- `IngestJob`: scheduled S3 or CloudWatch import config, interval, enabled state, and last run status.
- `Workspace`: tenant, name, current evidence snapshot, detections, source inventory, hunts, enrichment, rule profile, and baseline signatures.
- `Case`: tenant, title, assignee, status, severity override, notes, linked detection, and audit trail.
- `ManagedSource`: tenant, source type, account, region, scope, and inferred S3/CloudWatch ingest target.
- `TenantUser`: tenant roster entry with email, role, status, and owned/assigned sources.
- `EvidencePackage`: full raw evidence package with bounded record sample, analysis summary, object URI, retention deadline, and storage mode.
- `AsyncJobRun`: queued, running, completed, or failed import execution with progress, status message, and evidence package reference.
- `DetectionRule`: custom analytic with hunt query, severity, ATT&CK mapping, owner, status, and test history.
- `EnterpriseSettings`: tenant governance, Security Lake/SIEM, retention, and data platform posture.
- `EnterpriseArtifact`: tenant-scoped artifact for copilot notes, threat-intel imports, playbook runs, vault bundles, reports, and export manifests.
- `ThreatIntelIndicator`: IP/domain reputation record with severity, confidence, source, and label.
- `PlaybookRun`: case-linked response plan with template, step owners, status, and created time.
- `EvidenceVaultBundle`: chain-of-custody manifest with retention deadline, legal hold flag, counts, hash, and storage posture.
- `EnterpriseReport`: generated stakeholder report for analyst, executive, compliance, or manager views.
- `AssetContext`: owner, environment, criticality, account, role, IP, ENI, and instance metadata.
- `PolicyFinding`: public exposure, sensitive access, and high-volume egress review finding.
- `AuditRecord`: append-only actor, role, action, details, creation time, and retention deadline.
- `ExportApproval`: tenant, export kind, payload hash, requester, separate approver, expiration, one-time consumption state, and approved payload.
- `Session`: server-side tenant-scoped principal, CSRF, revocation, and TTL record referenced by an opaque signed browser session ID.
- `TelemetryEvent`: bounded common schema for cloud identity, DNS, threat findings, Zeek, Suricata, and generic sensor events.
- `CorrelationFinding`: explainable cross-source rule result with score, entity, ATT&CK mapping, source formats, and evidence IDs.
- `ResponseAction`: tenant action request with target, case/correlation links, separate approver, execution status, and EventBridge event ID.
- `DetectionContentBundle`: verified publisher/version metadata, Ed25519 algorithm, rules digest, import actor, and rule count.
- `BehaviorProfile` / `BehaviorFinding`: learned peers, services, hours, volume, risk, explainable deviations, and evidence IDs.
- `Campaign`: linked stages, entities, signals, evidence, confidence, source formats, and blast radius.
- `HuntRun`: safe normalized query, scanned/matched counts, facets, and bounded event results.
- `Connector`: governed catalog type, direction, format, endpoint, Secrets Manager reference, and adapter test status.
- `EvidenceUpload`: presigned immutable upload session, SHA-256, size, object URI, retention, expiry, and completion state.
- `RoleDefinition` / `ServiceAccount`: custom tenant permission set and expiring non-human identity with digest-only token storage.
- `AiAgentRun`: bounded objective, deterministic steps, optional Bedrock synthesis, signal/campaign links, evidence citations, and feedback.

## Production security profile

Set `NDR_PRODUCTION_HARDENING=true` only with HTTPS, a dedicated 32+ character session secret, a separate 32+ character evidence-attestation secret, OIDC authentication, secure cookies, DynamoDB, SQS, and immutable S3 audit/evidence storage. The Terraform module enforces HTTPS, a digest-pinned image, and a trusted detection-content public key for production; it also provisions WAF, ALB logs, EFS backups, DynamoDB TTL/PITR, separate API/workers, SQS/DLQ, EventBridge archive, task hardening, alarms, and Object Lock buckets.

See [Security Hardening](docs/SECURITY_HARDENING.md) for the control matrix, threat model, production gate, and residual risks.

See [Enterprise Platform](docs/ENTERPRISE_PLATFORM.md) for advanced analytics, the Platform workspace, OCSF/Parquet data plane, Organizations onboarding, connector boundary, SCIM/service-account model, and production rollout.
