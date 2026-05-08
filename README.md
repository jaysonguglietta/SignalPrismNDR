# SignalPrism NDR

SignalPrism NDR is a local and cloud-ready Network Detection and Response console for uploading or ingesting AWS VPC Flow Logs and reviewing traffic volume, rejected flows, top ports, detections, entity risk, internal paths, external paths, and filtered evidence records.

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
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## Open

Open `index.html` in a browser for local file-only analysis.

Run the backend-enabled version with:

```bash
npm start
```

Then open `http://localhost:4173`.

Cloud ingest uses environment credentials:

```bash
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... npm start
```

The backend stores tenant workspaces, cases, evidence-run metadata, managed sources, job metadata, ingest runs, and audit records under `.ndr-data/` by default. Set `NDR_STORE=dynamodb` and `NDR_DDB_TABLE` to use DynamoDB for the tenant store.

For shared environments, set `NDR_API_KEY` and configure clients to send `x-ndr-api-key`, or configure OIDC/SSO with `NDR_OIDC_ISSUER`, `NDR_OIDC_CLIENT_ID`, `NDR_OIDC_AUDIENCE`, `NDR_TENANT_CLAIM`, and the role group mappings. The backend supports tenant-aware `admin`, `analyst`, and `viewer` roles.

Enable AWS Bedrock AI assistance with:

```bash
NDR_BEDROCK_ENABLED=true \
NDR_BEDROCK_REGION=us-east-1 \
NDR_BEDROCK_MODEL_ID=anthropic.claude-3-haiku-20240307-v1:0 \
npm start
```

The AI assistant uses the backend role checks, signs Bedrock Runtime requests server-side, sends a bounded investigation context, and is disabled by default.

Backend operational endpoints:

- `GET /api/health`
- `GET /api/ready`
- `GET /api/metrics`
- `GET /api/auth/config`
- `GET /api/auth/me`
- `GET /api/ai/config`
- `POST /api/ai/ask`
- `GET /api/audit/export`

Run smoke checks with:

```bash
node smoke-test.js
```

Run backend integration checks with:

```bash
npm run integration
```

Run automated UI workflow checks with:

```bash
npm run ui:test
```

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
9. Track managed sources, coverage, ingest history, and saved baselines, then ingest or schedule CloudWatch/S3 imports directly from source inventory.
10. Paste DNS/TLS/HTTP/application enrichment and review application intelligence.
11. Simulate traffic reduction policies and export detections, records, and full investigation packages.

## Supported input

- Default AWS VPC Flow Logs field order.
- Logs with a `#Fields:` header.
- CSV exports with recognized VPC Flow Log column names.
- Gzipped log files in browsers that support `DecompressionStream`.
- CloudWatch-style JSON or JSONL records with a `message` field.
- Azure NSG Flow Log JSON.
- GCP VPC Flow Log JSON.

Core parsing and detection run in the browser. When the backend is enabled, workspaces, cases, evidence-run samples, managed source definitions, and controlled investigation exports are persisted through tenant-scoped APIs.

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
- DynamoDB persistence option for tenant workspaces, cases, evidence runs, managed sources, jobs, runs, and audit records.
- Append-only audit export with retention metadata and Terraform Object Lock retention.
- Feature-flagged AWS Bedrock assistant for natural-language investigation questions and AI-generated summaries.
- Bedrock prompt presets for top risk, executive summary, attack path, containment, evidence gaps, and SIEM query ideas.
- IndexedDB evidence and case fallback when the backend is offline.
- Tenant-backed investigation workspaces with guided demo mode.
- Case queue with status, severity override, assignee, notes, and audit log.
- Detection explainability, confidence interpretation, and tunable rule profiles.
- Managed AWS source inventory with account, region, source type, ENIs, CIDRs, log groups, prefixes, direct ingest, and schedule creation.
- RBAC-controlled portable investigation package export.
- Visual topology map with playable time replay, scrubbing, step controls, and recent-event trail.
- Automated UI flow tests for upload/demo analysis, rule tuning, AI context, investigation export, and topology replay.

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
- `AuditRecord`: append-only actor, role, action, details, creation time, and retention deadline.
