# Developer Guide

## Repository Layout

```text
.
├── app.js
├── index.html
├── styles.css
├── server.mjs
├── smoke-test.js
├── integration-test.mjs
├── ui-flow-test.mjs
├── playwright.config.mjs
├── scripts/
│   └── build.mjs
├── src/
│   ├── aws-sigv4.mjs
│   ├── backend-client.js
│   ├── idb-store.js
│   └── topology.js
├── infra/aws/terraform/
├── docs/
├── Dockerfile
├── docker-compose.yml
└── .github/workflows/ci.yml
```

## Scripts

```bash
npm start
```

Starts the backend and serves the app.

```bash
npm run smoke
```

Runs parser and detection smoke tests.

```bash
npm run integration
```

Starts temporary backend instances and verifies API auth/revocation/MFA step-up, explicit tenant/source RBAC, atomic case updates, rate limiting, AI disabled behavior, governed detections/responses/exports, durable stream retry, and SigV4 signing.

```bash
npm run ui:test
```

Runs no-dependency UI workflow checks for upload/demo analysis, rule tuning, AI context shaping, investigation export, topology replay, CSV injection defense, OCSF timestamp handling, and advanced enterprise models.

```bash
npm run visual:test
```

Runs the locked Playwright functional and visual regression suite under `tests/visual/`. Install browser binaries once with `npx playwright install chromium webkit`.

```bash
npm run visual:update
```

Updates Playwright snapshots after an intentional UI change.

```bash
npm run check
```

Runs syntax checks, smoke tests, integration tests, and UI workflow checks.

```bash
npm run build
```

Copies the browser application into `dist/`.

## Coding Conventions

- Keep the app dependency-free unless a dependency earns its complexity.
- Keep browser raw-evidence caching disabled by default; retained production evidence belongs in the governed object-storage path.
- Keep AWS credentials in the backend only.
- Use clear browser states for disabled, loading, error, and success.
- Use `apply_patch` for manual changes when working through Codex.
- Avoid committing generated output in `dist/`.
- Avoid committing `.ndr-data/` or `.env`.

## Frontend Notes

`app.js` remains the compatibility orchestrator for:

- VPC Flow Log parsing.
- Multi-cloud flow JSON parsing.
- Analysis and detections.
- Rendering.
- Filtering and sorting.
- Hunts.
- Coverage and baselines.
- Cases.
- Exports.
- AI evidence context shaping and shared browser state.
- Pure testable helpers for detection tuning, AI context, investigation packages, and topology replay state.

The build step copies a production static root and separates browser modules from backend-only source. Enterprise domains are already split across `platform-ui.mjs`, `operations-ui.mjs`, `enterprise-telemetry.mjs`, `enterprise-analytics.mjs`, `advanced-operations.mjs`, `ocsf.mjs`, and `connector-catalog.mjs`. Continue extracting only cohesive legacy workbench domains; keep `app.js` exports stable for contract tests during migration.

## Backend Notes

`server.mjs` uses Node built-ins for:

- HTTP server.
- Static serving.
- Auth and RBAC.
- Storage adapters.
- Tenant isolation.
- AWS API calls.
- Rate limiting.
- Metrics.
- Durable stream outbox, retry worker, and replay.
- Atomic local/DynamoDB counters and conditional transitions.

No AWS SDK dependency is required; AWS calls use `src/aws-sigv4.mjs`.

## Testing

Smoke tests validate:

- AWS VPC Flow Log parsing.
- CSV parsing.
- CloudWatch JSON parsing.
- Azure NSG JSON parsing.
- GCP VPC JSON parsing.
- Beaconing detection.

Integration tests validate:

- Public health access.
- Protected API auth.
- API key behavior.
- Tenant-scoped cases, workspaces, evidence runs, sources, and exports.
- Tenant admin users and source ownership.
- Raw evidence package metadata and local package persistence.
- Async job run list access.
- Enterprise settings, detection-rule APIs, enterprise artifact APIs, Security Lake export manifests, and policy exposure helpers.
- Viewer write/export/AI restrictions.
- Disabled Bedrock endpoint behavior.
- Rate limiting.
- SigV4 signer shape.
- Multi-format telemetry ingestion, cross-source correlation, tenant isolation, two-person response approval, signed-content verification/import, tamper rejection, and durable-queue production startup requirements.
- Canonical SHA-256 event identity, malformed-line isolation, forged backtest rejection, concurrent case conflicts, source default-deny behavior, stream outbox idempotency, and privileged MFA step-up.

`enterprise-test.mjs` validates pure telemetry normalization/correlation plus SQS URL, query, and XML message contracts. `npm run readiness:check` validates that deployment-critical queue, worker, retention, response, signed-content, container, CI, and configuration wiring remains present.

UI flow tests validate:

- Upload/demo evidence analysis.
- Detection profile tuning.
- AI summary context content.
- Investigation package shape and evidence caps.
- Topology replay timeline state.
- OCSF network/finding export helpers.
- Policy exposure analysis.
- Threat-intel parsing, cited copilot answers, detection-as-code bundles, entity risk scoring, playbook steps, vault manifests, source-health checks, and enterprise report models.

Visual regression specs cover:

- Guided demo dashboard.
- Topology replay.
- Tenant admin management.
- Enterprise signal fusion and governed response workflow.
- Session-bound AES-GCM IndexedDB evidence caching and wrong-session denial.

They are intentionally separate from `npm run check` so the server and pure-logic test path stays fast. CI runs the browser suite independently in Chromium and WebKit-compatible mobile coverage.

## CI

GitHub Actions runs:

- Locked dependency installation and a high-severity dependency audit.
- `npm run check` and `npm run build`.
- Chromium/WebKit functional and visual regression tests.
- CodeQL and dependency review with pinned action commits and least-privilege workflow permissions.

## Adding A Detection

1. Add detection logic inside `analyzeRecords` or a helper in `app.js`.
2. Use `createDetection`.
3. Include severity, confidence, tactic, technique, entity, response, tags, and linked records.
4. Update `DATA_AND_DETECTIONS.md`.
5. Add or adjust smoke tests if behavior is stable and important.

## Adding A Backend Endpoint

1. Add route in `routeApi`.
2. Decide public/protected status.
3. Apply `requireRole` for protected endpoints.
4. Validate request body size and required fields.
5. Append audit records for security-relevant mutations.
6. Register the route's exact permission, source scope, rate class, and audit action; avoid relying on the default `admin:manage` fallback.
7. Update `docs/API.md`.
8. Add negative authorization, tenant-boundary, concurrency, and malformed-input integration coverage.

## Release Workflow

1. Update docs and changelog.
2. Run `npm run check`.
3. Run `npm run build`.
4. Run `npm run visual:test` and `npm audit --audit-level=high`.
5. Review `git diff --check` and generated Terraform formatting.
6. Commit with a concise message.
7. Push a review branch and merge through protected-branch checks.
