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

Starts temporary backend instances and verifies API auth, tenant-scoped RBAC, tenant isolation, rate limiting, AI disabled behavior, controlled exports, and SigV4 signing.

```bash
npm run ui:test
```

Runs no-dependency UI workflow checks for upload/demo analysis, rule tuning, AI context shaping, investigation package export, and topology replay helpers.

```bash
npm run check
```

Runs syntax checks, smoke tests, integration tests, and UI workflow checks.

```bash
npm run build
```

Copies the dependency-free app into `dist/`.

## Coding Conventions

- Keep the app dependency-free unless a dependency earns its complexity.
- Keep raw evidence local by default.
- Keep AWS credentials in the backend only.
- Use clear browser states for disabled, loading, error, and success.
- Use `apply_patch` for manual changes when working through Codex.
- Avoid committing generated output in `dist/`.
- Avoid committing `.ndr-data/` or `.env`.

## Frontend Notes

`app.js` currently owns:

- VPC Flow Log parsing.
- Multi-cloud flow JSON parsing.
- Analysis and detections.
- Rendering.
- Filtering and sorting.
- Hunts.
- Coverage and baselines.
- Cases.
- Exports.
- AI evidence context shaping.
- Pure testable helpers for detection tuning, AI context, investigation packages, and topology replay state.

The next major frontend architecture step is to introduce a build step and split `app.js` into modules by domain.

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
- Viewer write/export/AI restrictions.
- Disabled Bedrock endpoint behavior.
- Rate limiting.
- SigV4 signer shape.

UI flow tests validate:

- Upload/demo evidence analysis.
- Detection profile tuning.
- AI summary context content.
- Investigation package shape and evidence caps.
- Topology replay timeline state.

## CI

GitHub Actions runs:

- `npm run check`
- `npm run build`

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
6. Update `docs/API.md`.
7. Add integration coverage when feasible.

## Release Workflow

1. Update docs and changelog.
2. Run `npm run check`.
3. Run `npm run build`.
4. Commit with a concise message.
5. Push to `main` or open a PR depending on team workflow.
