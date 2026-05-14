# API Reference

The backend is implemented in `server.mjs` and serves JSON under `/api/*`.

## Authentication

Public endpoints:

- `GET /api/health`
- `GET /api/ready`
- `GET /api/metrics`
- `GET /api/auth/config`
- `POST /api/auth/token`
- `GET /api/ai/config`

Protected endpoints require one of:

- `x-ndr-api-key: <key>` when `NDR_API_KEY` is set.
- `Authorization: Bearer <jwt>` when OIDC is configured.
- Local development mode when neither API key nor OIDC is configured.

## Roles

- `admin`: all protected endpoints, including tenant roster, source ownership, destructive deletes, and audit export.
- `analyst`: save tenant workspaces, cases, evidence runs, sources, ingest, create jobs, run jobs, export investigations, and use the AI assistant.
- `viewer`: read tenant workspaces, cases, evidence runs, sources, jobs, and runs.

Tenant isolation uses `principal.tenantId`. OIDC tenants come from `NDR_TENANT_CLAIM` with fallback claims. API key and local-dev sessions use `NDR_DEFAULT_TENANT`.

## Operational Endpoints

### `GET /api/health`

Returns backend liveness and feature status.

Example response:

```json
{
  "ok": true,
  "authMode": "api-key",
  "oidcConfigured": false,
  "awsConfigured": true,
  "bedrockEnabled": false,
  "evidenceObjectStorage": "local",
  "storeMode": "local",
  "time": "2026-05-05T12:00:00.000Z"
}
```

### `GET /api/ready`

Returns readiness and storage configuration.

Readiness includes the persistence mode plus evidence package storage settings, including whether packages are written locally or to S3.

### `GET /api/metrics`

Returns Prometheus-style text metrics:

- `ndr_requests_total`
- `ndr_errors_total`
- `ndr_ingest_runs_total`
- `ndr_jobs_run_total`
- `ndr_async_job_runs_total`
- `ndr_uptime_seconds`

## Authentication Endpoints

### `GET /api/auth/config`

Returns OIDC client configuration safe for the browser.

### `POST /api/auth/token`

Exchanges an OIDC authorization code and PKCE verifier for tokens.

Request:

```json
{
  "code": "authorization-code",
  "codeVerifier": "pkce-verifier",
  "redirectUri": "http://localhost:4173/"
}
```

### `GET /api/auth/me`

Protected. Returns the resolved principal and roles.

## AI Endpoints

### `GET /api/ai/config`

Returns Bedrock assistant feature state.

Example response:

```json
{
  "enabled": false,
  "provider": "aws-bedrock",
  "region": "us-east-1",
  "modelId": "",
  "maxTokens": 900,
  "maxContextChars": 24000,
  "modes": ["answer", "summary"]
}
```

### `POST /api/ai/ask`

Protected. Requires `admin` or `analyst`. Requires `NDR_BEDROCK_ENABLED=true`.

The browser builds a bounded investigation context. It can include workspace name, managed sources, active rule profile, summary metrics, detections, priority entities, paths, and a sample of filtered records.

Request:

```json
{
  "mode": "answer",
  "question": "Which entities should I investigate first?",
  "context": {
    "metrics": {
      "records": 100,
      "detections": 3
    },
    "detections": []
  }
}
```

Response:

```json
{
  "answer": "Start with 10.0.1.15 because...",
  "mode": "answer",
  "modelId": "anthropic.claude-3-haiku-20240307-v1:0",
  "region": "us-east-1",
  "stopReason": "end_turn",
  "usage": {}
}
```

## Workspace, Evidence, Source, Case, And Export Endpoints

### `GET /api/workspaces`

Protected. Requires `admin`, `analyst`, or `viewer`. Returns tenant workspaces.

### `POST /api/workspaces`

Protected. Requires `admin` or `analyst`. Saves a tenant workspace snapshot.

### `DELETE /api/workspaces/{id}`

Protected. Requires `admin`.

### `GET /api/evidence-runs`

Protected. Requires `admin`, `analyst`, or `viewer`. Returns bounded evidence run metadata.

### `POST /api/evidence-runs`

Protected. Requires `admin` or `analyst`. Stores evidence-run metadata, detection summary, a bounded record sample, and a full raw evidence package when `rawEvidenceText`, `evidenceText`, or `text` is present.

The response includes package metadata:

```json
{
  "id": "evidence-1714910400000",
  "package": {
    "mode": "s3",
    "uri": "s3://signalprism-evidence/signalprism/evidence-packages/default/evidence-1714910400000.json",
    "retentionUntil": "2026-08-03T12:00:00.000Z",
    "retentionMode": "GOVERNANCE",
    "bytes": 23184,
    "rawEvidenceStored": true
  }
}
```

### `GET /api/evidence-runs/{id}/package`

Protected. Requires `admin`, `analyst`, or `viewer`. Returns the stored package metadata for an evidence run. The endpoint intentionally returns package metadata, not raw package contents.

### `GET /api/sources`

Protected. Requires `admin`, `analyst`, or `viewer`. Returns managed source inventory.

### `POST /api/sources`

Protected. Requires `admin` or `analyst`. Saves a managed AWS source.

### `POST /api/sources/{id}/ingest`

Protected. Requires `admin` or `analyst`. Infers CloudWatch or S3 ingest from the managed source scope, imports evidence synchronously, stores a raw evidence package, and returns imported text.

### `POST /api/sources/{id}/ingest-async`

Protected. Requires `admin` or `analyst`. Infers CloudWatch or S3 ingest from the managed source scope, starts a background import, and returns `202` with an async job run.

### `POST /api/sources/{id}/jobs`

Protected. Requires `admin` or `analyst`. Creates a scheduled ingest job from a managed source.

### `DELETE /api/sources/{id}`

Protected. Requires `admin`.

## Tenant Admin Endpoints

### `GET /api/admin/users`

Protected. Requires `admin`. Returns tenant roster entries used for role and source ownership administration.

### `POST /api/admin/users`

Protected. Requires `admin`. Creates or updates a tenant roster entry.

Request:

```json
{
  "name": "Priya Shah",
  "email": "priya@example.com",
  "role": "analyst",
  "status": "active",
  "sourceIds": ["source-prod-vpc"]
}
```

### `DELETE /api/admin/users/{id}`

Protected. Requires `admin`. Deletes a tenant roster entry.

### `POST /api/admin/source-owners`

Protected. Requires `admin`. Assigns or clears a managed source owner.

Request:

```json
{
  "sourceId": "source-prod-vpc",
  "ownerId": "tenant-user-1714910400000"
}
```

### `GET /api/cases`

Protected. Requires `admin`, `analyst`, or `viewer`. Returns tenant cases.

### `POST /api/cases`

Protected. Requires `admin` or `analyst`. Creates or updates a case and appends case audit history.

### `GET /api/cases/{id}/audit`

Protected. Requires `admin`, `analyst`, or `viewer`. Returns a case audit trail.

### `DELETE /api/cases/{id}`

Protected. Requires `admin`.

### `POST /api/exports/investigation`

Protected. Requires `admin` or `analyst`. Stamps tenant/export metadata and writes an audit event before the browser downloads the package.

## Ingest Endpoints

### `POST /api/ingest/s3`

Protected. Requires `admin` or `analyst`.

Request:

```json
{
  "region": "us-east-1",
  "bucket": "my-vpc-flow-log-bucket",
  "prefix": "AWSLogs/123456789012/vpcflowlogs/",
  "maxObjects": 20
}
```

Response:

```json
{
  "source": "s3",
  "sourceLabel": "s3://my-vpc-flow-log-bucket/AWSLogs/...",
  "objectCount": 2,
  "text": "2 123456789012 eni-...",
  "importedAt": "2026-05-05T12:00:00.000Z",
  "package": {
    "mode": "local",
    "uri": ".ndr-data/evidence-packages/default/ingest-s3-1714910400000.json",
    "retentionUntil": "2026-08-03T12:00:00.000Z",
    "rawEvidenceStored": true
  }
}
```

### `POST /api/ingest/cloudwatch`

Protected. Requires `admin` or `analyst`.

Request:

```json
{
  "region": "us-east-1",
  "logGroupName": "/aws/vpc/flowlogs/prod",
  "filterPattern": "REJECT",
  "startTime": 1714771200000,
  "endTime": 1714774800000,
  "limit": 2000
}
```

## Job Endpoints

### `GET /api/jobs`

Protected. Requires `admin`, `analyst`, or `viewer`.

### `POST /api/jobs`

Protected. Requires `admin` or `analyst`.

Request:

```json
{
  "name": "Prod VPC flow import",
  "type": "s3",
  "intervalMinutes": 15,
  "enabled": true,
  "config": {
    "region": "us-east-1",
    "bucket": "my-bucket",
    "prefix": "AWSLogs/"
  }
}
```

### `POST /api/jobs/{id}/run`

Protected. Requires `admin` or `analyst`.

### `POST /api/jobs/{id}/run-async`

Protected. Requires `admin` or `analyst`. Starts a background job execution and returns `202` with a run status object.

Response:

```json
{
  "id": "job-run-1714910400000",
  "jobId": "job-1",
  "jobName": "Prod VPC flow import",
  "status": "queued",
  "progress": 5,
  "message": "Queued for import"
}
```

### `DELETE /api/jobs/{id}`

Protected. Requires `admin`.

## Run And Audit Endpoints

### `GET /api/runs`

Protected. Requires `admin`, `analyst`, or `viewer`.

### `GET /api/job-runs`

Protected. Requires `admin`, `analyst`, or `viewer`. Returns async job runs for notification polling and investigation history.

### `GET /api/audit/export`

Protected. Requires `admin`. Returns `application/x-ndjson`.

## Error Shape

Errors use:

```json
{
  "error": "Human-readable message"
}
```

Common statuses:

- `401`: missing or invalid credentials.
- `403`: insufficient role or disabled feature.
- `404`: unknown endpoint or job.
- `429`: rate limit exceeded.
- `500`: backend or AWS request error.
