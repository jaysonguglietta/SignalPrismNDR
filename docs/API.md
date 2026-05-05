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

- `admin`: all protected endpoints.
- `analyst`: ingest, create jobs, run jobs, read jobs/runs, AI assistant.
- `viewer`: read jobs/runs and use AI assistant.

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
  "storeMode": "local",
  "time": "2026-05-05T12:00:00.000Z"
}
```

### `GET /api/ready`

Returns readiness and storage configuration.

### `GET /api/metrics`

Returns Prometheus-style text metrics:

- `ndr_requests_total`
- `ndr_errors_total`
- `ndr_ingest_runs_total`
- `ndr_jobs_run_total`
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

Protected. Requires `admin`, `analyst`, or `viewer`. Requires `NDR_BEDROCK_ENABLED=true`.

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
  "importedAt": "2026-05-05T12:00:00.000Z"
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

### `DELETE /api/jobs/{id}`

Protected. Requires `admin`.

## Run And Audit Endpoints

### `GET /api/runs`

Protected. Requires `admin`, `analyst`, or `viewer`.

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
