# Configuration

SignalPrism NDR is configured with environment variables. Start with `.env.example` for local or container deployments.

## Server

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `4173` | HTTP port. |
| `HOST` | `0.0.0.0` | HTTP bind address. |
| `NDR_DATA_DIR` | `.ndr-data` | Local backend data directory. |
| `NDR_API_KEY` | empty | Enables API-key auth when set. |
| `NDR_MAX_BODY_BYTES` | `1048576` | Maximum JSON request body. |
| `NDR_RATE_LIMIT_WINDOW_MS` | `60000` | Rate-limit window. |
| `NDR_RATE_LIMIT_MAX` | `120` | Requests per remote address per window. |
| `NDR_RETAIN_RUNS` | `50` | Local/DynamoDB run history limit returned by API. |
| `NDR_AUDIT_RETENTION_DAYS` | `2555` | Retention metadata stamped onto audit records. |

## Evidence Package Storage

The tenant evidence metadata store keeps summaries and bounded samples. Full raw evidence packages are stored separately so large uploads and imports can move to object storage without changing the evidence-run API shape.

| Variable | Default | Purpose |
| --- | --- | --- |
| `NDR_EVIDENCE_BUCKET` | empty | Optional S3 bucket for full raw evidence packages. Empty uses local package files under `NDR_DATA_DIR`. |
| `NDR_EVIDENCE_PREFIX` | `signalprism/evidence-packages` | S3 key prefix or local package namespace. |
| `NDR_EVIDENCE_REGION` | AWS region env or DynamoDB region | Region used for S3 package writes. |
| `NDR_EVIDENCE_RETENTION_DAYS` | `90` | Retention period stamped on evidence packages. |
| `NDR_EVIDENCE_OBJECT_LOCK_MODE` | `GOVERNANCE` | S3 Object Lock mode for evidence package writes. Use `COMPLIANCE` only when policy requires immutable legal retention. |

When `NDR_EVIDENCE_BUCKET` is set, the bucket must have S3 Object Lock enabled before objects are written. The backend writes package JSON with `x-amz-object-lock-mode` and `x-amz-object-lock-retain-until-date` headers.

## Persistence

| Variable | Default | Purpose |
| --- | --- | --- |
| `NDR_STORE` | `local` | `local` or `dynamodb`. |
| `NDR_DDB_TABLE` | empty | DynamoDB table name when using `dynamodb`. |
| `NDR_DDB_REGION` | AWS region env or `us-east-1` | DynamoDB region. |

Local mode stores:

- `jobs.json`
- `ingest-runs.json`
- `workspaces.json`
- `cases.json`
- `evidence-runs.json`
- `evidence-packages/<tenant>/*.json`
- `sources.json`
- `job-runs.json`
- `tenant-users.json`
- `audit.ndjson`

DynamoDB mode uses:

- Partition key: `pk`
- Sort key: `sk`
- Record payload: JSON string in `payload`
- Tenant partitions: `TENANT#<tenantId>#WORKSPACE`, `TENANT#<tenantId>#CASE`, `TENANT#<tenantId>#EVIDENCE`, `TENANT#<tenantId>#SOURCE`, `TENANT#<tenantId>#JOB_RUN`, and `TENANT#<tenantId>#TENANT_USER`.

## AWS Credentials

Local AWS calls use:

| Variable | Purpose |
| --- | --- |
| `AWS_ACCESS_KEY_ID` | Local access key. |
| `AWS_SECRET_ACCESS_KEY` | Local secret key. |
| `AWS_SESSION_TOKEN` | Optional temporary session token. |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | Default AWS region fallback. |

ECS/Fargate deployments should use task roles. The backend supports ECS container credentials through the standard credential endpoint variables.

## OIDC/SSO

| Variable | Default | Purpose |
| --- | --- | --- |
| `NDR_OIDC_ISSUER` | empty | OIDC issuer URL. |
| `NDR_OIDC_AUDIENCE` | empty | Expected token audience. |
| `NDR_OIDC_JWKS_URI` | discovered | Optional JWKS override. |
| `NDR_OIDC_CLIENT_ID` | empty | Browser-safe OIDC client ID. |
| `NDR_OIDC_CLIENT_SECRET` | empty | Optional confidential client secret, backend only. |
| `NDR_OIDC_REDIRECT_URI` | empty/local example | Registered redirect URI. |
| `NDR_OIDC_SCOPES` | `openid profile email groups` | Login scopes. |
| `NDR_ADMIN_GROUP` | `ndr-admin` | IdP group mapped to `admin`. |
| `NDR_ANALYST_GROUP` | `ndr-analyst` | IdP group mapped to `analyst`. |
| `NDR_VIEWER_GROUP` | `ndr-viewer` | IdP group mapped to `viewer`. |
| `NDR_DEFAULT_TENANT` | `default` | Tenant used for API-key and local-dev sessions. |
| `NDR_TENANT_CLAIM` | `tenant_id` | OIDC claim used to resolve tenant ownership. |

Tokens must be RS256 signed. The backend checks issuer, optional audience, expiry, not-before, and JWKS signature.

RBAC is enforced server-side:

- `admin`: full tenant access, tenant user/source ownership management, source/case/job deletes, audit export.
- `analyst`: save workspaces, cases, sources, evidence runs, run/schedule ingest, export investigations, and invoke Bedrock.
- `viewer`: read tenant workspaces, cases, sources, evidence runs, jobs, and runs.

## Bedrock AI Assistant

| Variable | Default | Purpose |
| --- | --- | --- |
| `NDR_BEDROCK_ENABLED` | `false` | Feature flag for AI assistant. |
| `NDR_BEDROCK_REGION` | AWS region env or `us-east-1` | Bedrock Runtime region. |
| `NDR_BEDROCK_MODEL_ID` | `anthropic.claude-3-haiku-20240307-v1:0` | Converse model ID. |
| `NDR_BEDROCK_MAX_TOKENS` | `900` | Max output tokens. |
| `NDR_BEDROCK_TEMPERATURE` | `0.2` | Model temperature. |
| `NDR_BEDROCK_MAX_CONTEXT_CHARS` | `24000` | Evidence context truncation limit. |

## Local Examples

API-key mode:

```bash
NDR_API_KEY=dev-key npm start
```

Cloud ingest:

```bash
AWS_ACCESS_KEY_ID=... \
AWS_SECRET_ACCESS_KEY=... \
AWS_SESSION_TOKEN=... \
npm start
```

Bedrock:

```bash
NDR_BEDROCK_ENABLED=true \
NDR_BEDROCK_REGION=us-east-1 \
AWS_ACCESS_KEY_ID=... \
AWS_SECRET_ACCESS_KEY=... \
npm start
```

DynamoDB:

```bash
NDR_STORE=dynamodb \
NDR_DDB_TABLE=signalprism-dev \
NDR_DDB_REGION=us-east-1 \
AWS_ACCESS_KEY_ID=... \
AWS_SECRET_ACCESS_KEY=... \
npm start
```
