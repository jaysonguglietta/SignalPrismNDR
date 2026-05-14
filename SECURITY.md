# Security Notes

SignalPrism NDR is designed as a local or privately deployed security workbench.

For broader operational, architecture, and deployment context, see:

- [Architecture](docs/ARCHITECTURE.md)
- [Configuration](docs/CONFIGURATION.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Operations Runbook](docs/OPERATIONS_RUNBOOK.md)
- [Bedrock AI Assistant](docs/BEDROCK_AI.md)

## Secrets

- Do not commit AWS credentials or `NDR_API_KEY`.
- Use IAM roles in production where possible.
- Use `AWS_SESSION_TOKEN` for temporary credentials.

## Reporting Security Issues

Do not open public issues for suspected secrets exposure, authentication bypass, data leakage, or IAM privilege problems. Contact the repository owner directly and include:

- A concise impact summary.
- Affected commit, deployment mode, or configuration.
- Reproduction steps when safe to share.
- Any logs or screenshots with sensitive values redacted.

## API Access

Set `NDR_API_KEY` for shared or network-accessible deployments. Clients must send it as `x-ndr-api-key`.

For SSO, configure `NDR_OIDC_ISSUER`, `NDR_OIDC_CLIENT_ID`, `NDR_OIDC_AUDIENCE`, and the group mapping variables. The backend verifies RS256 JWTs against the issuer JWKS and maps identity-provider groups to these roles:

- `admin`: full tenant access, tenant user/source ownership management, destructive deletes, ingest, controlled exports, and audit export.
- `analyst`: manage tenant workspaces, cases, sources, evidence runs, ingest, schedules, investigation exports, and AI actions.
- `viewer`: read tenant workspaces, cases, sources, evidence runs, jobs, and run history.

Tenant ownership is resolved from `NDR_TENANT_CLAIM` for OIDC and `NDR_DEFAULT_TENANT` for API-key/local-dev sessions.

The browser uses Authorization Code with PKCE through `/api/auth/token`; do not expose `NDR_OIDC_CLIENT_SECRET` outside the backend runtime.

## Data Handling

- Flow logs can contain internal IPs, account IDs, ENIs, and infrastructure metadata.
- Redacted export is available in the UI.
- Tenant workspaces, cases, evidence-run samples, managed sources, tenant users, jobs, async job runs, and ingest metadata are stored under `NDR_DATA_DIR` for local mode or in DynamoDB when `NDR_STORE=dynamodb`.
- Full raw evidence packages are stored separately from evidence-run metadata. Local mode writes them under `.ndr-data/evidence-packages/`; production should use an S3 bucket with Object Lock enabled through `NDR_EVIDENCE_BUCKET`.
- Audit records are append-only NDJSON in local mode and append-only DynamoDB records in DynamoDB mode. Each record includes `retentionUntil` based on `NDR_AUDIT_RETENTION_DAYS`.
- The Terraform production stack creates an S3 audit bucket with Object Lock COMPLIANCE retention for immutable exported audit evidence.
- The Terraform production stack also creates a separate evidence package bucket with versioning, encryption, public access block, and configurable Object Lock retention for raw evidence packages.

## Bedrock AI

The AWS Bedrock assistant is disabled unless `NDR_BEDROCK_ENABLED=true`. When enabled, the backend sends a bounded investigation context, not the entire raw upload, to Bedrock Runtime through server-side SigV4 signing. Treat prompts and responses as investigation data:

- Use least-privilege IAM for `bedrock:InvokeModel`.
- Choose an approved model and region with `NDR_BEDROCK_MODEL_ID` and `NDR_BEDROCK_REGION`.
- Keep `NDR_BEDROCK_MAX_CONTEXT_CHARS` low enough to avoid unnecessary data exposure.
- Validate AI responses against source evidence before taking response action.
- Restrict AI invocation to `admin` and `analyst` roles.

## Production Recommendations

- Put the container behind HTTPS.
- Run Fargate tasks in private subnets behind the ALB and require OIDC/SSO for shared deployments.
- Use least-privilege IAM policies for S3 and CloudWatch Logs.
- Use DynamoDB for tenant workspaces, cases, evidence metadata, sources, jobs, runs, and audit records; use encrypted EFS only for local scratch/evidence storage.
- Use S3 Object Lock for retained raw evidence packages and choose retention mode/days before production rollout.
- Store `NDR_API_KEY` and any OIDC client secret in Secrets Manager.
- Keep the Bedrock feature flag off in environments that are not approved for AI-assisted analysis.
- Forward JSON logs to your SIEM.
- Scrape `/api/metrics` and alert on ingest errors.
- Rotate API keys and IdP client credentials on a regular schedule.
