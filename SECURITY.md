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

- `admin`: manage jobs, run ingest, delete schedules, and export audit logs.
- `analyst`: run ingest and create schedules.
- `viewer`: inspect backend status, jobs, and run history.

The browser uses Authorization Code with PKCE through `/api/auth/token`; do not expose `NDR_OIDC_CLIENT_SECRET` outside the backend runtime.

## Data Handling

- Flow logs can contain internal IPs, account IDs, ENIs, and infrastructure metadata.
- Redacted export is available in the UI.
- Backend ingest metadata is stored under `NDR_DATA_DIR` for local mode or in DynamoDB when `NDR_STORE=dynamodb`.
- Audit records are append-only NDJSON in local mode and append-only DynamoDB records in DynamoDB mode. Each record includes `retentionUntil` based on `NDR_AUDIT_RETENTION_DAYS`.
- The Terraform production stack creates an S3 audit bucket with Object Lock COMPLIANCE retention for immutable exported audit evidence.

## Bedrock AI

The AWS Bedrock assistant is disabled unless `NDR_BEDROCK_ENABLED=true`. When enabled, the backend sends a bounded investigation context, not the entire raw upload, to Bedrock Runtime through server-side SigV4 signing. Treat prompts and responses as investigation data:

- Use least-privilege IAM for `bedrock:InvokeModel`.
- Choose an approved model and region with `NDR_BEDROCK_MODEL_ID` and `NDR_BEDROCK_REGION`.
- Keep `NDR_BEDROCK_MAX_CONTEXT_CHARS` low enough to avoid unnecessary data exposure.
- Validate AI responses against source evidence before taking response action.

## Production Recommendations

- Put the container behind HTTPS.
- Run Fargate tasks in private subnets behind the ALB and require OIDC/SSO for shared deployments.
- Use least-privilege IAM policies for S3 and CloudWatch Logs.
- Use DynamoDB for job/run/audit records and encrypted EFS only for local scratch/evidence storage.
- Store `NDR_API_KEY` and any OIDC client secret in Secrets Manager.
- Keep the Bedrock feature flag off in environments that are not approved for AI-assisted analysis.
- Forward JSON logs to your SIEM.
- Scrape `/api/metrics` and alert on ingest errors.
- Rotate API keys and IdP client credentials on a regular schedule.
