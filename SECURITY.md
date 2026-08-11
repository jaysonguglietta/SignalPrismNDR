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
- Use separate generated values for `NDR_SESSION_SECRET` and `NDR_EVIDENCE_ATTESTATION_SECRET`; never reuse the API key or OIDC client secret.
- Pass existing Secrets Manager ARNs into Terraform. Secret plaintext must not be supplied as Terraform variables or committed in `.tfvars`.

## Reporting Security Issues

Do not open public issues for suspected secrets exposure, authentication bypass, data leakage, or IAM privilege problems. Contact the repository owner directly and include:

- A concise impact summary.
- Affected commit, deployment mode, or configuration.
- Reproduction steps when safe to share.
- Any logs or screenshots with sensitive values redacted.

## API Access

Set `NDR_API_KEY` for shared or network-accessible deployments that use API-key access. Browser users submit the key once to create an opaque HMAC-protected HttpOnly SameSite session ID; principal and revocation state remain server-side. API clients may still send `x-ndr-api-key` directly.

For SSO, configure `NDR_OIDC_ISSUER`, `NDR_OIDC_CLIENT_ID`, `NDR_OIDC_AUDIENCE`, and the group mapping variables. The backend verifies RS256 JWTs against the issuer JWKS and maps identity-provider groups to these roles:

- `admin`: full tenant access, tenant user/source ownership management, enterprise settings, destructive deletes, ingest, controlled exports, and audit export.
- `analyst`: manage tenant workspaces, cases, sources, evidence runs, enterprise artifacts, ingest, schedules, investigation exports, and AI actions.
- `viewer`: read tenant workspaces, cases, sources, evidence runs, jobs, run history, enterprise settings, detection rules, and enterprise artifacts.

Tenant ownership is resolved from `NDR_TENANT_CLAIM` for OIDC and `NDR_DEFAULT_TENANT` for API-key/local-dev sessions. OIDC audience and tenant claims are required by default.

The browser uses Authorization Code with PKCE through `/api/auth/token`; do not expose `NDR_OIDC_CLIENT_SECRET` outside the backend runtime.

When no API key or OIDC issuer is configured, local-dev admin is limited to loopback requests. Do not set `NDR_ALLOW_LOCAL_DEV_ADMIN=true` outside trusted local development.

Session-authenticated mutating requests require the backend-issued CSRF token in `x-ndr-csrf`. Sessions are registered in tenant storage for logout and roster-driven revocation; production refuses to disable the registry. Set `NDR_SESSION_COOKIE_SECURE=true` behind HTTPS and use a stable, dedicated `NDR_SESSION_SECRET` for every multi-instance deployment. Packet access, controlled export approval, and response approval require recent OIDC MFA when production hardening is enabled.

Analyst-created sources are owned by the analyst unless an admin assigns them. Ownership fields from analyst requests are not authoritative. Detection-rule production changes and controlled exports are admin approval actions; separate approvers, expiration, and one-time consumption are enabled by default.

Normalized telemetry, correlation findings, response requests, and signed content metadata use the same tenant-scoped storage partitions and role checks. Analysts may request response actions but cannot execute them directly. A different tenant admin must approve; execution is disabled by default and can emit only to the configured EventBridge bus. Analyst-controlled webhook URLs and role ARNs are not accepted.

Detection content uses an Ed25519 publisher signature plus SHA-256 rules digest. The runtime contains only the trusted public key. Imports require an admin, enter `test` status with no passing tests, cannot overwrite production rules, and retain the existing independent production approval gate.

## Data Handling

- Flow logs can contain internal IPs, account IDs, ENIs, and infrastructure metadata.
- Redacted export uses session-scoped HMAC-SHA256 pseudonyms. Evidence vault manifests use SHA-256 and server-persisted vault artifacts receive a separate HMAC-SHA256 attestation.
- Tenant workspaces, cases, evidence-run samples, managed sources, tenant users, enterprise settings, detection rules, enterprise artifacts, jobs, async job runs, and ingest metadata are stored under `NDR_DATA_DIR` for local mode or in DynamoDB when `NDR_STORE=dynamodb`.
- Full raw evidence packages are stored separately from evidence-run metadata. Local mode writes them under `.ndr-data/evidence-packages/`; production should use an S3 bucket with Object Lock enabled through `NDR_EVIDENCE_BUCKET`.
- Production uploads use a versioned quarantine bucket and require server-observed checksum identity plus a fresh signed scanner attestation before a version-pinned, reverified vault copy. Packet reads are limited to approved evidence locations and trusted provenance.
- Audit records are append-only NDJSON in local mode and append-only DynamoDB records in DynamoDB mode. Each record includes `retentionUntil` based on `NDR_AUDIT_RETENTION_DAYS`.
- Configure `NDR_AUDIT_BUCKET` to write each audit event to S3 with Object Lock headers. Terraform enables COMPLIANCE retention and sets audit object writes to fail closed.
- Direct arbitrary S3/CloudWatch ingest is disabled by default. Analysts should ingest from managed tenant sources so source ownership and scope controls apply.
- Production async ingest uses SQS and separate worker tasks. Queue URLs are restricted to AWS SQS HTTPS endpoints, worker messages carry bounded principal/tenant data, completed runs are idempotently acknowledged, and repeated failures move to the DLQ.
- The Terraform production stack also creates a separate evidence package bucket with versioning, encryption, public access block, and configurable Object Lock retention for raw evidence packages.

## Bedrock AI

The AWS Bedrock assistant is disabled unless `NDR_BEDROCK_ENABLED=true`. When enabled, the backend sends a bounded, structurally sanitized investigation context, not the entire raw upload, to Bedrock Runtime through server-side SigV4 signing. Evidence is explicitly marked as attacker-controlled data and embedded instructions are not authoritative. Treat prompts and responses as investigation data:

- Use least-privilege IAM for `bedrock:InvokeModel`.
- Choose an approved model and region with `NDR_BEDROCK_MODEL_ID` and `NDR_BEDROCK_REGION`.
- Keep `NDR_BEDROCK_MAX_CONTEXT_CHARS` low enough to avoid unnecessary data exposure.
- Validate AI responses against source evidence before taking response action.
- Restrict AI invocation to `admin` and `analyst` roles.

## Production Recommendations

- Put the container behind HTTPS.
- Enable `NDR_PRODUCTION_HARDENING=true`; startup then rejects insecure cookies, missing/deduplicated secrets, weak API keys, missing authentication, and insecure OIDC issuers.
- Run Fargate tasks in private subnets behind the ALB and require OIDC/SSO for shared deployments.
- Use least-privilege IAM policies for S3 and CloudWatch Logs.
- Use DynamoDB for tenant workspaces, cases, evidence metadata, sources, enterprise artifacts, jobs, runs, and audit records; use encrypted EFS only for local scratch/evidence storage.
- Require SQS durable ingest in production, monitor oldest-message age and DLQ depth, and set visibility timeout above the maximum supported import duration.
- Use S3 Object Lock for retained raw evidence packages and choose retention mode/days before production rollout.
- Use S3 Object Lock for immutable audit events, and keep `NDR_AUDIT_OBJECT_STORAGE_REQUIRED=true` in production.
- Treat OCSF/Security Lake exports, detection rules, enterprise artifacts, threat intelligence, asset context, playbooks, vault manifests, and policy findings as tenant security data subject to audit and retention controls.
- Store API-key, session, evidence-attestation, and OIDC client secrets in Secrets Manager and rotate them under separate ownership where practical.
- Prefer browser session login over storing API keys or bearer tokens in client-side storage.
- Keep the Bedrock feature flag off in environments that are not approved for AI-assisted analysis.
- Forward JSON logs to your SIEM.
- Scrape admin-protected `/api/metrics` from a trusted monitoring path and alert on ingest errors.
- Rotate API keys and IdP client credentials on a regular schedule.
- Keep the detection-content private key in an offline or dedicated signing service and rotate trusted public keys through a controlled deployment.
- Keep response execution disabled until every EventBridge target validates tenant scope, uses a least-privilege role, records rollback state, and deduplicates by action ID.

The deployable control matrix, test coverage, production gate, and residual risks are maintained in [Security Hardening](docs/SECURITY_HARDENING.md).

The closure evidence for the 2026-07-17 adversarial findings is maintained in [Security Remediation Record](docs/SECURITY_REMEDIATION_2026-07-17.md).
