# Operations Runbook

## Health Checks

### Liveness

```bash
curl http://localhost:4173/api/health
```

Use this to confirm the process is alive and serving API requests.

### Readiness

```bash
curl http://localhost:4173/api/ready
```

Use this to confirm storage mode, local file availability, DynamoDB configuration, OIDC state, and Bedrock state.

### Metrics

```bash
curl http://localhost:4173/api/metrics
```

Metrics:

- `ndr_requests_total`
- `ndr_errors_total`
- `ndr_ingest_runs_total`
- `ndr_jobs_run_total`
- `ndr_async_job_runs_total`
- `ndr_uptime_seconds`

## Logs

The backend emits structured JSON logs with:

- `level`
- `event`
- `time`
- request method/path/status/duration
- remote address

In AWS, container logs go to the CloudWatch log group provisioned by Terraform.

## Common Incidents

### Backend Offline

Symptoms:

- UI says backend offline.
- `/api/health` fails.

Actions:

1. Confirm process/container is running.
2. Check port binding and ALB target health.
3. Inspect logs for startup errors.
4. Confirm `NDR_DATA_DIR` is writable in local mode.
5. Confirm task role and Secrets Manager access in ECS.

### Cloud Ingest Fails

Symptoms:

- S3 or CloudWatch import returns `500`.
- Job last status becomes `error`.

Actions:

1. Confirm AWS credentials or ECS task role.
2. Verify region.
3. For S3, confirm bucket ARN permissions and prefix.
4. For CloudWatch Logs, confirm log group ARN permissions.
5. Confirm source logs contain VPC Flow Log messages.
6. Review backend logs for AWS status and error body.

### Async Import Stalls

Symptoms:

- A source or job async run remains `queued` or `running`.
- The UI does not show a completion/failure toast.

Actions:

1. Refresh `/api/job-runs` and confirm the run status.
2. Check backend logs for `job.run.async.*` audit activity and AWS errors.
3. Confirm the process was not restarted during the import; local async jobs run in-process.
4. Re-run the import synchronously to isolate source permissions from background execution.
5. For production, confirm autoscaling and deployment workflows allow in-flight jobs to drain.

### API Key Or SSO Failure

Symptoms:

- `401 API key required`.
- `401 Bearer token required`.
- `Invalid OIDC token`.
- `403 Insufficient role`.

Actions:

1. Confirm `NDR_API_KEY` matches the browser API key.
2. Confirm OIDC issuer and audience.
3. Confirm token is RS256 signed and not expired.
4. Confirm IdP groups match configured role group variables.
5. Confirm redirect URI exactly matches IdP registration.

### Rate Limit Exceeded

Symptoms:

- `429 Rate limit exceeded`.

Actions:

1. Wait for `NDR_RATE_LIMIT_WINDOW_MS`.
2. Increase `NDR_RATE_LIMIT_MAX` for trusted internal deployments.
3. Investigate repeated requests or browser loops.

### Bedrock Assistant Fails

Symptoms:

- UI says Bedrock disabled.
- AI request returns `403` or `500`.

Actions:

1. Confirm `NDR_BEDROCK_ENABLED=true`.
2. Confirm AWS credentials/task role.
3. Confirm `bedrock:InvokeModel` permission.
4. Confirm model access and region.
5. Reduce context size if request payload is too large.

## Backup And Recovery

### Browser Data

IndexedDB and LocalStorage are local to the analyst browser. Durable multi-user deployments should use the backend tenant store for evidence metadata and S3 Object Lock evidence package storage for retained raw evidence.

### Local Backend Mode

Back up `NDR_DATA_DIR`:

- `jobs.json`
- `job-runs.json`
- `ingest-runs.json`
- `workspaces.json`
- `cases.json`
- `evidence-runs.json`
- `evidence-packages/`
- `sources.json`
- `tenant-users.json`
- `audit.ndjson`

### DynamoDB Mode

Terraform enables point-in-time recovery. Confirm backups and retention with account policy. Tenant-scoped workspaces, cases, evidence runs, managed sources, tenant users, and async job runs use `TENANT#<tenantId>#<kind>` partition keys.

### Audit Exports

Terraform creates an S3 Object Lock bucket for immutable audit exports. Retention is controlled by `audit_retention_days`.

### Evidence Packages

Local evidence packages are JSON files under `evidence-packages/<tenant>/`. In AWS, Terraform creates a separate S3 Object Lock bucket for full raw evidence packages. Retention is controlled by `evidence_retention_days` and `evidence_object_lock_mode`.

## Maintenance

Recommended recurring tasks:

- Rotate API keys and OIDC client secrets.
- Review IAM permissions for least privilege.
- Review CloudWatch log retention.
- Confirm DynamoDB point-in-time recovery remains enabled.
- Confirm evidence package retention and Object Lock mode match policy.
- Confirm Bedrock model allow-list and approval status.
- Run `npm run check` before deployment.
- Review scheduled job errors.

## Release Checklist

1. Pull latest `main`.
2. Run `npm run check`.
3. Run `npm run build`.
4. Build and push container image.
5. Update Terraform `container_image`.
6. Run Terraform plan.
7. Apply during approved window.
8. Verify health, ready, metrics, auth, ingest, and audit export.
