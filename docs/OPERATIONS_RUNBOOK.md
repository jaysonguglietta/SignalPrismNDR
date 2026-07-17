# Operations Runbook

## Health Checks

### Liveness

```bash
curl http://localhost:4173/api/health
```

Use this to confirm the process is alive and serving API requests.

### Readiness

```bash
curl -H 'x-ndr-api-key: <key>' http://localhost:4173/api/ready
```

Use this as an admin to confirm storage mode, local file availability, DynamoDB configuration, OIDC state, and Bedrock state.

### Metrics

```bash
curl -H 'x-ndr-api-key: <key>' http://localhost:4173/api/metrics
```

Metrics:

- `ndr_requests_total`
- `ndr_errors_total`
- `ndr_ingest_runs_total`
- `ndr_jobs_run_total`
- `ndr_async_job_runs_total`
- `ndr_queue_messages_sent_total`
- `ndr_queue_messages_processed_total`
- `ndr_queue_messages_failed_total`
- `ndr_telemetry_events_accepted_total`
- `ndr_correlations_created_total`
- `ndr_response_actions_executed_total`
- `ndr_stream_records_accepted_total`
- `ndr_stream_deliveries_retried_total`
- `ndr_stream_deliveries_dead_lettered_total`
- `ndr_security_lake_records_published_total`
- `ndr_ai_agent_runs_total`
- `ndr_packet_access_grants_total`
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
6. Treat any production hardening startup rejection as a configuration failure; do not disable `NDR_PRODUCTION_HARDENING` to bypass it.

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
3. In production, inspect SQS `ApproximateAgeOfOldestMessage`, visible/in-flight counts, worker desired/running counts, and worker logs.
4. Confirm `NDR_QUEUE_VISIBILITY_SECONDS` exceeds normal import duration and the task role can receive/delete from the queue.
5. Inspect the DLQ. Redrive only after fixing the source permission, parsing, object-size, or worker failure that caused retries.
6. Local mode can still run async work in-process; process restart can interrupt only that development fallback.

### Response Action Fails

Symptoms:

- Action is `execution-failed` or remains `approved` instead of `executed`.

Actions:

1. Confirm a different tenant admin approved the request.
2. Confirm `NDR_RESPONSE_EXECUTION_ENABLED=true` only when execution is intended.
3. Verify `events:PutEvents` permission and `NDR_RESPONSE_EVENT_BUS` region/name.
4. Search the EventBridge archive by action ID and inspect target delivery/DLQ metrics.
5. Do not blindly retry a timed-out action; confirm downstream idempotency using the action ID first.

### Signed Content Rejected

1. Confirm the bundle manifest `contentHash` matches canonical rules JSON.
2. Confirm it was signed with the private half of the configured Ed25519 public key.
3. Confirm base64 public-key configuration contains PEM or SPKI DER bytes, not a private key.
4. Re-sign after any rule or manifest change.
5. Treat an unexpected signature failure from a known publisher as a supply-chain incident.

### API Key Or SSO Failure

Symptoms:

- `401 API key required`.
- `401 Bearer token required`.
- `Invalid OIDC token`.
- `403 Insufficient role`.

Actions:

1. Confirm `NDR_API_KEY` matches the browser API key.
2. Confirm configured OIDC issuer exactly matches discovery metadata and the token issuer/audience.
3. Confirm token is RS256 signed and not expired.
4. Confirm IdP groups match configured role group variables.
5. Confirm redirect URI exactly matches IdP registration.
6. Inspect the tenant roster for disabled/revoked status or a server-side role override, then confirm the session registry record has not expired.
7. For packet/export/response approval, confirm the IdP emitted MFA in `amr`/`acr` and a recent `auth_time` within `NDR_STEP_UP_MAX_AGE_SECONDS`.

### Rate Limit Exceeded

Symptoms:

- `429 Rate limit exceeded`.

Actions:

1. Wait for `NDR_RATE_LIMIT_WINDOW_MS`.
2. Increase `NDR_RATE_LIMIT_MAX` for trusted internal deployments.
3. Investigate repeated requests or browser loops.
4. Confirm `NDR_TRUST_PROXY=true` only when the ALB/proxy overwrites forwarded client addresses; otherwise leave it false.

### Export Approval Fails

Symptoms:

- Export remains pending, returns `403`/`409`, or no longer downloads.

Actions:

1. Confirm a different tenant admin approved the request when separate approval is required.
2. Confirm requester, approver, and consumer are in the same tenant.
3. Check the approval has not expired or already been consumed.
4. For Security Lake, regenerate OCSF from the same filtered evidence and verify its SHA-256 matches the approved `contentSha256`.
5. Review `export.approval.*` and export events in the audit UI.

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
6. For `429`, inspect the tenant's daily agent-run, Bedrock-call, and reserved-token budgets before raising a reviewed quota.

### Stream Delivery Retries Or Dead-Letters

1. Read `GET /api/stream/deliveries` as a tenant operator and filter for `pending`, `delivering`, or `dead-letter` state.
2. Alert on growth in `ndr_stream_deliveries_retried_total` and any increase in `ndr_stream_deliveries_dead_lettered_total`.
3. Confirm Kinesis/Firehose stream identity, region, task-role permission, quota, and destination health. Inspect per-record failure IDs rather than replaying the entire source batch.
4. Let leases expire naturally when a worker is lost; do not edit outbox records directly.
5. After correcting the destination, use `POST /api/stream/deliveries/{id}/replay`. Stable event and outbox IDs prevent acknowledged records from being recreated.
6. Preserve terminal records and associated audit events until delivery and downstream consumer state are reconciled.

### OCSF Streaming Or Security Lake Publish Fails

1. Check `/api/stream/status` and confirm the configured stream name and region.
2. Inspect Data Firehose `DeliveryToS3.*`, conversion, freshness, throttling, and failed-record metrics.
3. Confirm the ECS task can call `firehose:PutRecord` and `firehose:PutRecordBatch` only on the expected stream.
4. Inspect the Firehose error-output prefix before replaying failed records.
5. Verify Glue schema changes remain backward compatible with the OCSF projection.
6. A partial batch failure is an incomplete export; preserve the audit event and republish only the rejected records with stable evidence IDs.

### Direct Evidence Upload Fails

1. Confirm the browser origin exactly matches `direct_upload_allowed_origins`; wildcard CORS is intentionally unsupported.
2. Confirm the upload session has not expired and the signed `Content-Type`, checksum, tenant, upload ID, Object Lock mode, and retention headers are unchanged.
3. Compare browser SHA-256 and file size with the completion request.
4. Verify both quarantine and vault buckets have versioning, the vault has Object Lock, and the task can issue version-aware `HeadObject`, `CopyObject`, and delete for the tenant prefix.
5. Never weaken retention or reuse a presigned URL to work around a failed upload; create a new upload session.
6. Confirm the scanner subject is allowlisted and its HMAC covers the exact staging version, checksum, outcome, engine/version, timestamp, and unique nonce. Reject stale or replayed attestations.

### DynamoDB Migration Or Missing Records

1. Keep `NDR_DDB_GSI_MIGRATION_MODE=dual-read` while legacy items are present.
2. Compare legacy partition queries with `tenant-kind-createdAt-index` counts and sampled object IDs for every tenant/kind.
3. Backfill `schemaVersion`, `gsi2pk`, `gsi2sk`, `updatedAt`, and revision fields with an idempotent, checkpointed job.
4. Move to `gsi-only` only after completeness metrics remain clean through a normal retention window. Use `legacy-only` as a controlled rollback, not a permanent production mode.

### SCIM Or Service Account Failure

1. Confirm the dedicated SCIM bearer token and service-account HMAC pepper are distinct 32+ character Secrets Manager values.
2. Confirm `NDR_SCIM_TENANT_ID` names the tenant the IdP is allowed to administer.
3. Review `scim.*` or `service_account.*` audit records and verify deactivation revoked active sessions.
4. Rotate a service account to replace a lost token; the old digest must become unusable immediately.
5. Check optional source scopes before widening the role. A token should receive only the managed sources needed for its automation.

### Organization Discovery Or Cross-Account Import Fails

1. Confirm Organizations discovery is enabled only in the management or delegated administrator account.
2. Verify the member role from `infra/aws/member-account-role.yaml` trusts the exact central task role and expected external ID.
3. Confirm the role grants read access only to the selected S3 prefixes and CloudWatch log groups.
4. Check STS and Organizations CloudTrail events for denied or unexpected calls.
5. Re-onboard the account after correcting role ARN or external ID; do not add permanent member-account credentials to SignalPrism.

### Connector Or Packet Capture Intent Fails

1. Confirm the connector holds only a Secrets Manager ARN and the endpoint is HTTPS and non-private.
2. Validate the connector in dry-run mode; the API never fetches analyst-supplied URLs.
3. Inspect EventBridge archive, target delivery, adapter logs, and adapter DLQ using the action or connector-test ID.
4. For packet capture, verify the target sensor enforces scope, duration, size, retention, and approved filter policy before collecting data.
5. Keep packet payloads and decryption keys in the sensor evidence plane; store only immutable package references and chain-of-custody metadata in SignalPrism.

### Enterprise Artifact Save Fails

Symptoms:

- Copilot notes, threat-intel imports, playbook runs, vault bundles, or reports save only locally.
- The UI shows an artifact persistence warning.

Actions:

1. Confirm the user has `admin` or `analyst` role.
2. Confirm `/api/enterprise/artifacts` is reachable.
3. Confirm `NDR_DATA_DIR` is writable in local mode.
4. In DynamoDB mode, confirm the table allows `ENTERPRISE_ARTIFACT` partition writes.
5. Review audit logs for `enterprise.artifact.saved` or related errors.

## Backup And Recovery

### Browser Data

IndexedDB and LocalStorage are local to the analyst browser. Raw evidence caching is opt-in, AES-GCM sealed, session-bound, and purged when disabled; it is not a durable backup. Multi-user deployments should use the backend tenant store for metadata and S3 Object Lock for retained raw evidence.

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
- `detection-rules.json`
- `enterprise-settings.json`
- `enterprise-artifacts.json`
- `export-approvals.json`
- `sessions.json`
- `telemetry-events.json`
- `correlations.json`
- `response-actions.json`
- `content-bundles.json`
- `audit-<tenant>.ndjson`

### DynamoDB Mode

Terraform enables point-in-time recovery and TTL. Confirm restore drills, EFS backup status, and retention with account policy. All application records, including jobs, audit, sessions, approvals, leases, and active-run slots, use tenant-scoped partitions.

### Audit Exports

Terraform creates an S3 Object Lock bucket for immutable audit exports. Retention is controlled by `audit_retention_days`.

### Evidence Packages

Local evidence packages are JSON files under `evidence-packages/<tenant>/`. In AWS, Terraform creates a separate S3 Object Lock bucket for full raw evidence packages. Retention is controlled by `evidence_retention_days` and `evidence_object_lock_mode`.

## Maintenance

Recommended recurring tasks:

- Rotate API keys and OIDC client secrets.
- Rotate session and evidence-attestation secrets using a planned session invalidation and attestation-key rollover procedure.
- Rotate SCIM and service-account secrets, then verify prior values no longer authenticate.
- Review IAM permissions for least privilege.
- Review CloudWatch log retention.
- Confirm DynamoDB point-in-time recovery remains enabled.
- Confirm evidence package retention and Object Lock mode match policy.
- Review Firehose failures, Glue schema drift, analytics lifecycle, and Security Lake subscriber access.
- Review Organizations account inventory, member-role trust, and stale source ownership.
- Review enterprise artifacts for stale threat-intel imports, unfinished playbooks, old reports, and vault bundles nearing retention deadlines.
- Confirm Bedrock model allow-list and approval status.
- Run `npm run check` before deployment.
- Run `npm run readiness:check` and review `/api/enterprise/readiness` before promotion.
- Run `npm audit --audit-level=high`, `npm run visual:test`, CodeQL, dependency review, image scanning, and Terraform validation before deployment.
- Review scheduled job errors.

## Release Checklist

1. Pull latest `main`.
2. Run `npm run check`.
3. Run `npm run build`.
4. Build, scan, attest, and push the container image.
5. Update Terraform `container_image` to the approved `@sha256:` digest.
6. Run Terraform plan.
7. Apply during approved window.
8. Verify health, ready, metrics, auth/session revocation, ownership denial, export/response approval, queue processing and DLQ alarms, signed content rejection/import, telemetry isolation/correlation, Bedrock policy, ALB logs, and immutable audit/evidence writes.
