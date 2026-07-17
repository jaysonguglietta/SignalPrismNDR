# API Reference

The backend is implemented in `server.mjs` and serves JSON under `/api/*`.

Every response includes `x-request-id` and a W3C `traceparent`. Clients may provide a safe `x-request-id` and valid version-00 `traceparent`; otherwise the server creates them. Include both identifiers when opening an operations incident.

## Authentication

Public endpoints:

- `GET /api/health`
- `GET /api/auth/config`
- `POST /api/auth/token`
- `GET /api/ai/config`

Protected endpoints require one of:

- An opaque HMAC-protected HttpOnly `signalprism_session` identifier created by API-key or OIDC login. Principal, CSRF, expiry, and revocation state remain server-side. Mutating session-authenticated requests must include `x-ndr-csrf`.
- `x-ndr-api-key: <key>` when `NDR_API_KEY` is set, for API clients.
- `Authorization: Bearer <jwt>` when OIDC is configured, for API clients.
- Loopback-only local development mode when neither API key nor OIDC is configured.

## Roles

- `admin`: all protected endpoints, including tenant roster, source ownership, destructive deletes, and audit export.
- `analyst`: save tenant workspaces, cases, evidence runs, sources, enterprise artifacts, ingest, create jobs, run jobs, export investigations, and use the AI assistant.
- `viewer`: read tenant workspaces, cases, evidence runs, sources, jobs, runs, enterprise settings, detection rules, and enterprise artifacts.

Tenant isolation uses `principal.tenantId`. OIDC tenants come from `NDR_TENANT_CLAIM` with fallback claims and are required by default. API key and local-dev sessions use `NDR_DEFAULT_TENANT`.

## Operational Endpoints

### `GET /api/health`

Public. Returns only backend liveness and server time so load balancers do not expose deployment posture.

Example response:

```json
{
  "ok": true,
  "time": "2026-05-05T12:00:00.000Z"
}
```

### `GET /api/status`

Protected. Available to tenant roles with `detections:read`. Returns the authenticated runtime feature posture used by the UI, including auth mode, persistence, queue, evidence, streaming, Bedrock, and browser-cache policy. It does not return secret values.

### `GET /api/ready`

Protected. Requires `admin`. Returns readiness and storage configuration.

Readiness includes the persistence mode plus evidence package storage settings, including whether packages are written locally or to S3. It intentionally omits local filesystem paths.

### `GET /api/metrics`

Protected. Requires `admin`. Returns Prometheus-style text metrics:

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

## Authentication Endpoints

### `GET /api/auth/config`

Returns OIDC client configuration safe for the browser.

### `POST /api/auth/token`

Exchanges an OIDC authorization code and PKCE verifier for an opaque server-side session. The backend sets an HMAC-protected HttpOnly SameSite session ID and returns the CSRF token needed for mutating requests.

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

### `POST /api/auth/api-key-session`

Exchanges an API key for an opaque server-side session. The raw API key is not stored by the browser after this call.

Request:

```json
{
  "apiKey": "redacted"
}
```

Response:

```json
{
  "ok": true,
  "csrf": "session-csrf-token",
  "expiresAt": "2026-05-05T20:00:00.000Z",
  "principal": {
    "subject": "api-key-session",
    "roles": ["admin"],
    "authType": "api-key-session",
    "tenantId": "default"
  }
}
```

### `POST /api/auth/logout`

Revokes the server-side session record and clears the backend session cookie. Cookie-authenticated requests must include `x-ndr-csrf`.

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
  "contextSha256": "sha256-of-bounded-context",
  "evidenceTrust": "untrusted-data",
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

Protected. Requires `admin` or `analyst`. Infers CloudWatch or S3 ingest from the managed source scope, imports evidence synchronously, stores a raw evidence package, and returns imported text. If a source is assigned to an owner, non-admin analysts can ingest it only when their resolved subject, email, or name matches the owner.

### `POST /api/sources/{id}/ingest-async`

Protected. Requires `admin` or `analyst`. Infers CloudWatch or S3 ingest from the managed source scope, starts a background import, and returns `202` with an async job run. Source ownership rules match synchronous ingest.

### `POST /api/sources/{id}/jobs`

Protected. Requires `admin` or `analyst`. Creates a scheduled ingest job from a managed source. Source ownership rules match direct source ingest.

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

Protected. Requires `admin`. Soft-revokes a tenant roster entry and all matching sessions. The final active tenant admin cannot be revoked or demoted.

### `POST /api/admin/source-owners`

Protected. Requires `admin`. Assigns or clears a managed source owner.

Request:

```json
{
  "sourceId": "source-prod-vpc",
  "ownerId": "tenant-user-1714910400000"
}
```

## Enterprise Endpoints

### `GET /api/enterprise/settings`

Protected. Requires `admin`, `analyst`, or `viewer`. Returns tenant enterprise posture settings for Security Lake, SIEM, governance, and data platform readiness.

### `POST /api/enterprise/settings`

Protected. Requires `admin`. Saves tenant enterprise settings and writes an audit event.

Request:

```json
{
  "securityLake": {
    "bucket": "aws-security-data-lake-us-east-1",
    "prefix": "custom/SignalPrismNDR",
    "region": "us-east-1",
    "format": "ocsf-ndjson"
  },
  "governance": {
    "evidenceRetentionDays": 365,
    "legalHold": false,
    "exportApprovalRequired": true
  },
  "dataPlatform": {
    "analyticsStore": "Security Lake + Athena",
    "queryEngine": "Athena"
  }
}
```

### `GET /api/enterprise/artifacts`

Protected. Requires `admin`, `analyst`, or `viewer`. Returns tenant enterprise artifacts. Use the optional `type` query parameter to filter artifacts such as `COPILOT_NOTE`, `THREAT_INTEL`, `PLAYBOOK_RUN`, `EVIDENCE_VAULT_BUNDLE`, or `ENTERPRISE_REPORT`.

### `POST /api/enterprise/artifacts`

Protected. Requires `admin` or `analyst`. Saves a tenant-scoped enterprise artifact and writes an audit event. This endpoint supports advanced workflows without creating a separate route per artifact type.

Request:

```json
{
  "type": "PLAYBOOK_RUN",
  "title": "Public admin containment - Case 42",
  "status": "active",
  "payload": {
    "caseId": "case-42",
    "steps": []
  }
}
```

### `DELETE /api/enterprise/artifacts/{id}`

Protected. Requires `admin`. Deletes an enterprise artifact and writes an audit event.

### `GET /api/detection-rules`

Protected. Requires `admin`, `analyst`, or `viewer`. Returns tenant detection engineering rules.

### `POST /api/detection-rules`

Protected. Requires `admin` or `analyst`. Creates or updates a tenant detection rule in draft/test state. Client-supplied production approval metadata is ignored.

Request:

```json
{
  "name": "Accepted sensitive lateral access",
  "query": "action:ACCEPT port:5432",
  "severity": "medium",
  "tactic": "Lateral Movement",
  "technique": "Remote Services",
  "attackId": "T1021",
  "status": "test"
}
```

### `POST /api/detection-rules/{id}/promote`

Protected. Requires `admin`. Moves a passing test rule to `production` or a production rule to `retired`. Production requires a passing test, ATT&CK ID, substantive description, and a separate approver when `NDR_REQUIRE_SEPARATE_APPROVER=true`.

### `DELETE /api/detection-rules/{id}`

Protected. Requires `admin`. Deletes a tenant detection rule.

### `GET /api/cases`

Protected. Requires `admin`, `analyst`, or `viewer`. Returns tenant cases.

### `POST /api/cases`

Protected. Requires `admin` or `analyst`. Creates or updates a case and appends case audit history.

### `GET /api/cases/{id}/audit`

Protected. Requires `admin`, `analyst`, or `viewer`. Returns a case audit trail.

### `DELETE /api/cases/{id}`

Protected. Requires `admin`.

### `POST /api/exports/investigation`

Protected. Requires `admin` or `analyst`. When tenant export approval is enabled, the first request returns `202` with a pending approval. A second request with an approved `approvalId` consumes the time-limited approval once and returns the server-stored reviewed payload with tenant/export metadata. Requests beyond the tenant pending-approval quota return `429`.

### `POST /api/exports/security-lake`

Protected. Requires `admin` or `analyst`. Uses the same approval workflow. The browser creates OCSF NDJSON and sends its SHA-256. Approval consumption requires the same `contentSha256`, binding the manifest to the reviewed evidence bytes.

Request:

```json
{
  "recordCount": 1200,
  "findingCount": 8,
  "destination": "s3://aws-security-data-lake-us-east-1/custom/SignalPrismNDR",
  "format": "ocsf-ndjson",
  "accountId": "123456789012",
  "region": "us-east-1",
  "contentSha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

### `GET /api/export-approvals`

Protected. Requires `admin` or `analyst`. Admins see the tenant queue; analysts see only their own requests. Payloads are not returned by the queue API.

### `POST /api/export-approvals/{id}/approve`

Protected. Requires `admin`. Atomically approves a pending request for the configured short consumption window. Cross-tenant approval, self-approval, expired requests, concurrent duplicate approval, and repeated approval are rejected.

## Ingest Endpoints

### `POST /api/ingest/s3`

Protected. Requires `admin` or `analyst`. By default this endpoint accepts a managed `sourceId` so tenant source inventory and ownership are enforced. Arbitrary bucket/prefix payloads require `NDR_ALLOW_DIRECT_INGEST=true`.

Request:

```json
{
  "sourceId": "source-prod-vpc-flowlogs"
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

Protected. Requires `admin` or `analyst`. By default this endpoint accepts a managed `sourceId` so tenant source inventory and ownership are enforced. Arbitrary log group payloads require `NDR_ALLOW_DIRECT_INGEST=true`.

Request:

```json
{
  "sourceId": "source-prod-cloudwatch-flowlogs"
}
```

## Job Endpoints

### `GET /api/jobs`

Protected. Requires `admin`, `analyst`, or `viewer`.

### `POST /api/jobs`

Protected. Requires `admin` or `analyst`. By default jobs are created from a managed `sourceId`; arbitrary direct job configs require `NDR_ALLOW_DIRECT_INGEST=true`.

Request:

```json
{
  "name": "Prod VPC flow import",
  "sourceId": "source-prod-vpc-flowlogs",
  "intervalMinutes": 15,
  "enabled": true
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

### `GET /api/audit/events`

Protected. Requires `admin`. Returns recent tenant audit events for review UI filtering.

Query parameters:

- `limit`: 1 to 500 events. Default `100`.
- `action`: optional case-insensitive action substring filter.
- `actor`: optional case-insensitive actor substring filter.

Example response:

```json
{
  "tenantId": "default",
  "count": 2,
  "events": [
    {
      "id": "1714910400000-a1",
      "createdAt": "2026-05-05T12:00:00.000Z",
      "retentionUntil": "2033-05-03T12:00:00.000Z",
      "action": "case.created",
      "actor": "analyst@example.com",
      "roles": ["analyst"],
      "tenantId": "default",
      "details": {
        "caseId": "case-1714910400000",
        "title": "Suspicious egress"
      }
    }
  ]
}
```

## Enterprise Telemetry And Correlation

### `POST /api/telemetry/events`

Requires `admin` or `analyst`. Accepts up to 1,000 events per request as JSON, JSONL/CEF text, an event array, or an AWS `Records` envelope. Supported formats are `auto`, `cloudtrail`, `route53-dns`, `guardduty`, `zeek`, `suricata`, `azure-nsg`, `azure-activity`, `entra-audit`, `gcp-vpc-flow`, `gcp-audit`, `kubernetes-audit`, `cilium-hubble`, `gigamon`, `extrahop`, and `generic`.

```json
{
  "format": "auto",
  "payload": [{ "eventTime": "2026-07-16T12:00:00Z", "eventSource": "sts.amazonaws.com", "eventName": "AssumeRole" }]
}
```

`GET /api/telemetry/events` is available to all tenant roles and supports an optional `format` query parameter.

### `POST /api/telemetry/correlate`

Requires `admin` or `analyst`. Correlates recent tenant telemetry for authentication spray, privilege-to-network chains, GuardDuty corroboration, suspicious DNS labels, and repeated IDS signatures. `windowMinutes` is bounded from 5 to 1,440. Findings include rule ID, score, ATT&CK mapping, entity, source formats, and evidence event IDs.

`GET /api/correlations` is available to all tenant roles.

## Governed Response

### `POST /api/response-actions`

Requires `admin` or `analyst`. Supported action types are `isolate-entity`, `block-ip`, `disable-access-key`, `restrict-security-group`, `quarantine-workload`, `revoke-session`, `capture-packets`, `create-ticket`, and `notify-soc`. A reason of 10 to 2,000 characters is required. Requests default to `dry-run`; `enforce` still requires independent approval and configured EventBridge execution. `capture-packets` emits a bounded sensor request; the API does not collect packet contents itself.

### `POST /api/response-actions/{id}/approve`

Requires `admin`. The requester cannot approve the same action when separate approval is enabled. Approved actions remain approval-only unless `NDR_RESPONSE_EXECUTION_ENABLED=true`; when enabled, the backend emits a bounded event with an idempotency key to the configured EventBridge bus. It never calls analyst-supplied webhook URLs.

`GET /api/response-actions` is available to all tenant roles.

## Signed Detection Content

- `POST /api/detection-content/verify`: `admin` or `analyst`; verifies manifest hash and Ed25519 signature.
- `POST /api/detection-content/import`: `admin`; imports verified rules into `test` status without trusted backtest evidence. It cannot overwrite a production rule.
- `GET /api/detection-content/bundles`: all tenant roles; returns imported bundle metadata without private keys.

Production promotion remains a separate admin action and retains the test-evidence and independent-approver requirements.

## Enterprise Readiness

`GET /api/enterprise/readiness` returns tenant and deployment controls for OIDC, DynamoDB, SQS, Object Lock, secure cookies, managed ingest, separate approval, signed content, response automation, OCSF streaming, SCIM, Organizations discovery, source ownership, and tested production rules.

## Enterprise Platform API

### Streaming and OCSF

- `GET /api/stream/status`: all tenant roles; reports local or Firehose mode and supported formats.
- `POST /api/stream/events`: `admin` or `analyst`; creates a deterministic tenant outbox, normalizes and policy-processes the events, stores them, maps to OCSF, and dispatches up to 1,000 events idempotently.
- `GET /api/stream/deliveries`: all tenant roles; lists bounded outbox state including pending, delivering, delivered, preview, and dead-letter records.
- `POST /api/stream/deliveries/{id}/replay`: `admin` or `analyst`; resets one tenant dead-letter delivery for controlled retry without duplicating already acknowledged records.
- `POST /api/security-lake/publish`: `admin` or `analyst`; builds tenant OCSF Network Activity and Security Finding records. Export approval applies. With Firehose configured, records are dispatched in batches of 500; otherwise a validated preview is returned.

Native streaming defaults to the `native-current` OCSF 1.8 profile. Security Lake publication defaults to `security-lake-1.3`, separates event classes into different delivery streams, sorts records by event time, and declares Zstandard and five-minute/size-aware delivery requirements.

### Advanced detection operations

- `GET /api/operations/summary`: all tenant roles; returns urgency, source health, temporal entity graph, seasonal behavior, encrypted/protocol analytics, exposure paths, telemetry economics, deployment posture, and SLA breaches.
- `POST /api/operations/analyze`: `admin` or `analyst`; runs and persists the deterministic advanced-analysis snapshot.
- `GET /api/schema/profiles`: all tenant roles; returns native OCSF 1.8, Security Lake OCSF 1.3, and migration-only 1.4 profiles.
- `POST /api/schema/validate`: `admin` or `analyst`; validates a bounded tenant batch against one selected profile and reports class batches and rejected records.
- `GET /api/security-lake/sources`: all tenant roles; lists class-specific Security Lake source registrations.
- `POST /api/security-lake/sources/register`: `admin`; stores the Security Lake-assigned prefix and provider account/external identity and creates one OCSF 1.3 record per event class.
- `GET /api/streams/control`: all tenant roles; reports Kinesis/MSK/Firehose/local mode, replay limits, quotas, lag, and backpressure policy.
- `POST /api/streams/replay`: `admin` or `analyst`; builds a time-ordered, bounded replay preview or dispatches it when explicitly requested.
- `GET|POST /api/search/jobs`: tenant read and analyst write; executes and persists a bounded interactive hunt. `opensearch` mode signs tenant-filtered AWS OpenSearch/OpenSearch Serverless queries with the task role; local mode uses the deterministic bounded query engine. ClickHouse mode fails closed until its separate query bridge is deployed.
- `GET|POST /api/sensors`: tenant read and admin write; manages packet/protocol sensor health inventory.
- `GET|POST /api/packet-manifests`: tenant read and analyst write; creates immutable, SHA-256-bound packet manifests.
- `POST /api/packet-manifests/:id/authorize`: admin; creates a separate, reason-bound, expiring packet access grant. The manifest creator cannot approve access when separate approval is enabled.
- `GET|POST /api/response-policy`: tenant read and admin write; controls observe/approve/enforce mode, allowed adapters, linked-case and rollback requirements, and verification window.
- `POST /api/response-policy/kill-switch`: admin; immediately changes the tenant response kill switch.
- `GET|POST /api/threat-intel/feeds`: tenant read and analyst write; stores bounded indicators with provider, TLP, confidence, and expiry metadata.
- `POST /api/threat-intel/retromatch`: `admin` or `analyst`; matches active indicators against historical event fields and persists sightings.
- `GET|POST /api/case-tasks`: tenant read and analyst write; manages case tasks, assignees, watchers, due dates, and escalation policy.
- `GET|POST /api/pipeline-policy`, `/api/exposure-context`, `/api/regional-cells`, `/api/provider-workspaces`, and `/api/notification-policies`: tenant read and admin write for enforced deduplication/masking/tiering, vulnerability/IAM/route/security-group context, residency/failover, MDR workspace, and notification resources.
- `GET|POST /api/agent/evaluations`: tenant read and analyst write; scores citations, unsupported claims, approval-gated tools, and tenant scope.

Telemetry formats also include `azure-nsg`, `azure-activity`, `entra-audit`, `gcp-vpc-flow`, `gcp-audit`, `kubernetes-audit`, `cilium-hubble`, `gigamon`, and `extrahop`. CEF lines are normalized as Gigamon-compatible sensor records.

### Analytics and hunts

- `GET|POST /api/analytics/behavior`: read or recompute baseline-aware entity profiles and deviations.
- `GET /api/campaigns` and `POST /api/campaigns/build`: list or assemble linked campaigns.
- `GET|POST /api/hunts/retrospective`: list or execute safe historical hunts.
- `POST /api/detection-rules/{id}/backtest`: evaluate a rule and optional labeled evidence.
- `GET|POST /api/governance/traffic-posture`: list or compute AI service and cryptography posture.

### Investigation agent

- `GET /api/ai/investigations`: list tenant runs.
- `POST /api/ai/investigate`: run deterministic collection, ranking, campaign context, optional hunt, citations, and optional Bedrock synthesis.
- `POST /api/ai/investigations/{id}/feedback`: save `helpful` or `not-helpful` feedback.

The daily tenant quota is controlled by `NDR_MAX_AI_AGENT_RUNS_PER_DAY`.

### Connectors and evidence

- `GET /api/connectors/catalog` and `GET /api/connectors`: all tenant roles.
- `POST|DELETE /api/connectors[/{id}]` and `POST /api/connectors/{id}/test`: `admin` only.
- `GET /api/evidence-uploads`: all tenant roles.
- `POST /api/evidence-uploads` and `POST /api/evidence-uploads/{id}/complete`: `admin` or `analyst`.
- `POST /api/evidence-uploads/{id}/scan`: a restrictive scanner service identity from `NDR_EVIDENCE_SCANNER_SUBJECTS` with `evidence:scan`; accepts `outcome` (`clean`, `infected`, or `error`), engine, version, timestamp, nonce, and HMAC signature. In production the signature is required and is bound to tenant, upload, bucket, key, staging version, SHA-256, outcome, engine, scanner version, time, and nonce. The uploader cannot attest its own scan. Only a clean, fresh, non-replayed attestation triggers a version-pinned copy and post-copy verification in the immutable vault.

Only Secrets Manager ARNs may be stored as connector secret references. Connector tests validate locally or emit EventBridge adapter intent; the API never sends requests to connector endpoints.

### Organizations and identity

- `GET /api/organization/accounts`, `POST /api/organization/discover`, and `POST /api/organization/accounts/{id}/onboard` manage cross-account source inventory. Mutations require `admin`.
- `GET|POST /api/admin/roles` and `DELETE /api/admin/roles/{id}` manage custom roles.
- `GET|POST /api/admin/service-accounts`, `POST /api/admin/service-accounts/{id}/rotate`, and `DELETE /api/admin/service-accounts/{id}` manage non-human identities.
- `/scim/v2` exposes SCIM 2.0 discovery, groups, and user lifecycle endpoints under a dedicated bearer token.

### Response lifecycle

- `GET /api/response-adapters`: lists supported intent adapters.
- `POST /api/response-actions/{id}/verify`: stores validation outcome and evidence.
- `POST /api/response-actions/{id}/rollback`: `admin`; creates a separately approved rollback action for reversible adapters.

Response requests accept `executionMode` (`dry-run` or `enforce`), `expiresInMinutes`, and optional `rollbackPlan`. New intents include `restrict-security-group`, `quarantine-workload`, `revoke-session`, and time-bounded `capture-packets` requests.

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
- `413`: request, AWS response, or imported evidence text exceeded configured limits.
- `429`: rate limit exceeded.
- `502`: upstream AWS/service request failed.
- `503`: backend AWS credentials are unavailable.
