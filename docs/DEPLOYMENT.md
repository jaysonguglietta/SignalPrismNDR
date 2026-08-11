# Deployment

## Local Static Mode

Use this mode for browser-only parsing and analysis.

```bash
open index.html
```

Limitations:

- No S3 or CloudWatch ingest.
- No scheduled jobs.
- No backend audit export.
- No OIDC/API-key enforcement.
- No Bedrock assistant.

## Local Backend Mode

```bash
npm start
```

Open `http://localhost:4173`.

This mode enables:

- Static app serving.
- Public API health and admin-protected readiness/metrics.
- Managed-source S3/CloudWatch ingest when AWS credentials are configured.
- Local scheduled jobs.
- Async CloudWatch/S3 job status polling.
- Local backend audit.
- Local raw evidence package files.
- Local enterprise artifact persistence for copilot notes, threat-intel imports, playbook runs, evidence vault bundles, and reports.
- Optional API key.
- Optional OIDC.
- Optional Bedrock.

## Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

The container exposes port `4173`.

Docker Compose sets `HOST=0.0.0.0` so the published port works. Set `NDR_API_KEY` or OIDC variables in `.env`; without auth, backend APIs are denied to non-loopback callers.

The Compose service uses a read-only root filesystem, capability drop, no-new-privileges, bounded processes/memory/CPU, an executable-disabled temporary filesystem, an init process, and a persistent `/data` volume.

## AWS ECS/Fargate

Terraform lives under `infra/aws/terraform`.

The production path provisions:

- ECR repository.
- ECS Fargate cluster with separate replicated API and autoscaled ingest-worker services.
- ALB with health checks, access logs, production HTTPS/deletion protection, and invalid-header dropping.
- AWS WAF managed common rules and per-IP rate limiting.
- Encrypted EFS access point with automatic backups.
- DynamoDB with encryption, PITR, TTL, and scheduler GSI.
- ECS secret injection from existing Secrets Manager ARNs; Terraform does not accept secret plaintext.
- CloudWatch Logs.
- S3 Object Lock audit bucket.
- S3 Object Lock evidence package bucket.
- SQS ingest queue and DLQ with managed encryption, long polling, retry policy, queue-age alarm, and worker queue-depth autoscaling.
- EventBridge response bus and retained archive for approved containment/ticket/notification requests.
- Task IAM policies.
- Autoscaling, Container Insights, and CloudWatch ECS/ALB alarms.

### Prerequisites

- Existing VPC.
- Public subnets for ALB.
- Private subnets for tasks and EFS.
- Route/NAT access to AWS APIs and OIDC provider.
- ACM certificate for HTTPS.
- Flow log S3 bucket and/or CloudWatch log group.
- Bedrock model access if AI is enabled.
- Separate pre-created Secrets Manager values for session signing and evidence attestation; optionally API key and OIDC client secret.
- An offline or controlled Ed25519 signing key pair for detection content. Terraform receives only the base64-encoded public key.
- Terraform `>=1.6` with encrypted remote state and locking configured by the deployment environment.

### Build And Push Image

1. Create/apply Terraform once to get `ecr_repository_url`.
2. Build the container.
3. Push to ECR.
4. Re-apply Terraform with `container_image`.

### Terraform Example

```bash
terraform -chdir=infra/aws/terraform init
terraform -chdir=infra/aws/terraform apply \
  -var='environment=prod' \
  -var='vpc_id=vpc-...' \
  -var='public_subnet_ids=["subnet-...","subnet-..."]' \
  -var='private_subnet_ids=["subnet-...","subnet-..."]' \
  -var='container_image=123456789012.dkr.ecr.us-east-1.amazonaws.com/ndr-flow-console@sha256:<64-hex-digest>' \
  -var='certificate_arn=arn:aws:acm:us-east-1:123456789012:certificate/...' \
  -var='allowed_ingress_cidrs=["10.0.0.0/8"]' \
  -var='api_key_secret_arn=arn:aws:secretsmanager:us-east-1:123456789012:secret:signalprism-api-key-...' \
  -var='session_secret_arn=arn:aws:secretsmanager:us-east-1:123456789012:secret:signalprism-session-...' \
  -var='evidence_attestation_secret_arn=arn:aws:secretsmanager:us-east-1:123456789012:secret:signalprism-attestation-...' \
  -var='detection_content_public_key_b64=<base64-public-key>'
```

## Auth Deployment Patterns

### Private Local/Internal

- Set `NDR_API_KEY`.
- Restrict network access.
- Use HTTPS if exposed beyond localhost.
- Browser API-key login creates an opaque HMAC-protected HttpOnly SameSite session ID backed by the server-side registry; API clients may continue to send `x-ndr-api-key`.

### Enterprise SSO

- Configure OIDC issuer, client ID, audience, redirect URI, scopes, and group mappings.
- Ensure tokens include the configured tenant claim. The backend rejects OIDC tokens without a tenant claim unless `NDR_REQUIRE_OIDC_TENANT_CLAIM=false`.
- Store any client secret in Secrets Manager.
- Use HTTPS redirect URIs.

### Production Recommendation

Use OIDC with private subnets, ALB HTTPS, restricted ingress CIDRs, DynamoDB persistence, task roles, `NDR_PRODUCTION_HARDENING=true`, trusted-proxy handling, immutable audit storage, and separate session/attestation secrets.

Terraform configures `NDR_PROCESS_ROLE=api` on the ALB service and `NDR_PROCESS_ROLE=worker` on the worker service. Both services use the durable SQS queue; production startup rejects a missing queue. The worker is not registered with the ALB and scales from visible queue depth.

The Terraform ALB listener redirects HTTP to HTTPS when `certificate_arn` is set. Without a certificate, keep `allowed_ingress_cidrs` private.

Terraform sets `NDR_SESSION_COOKIE_SECURE=true`, server-side session registration, separate-approver governance, managed-source-only ingest, production startup checks, and bounded tenant quotas. Session and evidence-attestation secret ARNs are required inputs.

Production also sets `NDR_TENANT_DIRECTORY_REQUIRED=true`, limits OIDC sessions to 15 minutes, stores export approval bodies in the KMS-encrypted evidence staging bucket, and refuses local persistence or non-immutable audit configuration. Populate tenant users with their stable IdP subject before enabling SSO. When response execution is enabled, configure `response_verifier_subjects` with independent verifier identities.

Production also enables distributed DynamoDB rate counters, recent MFA step-up for privileged approvals, fail-closed evidence storage/checksum/scan attestation, packet object provenance verification, durable stream retry settings, and daily Bedrock/agent budgets.

## Persistence Deployment Patterns

### Local

Good for development and single-user demos.

```text
NDR_STORE=local
```

### DynamoDB

Recommended for shared deployments.

```text
NDR_STORE=dynamodb
NDR_DDB_TABLE=<table>
```

Enable point-in-time recovery and server-side encryption. Terraform does this by default.

DynamoDB stores tenant-scoped workspaces, cases, evidence-run metadata, managed sources, tenant users, enterprise settings, detection rules, enterprise artifacts, jobs, async job runs, ingest runs, and audit records. Configure `NDR_DEFAULT_TENANT` for API-key deployments and `NDR_TENANT_CLAIM` for OIDC deployments.

Keep `NDR_DDB_GSI_MIGRATION_MODE=dual-read` during upgrade. Backfill legacy items with schema-v2 GSI fields, compare legacy/index counts and sampled IDs, then move to `gsi-only` in a separate reviewed deployment. `legacy-only` is the rollback mode.

The task policy permits DynamoDB deletes only for tenant partitions. Audit APIs remain append-only; session, lease, approval, and run-slot lifecycle records are tenant-scoped and TTL-backed.

## Audit Object Storage

Production Terraform creates an audit bucket with Object Lock enabled and passes:

```text
NDR_AUDIT_BUCKET=<terraform audit bucket>
NDR_AUDIT_PREFIX=signalprism/audit
NDR_AUDIT_OBJECT_LOCK_MODE=COMPLIANCE
NDR_AUDIT_OBJECT_STORAGE_REQUIRED=true
```

With `NDR_AUDIT_OBJECT_STORAGE_REQUIRED=true`, protected actions fail if the immutable audit object cannot be written.

## Evidence Package Storage

Local backend mode writes full raw evidence packages to `.ndr-data/evidence-packages/`. Production Terraform creates an S3 bucket with Object Lock enabled and passes these environment variables to the task:

```text
NDR_EVIDENCE_BUCKET=<terraform evidence bucket>
NDR_EVIDENCE_PREFIX=signalprism/evidence-packages
NDR_EVIDENCE_RETENTION_DAYS=90
NDR_EVIDENCE_OBJECT_LOCK_MODE=GOVERNANCE
NDR_EVIDENCE_STORAGE_REQUIRED=true
NDR_EVIDENCE_CHECKSUM_REQUIRED=true
NDR_EVIDENCE_SCAN_ATTESTATION_REQUIRED=true
NDR_EVIDENCE_SCANNER_SUBJECTS=<scanner-service-subject>
```

Choose retention values before production rollout. Buckets using Object Lock must be created with Object Lock enabled, and reducing locked retention later may be constrained by AWS and your compliance policy.

## Bedrock Deployment

Keep disabled unless approved:

```text
NDR_BEDROCK_ENABLED=false
```

When enabled:

- Scope `bedrock_model_arns`.
- Confirm model availability in `NDR_BEDROCK_REGION`.
- Use task role permissions.
- Audit responses as investigation data.

## Detection Content Signing

Generate and protect an Ed25519 key pair outside Terraform. One OpenSSL-compatible workflow is:

```bash
openssl genpkey -algorithm ED25519 -out detection-content-private.pem
openssl pkey -in detection-content-private.pem -pubout -out detection-content-public.pem
base64 < detection-content-public.pem | tr -d '\n'
npm run content:sign -- unsigned-bundle.json detection-content-private.pem signed-bundle.json
```

Store the private key in an approved signing service or offline release process. Configure only the base64 public key through `detection_content_public_key_b64`. Signed imports enter `test`; a passing test and independent admin are still required for production.

## Response Automation

Terraform creates the response bus and archive. `response_execution_enabled=false` is the safe default. Before enabling it, attach environment-owned EventBridge rules and targets that:

- Allow only expected `actionType` values.
- Validate tenant and target scope against authoritative inventory.
- Deduplicate using `idempotencyKey`/`actionId`.
- Record rollback state and execution outcome in the downstream system.
- Use narrowly scoped target roles for Systems Manager, Network Firewall, IAM, ticketing, or notification actions.

The SignalPrism API does not invoke analyst-provided URLs or accept AWS role ARNs in a response request.

## Post-Deployment Verification

```bash
curl https://<alb-dns-or-domain>/api/health
curl -H 'x-ndr-api-key: <key>' https://<alb-dns-or-domain>/api/ready
curl -H 'x-ndr-api-key: <key>' https://<alb-dns-or-domain>/api/metrics
```

Then validate:

- Login works.
- OIDC discovery issuer mismatch, wrong audience, stale authentication, and revoked sessions are rejected.
- Role mappings are correct.
- Managed-source S3 ingest succeeds.
- Managed-source CloudWatch ingest succeeds.
- A forced evidence-vault failure prevents run success and checkpoint advancement.
- Async source/job ingest reports completion or failure.
- API task replacement does not lose queued work; failed work retries and reaches the DLQ after the configured receive count.
- Queue age and DLQ alarms notify the configured SNS topics.
- CloudTrail/DNS/GuardDuty/Zeek/Suricata normalization and correlation produce tenant-scoped findings.
- Response requests require a different admin and emit only when response execution is enabled.
- Packet, export, and response approvals reject sessions without recent MFA in production.
- Stream partial failures enter retry state, eventually deliver acknowledged records, and expose dead-letter replay state.
- Tampered detection content is rejected and valid content imports into test status.
- Job create/run/delete follows role rules.
- Tenant admin user and source ownership flows work for admins and are blocked for viewers.
- Enterprise artifact creation works for analysts/admins and is read-only for viewers.
- Detection-as-code export, threat-intel import, evidence vault bundle, and stakeholder report flows work.
- Audit export works for admins.
- Bedrock config reflects expected enabled/disabled state.

## Enterprise Platform Deployment

The Terraform stack provisions a customer-managed KMS key, replayable Kinesis telemetry stream, class-specific OCSF Firehose streams, dynamic S3 partitions, Zstandard Parquet conversion, Glue catalog, analytics retention, and direct evidence-upload CORS. The task role is limited to Kinesis/Firehose publish, Organizations list, constrained member-role assume, source read, Object Lock write, and required KMS operations.

Deploy `infra/aws/member-account-role.yaml` to approved AWS accounts through CloudFormation StackSets. Supply the central ECS task role ARN, a unique external ID, exact flow-log bucket/object ARNs, and exact CloudWatch log-group ARNs.

After Terraform apply:

1. Set `direct_upload_allowed_origins` to exact production application origins.
2. Store SCIM and service-account values in Secrets Manager and pass their ARNs.
3. Configure the same external ID in the central stack and member-role trust.
4. Verify Firehose writes `region/accountId/eventDay` Parquet partitions.
5. Query the Glue table with Athena and validate representative Network Activity and Security Finding rows.
6. Register the Parquet zone as an AWS Security Lake custom source if Security Lake owns the target operating model.
7. Exercise connector and response adapters in validation/dry-run mode before enforcement.

`terraform fmt -check -recursive infra/aws/terraform` runs without provider plugins. `terraform validate` requires Terraform 1.6+ and an initialized AWS provider.
