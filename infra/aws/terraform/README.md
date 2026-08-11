# AWS Deployment

This Terraform module provisions a production-oriented AWS path for SignalPrism NDR:

- ECR repository for the container image
- ECS Fargate cluster with replicated API service, separate ingest-worker service, CPU autoscaling, and queue-depth worker autoscaling
- Application Load Balancer with health checks, access logs, invalid-header dropping, production deletion protection, required production HTTPS, and HTTP-to-HTTPS redirect
- AWS WAF managed common rules and per-IP rate limiting
- Encrypted EFS access point mounted at `/mnt/ndr-data`
- DynamoDB table with PITR, TTL, global scheduler discovery, and tenant-bounded listing indexes for tenant data, sessions, leases, approvals, jobs, ingest runs, and audit records
- Existing Secrets Manager ARNs injected into ECS without placing secret values in Terraform state
- CloudWatch Logs, ECS/ALB alarms, Container Insights, and configurable alarm destinations
- S3 audit bucket with versioning, public access block, encryption, and Object Lock COMPLIANCE retention
- S3 evidence package bucket with versioning, public access block, encryption, and configurable Object Lock retention
- Customer-managed KMS key for DynamoDB, queues, EFS, audit, evidence, and analytics data
- Replayable Kinesis telemetry stream plus class-specific OCSF 1.3 Data Firehose streams with dynamic region/account/day partitions, Zstandard Parquet conversion, Glue catalog, and lifecycle-managed analytics bucket
- Exact-origin CORS support for signed browser-to-S3 immutable evidence uploads
- SQS ingest queue and DLQ with managed encryption, retry policy, long polling, age/dead-letter alarms, and durable API-to-worker handoff
- EventBridge Scheduler role and durable per-source schedules targeting the ingest queue
- Short-lived encrypted evidence quarantine bucket; production uploads require external clean-scan attestation before copy into the Object Lock evidence vault
- EventBridge response bus and retained archive for independently approved containment actions
- Read-only, non-root ECS task with dropped Linux capabilities and narrowed HTTPS/DNS/EFS/credential-endpoint egress
- Least-privilege task IAM for S3 flow log read, CloudWatch Logs ingest read, DynamoDB persistence/index queries, SQS work, EventBridge approved-response emission, evidence package writes, immutable audit object writes, EFS, and Bedrock model invocation

## Deployment Flow

1. Build and push the Docker image to the `ecr_repository_url` output.
2. Set `container_image` to the pushed image URI.
3. Provide existing `vpc_id`, `public_subnet_ids`, and `private_subnet_ids`.
4. Create separate Secrets Manager values for session signing and evidence attestation, plus API key and OIDC client secret when used. Pass only their ARNs.
5. Configure `detection_content_public_key_b64` with the trusted Ed25519 public key. Keep the private key outside the application and Terraform state.
6. Use an ACM `certificate_arn` and an image URI pinned by `@sha256:<digest>` for production; Terraform rejects a production plan without them.
7. Deploy `../member-account-role.yaml` through StackSets before enabling Organizations onboarding. Use exact source ARNs and a unique external ID.

Example:

```bash
terraform init
terraform apply \
  -var='environment=prod' \
  -var='vpc_id=vpc-...' \
  -var='public_subnet_ids=["subnet-...","subnet-..."]' \
  -var='private_subnet_ids=["subnet-...","subnet-..."]' \
  -var='container_image=123456789012.dkr.ecr.us-east-1.amazonaws.com/ndr-flow-console@sha256:<64-hex-digest>' \
  -var='certificate_arn=arn:aws:acm:us-east-1:123456789012:certificate/...' \
  -var='api_key_secret_arn=arn:aws:secretsmanager:us-east-1:123456789012:secret:signalprism-api-key-...' \
  -var='session_secret_arn=arn:aws:secretsmanager:us-east-1:123456789012:secret:signalprism-session-...' \
  -var='evidence_attestation_secret_arn=arn:aws:secretsmanager:us-east-1:123456789012:secret:signalprism-attestation-...' \
  -var='oidc_issuer=https://idp.example.com/oauth2/default' \
  -var='oidc_client_id=ndr-flow-console' \
  -var='bedrock_enabled=true' \
  -var='bedrock_model_arns=["arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"]' \
  -var='detection_content_public_key_b64=<base64-public-key>'
```

## Persistence

Production defaults to `NDR_STORE=dynamodb`. Local JSON persistence remains available for development, but DynamoDB should be used for shared environments because it survives task replacement and supports point-in-time recovery. Tenant-scoped objects use `TENANT#<tenantId>#<kind>` partitions for workspaces, cases, evidence metadata, managed sources, tenant users, detection rules, enterprise settings, enterprise artifacts, and async job runs.

The table enables TTL for sessions and run slots, `kind-createdAt-index` for cross-tenant scheduler discovery/legacy recovery, and `tenant-kind-createdAt-index` for newest-first tenant object reads. EventBridge Scheduler owns production cadence, conditional run slots enforce per-tenant async concurrency, and SQS preserves queued imports across API/worker replacement. Workers extend message visibility during long imports. Failed messages move to the DLQ after `queue_max_receive_count` attempts.

## Response Automation Boundary

`response_execution_enabled` defaults to `false`. When enabled, approved actions are emitted to the Terraform-created EventBridge bus and archived. Attach customer-owned rules and targets with dedicated least-privilege roles. Targets must validate scope and deduplicate using the supplied action ID; SignalPrism never executes analyst-provided webhook URLs.

EFS is still mounted for local scratch data and fallback package storage. It is encrypted at rest and mounted with an access point.

## Audit Retention

The app writes append-only audit records with a `retentionUntil` timestamp and, in this Terraform deployment, writes each audit event to the audit bucket with Object Lock COMPLIANCE headers. `NDR_AUDIT_OBJECT_STORAGE_REQUIRED=true` makes protected actions fail closed if the immutable audit write fails. Choose `audit_retention_days` to match your retention policy before production use; reducing Object Lock retention later may not be possible for locked objects.

## Evidence Package Retention

The app writes full raw evidence packages to the evidence bucket when `NDR_EVIDENCE_BUCKET` is configured. Terraform creates that bucket with Object Lock enabled, versioning, public access block, and SSE-S3 encryption. The task receives:

- `NDR_EVIDENCE_BUCKET`
- `NDR_EVIDENCE_PREFIX`
- `NDR_EVIDENCE_REGION`
- `NDR_EVIDENCE_RETENTION_DAYS`
- `NDR_EVIDENCE_OBJECT_LOCK_MODE`
- `NDR_EVIDENCE_STAGING_BUCKET`
- `NDR_EVIDENCE_SCAN_REQUIRED=true`

Choose `evidence_retention_days` and `evidence_object_lock_mode` before production use. `GOVERNANCE` is the default; `COMPLIANCE` should be reserved for environments where immutable retention policy has been formally approved.

Uploaded objects first land in the versioned quarantine bucket. Completion requires the declared length, S3 SHA-256 checksum, and staging version. A subject listed in `evidence_scanner_subjects` signs an attestation over the exact tenant, upload, bucket, key, version, hash, outcome, engine, scanner version, time, and nonce. Only a fresh `clean` attestation triggers a version-pinned copy; the vault checksum/length/version is reverified before the exact staging version is deleted. The scanner itself is deliberately deployment-owned and is not shipped in this repository.

## Security Notes

- Create secrets outside Terraform and pass only `api_key_secret_arn`, `session_secret_arn`, `evidence_attestation_secret_arn`, and optional `oidc_client_secret_arn`. This prevents plaintext secret values from being persisted in Terraform state.
- Session and evidence-attestation secrets must be separate random values of at least 32 characters. API keys must be at least 24 characters in production hardening mode.
- Use private subnets for tasks.
- Restrict `allowed_ingress_cidrs` to corporate/VPN ranges or place the ALB behind stronger perimeter controls.
- Map IdP groups to `admin`, `analyst`, and `viewer` with `admin_group`, `analyst_group`, and `viewer_group`.
- Set `tenant_claim` to the OIDC claim that identifies the tenant or organization boundary.
- Require IdP MFA and preserve `amr`, `acr`, and `auth_time` claims so production packet/export/response approvals can enforce recent step-up.
- Use task roles rather than static AWS keys in production.
- Keep `ddb_gsi_migration_mode=dual-read` through schema-v2 backfill and completeness validation; change to `gsi-only` only in a separately reviewed rollout.
- Confirm evidence and audit retention settings before storing regulated evidence.
- Leave `bedrock_enabled=false` unless the environment is approved for AI-assisted analysis.
- Scope `bedrock_model_arns` to approved foundation model or inference profile ARNs instead of `*`.
- Empty `dns_resolver_cidrs` automatically uses the selected VPC resolver. Restrict `https_egress_cidrs` to an egress proxy or approved endpoint CIDRs; production rejects unrestricted HTTPS unless `production_allow_unrestricted_https_egress=true` records explicit acceptance. Attach `alarm_topic_arns` and prefer VPC endpoints for AWS API traffic.
- Set `alb_internal=true` for VPN, Direct Connect, or private-access deployments.
- `NDR_PLATFORM_KMS_KEY_ARN` identifies the stack-managed key. Set `tenant_byok_key_arn` only for a genuinely tenant-provided/imported key; this controls the reported BYOK posture.
- Store Terraform state in an encrypted, versioned remote backend with locking and tightly scoped access. Backend configuration is intentionally environment-specific and is not embedded in this module.
