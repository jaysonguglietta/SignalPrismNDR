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
- API health and metrics.
- S3/CloudWatch ingest when AWS credentials are configured.
- Local scheduled jobs.
- Async CloudWatch/S3 job status polling.
- Local backend audit.
- Local raw evidence package files.
- Optional API key.
- Optional OIDC.
- Optional Bedrock.

## Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

The container exposes port `4173`.

## AWS ECS/Fargate

Terraform lives under `infra/aws/terraform`.

The production path provisions:

- ECR repository.
- ECS Fargate cluster, task, service.
- ALB with health check and optional HTTPS listener.
- EFS access point.
- DynamoDB table.
- Secrets Manager secrets.
- CloudWatch Logs.
- S3 Object Lock audit bucket.
- S3 Object Lock evidence package bucket.
- Task IAM policies.
- Autoscaling.

### Prerequisites

- Existing VPC.
- Public subnets for ALB.
- Private subnets for tasks and EFS.
- Route/NAT access to AWS APIs and OIDC provider.
- ACM certificate for HTTPS.
- Flow log S3 bucket and/or CloudWatch log group.
- Bedrock model access if AI is enabled.

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
  -var='container_image=123456789012.dkr.ecr.us-east-1.amazonaws.com/ndr-flow-console:prod' \
  -var='certificate_arn=arn:aws:acm:us-east-1:123456789012:certificate/...' \
  -var='allowed_ingress_cidrs=["10.0.0.0/8"]'
```

## Auth Deployment Patterns

### Private Local/Internal

- Set `NDR_API_KEY`.
- Restrict network access.
- Use HTTPS if exposed beyond localhost.

### Enterprise SSO

- Configure OIDC issuer, client ID, audience, redirect URI, scopes, and group mappings.
- Store any client secret in Secrets Manager.
- Use HTTPS redirect URIs.

### Production Recommendation

Use OIDC with private subnets, ALB HTTPS, restricted ingress CIDRs, DynamoDB persistence, and task roles.

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

DynamoDB stores tenant-scoped workspaces, cases, evidence-run metadata, managed sources, tenant users, jobs, async job runs, ingest runs, and audit records. Configure `NDR_DEFAULT_TENANT` for API-key deployments and `NDR_TENANT_CLAIM` for OIDC deployments.

## Evidence Package Storage

Local backend mode writes full raw evidence packages to `.ndr-data/evidence-packages/`. Production Terraform creates an S3 bucket with Object Lock enabled and passes these environment variables to the task:

```text
NDR_EVIDENCE_BUCKET=<terraform evidence bucket>
NDR_EVIDENCE_PREFIX=signalprism/evidence-packages
NDR_EVIDENCE_RETENTION_DAYS=90
NDR_EVIDENCE_OBJECT_LOCK_MODE=GOVERNANCE
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

## Post-Deployment Verification

```bash
curl https://<alb-dns-or-domain>/api/health
curl https://<alb-dns-or-domain>/api/ready
curl https://<alb-dns-or-domain>/api/metrics
```

Then validate:

- Login works.
- Role mappings are correct.
- S3 ingest succeeds.
- CloudWatch ingest succeeds.
- Async source/job ingest reports completion or failure.
- Job create/run/delete follows role rules.
- Tenant admin user and source ownership flows work for admins and are blocked for viewers.
- Audit export works for admins.
- Bedrock config reflects expected enabled/disabled state.
