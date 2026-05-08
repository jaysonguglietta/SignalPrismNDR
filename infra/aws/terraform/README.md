# AWS Deployment

This Terraform module provisions a production-oriented AWS path for SignalPrism NDR:

- ECR repository for the container image
- ECS Fargate cluster, task definition, service, and CPU autoscaling
- Application Load Balancer with health checks and optional HTTPS listener
- Encrypted EFS access point mounted at `/mnt/ndr-data`
- DynamoDB table for tenant workspaces, cases, evidence runs, managed sources, jobs, ingest runs, and audit records
- Secrets Manager secrets for `NDR_API_KEY` and optional OIDC client secret
- CloudWatch Logs with configurable retention
- S3 audit bucket with versioning, public access block, encryption, and Object Lock COMPLIANCE retention
- Least-privilege task IAM for S3 flow log read, CloudWatch Logs ingest read, DynamoDB persistence, EFS, Bedrock model invocation, and audit exports

## Deployment Flow

1. Build and push the Docker image to the `ecr_repository_url` output.
2. Set `container_image` to the pushed image URI.
3. Provide existing `vpc_id`, `public_subnet_ids`, and `private_subnet_ids`.
4. Set `api_key_value` and, for SSO, the OIDC variables.
5. Prefer an ACM `certificate_arn` and HTTPS for production.

Example:

```bash
terraform init
terraform apply \
  -var='environment=prod' \
  -var='vpc_id=vpc-...' \
  -var='public_subnet_ids=["subnet-...","subnet-..."]' \
  -var='private_subnet_ids=["subnet-...","subnet-..."]' \
  -var='container_image=123456789012.dkr.ecr.us-east-1.amazonaws.com/ndr-flow-console:prod' \
  -var='certificate_arn=arn:aws:acm:us-east-1:123456789012:certificate/...' \
  -var='oidc_issuer=https://idp.example.com/oauth2/default' \
  -var='oidc_client_id=ndr-flow-console' \
  -var='bedrock_enabled=true' \
  -var='bedrock_model_arns=["arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"]'
```

## Persistence

Production defaults to `NDR_STORE=dynamodb`. Local JSON persistence remains available for development, but DynamoDB should be used for shared environments because it survives task replacement and supports point-in-time recovery. Tenant-scoped objects use `TENANT#<tenantId>#<kind>` partitions.

EFS is still mounted for larger local evidence scratch data and future IndexedDB/API evidence migration work. It is encrypted at rest and mounted with an access point.

## Audit Retention

The app writes append-only audit records with a `retentionUntil` timestamp. The infrastructure also creates an S3 audit bucket with Object Lock COMPLIANCE mode for immutable audit exports. Choose `audit_retention_days` to match your retention policy before production use; reducing Object Lock retention later may not be possible for locked objects.

## Security Notes

- Replace the default `api_key_value` immediately.
- Use private subnets for tasks.
- Restrict `allowed_ingress_cidrs` to corporate/VPN ranges or place the ALB behind stronger perimeter controls.
- Map IdP groups to `admin`, `analyst`, and `viewer` with `admin_group`, `analyst_group`, and `viewer_group`.
- Set `tenant_claim` to the OIDC claim that identifies the tenant or organization boundary.
- Use task roles rather than static AWS keys in production.
- Leave `bedrock_enabled=false` unless the environment is approved for AI-assisted analysis.
- Scope `bedrock_model_arns` to approved foundation model or inference profile ARNs instead of `*`.
