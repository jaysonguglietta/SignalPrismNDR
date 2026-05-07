# Changelog

All notable changes to SignalPrism NDR are tracked here.

## Unreleased

### Added

- Local investigation workspaces with evidence snapshot restore.
- Guided demo mode with sample evidence, managed sources, prompt preset, and starter case.
- Detection explainability blocks for why it fired, evidence basis, and confidence interpretation.
- Detection policy profiles for strict, balanced, and focused triage.
- Managed source inventory fields for source type, account/owner, region, ENIs, CIDRs, log groups, and prefixes.
- Bedrock assistant prompt presets.
- Portable investigation package export.
- Demo script documentation.

## 0.2.0 - 2026-05-05

### Added

- SignalPrism NDR product identity and logo.
- Browser-based VPC Flow Log upload, paste, parsing, and analysis.
- AWS, Azure NSG, GCP VPC, CloudWatch JSON, CSV, and gzipped input support.
- NDR overview, detections, entities, records, hunt, coverage, pipeline, cases, topology, and reports views.
- Entity risk scoring, topology replay, saved hunts, coverage baselines, enrichment, and traffic optimization simulator.
- Case management with status, assignee, severity override, notes, and local audit trail.
- S3 and CloudWatch backend ingest with SigV4 signing.
- Scheduled ingest jobs.
- API key auth, OIDC/SSO, RBAC, rate limiting, security headers, metrics, health, and readiness endpoints.
- DynamoDB-backed persistence option for backend jobs, runs, and audit records.
- Append-only audit export and retention metadata.
- Feature-flagged AWS Bedrock AI assistant for natural-language questions and summaries.
- ECS/Fargate Terraform with ALB, EFS, Secrets Manager, DynamoDB, autoscaling, and S3 Object Lock audit bucket.
- Smoke and integration checks.
- Comprehensive documentation set under `docs/`.

### Notes

- Bedrock is disabled by default.
- Local backend storage defaults to `.ndr-data/`.
- Generated `dist/` output is intentionally ignored by Git.
