# Product Brief

## Product

**SignalPrism NDR** is a Network Detection and Response application for cloud flow telemetry. It ingests AWS VPC Flow Logs from upload, paste, S3, or CloudWatch Logs, normalizes records in the browser, detects suspicious traffic patterns, ranks risky entities, supports investigation workflows, and optionally uses AWS Bedrock for natural-language investigation assistance.

## Target Users

- SOC analysts who triage cloud network activity.
- Cloud security engineers validating VPC flow log coverage and segmentation.
- Detection engineers tuning NDR logic, hunt queries, and SIEM exports.
- Security managers who need concise investigation summaries and evidence exports.
- Platform teams deploying a private, cloud-native security workbench.

## Core Problem

VPC flow logs are high-volume, difficult to inspect manually, and often disconnected from analyst workflows. Teams need a practical way to upload or ingest flow evidence, detect suspicious behavior, preserve context, create cases, and export useful summaries without building a full SIEM pipeline first.

## Primary Outcome

An analyst can load flow evidence, understand what matters, pivot through affected entities and paths, create or update cases, ask natural-language questions when Bedrock is enabled, and export defensible investigation artifacts.

## Primary Workflows

1. **Evidence Intake**
   Upload, paste, or ingest logs from S3/CloudWatch, then validate parse quality.

2. **Triage**
   Review risk metrics, detections, observations, entity risk, ports, protocols, rejects, and traffic over time.

3. **Investigation**
   Pivot to entity detail, topology, raw records, and saved hunt queries.

4. **Case Management**
   Create cases, assign owners, override severity, record notes, and view case audit history.

5. **Reporting And Export**
   Generate analyst summaries, policy recommendations, redacted records, OCSF-like JSON, CEF, CSV, and optional Bedrock summaries.

6. **Continuous Ingest**
   Configure protected S3 or CloudWatch ingest jobs and run them manually or on a schedule.

## Main Screens

- **Overview**: risk metrics, timeline, priority entities, top destination ports.
- **Detections**: severity-filtered detection queue with response guidance and linked evidence.
- **Entities**: entity risk list, entity timeline, peer relationships, and traffic detail.
- **Records**: searchable, sortable normalized evidence table.
- **Hunt**: fielded query workflow with saved hunts.
- **Coverage**: expected source coverage, blind spots, history, and baselines.
- **Pipeline**: enrichment, cloud ingest, scheduled jobs, application intelligence, traffic optimization.
- **Cases**: case intake, queue, notes, severity override, and audit log.
- **Topology**: entity-to-entity path map with replay slider.
- **Reports**: Bedrock assistant, analyst summary, policy recommendations, and privacy exports.

## User Roles

- `admin`: full backend access, job deletion, audit export, ingest, and AI assistant.
- `analyst`: ingest, scheduled job creation, job execution, read access, and AI assistant.
- `viewer`: read access and AI assistant, without mutating ingest schedules.

Local development runs as `local-dev` admin when neither API key nor OIDC is configured.

## Key Data Models

- `FlowRecord`: normalized network flow evidence.
- `Detection`: rule output with severity, tactic, technique, confidence, entity, response guidance, and linked evidence.
- `EntityRisk`: ranked entity score with peers, ports, rejects, bytes, packets, and linked findings.
- `Path`: ranked source-to-destination path.
- `Hunt`: saved query and result history.
- `CoverageSource`: expected ENI/CIDR/source metadata.
- `CaseRecord`: title, assignee, status, severity, notes, related detection.
- `AuditRecord`: append-only actor/action/detail with retention metadata.
- `IngestJob`: scheduled S3 or CloudWatch import configuration.

## Important Edge Cases

- Empty uploads, malformed rows, mixed formats, and partial parser failures.
- Gzipped files in browsers without `DecompressionStream`.
- Large evidence sets that should stay bounded in browser memory.
- Missing AWS credentials, disabled Bedrock, or insufficient IAM permissions.
- Expired OIDC tokens or unmapped identity-provider groups.
- Scheduled jobs that fail because source buckets/log groups change.
- Audit export and retention expectations in regulated environments.

## Assumptions

- AWS is the first-class cloud provider.
- Browser-side analysis is acceptable for the first production-shaped version.
- Shared deployments run privately behind HTTPS with API key or OIDC.
- DynamoDB is the preferred cloud persistence option for jobs, runs, and audit records.
- Bedrock is opt-in and disabled by default.

## Done For This Version

- Usable analyst UI across desktop and mobile.
- Local upload/paste analysis.
- S3 and CloudWatch ingest backend with SigV4.
- Scheduled ingest jobs.
- IndexedDB evidence/case persistence.
- Case management and case audit history.
- OIDC/API-key backend access controls.
- DynamoDB persistence option.
- Append-only audit export.
- Bedrock feature flag and AI assistant.
- ECS/Fargate Terraform production path.
- Smoke and integration checks.
