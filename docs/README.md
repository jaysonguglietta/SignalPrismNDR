# SignalPrism NDR Documentation

SignalPrism NDR is a cloud-ready Network Detection and Response workbench for AWS VPC Flow Logs and adjacent flow telemetry. It helps analysts turn raw network evidence into detections, entity risk, topology paths, cases, evidence-cited answers, playbooks, retained artifacts, exports, and optional AWS Bedrock-assisted summaries.

## Documentation Map

- [Product Brief](PRODUCT_BRIEF.md): target users, outcomes, workflows, acceptance criteria.
- [User Guide](USER_GUIDE.md): how analysts upload evidence, triage detections, hunt, use enterprise workflows, manage cases, administer tenants, and export reports.
- [Architecture](ARCHITECTURE.md): frontend, backend, persistence, AWS integrations, and deployment shape.
- [API Reference](API.md): backend endpoints, authentication, request examples, and role requirements.
- [Configuration](CONFIGURATION.md): environment variables and local/cloud configuration patterns.
- [Data And Detections](DATA_AND_DETECTIONS.md): supported inputs, normalized models, detection logic, and export formats.
- [Bedrock AI Assistant](BEDROCK_AI.md): feature flag, prompt boundary, IAM, security posture, and usage.
- [Security Hardening](SECURITY_HARDENING.md): trust boundaries, implemented controls, production gate, tests, and residual risks.
- [Security Remediation Record](SECURITY_REMEDIATION_2026-07-17.md): closure evidence for the twelve deep-dive findings and additional hardening.
- [Threat Model](THREAT_MODEL.md): protected assets, attacker personas, abuse cases, controls, and validation ownership.
- [Deep-Dive Review](DEEP_DIVE_REVIEW_2026-07-17.md): historical adversarial product, architecture, and security assessment.
- [Enterprise Platform](ENTERPRISE_PLATFORM.md): behavior analytics, campaigns, OCSF streaming, cross-account onboarding, SCIM, service accounts, connectors, response adapters, and rollout guidance.
- [2026 Competitive Gap Analysis](COMPETITIVE_GAP_ANALYSIS_2026.md): evidence-based comparison with NDR leaders and a prioritized enterprise feature roadmap.
- [Deployment](DEPLOYMENT.md): local, Docker, and AWS ECS/Fargate deployment flows.
- [Operations Runbook](OPERATIONS_RUNBOOK.md): health checks, metrics, incidents, backups, and maintenance.
- [Developer Guide](DEVELOPER_GUIDE.md): repository layout, scripts, testing, coding conventions, and release workflow.
- [Demo Script](DEMO_SCRIPT.md): guided walkthrough for evaluators, clients, and stakeholders.

Additional top-level docs:

- [README](../README.md): quick start and feature overview.
- [SECURITY](../SECURITY.md): security guidance and production recommendations.
- [CONTRIBUTING](../CONTRIBUTING.md): contribution workflow.
- [CHANGELOG](../CHANGELOG.md): release history.

## Quick Start

```bash
npm start
```

Open `http://localhost:4173`.

Run all checks:

```bash
npm run check
```

Build the dependency-free distributable:

```bash
npm run build
```
