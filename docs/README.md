# SignalPrism NDR Documentation

SignalPrism NDR is a cloud-ready Network Detection and Response workbench for AWS VPC Flow Logs and adjacent flow telemetry. It helps analysts turn raw network evidence into detections, entity risk, topology paths, cases, exports, and optional AWS Bedrock-assisted summaries.

## Documentation Map

- [Product Brief](PRODUCT_BRIEF.md): target users, outcomes, workflows, acceptance criteria.
- [User Guide](USER_GUIDE.md): how analysts upload evidence, triage detections, hunt, manage cases, and export reports.
- [Architecture](ARCHITECTURE.md): frontend, backend, persistence, AWS integrations, and deployment shape.
- [API Reference](API.md): backend endpoints, authentication, request examples, and role requirements.
- [Configuration](CONFIGURATION.md): environment variables and local/cloud configuration patterns.
- [Data And Detections](DATA_AND_DETECTIONS.md): supported inputs, normalized models, detection logic, and export formats.
- [Bedrock AI Assistant](BEDROCK_AI.md): feature flag, prompt boundary, IAM, security posture, and usage.
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
