# Demo Script

Use this flow for a 5 to 8 minute product walkthrough.

## 1. Start With The Product

Open `http://localhost:4173`.

Say:

> SignalPrism NDR turns cloud flow logs into an analyst-ready investigation workspace. It is local-first for evidence handling, with backend support for AWS ingest, SSO, audit, and Bedrock.

## 2. Load The Guided Demo

Select `Demo` in the `Investigation` panel.

Show:

- Workspace name.
- Managed AWS sources.
- Overview metrics.
- Priority entities.

## 3. Explain The First Detection

Open `Detections`.

Show:

- Severity.
- Confidence.
- Why it fired.
- Evidence basis.
- Response guidance.

Say:

> The detection card is designed to answer why this matters before an analyst pivots to raw records.

## 4. Tune Detection Policy

Switch between `Strict`, `Balanced`, and `Focused`.

Show how focused mode suppresses lower-confidence noise.

## 5. Pivot To Entity And Topology

Open `Entities`, select the top entity, then open `Topology`.

Show:

- Peer relationships.
- Time replay.
- Internal and external paths.

## 6. Create Or Review A Case

Open `Cases`.

Show the demo case, status, severity, assignee, notes, and audit trail.

## 7. Use AI Assistance

Open `Reports`.

Show Bedrock prompt presets. If Bedrock is disabled, point out the disabled state and explain the feature flag. If enabled, run `Top risk explanation`.

## 8. Export Package

Select `Package`.

Say:

> The package is a portable investigation handoff: detections, observations, top entities, managed sources, cases, summaries, AI output, and bounded evidence samples.

## 9. Close With Deployment

Summarize:

- Local browser analysis.
- Backend AWS ingest.
- OIDC/RBAC.
- DynamoDB persistence.
- ECS/Fargate Terraform.
- S3 Object Lock audit retention.
