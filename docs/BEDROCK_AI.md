# Bedrock AI Assistant

SignalPrism NDR includes an optional AWS Bedrock assistant for natural-language investigation questions and AI-generated summaries.

## Feature Flag

The assistant is disabled by default.

Enable it with:

```bash
NDR_BEDROCK_ENABLED=true
```

Required AWS access:

- Local credentials through `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
- Or an ECS task role in Fargate.

Required IAM action:

```text
bedrock:InvokeModel
```

## Model Configuration

Default:

```text
anthropic.claude-3-haiku-20240307-v1:0
```

Variables:

- `NDR_BEDROCK_REGION`
- `NDR_BEDROCK_MODEL_ID`
- `NDR_BEDROCK_MAX_TOKENS`
- `NDR_BEDROCK_TEMPERATURE`
- `NDR_BEDROCK_MAX_CONTEXT_CHARS`

## How It Works

1. Analyst loads and analyzes evidence in the browser.
2. Browser builds a bounded investigation context containing metrics, top detections, priority entities, paths, application mix, ports, and sample records.
3. Browser sends the context and question to `POST /api/ai/ask`.
4. Backend checks role access.
5. Backend signs a Bedrock Runtime Converse API request with SigV4.
6. Backend returns the generated answer or summary.
7. Backend appends an audit record for the AI invocation.

## Context Boundary

The assistant does not automatically send the entire raw upload. It sends a bounded JSON context capped by `NDR_BEDROCK_MAX_CONTEXT_CHARS`.

Context includes:

- Workspace name.
- Source label.
- Generated timestamp.
- Counts and volume metrics.
- Top detections.
- Observations.
- Priority entities.
- Top applications and ports.
- Internal and external paths.
- Sample filtered records.
- Managed sources.
- Active rule profile.

## Recommended Prompts

Built-in presets:

- Top risk explanation.
- Executive summary.
- Attack path.
- Containment plan.
- Evidence gaps.
- SIEM query ideas.

Custom examples:

- `Which entities should I investigate first and why?`
- `Summarize the likely attack path in this evidence.`
- `What facts support the highest severity detection?`
- `What should I validate before escalating?`
- `What containment actions are reasonable based on the evidence?`
- `Where are the blind spots in this dataset?`

## Security Posture

- Disabled by default.
- Server-side signing keeps AWS credentials out of the browser.
- Backend role checks apply.
- Requests are rate limited with the rest of the API.
- AI invocations are audited.
- Context is truncated.
- Responses should be treated as analyst assistance, not authoritative findings.

## Production Guardrails

- Use approved model IDs only.
- Scope `bedrock_model_arns` in Terraform rather than using `*`.
- Keep the feature disabled in environments not approved for AI-assisted analysis.
- Review data residency and provider terms for the selected model and region.
- Prefer private deployments with OIDC and tenant/role controls.
- Validate AI output before containment, escalation, or customer-facing reporting.

## Failure Modes

- `403`: Bedrock feature flag disabled or insufficient role.
- `500`: missing AWS credentials, IAM deny, model unavailable, or Bedrock service error.
- Empty answer: model returned no text; retry with a narrower prompt.
- Truncated context: increase `NDR_BEDROCK_MAX_CONTEXT_CHARS` only after privacy review.
