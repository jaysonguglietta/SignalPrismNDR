# Contributing

Thanks for improving SignalPrism NDR. This repository is intentionally lightweight and dependency-free, so contributions should preserve clarity and operational safety.

## Local Setup

```bash
npm start
```

Open `http://localhost:4173`.

Run checks:

```bash
npm run check
```

## Contribution Guidelines

- Keep raw evidence local unless a backend workflow explicitly requires upload.
- Keep AWS credentials and secrets out of browser code.
- Keep UI controls functional or clearly disabled.
- Add error states for new workflows.
- Preserve accessibility basics: labels, keyboard access, focus states, and semantic HTML.
- Avoid committing `.env`, `.ndr-data/`, Terraform state, `dist/`, or generated logs.
- Update documentation for user-visible or operational changes.

## Pull Request Checklist

- [ ] `npm run check` passes.
- [ ] `npm run build` passes when frontend/static assets changed.
- [ ] Docs are updated when behavior, configuration, APIs, or deployment changes.
- [ ] Security implications are noted for auth, data handling, AI, or AWS/IAM changes.
- [ ] New backend endpoints include role checks.
- [ ] New destructive actions require confirmation in the UI.

## Commit Style

Use concise, imperative commit messages:

```text
Add Bedrock assistant docs
Fix CloudWatch ingest validation
Update ECS Terraform outputs
```

## Security Issues

Do not open public issues for secrets, auth bypasses, or data exposure concerns. Use the security reporting process in [SECURITY.md](SECURITY.md).
