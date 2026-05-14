# User Guide

## First Run

Start the backend-enabled app:

```bash
npm start
```

Open `http://localhost:4173`.

For file-only local analysis, open `index.html` directly in a browser. Tenant persistence, cloud ingest, jobs, SSO, controlled exports, audit export, and Bedrock require the backend.

## Guided Demo

Select `Demo` in the `Investigation` panel to load a complete sample investigation. The demo:

- Loads realistic VPC flow evidence.
- Saves a demo workspace.
- Adds managed AWS sources.
- Runs the analysis.
- Creates a starter case from the top detection.
- Selects a useful Bedrock prompt preset.

Use this when evaluating the product or presenting it to stakeholders.

## Investigation Workspaces

The `Investigation` panel stores repeatable workspaces. With the backend running, workspaces are saved to the tenant store. Without the backend, the browser uses local fallback storage. A workspace can retain:

- Name and source file label.
- Evidence text snapshot.
- Detection counts and risk summary.
- Managed source inventory.
- Saved hunts.
- Enrichment.
- Rule profile.

When the backend is available, saved evidence runs also create a raw evidence package. Local mode stores package JSON under `.ndr-data/evidence-packages/`; S3 mode stores package JSON in the configured evidence bucket with retention metadata.

Controls:

- `New`: starts a draft workspace.
- `Save`: stores or updates the current workspace.
- `Package`: exports the current investigation package.
- Workspace selector: restores saved workspace metadata and evidence when available.

## Load Evidence

Use one of these intake paths:

- Drag a `.log`, `.txt`, `.csv`, `.gz`, `.json`, or `.jsonl` file into the upload area.
- Paste flow log text and select `Analyze`.
- Select `Sample` to load realistic sample evidence.
- Use `Pipeline > Cloud ingest` to import from S3 or CloudWatch Logs.

After loading evidence, check `Import Quality` for skipped rows or malformed fields.

## Triage The Overview

The `Overview` tab shows:

- NDR risk score.
- Total detections.
- Entity count.
- Rejected flow volume.
- Data volume and packet count.
- Traffic timeline.
- Priority entities.
- Top destination ports.

Start with high-severity detections and priority entities with elevated rejects, sensitive ports, or high byte volume.

## Investigate Detections

Open `Detections` to filter by severity and review:

- Title and severity.
- Tactic and technique.
- Confidence.
- Affected entity.
- Response guidance.
- Linked evidence.
- Why the detection fired.
- Evidence basis.
- Confidence interpretation.

Use `Create Case` from a high-value detection when an item needs tracking.

## Tune Detection Policy

Open `Detections > Detection policy`.

Profiles:

- `Strict`: shows every detection and observation for maximum sensitivity.
- `Balanced`: default triage mix.
- `Focused`: suppresses lower-confidence medium and low items for executive triage.

Rule profile changes are included in saved workspaces and investigation packages.

## Pivot Through Entities

Open `Entities` to review ranked entity risk. Selecting an entity shows:

- Peer relationships.
- Ports and byte volume.
- Timeline of activity.
- Related detections.
- Evidence rows involving the entity.

Use this view to validate whether a source is scanning, receiving suspicious inbound traffic, or moving laterally.

## Search Raw Records

Open `Records` for the normalized evidence table. Use:

- Global search for IP, ENI, port, or action.
- Action and protocol filters.
- Sortable table columns.
- CSV export for filtered records.

## Hunt

Open `Hunt` to run fielded queries. Useful examples:

```text
action:REJECT dstport:22
src:10.0.1.15 action:ACCEPT
dst:203.0.113.82 bytes>1000000
```

Save repeatable hunts for later runs. Saved hunts persist locally in the browser.

## Coverage And Baselines

Open `Coverage` to track:

- Managed source inventory.
- Observed versus expected ENIs/CIDRs.
- Ingest history.
- Saved baseline drift.

Use baselines to catch new entities, destination ports, applications, and paths.

Managed sources can include source type, account or owner, region, expected ENIs, CIDRs, CloudWatch log groups, and S3 prefixes.

For direct ingest from source inventory:

- Use a CloudWatch source with a `/aws/...` log group in scope.
- Use an S3 source with a scope like `s3://bucket/AWSLogs/account/vpcflowlogs/`.
- Select `Ingest` on the source entry to pull evidence immediately.
- Select `Async` to start a long-running import and continue working while status updates arrive.
- Select `Schedule` to create a recurring backend ingest job from the source.

## Enrichment

Open `Pipeline > Enrichment` and paste JSONL or CSV metadata with fields such as:

- `ip`
- `dst`
- `domain`
- `sni`
- `host`
- `ja3`
- `certIssuer`
- `app`
- `category`
- `ai`

Enrichment improves application intelligence and flags candidate shadow AI traffic.

## Cloud Ingest

Open `Pipeline > Cloud ingest`.

For S3:

- Region.
- Bucket.
- Prefix.

For CloudWatch Logs:

- Region.
- Log group.
- Optional filter pattern.

Cloud ingest requires backend AWS credentials or an ECS task role.

## Scheduled Jobs

Create a scheduled job from the `Pipeline` tab:

1. Fill S3 or CloudWatch fields.
2. Choose type.
3. Set interval minutes.
4. Select `Create Job`.

Admins can delete jobs. Admins and analysts can run jobs manually.

Use `Async` on a scheduled job to queue a background CloudWatch or S3 import. The job status list shows queued, running, completed, and failed runs. SignalPrism polls the backend and shows a toast when an async import completes or fails.

## Cases

Open `Cases` to create or update investigation records.

Fields:

- Title.
- Assignee.
- Status.
- Severity.
- Notes.

Case audit history is saved in the tenant store when the backend is available, with IndexedDB as local fallback. Viewers can read cases; analysts and admins can create or update them; only admins can delete.

## Tenant Admin

Open `Admin` to manage the tenant roster and source ownership. This screen requires the backend and an `admin` role.

Admins can:

- Add or update tenant users with `admin`, `analyst`, or `viewer` roles.
- Mark users active or suspended.
- Associate users with managed sources.
- Assign or clear ownership for CloudWatch and S3 source inventory entries.

This roster documents SignalPrism ownership and access intent. It does not modify your identity provider; SSO group membership remains managed in the IdP.

## Topology Replay

Open `Topology` to visualize entity-to-entity paths. Move the replay slider to focus on activity up to a point in time, use `Play` for replay, or step backward and forward through the timeline. The recent-event trail shows the latest records included at the current replay position.

Use topology to explain lateral paths, high-volume egress, and repeated external contacts.

## Reports And AI Assistant

Open `Reports`.

The built-in analyst summary is generated locally from detections, entity risk, and application intelligence.

When Bedrock is enabled, use the AI assistant to ask questions such as:

- `Which entities should I investigate first and why?`
- `Summarize likely lateral movement paths.`
- `What evidence supports the highest severity detection?`
- `What should I validate before escalating this case?`

Use presets for common workflows:

- Top risk explanation.
- Executive summary.
- Attack path.
- Containment plan.
- Evidence gaps.
- SIEM query ideas.

The assistant sends a bounded investigation context through the backend, not the entire raw upload. AI actions require `admin` or `analyst`.

## Export

Supported exports:

- Filtered record CSV.
- Detection CSV.
- OCSF-like JSON.
- CEF.
- Redacted evidence JSON.
- Append-only backend audit NDJSON.
- Investigation package JSON.

Use redacted exports when sharing evidence outside the security team.

The investigation package includes workspace metadata, summary counts, detections, observations, top entities, topology paths, managed sources, saved hunts, cases, summaries, AI answer text, and a bounded record sample. When the backend is running, package export is RBAC-controlled and audited.

Raw evidence package storage is separate from the downloadable investigation package. It preserves the full raw upload or import payload for retained evidence handling, while analyst exports stay bounded and redacted when needed.
