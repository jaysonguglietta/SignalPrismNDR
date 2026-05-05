# User Guide

## First Run

Start the backend-enabled app:

```bash
npm start
```

Open `http://localhost:4173`.

For file-only local analysis, open `index.html` directly in a browser. Cloud ingest, jobs, SSO, audit export, and Bedrock require the backend.

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

Use `Create Case` from a high-value detection when an item needs tracking.

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

- Expected source watchlist.
- Observed versus expected ENIs/CIDRs.
- Ingest history.
- Saved baseline drift.

Use baselines to catch new entities, destination ports, applications, and paths.

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

## Cases

Open `Cases` to create or update investigation records.

Fields:

- Title.
- Assignee.
- Status.
- Severity.
- Notes.

Case audit history is stored in IndexedDB and records creation, updates, severity changes, and deletion.

## Topology Replay

Open `Topology` to visualize entity-to-entity paths. Move the replay slider to focus on activity up to a point in time.

Use topology to explain lateral paths, high-volume egress, and repeated external contacts.

## Reports And AI Assistant

Open `Reports`.

The built-in analyst summary is generated locally from detections, entity risk, and application intelligence.

When Bedrock is enabled, use the AI assistant to ask questions such as:

- `Which entities should I investigate first and why?`
- `Summarize likely lateral movement paths.`
- `What evidence supports the highest severity detection?`
- `What should I validate before escalating this case?`

The assistant sends a bounded investigation context through the backend, not the entire raw upload.

## Export

Supported exports:

- Filtered record CSV.
- Detection CSV.
- OCSF-like JSON.
- CEF.
- Redacted evidence JSON.
- Append-only backend audit NDJSON.

Use redacted exports when sharing evidence outside the security team.
