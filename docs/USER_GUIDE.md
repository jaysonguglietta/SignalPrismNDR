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

## Learn NDR In The Application

Open `Learn` for an analyst-oriented explanation of network detection and response and the SignalPrism interface. The learning center includes:

- The NDR lifecycle from observation through governed response.
- What network metadata can establish and when packet, endpoint, identity, or protocol evidence is still needed.
- The difference between detection severity and operational urgency.
- A screen map linking directly to Overview, Detections, Topology, Hunt, Cases, and Reports.
- A five-step signal investigation playbook.
- Expandable definitions for flow logs, entities, Community ID, OCSF, model drift, and false positives.

Select `Practice with guided demo` to load sample evidence and continue in the Overview. Learning-center navigation buttons switch to the corresponding operational view without changing the investigation.

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

- Drag or select one or more `.log`, `.txt`, `.csv`, `.gz`, `.json`, or `.jsonl` files in the upload area. SignalPrism parses each file independently, merges valid records for correlation, and retains the originating filename on every record.
- Paste flow log text and select `Analyze`.
- Select `Sample` to load realistic sample evidence.
- Use `Pipeline > Cloud ingest` to import from S3 or CloudWatch Logs.

After loading evidence, check the per-file summary and `Import Quality` for detected formats, failed sources, skipped rows, or malformed fields. Use the `Evidence source` filter to isolate one flow file, search by filename, or use `file:filename.log` in Hunt. Multi-file browser batches accept up to 20 files, 16 MB per file, and 32 MB of combined decoded evidence. A failed file does not discard records or telemetry from successful files in the same batch.

## Stitch Events Across Sources

Open `Topology > Event stitching` after loading two or more related evidence sources. SignalPrism automatically recognizes flow logs, CloudTrail, GuardDuty, Route 53 Resolver, Zeek, Suricata, OCSF, and bounded generic JSON events.

The chain workspace provides:

- Ordered attack stages and event timestamps.
- Original evidence filename and detected format for every event.
- Confidence and urgency scores.
- The shared entity and time relationship behind every link.
- Independent-source and cross-format corroboration.
- Missing identity, DNS, or independent detection telemetry.
- Blocked ambiguous joins and high-frequency shared entities that were suppressed.

Use `Correlation window` to choose 15 minutes, one hour, four hours, or 24 hours. Use `Link policy` to require balanced, high-confidence, or strict links. A wider window increases recall and false-link risk; strict confidence can split a real incident when evidence is sparse.

SignalPrism never joins different tenant IDs. Matching private or shared network addresses across AWS accounts are not linked without a stronger identity, workload, interface, Community ID, or session key. Event time is authoritative, so validate collector clock health when a sequence appears incomplete or reversed.

`Export chains` follows investigation export governance. When approval is required, it submits the full investigation package to the controlled export queue. Exported stitched events omit bounded raw payload bodies while retaining normalized evidence and provenance.

## Investigate With Heatmaps

Open `Topology` and choose a visualization mode:

- `Graph`: entity-to-entity paths for the current replay position and evidence selection.
- `Activity`: a zoomable time heatmap grouped by entity, subnet, cloud account, destination port, protocol, or evidence source.
- `Matrix`: a source-to-destination communication matrix for quickly finding dominant, sparse, or unusual paths.
- `Geographic`: public endpoint locations and communication arcs using imported enrichment coordinates.

Choose flow events, bytes, rejected flows, risk weight, or detection evidence as the cell metric. Use logarithmic color for skewed network volumes and linear color for direct comparisons. Scope the view to all replayed flows, detection-linked evidence, or stitched incidents.

Click a cell or map endpoint to filter Records, Detections, the graph, replay events, and event stitching to the same evidence. Double-click to open Records. In Activity mode, hold Shift and drag across cells in one row to select a time range. `Clear selection` restores the investigation context. Zoom, pan, replay, and Reset view are keyboard-accessible; Escape clears a selection.

`Export view` includes the active mode, grouping, metric, scale, replay position, bounded aggregate summary, selection, and up to 1,000 normalized evidence records. Tenant export approval and role policy apply.

SignalPrism never sends IPs to a third-party geolocation API. Import `latitude`, `longitude`, `country`, `region`, `city`, `geoSource`, and `geoPrecision` through Pipeline enrichment. Locations are marked approximate unless precision is explicitly `exact`; TEST-NET sample addresses use labeled demonstration coordinates, and unresolved endpoints remain visible in the status count.

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
- An explainable Top 10 findings table.

Start with high-severity detections and priority entities with elevated rejects, sensitive ports, or high byte volume.

The Top 10 table consolidates detections with the same title, tactic, and technique so one behavior does not crowd out other attack stories. Filter by evidence window, source, severity, or known environment. Select `Explain` to inspect the 100-point urgency calculation across severity, confidence, asset criticality, exposure, breadth, velocity, threat intelligence, and case/SLA pressure. Select `View evidence` to isolate the exact linked records. Unknown ownership or criticality remains `Unknown` and contributes no positive risk points.

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
- `latitude` / `longitude`
- `country`, `region`, and `city`
- `geoSource` and `geoPrecision`

Enrichment improves application intelligence, flags candidate shadow AI traffic, and supplies analyst-controlled geographic context without an external IP lookup.

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

## Enterprise Command Center

Open `Enterprise` for advanced NDR operations:

- `Operational readiness`: scores source ownership, rule maturity, Security Lake configuration, asset context, and governance controls.
- `Detection operations`: summarizes production-rule maturity, test freshness, ATT&CK mapping, current triage load, and async import failures.
- `Production hardening`: reviews authentication mode, session protection, direct-ingest posture, tenant persistence, raw evidence storage, audit visibility, source accountability, privileged access, retention, and AI guardrails.
- `Signal fusion`: ingests mixed CloudTrail, Route 53 DNS, GuardDuty, Zeek, or Suricata JSON and creates evidence-linked cross-source findings.
- `Governed response`: requests isolation, IP block, access-key disablement, ticket, or SOC notification actions. A different tenant admin must approve before optional automation.
- `Detection supply chain`: verifies signed detection bundles and lets admins import verified rules into test status.
- `Investigator copilot`: generates deterministic natural-language answers with citations to detections, flows, cases, assets, and threat-intel matches.
- `Source health`: checks managed source ownership, observed scope, async import status, and parser drift.
- `Source discovery`: extracts accounts, ENIs, CIDR hints, and source candidates from current evidence.
- `Threat intelligence`: imports JSONL or CSV indicators and enriches current evidence.
- `Entity risk`: calculates explainable risk scores from detections, sensitive flows, asset criticality, and threat intelligence.
- `Detection engineering`: creates, tests, clones, and exports detection-as-code rules. Only tenant admins can promote or retire production rules, and production promotion requires a passing test, ATT&CK mapping, a substantive description, and a separate approver by default.
- `Security Lake and SIEM`: creates OCSF NDJSON exports and records backend manifests.
- `Asset and identity context`: accepts owners, assets, criticality, environment, account, role, IP, ENI, or instance IDs.
- `Investigation graph` and `Timeline replay`: export entity graphs and incident reconstruction timelines.
- `Policy exposure`: compares pasted security group or NACL-style rules with observed sensitive access and high-volume egress.
- `Incident operations` and `Detection quality`: summarize case SLA pressure, production-rule maturity, noisy analytics, and ATT&CK mapping coverage.
- `Response playbooks`: creates case-linked containment, lateral movement, egress, and executive briefing runs.
- `Evidence vault`: creates retention and chain-of-custody manifests for investigation packages.
- `Enterprise reporting`: generates analyst, executive, compliance, and operations-manager reports.
- `Tenant administration`: summarizes SSO, SCIM, RBAC, and AI permission readiness.

For a first signal-fusion run, select `Load Sample`, then `Normalize and Ingest`, and finally `Correlate`. Review the source formats, evidence count, score, entity, and ATT&CK technique before linking a response request. Response execution may remain disabled even after approval; the status explicitly distinguishes `approved` from `executed`.

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
- Export an access review covering privileged users, analyst source scopes, stale roster entries, and source-owner gaps.
- Refresh, filter, and export tenant audit events as NDJSON.
- Review pending evidence-release requests, approve requests created by another user, and consume approved exports during their short validity window.

This roster documents SignalPrism ownership and access intent. It does not modify your identity provider; SSO group membership remains managed in the IdP.

## Controlled Exports

Backend-enabled investigation packages and Security Lake exports use a two-person release workflow by default:

1. An analyst requests the export and receives a pending approval ID.
2. A different tenant admin reviews and approves the request in `Admin > Evidence release approvals`.
3. The requester consumes the approval once before it expires.

Security Lake approvals are bound to the SHA-256 of the reviewed OCSF payload. If the evidence changes after approval, the export is rejected and a new request is required. Privacy-aware JSON exports use a random, session-scoped HMAC key so pseudonyms cannot be correlated across separate browser sessions.

## Topology Replay

Open `Topology` to visualize entity-to-entity paths. Move the replay slider to focus on activity up to a point in time, use `Play` for replay, or step backward and forward through the timeline. The recent-event trail shows the latest records included at the current replay position.

Use topology to explain lateral paths, high-volume egress, repeated external contacts, concentrated time windows, asymmetric communication, and public endpoint concentration. Heatmap selections remain synchronized with replay and linked evidence until cleared.

## Reports And AI Assistant

Open `Reports`.

### Executive security brief

Select a 7-, 30-, or 90-day window or the current evidence set, choose the information classification, enter the organization label, then select `Generate brief`. The report includes:

- Overall risk posture and prior-report delta.
- Current, previous, change, and interpretation columns for seven operational metrics.
- Evidence-cited Top 10 findings using `[F#]` references.
- Metric citations using `[M#]` references.
- Decisions, response actions, coverage gaps, and explicit unknown business context.
- A SHA-256 content digest.

`Evidence-cited` produces a deterministic local narrative. `Bedrock-assisted` sends only the bounded report facts to the configured backend and retains evidence anchors; when Bedrock is disabled or fails, SignalPrism keeps the deterministic narrative.

PDF, CSV, and JSON exports use the tenant approval policy. When approval is required, an analyst or admin requests the export, a separate stepped-up admin approves it, and the requester consumes the sealed report once. Approval queue metadata shows purpose, format, requester, status, and payload hash without exposing report content.

### Executive report schedules

Tenant admins can create weekly or monthly schedules for active tenant recipients. A schedule fixes the evidence period, classification, package format, and governed tenant-inbox recipients. `Run` creates a fresh report snapshot and delivery immediately; `Pause`, `Resume`, and `Delete` manage its lifecycle. Deliveries remain downloadable from the tenant inbox. This version evaluates due schedules while an authenticated admin console is active; use a production worker/scheduler integration for unattended external delivery.

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
- Executive brief PDF, CSV, and JSON.

Use redacted exports when sharing evidence outside the security team.

The investigation package includes workspace metadata, summary counts, detections, observations, top entities, topology paths, managed sources, saved hunts, cases, summaries, AI answer text, and a bounded record sample. When the backend is running, package export is RBAC-controlled and audited.

Raw evidence package storage is separate from the downloadable investigation package. It preserves the full raw upload or import payload for retained evidence handling, while analyst exports stay bounded and redacted when needed.

## Platform Workspace

Open **Platform** for advanced tenant operations:

1. Run behavior analytics after telemetry ingest to compare entities with the previous profile.
2. Build campaigns to link correlations and behavior findings by entity, evidence, and time.
3. Run a retrospective query such as `sourceIp:10.0.* AND (outcome:failure OR severity:high)`.
4. Set an investigation objective and optional hunt query. Bedrock synthesis is optional; deterministic evidence collection and citations always run.
5. Assess AI and cryptography posture after ingesting DNS, SNI, TLS, or sensor metadata.
6. Publish OCSF records. When export approval is enabled, a separate admin must approve dispatch.
7. Configure connectors with HTTPS endpoints and Secrets Manager ARNs. Tests validate locally or emit EventBridge adapter intent.
8. Discover Organizations accounts, select an account, and create managed S3/CloudWatch sources.
9. Upload full evidence directly to the Object Lock bucket. The browser hashes it before upload.
10. Create specialist roles and expiring service accounts. Record one-time tokens immediately; only token digests remain in SignalPrism.

Response actions default to **Dry run**. Select **Enforce after approval** only after the adapter and rollback have been tested.
