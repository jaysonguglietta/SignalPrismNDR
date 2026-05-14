# Data And Detections

## Supported Inputs

SignalPrism NDR supports:

- Default AWS VPC Flow Logs field order.
- AWS VPC Flow Logs with `#Fields:` headers.
- CSV exports with recognized VPC Flow Log column names.
- Gzipped logs in browsers with `DecompressionStream`.
- CloudWatch Logs JSON and JSONL records with `message`.
- Azure NSG Flow Log JSON.
- GCP VPC Flow Log JSON.

## Normalized Flow Record

`FlowRecord` fields include:

- `version`
- `accountId`
- `interfaceId`
- `source`
- `destination`
- `srcPort`
- `dstPort`
- `protocol`
- `packets`
- `bytes`
- `start`
- `end`
- `action`
- `logStatus`
- `raw`

The parser preserves enough source fields for analyst validation while normalizing protocol names, numeric fields, timestamps, and action labels.

## Parser Issues

Parser issues are non-fatal. They include:

- Empty lines.
- Unsupported JSON shape.
- Missing required source/destination fields.
- Invalid numeric ports or timestamps.
- Unknown field order without a header.

The import quality panel surfaces skipped rows so analysts can assess evidence completeness.

## Evidence Package Model

Evidence-run metadata stays bounded for fast UI and API reads. When the backend saves an evidence run or completes a CloudWatch/S3 import, it also writes a full raw evidence package containing:

- Package and tenant identifiers.
- Source label and creation time.
- Retention deadline and retention days.
- Raw evidence text.
- Bounded normalized record sample.
- Analysis summary.

Local mode stores package JSON under `.ndr-data/evidence-packages/<tenant>/`. Production mode can store packages in S3 with Object Lock retention.

## Detection Categories

### Sensitive-Port Probing

Flags repeated rejected traffic to services such as SSH, RDP, SMB, SQL Server, MySQL, PostgreSQL, and other high-value ports.

### High Rejection Rate

Flags windows or entities with elevated rejected traffic, often associated with scanning, blocked access attempts, or misconfigured services.

### Internal Remote-Service Access

Flags accepted internal access to administrative or database ports that may indicate lateral movement or unauthorized service reachability.

### Beaconing Candidate

Flags repeated outbound accepted connections with regular timing patterns.

### Suspicious DNS Volume

Flags unusual DNS flow volume or repeated DNS behavior that may require resolver or domain-level investigation.

### Large Accepted Transfer

Flags high-volume private-to-public transfers that may need egress ownership review.

### Public Sensitive-Service Access

Flags accepted public traffic to sensitive services.

### Unusual Protocols

Flags accepted protocols outside common TCP/UDP/ICMP expectations.

### Coverage Gaps

Flags `NODATA`, `SKIPDATA`, parser issues, and expected source blind spots.

### Baseline Drift

Flags new entities, destination ports, applications, and paths compared with a saved baseline.

### Shadow AI Candidate

Uses enrichment hints to identify traffic to AI service domains or application categories.

## Entity Risk

Entity risk combines:

- Linked detection severity.
- Rejected flow volume.
- Sensitive ports.
- Peer count.
- Data volume.
- External exposure.

The score is intended for triage order, not as a standalone severity.

## Detection Explainability

Detection cards include three explanation fields:

- `Why it fired`: a concise interpretation of the rule condition.
- `Evidence basis`: linked record count and time range.
- `Confidence`: high, medium, or low confidence guidance.

These explanations are deterministic and generated locally from detection metadata and linked evidence.

## Rule Profiles

SignalPrism supports rule tuning profiles:

- `Strict`: maximum sensitivity, keeps all detections and observations.
- `Balanced`: default day-to-day triage.
- `Focused`: suppresses lower-confidence medium and low items for executive or high-noise review.

The active profile is reflected in metrics, saved with workspaces, included in AI context, and exported in investigation packages.

## Path Ranking

Paths are ranked by bytes, packets, and frequency. Internal and external paths are shown separately to help analysts distinguish lateral movement from egress.

## Topology Replay

Topology replay uses normalized record timestamps to build a cutoff view of entity-to-entity paths. The scrubber, play control, and step controls all use the same deterministic replay snapshot: included records, cutoff time, and recent-event trail.

## Enrichment Model

Accepted enrichment fields:

- `ip`
- `dst`
- `destination`
- `domain`
- `sni`
- `host`
- `ja3`
- `certIssuer`
- `issuer`
- `app`
- `category`
- `ai`

Enrichment is stored in browser storage and can be included in tenant workspace snapshots.

## Export Formats

- CSV for filtered evidence.
- CSV for detections.
- OCSF-like JSON for SIEM-oriented downstream use.
- CEF for legacy SIEM ingestion.
- Redacted JSON for privacy-aware sharing.
- Investigation package JSON for complete case handoff. Backend-enabled exports are RBAC-controlled and audited.
- Backend audit NDJSON.

The raw evidence package is not the same as the analyst investigation package. Evidence packages are retention-oriented source artifacts; investigation packages are bounded handoff artifacts.

## Analyst Guidance

Detections are evidence leads. Validate against:

- Source ownership.
- Expected service exposure.
- Security group and NACL policy.
- Change windows.
- Asset criticality.
- Known scanners or vulnerability tools.
- Threat intelligence and endpoint telemetry.
