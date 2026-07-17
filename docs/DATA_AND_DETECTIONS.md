# Data And Detections

## Supported Inputs

SignalPrism NDR supports:

- Default AWS VPC Flow Logs field order.
- AWS VPC Flow Logs with `#Fields:` headers.
- CSV exports with recognized VPC Flow Log column names.
- Gzipped logs in browsers with `DecompressionStream`.
- CloudWatch Logs JSON and JSONL records with `message`.
- Azure NSG Flow Log JSON.
- Azure Activity and Microsoft Entra audit JSON.
- GCP VPC Flow Log JSON.
- GCP audit JSON.
- Kubernetes audit and Cilium Hubble JSON.
- CloudTrail, Route 53 Resolver, GuardDuty, Zeek, and Suricata JSON/JSONL.
- Gigamon IPFIX/CEF and ExtraHop RevealX records.
- A bounded generic JSON event contract for pre-normalized integrations.

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

Enterprise telemetry is normalized separately as `TelemetryEvent`. It adds provider, format, category, identity, resource, workload, application, DNS, TLS/certificate, JA3, post-quantum key-exchange, outcome, severity, and source evidence identifiers. Raw context is bounded before storage so a single event cannot expand tenant records without limit.

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

Raw evidence text is hashed with SHA-256. Evidence-vault manifests also receive a server-side HMAC-SHA256 attestation with a dedicated key and key identifier; this proves that a manifest passed through the trusted backend, while S3 Object Lock supplies retention enforcement for the underlying package.

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
- Loaded threat-intelligence matches.
- Asset criticality from asset context.

The score is intended for triage order, not as a standalone severity.

The Enterprise workspace also calculates an explainable entity risk list. Each score includes the main reasons, such as public sensitive probing, accepted lateral access, high-volume egress, matched indicators, or high-criticality assets.

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

## Detection-As-Code Model

Tenant detection rules include:

- Hunt query.
- Severity.
- ATT&CK tactic, technique, and technique ID.
- Owner.
- Status: `draft`, `test`, `production`, or `retired`.
- Version and approval metadata.
- Immutable backtest ID, rule digest/version, dataset/engine identity, quality gate, result metrics, and tested timestamp.

The Enterprise workspace can clone, test, score, and export these rules as `signalprism.detections.v1` JSON. Production promotion and retirement are admin-only server operations. Promotion requires a recent passing server backtest for the exact current rule digest/version, ATT&CK mapping, a substantive description, an atomic version match, and a separate author/approver by default. Client-supplied counters and timestamps are ignored, and any content edit invalidates prior backtest evidence.

Signed content bundles add a manifest ID/version, SHA-256 rules digest, publisher metadata, and Ed25519 signature. Verification uses the configured public key. Import never grants production status or carries over a passing backtest.

## Enterprise Telemetry And Correlation

The backend normalizes AWS, Azure, GCP, Kubernetes/Cilium, Gigamon, ExtraHop, Zeek, Suricata, and bounded generic events into `TelemetryEvent`. Common fields include time, provider, category, account/region, network endpoints, identity, action, outcome, resource/workload, application, DNS query, TLS posture, severity, signature, bytes, and bounded raw context.

Current cross-source rules identify:

- AWS authentication spray (`T1110`).
- Privilege change followed by related network activity (`T1098`).
- GuardDuty findings corroborated by independent network telemetry (`T1071`).
- Long/high-cardinality DNS label activity (`T1048`).
- Repeated Suricata IDS signatures (`T1071`).

Every correlation carries source formats and evidence IDs. Correlations are investigation leads, not automatic containment decisions.

## Behavior, Campaign, And Retrospective Analytics

Behavior profiles group evidence by resolved entity and compare recent activity with deterministic historical features. Findings cover new peers/services, off-hours behavior, three-sigma volume deviation, periodic beacon candidates, and repeated failures. Every finding includes the triggering feature values and evidence IDs.

Campaign assembly builds connected components across shared entities, evidence, and bounded time windows. It reports stage progression, blast radius, source diversity, confidence, and linked evidence without claiming causality that the records do not support.

Retrospective hunts use an allowlisted parser rather than `eval`, dynamic SQL, or user-provided regular expressions. Supported fields and operators are documented in the API guide. Detection backtests report matched evidence, noise, and optional precision/recall when labeled benign and malicious fixtures are provided.

## OCSF Projection

Normalized network events map to Network Activity (`class_uid=4001`); correlations, behavior findings, and campaigns map to Security Finding (`class_uid=2001`). Native integrations use OCSF 1.8, while Amazon Security Lake custom sources use an isolated OCSF 1.3 profile. Schema validation and event-time ordering occur before delivery. The AWS stack uses one Firehose stream per event class, converts records to Zstandard Parquet, and dynamically partitions by region, account ID, and event day.

## Threat Intelligence Model

Threat-intelligence imports accept JSONL or CSV with indicator fields:

- `indicator`, `ip`, `domain`, or `value`
- `type`
- `severity`
- `label`
- `source`
- `confidence`
- `firstSeen`
- `lastSeen`

Indicators are stored as tenant enterprise artifacts when the backend is online and mirrored in browser storage for offline enrichment.

## Path Ranking

Paths are ranked by bytes, packets, and frequency. Internal and external paths are shown separately to help analysts distinguish lateral movement from egress.

## Topology Replay

Topology replay uses normalized record timestamps to build a cutoff view of entity-to-entity paths. The scrubber, play control, and step controls all use the same deterministic replay snapshot: included records, cutoff time, and recent-event trail.

Enterprise replay export creates a JSON incident reconstruction timeline that overlays flow events with detection milestones.

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
- Redacted JSON for privacy-aware sharing using session-scoped HMAC-SHA256 pseudonyms.
- Investigation package JSON for complete case handoff. Backend-enabled exports are RBAC-controlled, audited, separately approved, expiring, and one-time by default.
- Backend audit NDJSON.
- Detection-as-code JSON.
- Investigation graph JSON.
- Replay timeline JSON.
- Security Lake OCSF NDJSON with approval bound to the payload SHA-256.

## Enterprise Artifacts

The backend stores advanced workflow outputs as tenant-scoped `EnterpriseArtifact` records:

- `COPILOT_NOTE`: evidence-cited deterministic answer.
- `THREAT_INTEL`: indicator import payload.
- `PLAYBOOK_RUN`: case-linked response steps.
- `EVIDENCE_VAULT_BUNDLE`: retention and chain-of-custody manifest.
- `ENTERPRISE_REPORT`: analyst, executive, compliance, or manager report.

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
