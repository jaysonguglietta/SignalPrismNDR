# SignalPrism NDR Deep-Dive Review

Date: 2026-07-17

> **Remediation status:** The twelve P0 findings and the directly related integrity controls were remediated on `codex/enterprise-integrity-hardening`. The findings below are retained as the historical assessment and should not be read as descriptions of the current implementation. See the [Security Remediation Record](SECURITY_REMEDIATION_2026-07-17.md) for the control-by-control closure evidence and current residual deployment responsibilities.

## 1. Executive assessment

SignalPrism has grown beyond a log viewer into a broad NDR control plane: browser and managed ingest, deterministic detections, behavior analytics, topology replay, governed AI, case management, evidence retention, OCSF export, response approvals, tenant administration, and AWS deployment infrastructure are all represented.

The strongest parts are the breadth of the domain model, secure-by-default production checks, tenant-keyed persistence, immutable audit/evidence concepts, dual OCSF profiles, and a surprisingly complete visual test suite. The principal risk is that the product surface now exceeds the depth of several underlying implementations. Some controls displayed as enterprise capabilities are metadata or workflow scaffolding rather than end-to-end enforcement.

No confirmed remote-code-execution or direct authentication-bypass vulnerability was found. The review originally confirmed several high-impact integrity, privacy, ingestion, and scale defects. Their repository remediations are complete; a production launch remains conditional on the environment-specific production gate, staging AWS contract tests, and operational drills.

### Current maturity

| Capability | Maturity | Assessment |
| --- | --- | --- |
| Analyst experience | 3/5 | Broad and usable, but navigation and dense workflows need consolidation. |
| Ingest and normalization | 2/5 | Many formats and AWS sources; checkpointing, policy enforcement, and large-batch handling need redesign. |
| Detection and correlation | 2.5/5 | Useful deterministic coverage; lifecycle, efficacy measurement, and model governance are shallow. |
| Investigation and cases | 3/5 | Real case workflow exists; collaboration, queue management, and evidence lineage need depth. |
| Tenant security and governance | 3/5 | Good foundations; source semantics, custom permissions, concurrency, and packet boundaries need hardening. |
| Response automation | 2/5 | Approval concepts are strong; adapters, target validation, verification, and rollback are not production-complete. |
| Data platform and scale | 1.5/5 | Current request-time/DynamoDB access patterns will not sustain enterprise telemetry volume. |
| AWS deployment | 3/5 | Strong Fargate baseline with WAF, encryption, autoscaling, and backups; multi-region, supply-chain, and operational controls remain. |
| Verification | 3/5 | Contract and visual checks are good; AWS integration, fuzz, load, accessibility, and detection-efficacy testing are missing. |

## 2. Product and architecture brief

**Target users:** SOC analysts, threat hunters, incident responders, detection engineers, security platform engineers, tenant administrators, auditors, and MDR/provider operators.

**Core problem:** turn AWS network and cloud telemetry into defensible detections, investigations, retained evidence, and governed response actions without losing tenant isolation or source provenance.

**Primary workflows:** onboard sources; ingest and validate evidence; triage prioritized signals; hunt and replay entity activity; open and manage cases; request and approve exports or response actions; administer tenants, roles, retention, integrations, and platform health.

**Main views:** operations overview, detections, entities, records, hunt, coverage, pipeline, cases, administration, topology, enterprise governance, platform operations, reports, and learning center.

**Primary data models:** principal, tenant directory user, role, managed source, job/run, normalized telemetry event, detection rule, correlation, behavior profile/finding, campaign, entity, workspace, case/task, audit event, evidence package/upload, packet manifest/grant, response action/policy, connector, threat-intelligence feed, pipeline policy, governance record, AI run/evaluation, OCSF export.

**Trust boundaries:** browser to API; OIDC/service account/API key to authorization; tenant to tenant; API to DynamoDB/S3/SQS/Kinesis/Firehose/EventBridge/Bedrock/Security Lake; untrusted evidence to parser/detection/AI; analysts to approval workflows; packet manifests to privileged S3 reads; CI to deployable container and Terraform.

## 3. Confirmed defects and security findings

### P0-1: Managed ingest bypasses pipeline privacy and tiering policy

- **Severity/confidence:** High / High
- **Evidence:** `processIngestResult` writes events directly at `server.mjs:2943-2957`; masking, policy deduplication, and tier assignment exist only in `storeTelemetryEvents` at `server.mjs:4495-4518`.
- **Impact:** S3 and CloudWatch, the primary enterprise ingest paths, can retain fields that administrators configured to mask and can bypass declared tiering behavior.
- **Fix:** make one policy engine the only normalized-event persistence entry point. Pass channel, source, provenance, and checkpoint metadata through it.
- **Acceptance:** identical fixtures sent through upload, API stream, S3, and CloudWatch produce equivalent masked, deduplicated, and tiered records; a contract test fails when any route calls the raw event repository directly.

### P0-2: S3 checkpointing can permanently skip objects

- **Severity/confidence:** High / High
- **Evidence:** `ingestS3` requests more keys than it intends to consume, stops mid-page, then stores the page's continuation token at `server.mjs:2792-2851`.
- **Exploit/failure:** with a target of 100 and a 200-key page, keys 101-200 are not processed, but the next run starts after the whole page.
- **Fix:** request at most the remaining object count, or persist a last-consumed key and do not advance the page token until every returned object is committed.
- **Acceptance:** deterministic tests over 2,500 keys with targets of 1, 10, 100, duplicate ETags, failures, and restarts prove exactly-once discovery with no gaps.

### P0-3: One malformed line aborts an entire telemetry batch

- **Severity/confidence:** High / High
- **Evidence:** `expandPayload` parses line-delimited input before per-record error handling and throws at `src/enterprise-telemetry.mjs:150-178`; batches are capped at 5,000 at `src/enterprise-telemetry.mjs:26-40`.
- **Impact:** a single corrupt or attacker-crafted line can quarantine a multi-megabyte managed import; valid records are not retained.
- **Fix:** use a streaming, bounded parser with per-line error collection, configurable reject thresholds, a quarantine stream, and resumable offsets.
- **Acceptance:** mixed valid/invalid 1M-line fixtures complete within memory limits, retain valid events, report exact rejects, and resume after an injected crash.

### P0-4: Event identity is collision-prone at ordinary enterprise volume

- **Severity/confidence:** High / High
- **Evidence:** normalized identifiers use a 32-bit FNV-style hash at `src/enterprise-telemetry.mjs:938-945`; similar browser IDs exist at `app.js:6668-6674`.
- **Impact:** collisions become probable around tens of thousands of unique values and can cause false deduplication or DynamoDB overwrites.
- **Fix:** prefer provider event IDs; otherwise hash a canonical event envelope with SHA-256 and retain at least 128 bits. Version the ID scheme and provide a backfill strategy.
- **Acceptance:** 100M generated events produce no collisions; reordering JSON keys does not change canonical IDs; legacy and new IDs remain traceable.

### P0-5: Detection production approval trusts client-supplied test state

- **Severity/confidence:** High / High
- **Evidence:** analysts can save test rules at `server.mjs:1264-1272`; `testCount` and `lastTestedAt` are copied from the request at `server.mjs:3973-4002`; promotion checks only status and count at `server.mjs:4005-4014`.
- **Impact:** an analyst can claim a test occurred. A separate admin may approve a rule that never passed the backtest quality gate.
- **Fix:** make backtests immutable server-owned records keyed by rule version, rule digest, dataset digest, engine version, result, and expiry. Promotion must reference a passing result for the exact rule version.
- **Acceptance:** forged counters cannot promote; any rule edit invalidates prior results; promotion races are conditionally rejected and audited.

### P0-6: Response approvals do not fully validate expiry, case, adapter, or target

- **Severity/confidence:** High / High
- **Evidence:** client adapter values and loosely typed targets are accepted at `server.mjs:3569-3602`; pending approval ignores `expiresAt` at `server.mjs:3710-3714`; `requireCase` checks only a non-empty ID at `server.mjs:3762-3767`.
- **Impact:** stale actions, fake case links, mismatched adapters, and malformed workload/resource targets can reach the execution event bus.
- **Fix:** enforce an adapter catalog and per-action JSON schemas; resolve the tenant case; check expiry and target count; freeze a signed policy snapshot; revalidate in the adapter; use conditional state transitions and idempotency.
- **Acceptance:** negative tests cover expired approvals, missing/deleted/cross-tenant cases, adapter mismatch, invalid ARNs/resource IDs, replay, partial failure, verification timeout, and rollback.

### P0-7: Evidence retention fails open during managed ingest

- **Severity/confidence:** High / High
- **Evidence:** evidence package failures are converted to `{mode: "error"}` while ingest continues at `server.mjs:2917-2935` and the synchronous source path at `server.mjs:1391-1409`.
- **Impact:** analytics and checkpoints can report success even though the promised immutable raw evidence was not retained.
- **Fix:** in production, stage raw evidence durably before normalization and commit source checkpoints only after evidence and normalized writes succeed. Add a transactional outbox and retry/DLQ state.
- **Acceptance:** S3, KMS, and Object Lock failures stop checkpoint advancement; recovery creates one package, no duplicates, and a high-severity platform alert.

### P0-8: The browser upload path cannot reliably persist its allowed evidence size

- **Severity/confidence:** High / High
- **Evidence:** the browser permits up to the configured multi-megabyte limits at `app.js:1110-1208`, then posts raw evidence in JSON at `app.js:3855-3867`; the API body defaults to 1 MB at `server.mjs:77` and `server.mjs:5795-5817`.
- **Impact:** analysis succeeds locally while central evidence persistence silently degrades to a warning. This undermines chain of custody and shared investigations.
- **Fix:** automatically use the direct S3 upload flow for raw evidence, then submit only checksum, manifest, source metadata, and analysis references to the API.
- **Acceptance:** 1 KB through maximum-size uploads follow one visible state machine: hashing, uploading, scanning, retaining, analyzing, and available; no success state is shown before retention succeeds.

### P0-9: Browser evidence caching defaults fail open before authentication and offline

- **Severity/confidence:** High / High
- **Evidence:** public health omits the cache policy at `server.mjs:397-401`; the frontend treats an absent value as enabled and explicitly enables offline cache at `app.js:3258-3291`; IndexedDB defaults enabled and purges only the active scope at `src/idb-store.js:1-20,146-160`.
- **Impact:** evidence may persist on a shared or managed endpoint when enterprise policy intended browser storage to be disabled; stale scopes may survive sign-out.
- **Fix:** default disabled, expose a non-sensitive pre-auth storage policy, bind encryption keys to an authenticated session, purge all expired scopes, and support an MDM-enforced no-local-storage mode.
- **Acceptance:** signed-out, failed-status, offline, logout, user-switch, expired-session, and disabled-policy tests leave no recoverable evidence.

### P0-10: Packet manifests can turn the API into a confused deputy

- **Severity/confidence:** High / High
- **Evidence:** an analyst can register any syntactically valid `s3://` URI and self-asserted hash at `src/advanced-operations.mjs:428-450`; after approval, the API presigns a read with its own AWS role at `server.mjs:4698-4716`.
- **Impact:** a misleading manifest and approval could expose any object the task role can read, outside the intended evidence namespace.
- **Fix:** only accept packet objects created by trusted sensors or the evidence broker; allowlist bucket, account, prefix, KMS key, tags, and version; use `GetObjectAttributes` to verify checksum and size before registration.
- **Acceptance:** arbitrary buckets, prefixes, unversioned objects, missing tenant tags, changed object versions, and task-role-readable non-evidence objects are denied.

### P0-11: Evidence scan and checksum attestations are not strong enough

- **Severity/confidence:** High / Medium
- **Evidence:** upload completion proceeds when S3 returns no checksum at `server.mjs:4794-4809`; scan `signature` is stored but never verified at `server.mjs:4814-4828`.
- **Impact:** a privileged or compromised client can assert a clean scan, and a completed object may not have server-verified content identity.
- **Fix:** require `GetObjectAttributes` checksum and object version; accept scanner attestations only from a dedicated IAM/OIDC/mTLS workload and verify a signature over tenant, bucket, key, version, hash, outcome, engine, and timestamp.
- **Acceptance:** missing checksums, stale/replayed attestations, wrong object versions, wrong scanner identities, and post-scan object changes fail closed.

### P0-12: Stream delivery can lose downstream events after local success

- **Severity/confidence:** High / High
- **Evidence:** API stream ingestion stores events before sending to Kinesis/Firehose at `server.mjs:699-710`; delivery functions do not durably retry individual partial failures around `server.mjs:4603-4669`.
- **Impact:** a client retry may be deduplicated locally while the downstream record remains absent.
- **Fix:** persist an outbox/delivery record with idempotency state, publish asynchronously, retry failed entries, and move terminal failures to a DLQ with replay tooling.
- **Acceptance:** injected timeouts and partial batch failures eventually deliver exactly once from the consumer perspective without losing local records.

## 4. Important integrity, scale, and defense-in-depth improvements

### P1-1: Replace request-time telemetry access patterns

All events of a tenant/kind share one DynamoDB partition key and each payload is serialized into an item at `server.mjs:5239-5258`; analytics repeatedly load as many as 20,000 records into API memory at `server.mjs:4403-4419`. This creates a hot logical key and caps search depth. The 400 KB DynamoDB item limit also threatens large workspaces, governance records, and feeds. AWS explicitly recommends splitting large items or storing large payloads in S3.

Use S3 Parquet as the evidence/event source of truth, Kinesis or MSK for streaming, OpenSearch or ClickHouse for the hot hunt tier, Athena for cold search, and DynamoDB only for control-plane metadata. Partition by tenant, source, region, event class, and time shard. Every list API should use opaque cursor pagination and bounded projections.

### P1-2: Make optimistic concurrency atomic

Case revision is checked in a read and then written unconditionally at `server.mjs:4360-4400` and `server.mjs:5221-5236`. Concurrent clients can both pass and overwrite each other. Use DynamoDB `ConditionExpression` or transactional writes for cases, rules, policies, source ownership, packet grants, and response transitions. Return `409` with the latest revision.

### P1-3: Complete the DynamoDB GSI migration path

`ddbListScoped` falls back to the legacy query only when the GSI query throws at `server.mjs:5302-5340`. Legacy items without GSI attributes silently disappear once the index exists. Add an explicit schema version, backfill job, completeness marker, dual-read/merge period, metrics, and rollback plan.

### P1-4: Define source access explicitly

For human users, an empty `sourceIds` list currently means unrestricted access unless a source has another owner at `server.mjs:2733-2745`; for service accounts, empty means denied. Replace this ambiguity with `sourceAccessMode: all | assigned | group`, make least privilege the default for analysts and custom roles, and enforce source scope on every derived object, export, AI context, case, hunt, and response action.

### P1-5: Replace the hand-maintained permission route map

Unmapped routes default to `admin:manage` at `server.mjs:2307-2325`, even when route-level role checks allow viewers. This makes custom least-privilege roles unpredictably fail on runs, readiness, enterprise settings, and governance reads. Register each endpoint declaratively with authentication, role, permission, source scope, rate class, input schema, audit action, and owner. CI must fail when a route is unregistered.

### P1-6: Distribute rate limits, quotas, and metrics

Rate buckets and counters are process-local at `server.mjs:2645-2687`; replicas multiply limits and fragment metrics. AI investigation quotas use a non-atomic read/count at `server.mjs:4915-4925`, while simple AI questions have no tenant cost budget. Use WAF for coarse abuse controls and Redis/DynamoDB atomic token buckets for tenant, principal, source, IP, and action-class limits. Add Bedrock token and dollar budgets, concurrency limits, cancellation, and billing alarms.

### P1-7: Harden authentication lifecycle

The signed cookie embeds the complete principal at `server.mjs:2459-2477`, risking browser cookie-size failures for custom permissions and large source scopes. Store only a random session ID in the cookie and keep the principal server-side. Add OIDC metadata-driven algorithm allowlisting, JWKS refresh on unknown key ID, step-up authentication for packet/export/response approval, per-key API scopes, SCIM group lifecycle, and per-tenant SCIM credentials.

### P1-8: Prevent CSV formula injection

CSV export quotes delimiters but does not neutralize cells beginning with `=`, `+`, `-`, or `@` at `app.js:6471-6542,6705-6708`. Prefix dangerous text cells with an apostrophe or export typed XLSX/JSON. Test attacker-controlled interface IDs, names, and detection text.

### P1-9: Enforce full OCSF conformance

Runtime OCSF validation checks only a small required-field set at `src/ocsf.mjs:148-157`, and invalid timestamps become the current time at `src/ocsf.mjs:214-217`. Integrate the official validator/schema in CI and sampled runtime validation; quarantine invalid timestamps instead of laundering them. Keep separate `native-current` and `security-lake-1.3` mappings and conformance fixtures for every event class.

AWS Security Lake currently supports custom-source OCSF 1.3 and earlier, one class per source, assigned prefixes, Parquet, time ordering, region/account/day partitioning, and prefers Zstandard compression. OCSF itself is now at 1.8. SignalPrism's dual-profile direction is correct, but it needs an automated compatibility test and delivery receipt for every object.

### P1-10: Make capability state honest in the UI

Some capabilities are active; others are configured metadata or external adapter contracts. Label every integration as `Active`, `Configured`, `Preview`, `Degraded`, or `Adapter required`, and show last successful end-to-end transaction. ClickHouse/MSK bridges, response adapters, packet sensors, live cloud enrichment, Athena search, and provider/MDR controls should not look operational until a health-checked implementation exists.

## 5. Product and workflow improvements

### Detection operations

1. Build one prioritized investigation queue that groups duplicate signals into attack stories and exposes owner, SLA, age, asset criticality, identity privilege, confidence, blast radius, and recommended next action.
2. Add suppression and exception objects with scope, reason, owner, expiry, approval, maintenance window, and measured volume reduction. Never bury tuning in a rule edit.
3. Add detection lifecycle stages: draft, unit test, replay test, shadow, canary, production, deprecated, retired. Track precision, recall on labeled corpora, alert volume, analyst disposition, latency, and regression by version.
4. Map detections to MITRE ATT&CK data sources and techniques, coverage confidence, required telemetry, blind spots, and recent validation evidence.
5. Add content signing, staged rollout rings, rollback, tenant pinning, changelogs, and emergency revocation.

### Investigations and cases

1. Turn campaigns, detections, identity activity, topology, hunt results, packets, notes, and response actions into one time-ordered investigation story.
2. Add bookmarks, evidence citations, annotations, query notebook cells, reusable pivots, collaboration presence, watchers, mentions, immutable comments, and approval history.
3. Add queue views, saved filters, bulk assignment, SLA policies, escalation, shift handoff, disposition taxonomy, root-cause and impact fields, and closure requirements.
4. Add evidence lineage from raw object and parser version to normalized event, detection, case, export, and response action. Provide a chain-of-custody verifier.
5. Add incident templates for compromised identity, exfiltration, lateral movement, cryptomining, public admin access, and suspicious cloud control-plane activity.

### Telemetry and sensor operations

1. Add a real sensor/collector fleet manager: version, config drift, throughput, drops, lag, CPU/memory, clock skew, capture coverage, certificate health, upgrade rings, and remote diagnostics.
2. Support AWS Traffic Mirroring, Gateway Load Balancer, Kubernetes/eBPF, NetFlow/IPFIX, Zeek, Suricata, Route 53 Resolver, CloudTrail, GuardDuty, identity, vulnerability, and asset inventory as first-class source types.
3. Add schema registry, parse-quality score, field provenance, late-arrival handling, source clock correction, dedup reason, sampling disclosure, and per-source SLOs.
4. Add routing, redaction, tokenization, data tiering, retention, archive restore, replay, and per-tenant cost forecasting with a dry-run impact preview.
5. Add source canaries and synthetic events so the system proves collection-to-detection latency rather than only reporting heartbeats.

### Entity graph and exposure

1. Replace the 40-node circular SVG limit at `src/topology.js:1-70` with an interactive time-aware graph supporting zoom, pan, clustering, path search, filters, edge direction, protocols, risk overlays, and WebGL/canvas rendering for scale.
2. Model stable entities separately from observations: IP, ENI, EC2 instance, pod, container, host, user, role, account, application, domain, certificate, and external organization.
3. Continuously enrich from AWS Config, EC2, EKS, IAM, Identity Center, Inspector, Access Analyzer, security groups, NACLs, routes, TGW, load balancers, NAT, DNS, and tags.
4. Compute exposure paths that combine reachable routes, observed communication, privilege, vulnerability, data sensitivity, and compensating controls. Preserve point-in-time state for replay.

### Threat intelligence and retrospective search

1. Store indicators individually rather than embedding up to 5,000 inside one feed item at `server.mjs:1066-1083`.
2. Add STIX/TAXII 2.1, MISP, confidence decay, TLP enforcement, license constraints, indicator relationships, sightings, false-positive disposition, revocation, expiry, and source health.
3. Automatically retro-match new and changed indicators against hot and cold history; expose scan completeness, bytes scanned, cost, checkpoint, cancellation, and match provenance.
4. Add saved parameterized hunts, scheduled hunts, query versioning, schema-aware autocomplete, explain plans, quotas, async jobs, result snapshots, and export-to-case.

### Detection science and governed AI

1. Replace the current small-sample median/MAD seasonal model at `src/advanced-operations.mjs:162-209` with a model registry: training windows, cohort definitions, exclusions, feature lineage, quality metrics, approvals, shadow/canary deployment, drift, rollback, and poisoning controls that are actually enforced.
2. Add identity and asset peer groups, seasonality, newness, rarity, sequence, velocity, fan-in/fan-out, beaconing, domain age, prevalence, privilege, and exposure features.
3. Add encrypted-traffic analytics from TLS, QUIC, packet timing, certificate, SNI, ALPN, JA4 and only license-cleared fingerprints; explicitly disclose when inference is metadata-only.
4. Keep deterministic evidence collection separate from Bedrock narrative generation. Every AI claim should cite immutable event IDs and timestamps, report missing evidence, and carry model/prompt/context hashes.
5. Add prompt-injection regression suites, answer-groundedness evaluation, per-tenant model policy, PII redaction, human approval for tools, model fallback, cost budgets, and AI audit review.

### Response and integrations

1. Ship production adapters for AWS Network Firewall, security groups, IAM sessions/access keys, Kubernetes network policy, CrowdStrike, SentinelOne, ticketing, Slack, Teams, PagerDuty, Splunk, Sentinel, and generic signed webhooks.
2. Require customer-managed credentials, least-privilege installation checks, dry-run diffs, target previews, blast-radius limits, maintenance windows, two-person approval, kill switch, execution receipt, verification, timeout, and rollback.
3. Add connector delivery state, health, schema version, secret rotation, circuit breaker, retry, DLQ, replay, rate limit, destination acknowledgement, and sample-event testing.
4. Add Sigma import/export plus tested mappings to SPL, KQL, OCSF, ECS, STIX, and common SOAR case schemas.

## 6. UX and visual redesign

The interface is clean and consistent, but 14 horizontal tabs at `index.html:107-121` create a wide feature catalogue rather than a focused analyst workspace. Mobile becomes an extremely long page and the fixed left upload/filter rail dominates workflows where evidence upload is no longer relevant.

1. Use a persistent, collapsible left navigation grouped into `Monitor`, `Investigate`, `Respond`, `Data`, and `Administration`. Keep only role- and capability-relevant destinations visible.
2. Add real routes and deep links, browser history, preserved filters, shareable saved views, and a global command/search palette.
3. Make the default home a live analyst queue with compact metrics, freshness/health strip, attack stories, SLA risk, and assignments. Move ingest controls into `Data sources` and a global `Add evidence` action.
4. Use a consistent entity/case side drawer for pivots so analysts retain context. Add keyboard shortcuts, multi-select, bulk actions, column chooser, density control, sticky headers, and virtualized tables.
5. Replace large empty cards with actionable empty states. Distinguish `no data`, `not configured`, `not authorized`, `loading`, `degraded`, and `query returned zero`.
6. Reserve green for healthy/success, red for critical/destructive, amber for degraded/pending, blue for selected/informational, and neutral tones for structure. Current extensive green rules and bars make risk and normality harder to distinguish.
7. Use progressive rendering and Web Workers for 32 MB browser analysis at `app.js:1142-1181`; expose parse progress and cancellation.
8. Add automated axe/WCAG checks, reduced-motion support, chart data tables, non-color severity cues, focus restoration for dialogs/drawers, and screen-reader announcements for long jobs.

Industry leaders emphasize unified attack signal and identity context, deep packet/protocol evidence, historical search, sensor health, and fast alert-to-PCAP pivots. Vectra highlights cross-domain risk prioritization; ExtraHop combines sensors, NDR, IDS, NPM, and packet forensics; Corelight links Zeek evidence and detections to Smart PCAP; Gigamon emphasizes hybrid-cloud visibility, traffic optimization, topology, alarms, and centralized policy. SignalPrism should compete through AWS-native evidence governance and transparent open-schema interoperability, not by presenting every competitor feature at shallow depth.

## 7. Platform, deployment, and secure SDLC improvements

1. Pin the Docker base image by digest instead of mutable `node:22-alpine` at `Dockerfile:1`. Produce CycloneDX/SPDX SBOMs, sign images and provenance with Sigstore, verify at deploy, and scan the final image with Trivy or Grype.
2. Add Terraform `fmt`, `validate`, `tflint`, policy-as-code/Checkov, plan review, drift detection, and ephemeral integration environments to CI. Current CI at `.github/workflows/ci.yml:14-57` covers code, dependency audit, readiness, and browser tests but not infrastructure behavior.
3. Add secret scanning, dependency update automation, branch protection, CODEOWNERS for security/IaC/detection content, protected environments, OIDC-based deploy credentials, and artifact attestations.
4. Add CloudTrail data events for evidence/audit buckets, WAF logging, GuardDuty, Security Hub, AWS Config conformance, KMS key alarms, S3 access anomaly alerts, and centralized security-account delivery.
5. Emit OpenTelemetry traces, structured metrics, RED/USE dashboards, per-source freshness, queue lag, dropped events, parser rejects, delivery retries, Bedrock cost, and tenant cardinality. Define SLOs and error budgets.
6. Implement multi-AZ failure tests, cross-region S3 replication, DynamoDB global tables or a documented restore/failover strategy, Route 53 failover, backup restore drills, RTO/RPO evidence, and region-aware tenant placement.
7. Replace EFS/local operational state with explicit durable services where possible. Keep API tasks stateless and independently deploy/scale workers, indexers, schedulers, notification dispatchers, and response adapters.
8. Preserve the production egress risk gate, but prefer VPC endpoints and an egress proxy over the default `0.0.0.0/0` HTTPS option at `infra/aws/terraform/variables.tf:189-203`.

## 8. Test strategy additions

1. **Parser:** grammar/property tests, mutation fuzzing, decompression bombs, Unicode/control characters, huge fields, partial records, clock anomalies, and corpus regression per source version.
2. **Tenant/security:** cross-tenant object ID matrix for every route, custom-role route coverage, source-scope propagation, stale sessions, group changes, step-up authentication, export/packet/response approval chains, and browser-storage forensics.
3. **AWS contracts:** LocalStack or dedicated test account tests for S3 pagination/version/checksum/Object Lock, DynamoDB conditional races/GSI migration, SQS visibility/DLQ, Kinesis/Firehose partial failures, EventBridge responses, Security Lake registration, and Bedrock quotas.
4. **Detection quality:** labeled benign/malicious corpora, ATT&CK coverage fixtures, precision/recall and volume budgets, replay determinism, rule-version regression, model drift, and adversarial poisoning cases.
5. **Performance:** 1M/100M event ingest, burst/soak tests, hunt latency percentiles, hot-partition detection, browser worker limits, export sizes, and multi-tenant noisy-neighbor tests.
6. **Resilience:** kill API/worker during every state transition, throttle each AWS dependency, corrupt checkpoints, expire credentials, rotate keys, and prove replay without loss or double response.
7. **Frontend:** unmocked browser-to-local-backend workflows, axe scans, keyboard-only journeys, visual tests at narrow/wide/zoomed viewports, virtualized table checks, and locale/long-text stress.
8. **Deployment:** container vulnerability gate, SBOM/provenance validation, Terraform policy checks, ephemeral deployment smoke tests, DAST, backup restoration, and game-day evidence.

## 9. Prioritized delivery roadmap

### Phase 0: production blockers, 4-6 weeks

1. Unify ingest policy enforcement, repair S3 checkpoints, implement streaming parser/quarantine, and migrate event IDs.
2. Make evidence retention transactional and move browser raw evidence to direct upload.
3. Fail browser storage closed; harden packet/checksum/scanner trust boundaries.
4. Make rule promotion, case updates, packet grants, and response state transitions atomic and server-owned.
5. Add durable stream outbox, distributed quotas, and P0 regression tests.

**Exit gate:** no data-loss path under fault injection; no policy-bypass ingest path; no forged approval state; 100% endpoint authorization registry coverage.

### Phase 1: enterprise data plane, 6-10 weeks

1. Build Kinesis/S3 Parquet ingestion, OpenSearch or ClickHouse hot hunt, Athena cold hunt, and control-plane-only DynamoDB design.
2. Add schema registry, provenance, source SLOs, fleet health, async query/jobs, cost controls, and real integration delivery state.
3. Complete OCSF 1.8 native and Security Lake 1.3 conformance pipelines.

**Exit gate:** sustained representative load meets ingest and hunt SLOs with bounded cost, no hot key, and tested replay/backfill.

### Phase 2: analyst workflow redesign, 6-8 weeks

1. Introduce routed left navigation, unified investigation queue, attack stories, entity/case drawers, saved views, and virtualized records.
2. Complete detection lifecycle, tuning governance, case SLAs/collaboration, evidence lineage, and notification escalation.
3. Upgrade topology to the time-aware entity/exposure graph.

**Exit gate:** benchmark analyst scenarios complete without dead ends, retain context across pivots, meet accessibility checks, and reduce median triage steps/time.

### Phase 3: differentiated NDR, 8-12 weeks

1. Add sensor/Zeek/Suricata/PCAP depth, cloud and identity enrichment, encrypted-traffic analytics, and exposure paths.
2. Add model registry and governed peer behavior; validate with labeled and adversarial corpora.
3. Ship approved response adapters with verification and rollback plus MDR/provider operating workflows.

**Exit gate:** production pilots prove detection efficacy, investigation value, safe response, and operational supportability with measurable customer outcomes.

## 10. Verification performed

- `npm run check`: passed all syntax, smoke, enterprise, platform, advanced, integration, UI-flow, and readiness checks.
- `npm audit --audit-level=high`: zero known npm vulnerabilities.
- `terraform fmt -check -recursive infra/aws/terraform`: passed.
- `npm run visual:test`: 20 Chromium desktop and WebKit mobile tests passed.
- Visual review covered overview, platform operations, topology replay, tenant administration, and mobile layout snapshots.

## 11. Assumptions and open questions

1. This was a source and test review, not a live penetration test against a deployed AWS environment.
2. External response adapters, MSK/ClickHouse bridges, packet sensors, and customer cloud roles were treated as unavailable unless implemented in this repository.
3. Production data volume, retention, regions, RTO/RPO, compliance framework, and analyst concurrency are not yet specified; those numbers will materially shape the data plane.
4. The intended source-access policy for unassigned human users must be decided explicitly.
5. The product needs a clear deployment promise: customer-managed AWS account, vendor-managed SaaS, provider/MDR, or supported combinations. Isolation, upgrades, support, and compliance architecture differ substantially.

## 12. Current external references

- [AWS Security Lake custom source requirements](https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html)
- [OCSF schema releases](https://github.com/ocsf/ocsf-schema/releases)
- [AWS DynamoDB large-item guidance](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-use-s3-too.html)
- [AWS S3 ListObjectsV2 pagination](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html)
- [AWS S3 GetObjectAttributes checksums](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAttributes.html)
- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [Vectra AI platform](https://www.vectra.ai/platform)
- [ExtraHop RevealX platform](https://www.extrahop.com/platform/revealx)
- [Corelight Smart PCAP](https://corelight.com/products/smart-pcap/)
- [Corelight Fleet Manager](https://corelight.com/products/fleet-manager)
- [Gigamon Deep Observability Pipeline](https://www.gigamon.com/products/deep-observability-pipeline.html)
