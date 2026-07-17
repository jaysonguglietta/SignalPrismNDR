# SignalPrism NDR Competitive Gap Analysis

## Implementation update

The July 2026 implementation adds the recommended foundation: isolated OCSF 1.8 native and OCSF 1.3 Security Lake profiles; class-specific Zstandard Firehose delivery; assigned-prefix/provider registration records; Kinesis replay; signed OpenSearch hunt integration; source/sensor health; temporal entity resolution; seasonal peer models; encrypted and protocol metadata analytics; Community ID; multi-factor urgency; immutable packet manifests; response policy and kill switches; threat-intelligence retromatching; case tasks and SLAs; enforced pipeline masking/deduplication/tiering; exposure context; regional/provider/notification governance; and investigation-agent evaluation. Items that inherently require external systems remain adapter boundaries: packet sensor deployment, vendor response credentials, the MSK/ClickHouse bridges, delegated-administrator Security Lake API application, and staffed follow-the-sun MDR operations.

Analysis date: July 16, 2026

## Executive Conclusion

SignalPrism is strongest as an AWS-native, multi-tenant investigation and governance control plane. It already has unusually mature evidence retention, independent approvals, tenant administration, signed detection content, OCSF projection, case workflow, explainable analytics, and safe AI controls for a product at this stage.

It is not yet equivalent to a leading full-stack NDR product. The leaders combine an always-on sensor and packet acquisition plane with rich protocol metadata, time-aware entity identity, continuously trained behavior models, large detection libraries, packet-level proof, fleet operations, and native containment. SignalPrism currently consumes evidence produced elsewhere and adds analytics and governance; it does not yet create enough network evidence itself.

The recommended product direction is not to reproduce Gigamon appliances or every proprietary NDR sensor. SignalPrism should become an open, cloud-native NDR control plane that can operate its own lightweight collectors while treating Gigamon, Corelight, ExtraHop, Zeek, Suricata, cloud mirrors, and flow exporters as first-class evidence providers.

## Scope And Method

The repository was reviewed against current official product material from:

- Gigamon Deep Observability Pipeline and Application Metadata Intelligence.
- Vectra AI Platform, Recall, Respond, and MXDR.
- ExtraHop RevealX.
- Darktrace / NETWORK and Autonomous Response.
- Corelight Open NDR and Smart PCAP.
- Cisco Secure Network Analytics and Encrypted Traffic Analytics.
- Arista NDR.
- Adjacent XDR and SIEM capabilities from Cortex XDR and CrowdStrike Falcon Next-Gen SIEM.
- Amazon Security Lake custom-source requirements and MITRE ATT&CK network data components.

Vendor statements describe product capabilities, not independent performance validation. Competitive scores below reflect visible product breadth and repository evidence, not detection efficacy measured on a common dataset.

## Current SignalPrism Position

### Strong capabilities

- Multi-tenant OIDC, SCIM, built-in/custom roles, service accounts, source scoping, and audit history.
- Browser upload, direct S3 evidence upload, S3/CloudWatch jobs, SQS workers, and cross-account source onboarding.
- Immutable evidence and audit storage with Object Lock, KMS, retention, hashes, and export approvals.
- Normalization for AWS, Azure, GCP, Kubernetes, Cilium, Gigamon/CEF/IPFIX, ExtraHop, Zeek, and Suricata records.
- Explainable deterministic behavior findings, correlation, campaign assembly, topology replay, and safe retrospective hunts.
- Detection-as-code lifecycle, backtesting, ATT&CK mapping, independent promotion, and signed content bundles.
- Governed response intents with dry-run, independent approval, expiry, verification, and rollback workflows.
- OCSF projection, Parquet/Glue infrastructure, Security Lake-oriented partitions, and connector catalog.
- Case management, evidence-cited investigation runs, Bedrock feature flag, quotas, and prompt-injection boundaries.
- Responsive enterprise operations UI, local fallback, tests, production startup checks, and AWS Terraform.

### Architectural boundaries

- No native packet sensor, TAP, cloud traffic-mirroring collector, eBPF collector, or switch exporter management.
- No full protocol decoding, application fingerprint engine, payload extraction, or PCAP repository.
- No continuous multivariate ML service, seasonal peer-group modeling, model registry, or model drift control.
- No production search service for long-retention, high-cardinality evidence; Athena is an export/query path rather than the interactive hunt engine.
- Response and connector adapters are governed EventBridge intents, not deployed vendor-specific executors.
- Custom permission strings exist, but most API enforcement still resolves to conservative built-in base roles.
- The Terraform represents a production path but has not been deployed or measured at enterprise traffic volume.

## Industry Leader Comparison

### Gigamon

Gigamon's advantage is the acquisition and data-preparation plane. Its pipeline accesses physical, virtual, cloud, and container traffic; brokers it to tools; transforms it through filtering, deduplication, slicing, masking, and decryption; enriches it with application metadata; and centrally manages the fabric. Application Metadata Intelligence advertises deep packet inspection across thousands of applications and attributes.

SignalPrism has the downstream control plane Gigamon typically feeds, but not the traffic fabric. The best competitive move is deep Gigamon interoperability: inventory GigaVUE nodes, ingest AMI metadata, reconcile coverage, request filtered packet windows, and measure telemetry reduction and delivery health.

### Vectra AI

Vectra's strength is attack prioritization across network, identity, cloud, SaaS, IoT, and OT. Its urgency model combines breadth, velocity, attack profile, privilege, and customer importance. Recall provides long-term host- and account-oriented metadata search, while Respond and MXDR add native, integrated, and managed containment.

SignalPrism has early versions of entity risk, campaigns, historical hunts, and response governance. It lacks time-aware host/account identity, cross-surface scoring depth, continuous model learning, large-scale metadata retention, and a managed service operating model.

### ExtraHop RevealX

ExtraHop combines NDR, network performance monitoring, IDS, decryption, protocol decoding, cloud-scale machine learning, and packet forensics. Its primary advantage is transaction-level context from passive sensors and the ability to pivot from a detection to packets and application behavior.

SignalPrism can ingest ExtraHop findings but cannot independently reproduce transaction analytics, packet reconstruction, application performance, or evidence capture. An ExtraHop adapter should preserve detection participants, transaction context, packet references, and response status rather than flattening them into generic events.

### Darktrace

Darktrace emphasizes environment-specific self-learning, automatic investigation, cross-domain correlation, exposure management, and autonomous response constrained by organizational guardrails. It also offers incident readiness and managed detection services.

SignalPrism's deterministic explanations and two-person control are stronger governance primitives, but its behavior model is much narrower. It needs continuous baselines, peer groups, seasonality, learning exclusions, model health, and graded response modes before it can credibly claim autonomous NDR.

### Corelight

Corelight's Open NDR platform combines Zeek evidence, Suricata IDS, threat intelligence, YARA file analysis, encrypted traffic insights, and Smart PCAP. Smart PCAP links logs and detections to targeted packets and extends lookback by capturing only relevant byte ranges.

SignalPrism already accepts Zeek and Suricata records and can emit capture intents. The missing layer is evidence identity and retrieval: Community ID, sensor/capture rule management, PCAP object manifests, packet-level authorization, extracted-file lineage, and one-click investigation pivots.

### Cisco Secure Network Analytics

Cisco uses existing network infrastructure, NetFlow, endpoint network telemetry, identity context, continuous baselines, global threat intelligence, and encrypted traffic analytics. Its encrypted analytics uses intraflow metadata such as initial packet data and sequences of packet lengths and times without bulk decryption.

SignalPrism has flow analysis and basic TLS posture but no SPLT/initial-data-packet features, device-role classification, ISE-style group policy analysis, or network-exporter fleet. Privacy-preserving encrypted traffic analytics is a high-value addition that does not require SignalPrism to hold decryption keys.

### Arista NDR

Arista supplies physical, virtual, cloud, all-in-one, and switch-integrated sensors that produce Layer 2-7 evidence for centralized AI analysis. It specifically covers campus, data center, cloud, IoT, and OT networks.

SignalPrism has cloud and Kubernetes normalization but no physical/campus sensor story and little OT protocol context. A collector SDK and certified sensor program would close more of this gap than building proprietary hardware.

### Adjacent XDR And SIEM Platforms

Cortex XDR and CrowdStrike Falcon demonstrate buyer expectations beyond NDR: endpoint/identity/cloud fusion, petabyte-scale search, federated queries, live dashboards, workflow automation, adversary intelligence, managed response, and detection/content marketplaces. SignalPrism should integrate deeply with these systems instead of becoming another general-purpose SIEM.

## Capability Matrix

Maturity scale: `0` absent, `1` intent or metadata only, `2` functional but bounded, `3` production-shaped, `4` leader-level breadth and operations.

| Capability | SignalPrism | Leader expectation | Assessment |
| --- | ---: | ---: | --- |
| Cloud flow-log ingest | 3 | 4 | Strong AWS path; broaden event-driven streaming and provider-native onboarding. |
| Packet/sensor acquisition | 0 | 4 | Largest functional gap. |
| Protocol and application metadata | 1 | 4 | Consumes metadata but does not extract it. |
| Encrypted traffic analytics | 1 | 4 | TLS posture exists; behavioral encrypted-flow detection does not. |
| Continuous UEBA/ML | 2 | 4 | Explainable rules exist; seasonality, peer groups, and model operations do not. |
| Attack/campaign prioritization | 2 | 4 | Good deterministic foundation; needs breadth/velocity/privilege/spread scoring. |
| Identity/cloud/SaaS fusion | 2 | 4 | Cloud identity records supported; SaaS and privileged identity depth are limited. |
| Asset discovery and attribution | 1 | 4 | Asset context exists without time-aware IP/user/workload resolution. |
| Packet forensics | 1 | 4 | Capture intent exists; no capture repository or packet pivot. |
| Historical hunt/search | 2 | 4 | Safe hunt language is useful but bounded to tenant records in the app store. |
| Threat intelligence | 2 | 4 | Import/enrichment exists; no lifecycle, scoring, retro-match pipeline, or actor graph. |
| Detection engineering | 3 | 4 | Strong governance; needs larger content library, shadow deployment, and efficacy telemetry. |
| Response governance | 3 | 4 | Strong approval/verification model; native executors remain external. |
| Native autonomous response | 1 | 4 | Event intents only; no policy engine or deployed adapters. |
| Cases and immutable evidence | 4 | 3 | A meaningful SignalPrism differentiator. |
| Multi-tenant identity/governance | 3 | 3 | Strong foundation; custom permission enforcement should become first-class. |
| Open schema and data lake | 3 | 3 | Strong direction with a Security Lake compatibility issue to resolve. |
| Sensor/source fleet operations | 0 | 4 | No fleet lifecycle, drop monitoring, capacity, clock, or certificate management. |
| Network performance monitoring | 0 | 3 | Missing latency, retransmit, dependency, and service-health analytics. |
| IoT/OT visibility | 1 | 3 | Generic records only; no passive device/protocol classification. |
| MDR/service-provider workflows | 0 | 3 | No follow-the-sun queues, customer escalation, or provider tenancy. |
| Data economics and routing | 1 | 4 | Retention exists; no dedupe, sampling, masking, routing policy, or cost planner. |
| Model governance | 1 | 3 | AI quotas and deterministic explanations exist; no registry/evaluation/drift framework. |
| Production scale/HA evidence | 2 | 4 | Terraform is production-shaped but not deployed or load-tested. |

## Immediate Compatibility Finding

The current OCSF exporter declares OCSF `1.4.0`. The current upstream OCSF release is `1.8.0`, while Amazon Security Lake documentation states that custom sources support OCSF `1.3` and earlier. SignalPrism is therefore behind the open standard and ahead of the managed service compatibility ceiling at the same time. Security Lake also requires each custom source to contain one OCSF event class, requires the Security Lake-assigned prefix, specifies `region/accountId/eventDay` partitioning, recommends Zstandard compression, requires time ordering, and defines object size/rate boundaries.

Before describing the Firehose output as Security Lake-compatible, implement:

1. A schema-version target with `security-lake-1.3` and `native-ocsf-1.8` modes, plus migrations from the existing 1.4 mapping.
2. Separate delivery streams or dynamic prefixes for Network Activity and Security Finding classes.
3. Official OCSF validation in CI using representative golden records.
4. Time sorting and five-minute/size-aware buffering before Parquet object delivery.
5. Zstandard Parquet compression for the Security Lake target.
6. `CreateCustomLogSource` automation with provider identity, external ID, Glue crawler role, and regional source state.
7. Subscriber and Lake Formation verification tests.
8. Schema evolution rules and replay/migration tooling.

## Recommended Product Roadmap

### P0: Make The Existing Platform Operationally True

#### 1. Security Lake compatibility controller

- Backend: versioned OCSF mappers, event-class routers, schema registry, source registration, crawler status, subscriber checks.
- Data: `SchemaVersion`, `DeliveryTarget`, `CustomSource`, `SchemaValidationRun`.
- UI: compatibility status, rejected fields, source registration wizard, schema migration preview.
- Tests: official validation fixtures, partition/object-size tests, Glue/Athena integration, rollback between mapper versions.
- Effort: Medium.

#### 2. Durable streaming backbone

- Add Kinesis Data Streams or MSK as the continuous ingress boundary instead of relying on request/response API batches.
- Partition by tenant and stable source ID, enforce per-tenant quotas, preserve idempotency keys, and propagate backpressure.
- Add replay checkpoints, poison-record quarantine, event age, consumer lag, and exactly-once logical processing.
- Keep SQS for import jobs; do not overload it as the primary high-volume event stream.
- Effort: Large.

#### 3. Interactive search tier

- Add OpenSearch, ClickHouse, or a pluggable query service for hot evidence; retain Athena for cold/federated data.
- Compile the safe hunt AST to backend-specific query plans rather than exposing raw query syntax.
- Add asynchronous query jobs, cancellation, byte/time budgets, sampled previews, saved parameterized hunts, and result manifests.
- Effort: Large.

#### 4. Source and sensor health command center

- Track freshness, lag, drop rate, parse rejection, bytes/records, clock skew, gaps, permissions, version, certificate expiry, and capacity.
- Add SLOs, maintenance windows, ownership, alert routing, and coverage heat maps by account/VPC/subnet/source/type.
- Model blind spots as findings that can open cases and block readiness promotion.
- Effort: Medium.

### P1: Reach Competitive Detection Depth

#### 5. Time-aware entity identity graph

- Resolve IP, MAC, hostname, ENI, instance, pod, container, user, account, service principal, application, certificate, and cloud resource over time.
- Ingest DHCP, DNS, cloud inventory, CMDB, EDR, IdP, vulnerability, and ownership context.
- Preserve confidence, source, valid-from/valid-to, conflicting claims, and merge/split audit history.
- Make every detection, hunt, campaign, and case pivot on stable entities rather than current IP addresses.
- Effort: Large.

#### 6. Continuous behavior service

- Add per-entity and peer-group baselines with hour/day/week seasonality, robust quantiles, rare-event features, and change-point detection.
- Support learning exclusions, approved maintenance, baseline promotion, freeze/reset, and incident-contamination safeguards.
- Add model cards, feature provenance, drift, false-positive feedback, shadow deployment, and rollback.
- Keep every alert evidence-cited and expose contributing features instead of opaque anomaly scores.
- Effort: Large.

#### 7. Privacy-preserving encrypted traffic analytics

- Normalize JA4, licensed JA4+ fingerprints where appropriate, TLS version/cipher/extension order, SNI, ALPN, certificate chain, session reuse, QUIC metadata, and key-exchange posture.
- Add sequence-of-packet-length-and-time, burst, directionality, handshake, and periodicity features without payload decryption.
- Detect rare fingerprints, certificate anomalies, malware-like flow sequences, covert channels, and policy violations.
- Create explicit privacy controls for any initial-data-packet sampling.
- Complete a commercial license review before shipping JA4S/JA4H/JA4X or other JA4+ methods. The official project licenses base JA4 under BSD 3-Clause but requires OEM terms for monetized JA4+ use.
- Effort: Large.

#### 8. Protocol analytics packs

- Build normalized classes and detections for DNS, HTTP, TLS, SSH, RDP, SMB, Kerberos, LDAP, DHCP, NTP, FTP, database, RPC, and selected OT protocols.
- Prefer Zeek/Corelight integrations and a collector SDK over writing every parser from scratch.
- Add Community ID so alerts, Zeek logs, Suricata events, flows, and PCAP refer to the same conversation.
- Effort: Large.

#### 9. Attack urgency and exposure scoring

- Score entities and campaigns using detection breadth, velocity, stage progression, privilege, criticality, exposure, confidence, novelty, and blast radius.
- Separate likelihood, impact, confidence, and urgency so analysts can understand ranking changes.
- Add attack-path reachability from network routes, security groups, identities, vulnerabilities, and observed communication.
- Effort: Medium to large.

#### 10. Detection content expansion

- Add tested packs for ransomware precursors, C2, DNS tunneling, exfiltration, cryptomining, DDoS, credential abuse, remote administration, insider behavior, cloud persistence, Kubernetes compromise, and OT discovery.
- Add shadow mode, per-rule compute budgets, suppression scopes, duplicate clustering, canary tenants, rollout rings, and automatic rollback on noise regressions.
- Measure precision proxies, analyst disposition, mean time to acknowledge, recurrence, ATT&CK/data-component coverage, and evidence quality.
- Effort: Continuous program.

### P2: Close The Evidence And Response Loop

#### 11. Smart packet capture integration

- Turn `capture-packets` into a deployable adapter contract for Gigamon, Corelight, ExtraHop, Zeek/Arkime, and cloud mirrors.
- Require filter, target, byte depth, duration, maximum bytes, legal basis, retention, and approver.
- Store PCAP manifests in Object Lock, link by Community ID, and expose one-click download/open workflows with separate packet-access permission.
- Record sensor acknowledgement, collection start/stop, truncation, checksum, and evidence chain of custody.
- Effort: Medium for adapters; large for a native capture plane.

#### 12. File and payload evidence pipeline

- Ingest extracted-file metadata and optional approved samples from Zeek/Corelight/Suricata.
- Hash with SHA-256, scan with YARA, integrate a malware sandbox, preserve parent flow/packet lineage, and quarantine dangerous downloads.
- Keep payload storage opt-in and governed by privacy/data-residency policy.
- Effort: Medium.

#### 13. Deployed response adapters and policy engine

- Ship separately permissioned adapters for AWS Network Firewall, security groups, WAF, IAM/Identity Center, Entra/AD, Kubernetes, CrowdStrike, Defender, and major firewalls.
- Add response policies by tenant, entity importance, action, schedule, confidence, case state, and maximum blast radius.
- Support recommendation, human confirmation, bounded automatic, and emergency-stop modes.
- Add adapter heartbeats, idempotency, DLQs, verification queries, rollback tests, rate limits, and global kill switch.
- Effort: Large.

#### 14. SOC collaboration and notification workflows

- Add case tasks, watchers, comments, mentions, handoffs, SLAs, escalation policies, linked incidents, duplicate merge, and evidence requests.
- Add email, Slack/Teams, PagerDuty, webhook-through-adapter, and mobile push notifications with deduplication and quiet hours.
- Add shift dashboards, analyst workload, queue aging, disposition quality, and response verification backlog.
- Effort: Medium.

#### 15. Threat intelligence operations

- Add feed lifecycle, source trust, confidence decay, indicator expiry, sightings, false-positive suppression, actor/campaign/malware relationships, and STIX relationship preservation.
- Retro-match every new high-confidence indicator against hot and cold evidence with bounded query cost.
- Add tenant/private/global scopes and signed intelligence packages.
- Effort: Medium.

### P3: Differentiate As An Enterprise Platform

#### 16. Network performance and service dependency analytics

- Derive latency, retransmission, failed handshakes, connection churn, DNS delay, application response time, service dependencies, and path health where source metadata permits.
- Correlate security anomalies with availability impact and business services.
- Avoid positioning this as full NPM until packet/transaction telemetry exists.
- Effort: Large.

#### 17. Telemetry optimization and data economics

- Add routing policy, deduplication, sampling, field projection, tokenization/masking, tenant privacy zones, hot/warm/cold tiering, and cost forecasting.
- Show ingest volume by source, parser, tenant, event class, retention tier, and downstream destination.
- Simulate policy effects before deployment and prove that required detection fields remain available.
- Effort: Large.

#### 18. Multi-region, sovereign, and disconnected deployment

- Add active/passive regional control planes, Security Lake rollup-region awareness, tenant data residency, BYOK/external key controls, backup restore automation, and regional failover drills.
- Support private model endpoints and an air-gapped mode with signed offline content updates.
- Publish tested RPO/RTO and availability SLOs.
- Effort: Large.

#### 19. Service-provider and MDR operating model

- Add provider/tenant hierarchy, delegated administration, customer-visible escalation, evidence-sharing consent, service-level policies, analyst assignment pools, and follow-the-sun handoffs.
- Provide a secure expert-access workflow with explicit tenant approval and session recording.
- Treat actual 24x7 response as a service and staffing decision, not a UI label.
- Effort: Large plus operations.

#### 20. Governed investigation agents

- Give agents typed read-only tools for search, entity history, campaign expansion, threat intelligence, and case evidence.
- Require approval for state changes or response actions; keep the existing EventBridge governance boundary.
- Add prompt-injection fixtures, citation completeness, unsupported-claim checks, golden investigations, cost/latency budgets, and analyst feedback evaluation.
- Add cross-case memory only as explicit, tenant-scoped, redactable facts with provenance and expiry.
- Effort: Medium to large.

## Recommended Sequencing

### Release A: Compatibility And Operations

1. Security Lake 1.3 compatibility mode and custom-source registration.
2. Source health, coverage SLOs, and operational notifications.
3. Search service abstraction and hot-store proof of concept.
4. Community ID and stable source/entity identifiers.

### Release B: Detection Depth

1. Time-aware entity graph.
2. Continuous seasonal baselines and peer groups.
3. Encrypted traffic features and license-cleared JA4/JA4+ fingerprints.
4. Protocol analytics through Zeek/Corelight integration.
5. Urgency score and exposure graph.

### Release C: Evidence And Response

1. Smart PCAP adapter and packet evidence authorization.
2. Production response adapters with policy modes and kill switch.
3. Threat-intelligence retro-match pipeline.
4. SOC tasks, SLAs, and notifications.

### Release D: Enterprise Scale

1. Kinesis/MSK streaming and high-volume search.
2. Multi-region/residency and tested disaster recovery.
3. Telemetry cost controls and routing policy.
4. Service-provider/MDR hierarchy.
5. Governed agent evaluation and tool use.

## Product Positioning Recommendation

Do not position SignalPrism as a direct replacement for Gigamon, ExtraHop, or Corelight sensors yet. Position it as:

> An open, AWS-native NDR investigation and governance platform that turns cloud logs and network evidence from any sensor into explainable campaigns, immutable evidence, governed response, and Security Lake-ready analytics.

The long-term differentiator should be evidence governance plus interoperability: one control plane that can prove what was observed, why it mattered, who approved action, what changed, whether containment worked, and how the result was retained.

## Sources

- Gigamon Deep Observability Pipeline: https://www.gigamon.com/products/deep-observability-pipeline.html
- Gigamon Application Intelligence: https://www.gigamon.com/products/optimize-traffic/application-intelligence.html
- Vectra AI Platform: https://www.vectra.ai/platform
- Vectra Respond: https://www.vectra.ai/platform/respond
- Vectra Recall: https://www.vectra.ai/topics/vectra-recall
- Vectra MXDR: https://www.vectra.ai/products/mdr
- ExtraHop RevealX platform: https://www.extrahop.com/platform
- ExtraHop RevealX architecture: https://www.extrahop.com/platform/revealx/how-it-works
- Darktrace / NETWORK: https://www.darktrace.com/products/network
- Darktrace Autonomous Response: https://www.darktrace.com/darktrace-autonomous-response
- Corelight Open NDR: https://corelight.com/products/open-ndr
- Corelight Smart PCAP: https://corelight.com/products/smart-pcap/
- Cisco Secure Network Analytics: https://www.cisco.com/site/us/en/products/security/security-analytics/secure-network-analytics/index.html
- Cisco Secure Network Analytics data sheet: https://www.cisco.com/c/en/us/products/collateral/security/stealthwatch/datasheet-c78-739398.html
- Arista NDR: https://www.arista.com/en/solutions/security/nac
- Cortex XDR documentation: https://docs-cortex.paloaltonetworks.com/p/XDR
- CrowdStrike Next-Gen SIEM: https://www.crowdstrike.com/en-us/platform/next-gen-siem/
- Amazon Security Lake custom-source requirements: https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html
- Amazon Security Lake custom-source registration: https://docs.aws.amazon.com/security-lake/latest/userguide/adding-custom-sources.html
- OCSF schema releases: https://github.com/ocsf/ocsf-schema/releases
- JA4+ project and licensing: https://github.com/FoxIO-LLC/ja4
- MITRE ATT&CK Network Traffic Flow: https://attack.mitre.org/datacomponents/DC0078/
