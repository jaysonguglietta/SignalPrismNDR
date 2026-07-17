import assert from "node:assert/strict";
import {
  analyzeEncryptedTraffic,
  buildAdvancedOperations,
  buildRetrospectiveMatches,
  communityIdV1,
  evaluateInvestigationAgent,
  normalizePacketManifest,
  normalizeResponsePolicy,
  resolveOcsfProfile,
  scoreAttackUrgency
} from "./src/advanced-operations.mjs";
import { buildOcsfBatch, validateOcsfRecord } from "./src/ocsf.mjs";

const principal = { tenantId: "tenant-a", email: "analyst@example.com" };
const events = [
  { id: "event-2", timestamp: "2026-07-16T12:05:00Z", sourceIp: "10.0.0.5", destinationIp: "198.51.100.44", sourcePort: 50400, destinationPort: 443, protocol: "tcp", bytes: 9000, packets: 12, severity: "high", tlsVersion: "tls1.0", sni: "c2.example.net", ja4: "t13d1516h2_test", identity: "prod-admin", accountId: "123456789012", region: "us-east-1" },
  { id: "event-1", timestamp: "2026-07-16T12:00:00Z", sourceIp: "10.0.0.5", destinationIp: "10.0.1.9", sourcePort: 50401, destinationPort: 22, protocol: "tcp", application: "ssh", outcome: "failure", bytes: 200, packets: 4, severity: "medium", workload: "payments-api", accountId: "123456789012", region: "us-east-1" }
];
const findings = [{ id: "finding-1", title: "Privileged encrypted callback", severity: "high", score: 92, confidence: 0.88, eventCount: 20, entities: ["10.0.0.5", "prod-admin"], lastSeen: "2026-07-16T12:05:00Z", privileged: true }];

assert.equal(resolveOcsfProfile("native-current").version, "1.8.0");
assert.equal(resolveOcsfProfile("security-lake-1.3").version, "1.3.0");
assert.throws(() => resolveOcsfProfile("unknown"), /Unsupported/);

const native = buildOcsfBatch({ events, findings }, { tenantId: "tenant-a", region: "us-east-1", accountId: "123456789012", profile: "native-current" });
assert.equal(native.ocsfVersion, "1.8.0");
assert.equal(native.records[0].time <= native.records[1].time, true, "OCSF records must be time ordered");
assert.equal(native.records.every((record) => record.metadata.version === "1.8.0"), true);
assert.equal(validateOcsfRecord(native.records[0], "native-current"), true);

const securityLake = buildOcsfBatch({ events, findings }, { tenantId: "tenant-a", region: "us-east-1", accountId: "123456789012", profile: "security-lake-1.3" });
assert.equal(securityLake.ocsfVersion, "1.3.0");
const invalidTime = buildOcsfBatch({ events: [{ ...events[0], id: "invalid-time", timestamp: "not-a-timestamp" }] }, { tenantId: "tenant-a", profile: "native-current" });
assert.equal(invalidTime.recordCount, 0, "invalid timestamps must be quarantined instead of replaced with the current time");
assert.equal(invalidTime.rejectedCount, 1);
assert.equal(securityLake.compression, "zstd");
assert.equal(securityLake.deliveryPolicy.maxIntervalSeconds, 300);
assert.deepEqual(new Set(securityLake.eventClassBatches.map((batch) => batch.classUid)), new Set([4001, 2001]));
assert.equal(securityLake.eventClassBatches.every((batch) => new Set(batch.records.map((record) => record.class_uid)).size === 1), true);

const forwardCommunity = communityIdV1(events[0]);
const reverseCommunity = communityIdV1({ ...events[0], sourceIp: events[0].destinationIp, destinationIp: events[0].sourceIp, sourcePort: events[0].destinationPort, destinationPort: events[0].sourcePort });
assert.ok(forwardCommunity.startsWith("1:"));
assert.equal(forwardCommunity, reverseCommunity, "Community ID must be direction independent");
const ipv6Flow = { sourceIp: "2001:db8::10", destinationIp: "2001:db8::20", sourcePort: 51000, destinationPort: 443, protocol: "tcp" };
const ipv6Community = communityIdV1(ipv6Flow);
assert.ok(ipv6Community.startsWith("1:"));
assert.equal(ipv6Community, communityIdV1({ ...ipv6Flow, sourceIp: ipv6Flow.destinationIp, destinationIp: ipv6Flow.sourceIp, sourcePort: ipv6Flow.destinationPort, destinationPort: ipv6Flow.sourcePort }));

const urgencyBase = scoreAttackUrgency([{ ...findings[0], id: "urgency-base", entities: ["10.0.0.5"], eventCount: 2, privileged: false }], [], { nodes: [] }, { now: Date.parse("2026-07-16T12:10:00Z") })[0];
const urgencyExpanded = scoreAttackUrgency([{ ...findings[0], id: "urgency-expanded", entities: ["10.0.0.5", "prod-admin"], eventCount: 20, privileged: true }], [{ id: "campaign-expanded", signalIds: ["urgency-expanded"], blastRadius: { entityCount: 20, accountCount: 3, regionCount: 2 } }], { nodes: [] }, { now: Date.parse("2026-07-16T12:10:00Z") })[0];
assert.ok(urgencyExpanded.urgency > urgencyBase.urgency, "structured blast radius and privilege must increase urgency");
assert.equal(urgencyExpanded.scoring.blastRadius, 100);

const snapshot = buildAdvancedOperations({ events, findings, campaigns: [{ id: "campaign-1", signalIds: ["finding-1"], blastRadius: 4 }], sources: [{ id: "source-1", name: "VPC flow logs", status: "healthy", updatedAt: "2026-07-16T12:05:00Z" }] }, { now: "2026-07-16T12:10:00Z" });
assert.equal(snapshot.urgentFindings[0].scoring.confidence, 88);
assert.equal(snapshot.urgentFindings[0].urgency >= 70, true);
assert.equal(snapshot.entityGraph.nodes.some((node) => node.value === "prod-admin"), true);
assert.equal(snapshot.entityGraph.edges.some((edge) => edge.communityIds.includes(forwardCommunity)), true);
assert.equal(snapshot.sourceHealth[0].state, "healthy");
assert.equal(snapshot.encryptedTraffic.findings.some((finding) => finding.reasons.includes("obsolete TLS version")), true);

const encrypted = analyzeEncryptedTraffic(events);
assert.equal(encrypted.fingerprintCoveragePercent, 100);
assert.match(encrypted.licensePolicy, /license-cleared/);

const sightings = buildRetrospectiveMatches(events, [{ id: "ioc-1", value: "c2.example.net", confidence: 90 }]);
assert.equal(sightings.length, 1);
assert.equal(sightings[0].eventId, "event-2");

const manifest = normalizePacketManifest({ objectUri: "s3://evidence-bucket/tenant-a/packet.pcap", sha256: "a".repeat(64), bytes: 200, packetCount: 4 }, principal);
assert.equal(manifest.immutable, true);
assert.throws(() => normalizePacketManifest({ objectUri: "https://attacker.example/packet.pcap", sha256: "a".repeat(64) }, principal), /object URI/);

const policy = normalizeResponsePolicy({ mode: "enforce", killSwitch: true, requireCase: true }, principal);
assert.equal(policy.killSwitch, true);
assert.equal(policy.allowedAdapters.includes("aws-network-firewall"), true);

const goodEvaluation = evaluateInvestigationAgent({ tenantId: "tenant-a", citations: [{ id: "evidence-1" }], claims: [{ citationIds: ["evidence-1"] }], toolCalls: [{ mutating: true, approvalId: "approval-1" }] });
assert.equal(goodEvaluation.passed, true);
const badEvaluation = evaluateInvestigationAgent({ tenantId: "tenant-a", citations: [], claims: [{ citationIds: [] }], toolCalls: [{ mutating: true }] });
assert.equal(badEvaluation.passed, false);

console.log("advanced operations contract checks passed");
