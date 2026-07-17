import assert from "node:assert/strict";
import { analyzeAiTraffic, analyzeCryptoPosture, backtestDetectionRule, buildAttackCampaigns, buildBehaviorAnalytics, parseHuntQuery, runRetrospectiveHunt } from "./src/enterprise-analytics.mjs";
import { buildFirehoseRecords, buildOcsfBatch, securityLakePartition, validateOcsfRecord } from "./src/ocsf.mjs";
import { connectorCatalog, normalizeConnector, publicConnector } from "./src/connector-catalog.mjs";
import { parseTelemetryPayload } from "./src/enterprise-telemetry.mjs";
import { createPresignedAwsUrl } from "./src/aws-sigv4.mjs";

const start = Date.parse("2026-07-16T01:00:00Z");
const events = Array.from({ length: 7 }, (_, index) => ({
  id: `event-${index}`,
  timestamp: new Date(start + index * 60_000).toISOString(),
  format: "generic",
  provider: "aws",
  category: "network",
  sourceIp: "10.0.1.10",
  destinationIp: "198.51.100.25",
  destinationPort: 443,
  protocol: "TCP",
  action: "connect",
  outcome: index < 6 ? "failure" : "success",
  severity: index === 6 ? "high" : "informational",
  bytes: index === 6 ? 75_000_000 : 1_000,
  query: index === 6 ? "api.openai.com" : "",
  tlsVersion: index === 6 ? "TLS1.0" : "TLS1.3",
  cipher: index === 6 ? "TLS_RSA_WITH_3DES_EDE_CBC_SHA" : "TLS_AES_256_GCM_SHA384",
  certificateExpiresAt: index === 6 ? "2026-07-20T00:00:00Z" : "2027-07-20T00:00:00Z"
}));

const behavior = buildBehaviorAnalytics(events, {
  baselineProfiles: [{ entity: "10.0.1.10", peers: ["203.0.113.1"], ports: [80] }],
  businessHourStart: 6,
  businessHourEnd: 20
});
assert.equal(behavior.entityCount, 1);
assert.ok(behavior.findings.some((finding) => finding.ruleId === "SP-UEBA-001"));
assert.ok(behavior.findings.some((finding) => finding.ruleId === "SP-UEBA-005"));
assert.ok(behavior.findings.some((finding) => finding.ruleId === "SP-UEBA-006"));
assert.ok(behavior.findings.every((finding) => finding.evidenceIds.length > 0));

const hunt = runRetrospectiveHunt(events, "sourceIp:10.0.* AND (outcome:failure OR severity:high)");
assert.equal(hunt.matchCount, 7);
assert.equal(hunt.facets.outcome, undefined);
assert.throws(() => parseHuntQuery("constructor:attack"), /Unsupported hunt field/);
assert.throws(() => parseHuntQuery("sourceIp:10.0.0.1 OR (outcome:failure"), /Unclosed/);

const backtest = backtestDetectionRule({ id: "rule-1", query: "outcome:failure", maxNoiseRate: 0.9 }, events, { maliciousEventIds: ["event-0", "event-1"], benignEventIds: ["event-2"] });
assert.equal(backtest.matched, 6);
assert.equal(backtest.truePositives, 2);
assert.equal(backtest.falsePositives, 1);
assert.equal(backtest.falseNegatives, 0);

const campaigns = buildAttackCampaigns({
  findings: [{ id: "corr-1", title: "Authentication spray", tactic: "Credential Access", entity: "10.0.1.10", score: 80, firstSeen: events[0].timestamp, lastSeen: events[2].timestamp, evidenceIds: ["event-0", "event-1"] }],
  anomalies: behavior.findings,
  events
}, { windowMinutes: 120 });
assert.ok(campaigns.length >= 1);
assert.ok(campaigns[0].entities.includes("10.0.1.10"));
assert.ok(campaigns[0].blastRadius.entityCount >= 1);

const ai = analyzeAiTraffic(events, { sanctionedProviders: ["AWS Bedrock"] });
assert.equal(ai.observedEvents, 1);
assert.equal(ai.unsanctionedEvents, 1);
assert.equal(ai.observations[0].provider, "OpenAI");

const crypto = analyzeCryptoPosture(events);
assert.ok(crypto.findings.some((finding) => finding.ruleId === "SP-CRYPTO-001"));
assert.ok(crypto.findings.some((finding) => finding.ruleId === "SP-CRYPTO-002"));

const batch = buildOcsfBatch({ events, findings: behavior.findings, campaigns }, { tenantId: "tenant-a", region: "us-east-1", accountId: "123456789012" });
assert.equal(batch.rejectedCount, 0);
assert.equal(batch.recordCount, events.length + behavior.findings.length + campaigns.length);
assert.equal(validateOcsfRecord(batch.records[0]), true);
assert.match(securityLakePartition(batch.records[0], { region: "us-east-1", accountId: "123456789012" }), /^region=us-east-1\/accountId=123456789012\/eventDay=20260716\/$/);
assert.equal(buildFirehoseRecords(batch.records).length, batch.recordCount);

const formats = [
  [{ time: "2026-07-16T12:00:00Z", flowTuples: "1752667200,10.0.0.1,8.8.8.8,50000,53,U,O,A" }, "azure-nsg"],
  [{ timestamp: "2026-07-16T12:00:00Z", connection: { src_ip: "10.0.0.1", dest_ip: "8.8.8.8", src_port: 50000, dest_port: 53, protocol: 17 }, src_instance: { vm_name: "vm-a" }, reporter: "SRC" }, "gcp-vpc-flow"],
  [{ auditID: "audit-1", requestReceivedTimestamp: "2026-07-16T12:00:00Z", verb: "create", user: { username: "developer" }, objectRef: { resource: "pods", namespace: "prod", name: "debug" } }, "kubernetes-audit"],
  [{ time: "2026-07-16T12:00:00Z", verdict: "DROPPED", source: { pod_name: "frontend", namespace: "prod" }, destination: { pod_name: "database" }, IP: { source: "10.1.0.2", destination: "10.2.0.3" }, l4: { TCP: { source_port: 50100, destination_port: 5432 } } }, "cilium-hubble"],
  [{ timestamp: "2026-07-16T12:00:00Z", exporterAddress: "10.0.0.5", sourceIPv4Address: "10.0.0.1", destinationIPv4Address: "8.8.8.8", destinationTransportPort: 53 }, "gigamon"],
  [{ timestamp: "2026-07-16T12:00:00Z", detection_title: "Beaconing", risk_score: 90, src_ip: "10.0.0.1", dst_ip: "198.51.100.5" }, "extrahop"]
];
for (const [record, expected] of formats) {
  const parsed = parseTelemetryPayload([record]);
  assert.equal(parsed.accepted, 1);
  assert.equal(parsed.events[0].format, expected);
}
const cef = parseTelemetryPayload("CEF:0|Gigamon|AMI|1.0|100|Suspicious TLS|8|rt=2026-07-16T12:00:00Z src=10.0.0.1 dst=198.51.100.2 spt=50000 dpt=443 proto=TCP app=tls");
assert.equal(cef.events[0].format, "gigamon");
assert.equal(cef.events[0].severity, "high");

assert.ok(connectorCatalog().some((connector) => connector.id === "gigamon-vseries"));
const connector = normalizeConnector({ catalogId: "splunk-hec", name: "Splunk", format: "hec", endpoint: "https://splunk.example.com/services/collector", secretRef: "arn:aws:secretsmanager:us-east-1:123456789012:secret:signalprism/splunk" }, { tenantId: "tenant-a", subject: "admin" });
assert.equal(publicConnector(connector).secretConfigured, true);
assert.doesNotMatch(publicConnector(connector).secretRef, /signalprism\/splunk$/);
assert.throws(() => normalizeConnector({ catalogId: "splunk-hec", name: "Internal", format: "hec", endpoint: "https://127.0.0.1/collector" }, { tenantId: "tenant-a" }), /Private or loopback/);
assert.throws(() => normalizeConnector({ catalogId: "splunk-hec", name: "Plaintext", format: "hec", endpoint: "http://splunk.example.com" }, { tenantId: "tenant-a" }), /HTTPS/);

const presigned = createPresignedAwsUrl({
  accessKeyId: "AKIDEXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
  service: "s3",
  region: "us-east-1",
  method: "PUT",
  host: "evidence-bucket.s3.us-east-1.amazonaws.com",
  path: "/tenant/evidence.log",
  headers: { "content-type": "application/octet-stream" },
  expiresSeconds: 900,
  date: new Date("2026-07-16T12:00:00Z")
});
assert.match(presigned.url, /X-Amz-Algorithm=AWS4-HMAC-SHA256/);
assert.match(presigned.url, /X-Amz-Signature=[a-f0-9]{64}/);
assert.equal(presigned.headers["content-type"], "application/octet-stream");

console.log("platform analytics and integration checks passed");
