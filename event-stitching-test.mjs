import assert from "node:assert/strict";
import { buildStitchedIncidents, parseStitchingTelemetry } from "./src/event-stitching.mjs";

const sourceIp = "10.0.1.12";
const remoteIp = "198.51.100.44";
const base = Date.parse("2026-07-16T20:00:00Z");
const iso = (seconds) => new Date(base + seconds * 1000).toISOString();

const cloudTrail = parseStitchingTelemetry(JSON.stringify({
  Records: [{
    eventVersion: "1.09",
    eventID: "ct-privilege",
    eventTime: iso(0),
    eventSource: "iam.amazonaws.com",
    eventName: "AttachRolePolicy",
    awsRegion: "us-east-1",
    recipientAccountId: "123456789012",
    sourceIPAddress: sourceIp,
    userIdentity: { arn: "arn:aws:iam::123456789012:user/compromised-admin" },
    requestParameters: { roleArn: "arn:aws:iam::123456789012:role/ProductionAdmin" }
  }]
}), { sourceId: "cloudtrail", sourceName: "cloudtrail.json" });

const guardDuty = parseStitchingTelemetry(JSON.stringify({
  id: "gd-c2",
  type: "Backdoor:EC2/C&CActivity.B",
  title: "EC2 instance communicating with a command and control server",
  severity: 8.2,
  updatedAt: iso(120),
  accountId: "123456789012",
  region: "us-east-1",
  resource: { resourceType: "Instance", instanceDetails: { instanceId: "i-compromised", networkInterfaces: [{ privateIpAddress: sourceIp }] } },
  service: { action: { actionType: "NETWORK_CONNECTION", networkConnectionAction: { protocol: "TCP", localIpDetails: { ipAddressV4: sourceIp }, remoteIpDetails: { ipAddressV4: remoteIp } } } }
}), { sourceId: "guardduty", sourceName: "guardduty.json" });

const suricata = parseStitchingTelemetry(JSON.stringify({
  timestamp: iso(90),
  event_type: "alert",
  flow_id: 991,
  src_ip: sourceIp,
  src_port: 51234,
  dest_ip: remoteIp,
  dest_port: 443,
  proto: "TCP",
  community_id: "1:test-session",
  alert: { severity: 1, signature: "Known C2 TLS callback", category: "Command and Control", action: "allowed" }
}), { sourceId: "suricata", sourceName: "suricata.jsonl" });

const dns = parseStitchingTelemetry([
  { query_timestamp: iso(150), srcaddr: sourceIp, query_name: `${"x".repeat(64)}.exfil.example.`, query_type: "A", account_id: "123456789012" },
  { query_timestamp: iso(160), srcaddr: sourceIp, query_name: `${"y".repeat(64)}.exfil.example.`, query_type: "A", account_id: "123456789012" }
].map((record) => JSON.stringify(record)).join("\n"), { sourceId: "dns", sourceName: "route53.jsonl" });

assert.equal(cloudTrail.accepted, 1);
assert.equal(cloudTrail.events[0].format, "cloudtrail");
assert.equal(guardDuty.events[0].format, "guardduty");
assert.equal(suricata.events[0].format, "suricata");
assert.equal(dns.events[0].format, "route53-dns");

const events = [...cloudTrail.events, ...guardDuty.events, ...suricata.events, ...dns.events];
const stitched = buildStitchedIncidents(events, { windowMinutes: 60, minimumLinkConfidence: 0.62 });
assert.ok(stitched.chainCount >= 1, "mixed sources should produce a stitched incident chain");
assert.ok(stitched.linkCount >= 3, "the chain should include explainable links");
assert.ok(stitched.chains[0].evidenceSources.length >= 3, "the chain should retain independent source provenance");
assert.ok(stitched.chains[0].stages.includes("Privilege Escalation"), "the chain should identify privilege escalation");
assert.ok(stitched.chains[0].stages.includes("Command and Control"), "the chain should identify command and control");
assert.ok(stitched.chains[0].events.every((event) => event.stage), "every timeline event should carry its own stage classification");
assert.ok(stitched.chains[0].links.every((link) => link.reasons.length && link.confidence >= 0.62), "every link should be explainable and confidence-scored");

const ambiguous = buildStitchedIncidents([
  { ...suricata.events[0], id: "tenant-a-ip", accountId: "111111111111", evidenceSourceId: "a", evidenceSource: "account-a.json" },
  { ...suricata.events[0], id: "tenant-b-ip", timestamp: iso(100), accountId: "222222222222", evidenceSourceId: "b", evidenceSource: "account-b.json", communityId: "", sessionId: "" }
], { windowMinutes: 60 });
assert.equal(ambiguous.chainCount, 0, "private IP reuse across accounts must not create a chain without stronger evidence");
assert.ok(ambiguous.conflicts.some((conflict) => conflict.type === "ambiguous-private-ip"), "ambiguous cross-account IP reuse should be disclosed");

const tenantIsolation = buildStitchedIncidents([
  { ...guardDuty.events[0], id: "tenant-a", tenantId: "tenant-a", evidenceSourceId: "a", evidenceSource: "a.json" },
  { ...suricata.events[0], id: "tenant-b", tenantId: "tenant-b", evidenceSourceId: "b", evidenceSource: "b.json" }
]);
assert.equal(tenantIsolation.linkCount, 0, "events from different tenants must never stitch");

const clockSkewed = buildStitchedIncidents([
  { ...suricata.events[0], id: "skew-late", sourceIndex: 0, timestamp: iso(900), evidenceSourceId: "skewed", evidenceSource: "skewed-sensor.jsonl", communityId: "", sessionId: "" },
  { ...suricata.events[0], id: "skew-early", sourceIndex: 1, timestamp: iso(0), evidenceSourceId: "skewed", evidenceSource: "skewed-sensor.jsonl", communityId: "", sessionId: "" },
  { ...dns.events[0], id: "other-source", sourceIndex: 0, timestamp: iso(120), evidenceSourceId: "dns-other", evidenceSource: "dns-other.jsonl" }
], { windowMinutes: 60 });
assert.equal(clockSkewed.chainCount, 0, "clock-regressed sources must not create weak IP-only chains");
assert.ok(clockSkewed.conflicts.some((conflict) => conflict.type === "clock-skew-weak-link"), "clock-skew link suppression should be disclosed");

const broadWindow = buildStitchedIncidents([
  { ...suricata.events[0], id: "broad-one", timestamp: iso(0), evidenceSourceId: "broad-a", evidenceSource: "broad-a.json", communityId: "", sessionId: "" },
  { ...dns.events[0], id: "broad-two", timestamp: iso(12 * 60 * 60), evidenceSourceId: "broad-b", evidenceSource: "broad-b.json" }
], { windowMinutes: 1440 });
assert.equal(broadWindow.chainCount, 0, "broad windows must not bridge weak network entities beyond four hours");
assert.ok(broadWindow.conflicts.some((conflict) => conflict.type === "broad-window-weak-link"), "broad-window suppression should be disclosed");

console.log("event stitching checks passed");
