import assert from "node:assert/strict";
import { buildSqsQuery, parseSqsMessages, parseSqsQueueUrl } from "./src/aws-queue.mjs";
import { correlateTelemetry, parseTelemetryPayload } from "./src/enterprise-telemetry.mjs";

const queue = parseSqsQueueUrl("https://sqs.us-east-1.amazonaws.com/123456789012/signalprism-ingest", "us-east-1");
assert.equal(queue.region, "us-east-1");
assert.equal(queue.queueName, "signalprism-ingest");
assert.throws(() => parseSqsQueueUrl("https://example.com/123456789012/queue"), /SQS HTTPS/);
assert.match(buildSqsQuery("SendMessage", { MessageBody: "{\"id\":1}" }), /Action=SendMessage/);

const messages = parseSqsMessages("<ReceiveMessageResponse><ReceiveMessageResult><Message><MessageId>m-1</MessageId><ReceiptHandle>receipt</ReceiptHandle><Body>{&quot;type&quot;:&quot;managed-ingest&quot;}</Body><Attribute><Name>ApproximateReceiveCount</Name><Value>2</Value></Attribute></Message></ReceiveMessageResult></ReceiveMessageResponse>");
assert.equal(messages.length, 1);
assert.equal(JSON.parse(messages[0].body).type, "managed-ingest");
assert.equal(messages[0].receiveCount, 2);

const base = Date.parse("2026-07-16T12:00:00Z");
const iso = (seconds) => new Date(base + seconds * 1000).toISOString();
const records = [];
for (let index = 0; index < 6; index += 1) {
  records.push({ eventVersion: "1.09", eventTime: iso(index * 30), eventSource: "sts.amazonaws.com", eventName: "AssumeRole", sourceIPAddress: "203.0.113.77", errorCode: "AccessDenied", userIdentity: { arn: `arn:aws:iam::123456789012:user/test-${index}` } });
}
records.push({ eventVersion: "1.09", eventTime: iso(240), eventSource: "iam.amazonaws.com", eventName: "AttachRolePolicy", sourceIPAddress: "10.0.1.12", userIdentity: { arn: "arn:aws:iam::123456789012:user/admin" }, requestParameters: { roleArn: "arn:aws:iam::123456789012:role/Prod" } });
records.push({ timestamp: iso(300), event_type: "alert", src_ip: "10.0.1.12", dest_ip: "198.51.100.44", dest_port: 443, proto: "TCP", alert: { severity: 1, signature: "C2 callback", category: "Potentially Bad Traffic", action: "allowed" } });
records.push({ id: "gd-1", type: "Backdoor:EC2/C&CActivity.B", severity: 8.1, updatedAt: iso(305), resource: { resourceType: "Instance", instanceDetails: { instanceId: "i-test", networkInterfaces: [{ privateIpAddress: "10.0.1.12" }] } }, service: { action: { actionType: "NETWORK_CONNECTION", networkConnectionAction: { protocol: "TCP", localIpDetails: { ipAddressV4: "10.0.1.12" }, remoteIpDetails: { ipAddressV4: "198.51.100.44" } } } } });
for (let index = 0; index < 9; index += 1) records.push({ query_timestamp: iso(330 + index * 10), srcaddr: "10.0.1.12", query_name: `${"x".repeat(64)}${index}.example.net.`, query_type: "A" });

const normalized = parseTelemetryPayload(records, "auto");
assert.equal(normalized.accepted, records.length);
assert.ok(new Set(normalized.events.map((event) => event.format)).has("cloudtrail"));
assert.ok(new Set(normalized.events.map((event) => event.format)).has("guardduty"));
assert.ok(new Set(normalized.events.map((event) => event.format)).has("suricata"));
assert.ok(new Set(normalized.events.map((event) => event.format)).has("route53-dns"));

const vpcFlowPayload = [
  "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status",
  "2 123456789012 eni-0abc123 10.0.0.5 198.51.100.44 49152 443 6 12 9000 1784203200 1784203230 ACCEPT OK",
  "2 123456789012 eni-0abc123 203.0.113.77 10.0.0.5 52000 22 6 4 240 1784203260 1784203290 REJECT OK"
].join("\n");
const vpcFlow = parseTelemetryPayload(vpcFlowPayload, "auto");
assert.equal(vpcFlow.accepted, 2);
assert.equal(vpcFlow.events[0].format, "aws-vpc-flow");
assert.equal(vpcFlow.events[0].provider, "aws");
assert.equal(vpcFlow.events[0].protocol, "TCP");
assert.equal(vpcFlow.events[0].destinationPort, 443);
assert.equal(vpcFlow.events[0].outcome, "success");
assert.equal(vpcFlow.events[1].outcome, "failure");
assert.notEqual(vpcFlow.events[0].id, vpcFlow.events[1].id);
assert.match(vpcFlow.events[0].id, /^telemetry-[a-f0-9]{64}$/);

const partiallyMalformed = parseTelemetryPayload([
  "2 123456789012 eni-0abc123 10.0.0.5 198.51.100.44 49152 443 6 12 9000 1784203200 1784203230 ACCEPT OK",
  "this line is intentionally malformed",
  "2 123456789012 eni-0abc123 203.0.113.77 10.0.0.5 52000 22 6 4 240 1784203260 1784203290 REJECT OK"
].join("\n"), "auto");
assert.equal(partiallyMalformed.total, 3);
assert.equal(partiallyMalformed.accepted, 2);
assert.equal(partiallyMalformed.errors.length, 1);

const canonicalA = parseTelemetryPayload([{ timestamp: iso(600), sourceIp: "10.0.0.1", destinationIp: "198.51.100.1", action: "connect" }]);
const canonicalB = parseTelemetryPayload([{ action: "connect", destinationIp: "198.51.100.1", sourceIp: "10.0.0.1", timestamp: iso(600) }]);
assert.equal(canonicalA.events[0].id, canonicalB.events[0].id, "event identity must not depend on JSON property order");

const gcpAudit = parseTelemetryPayload([{ timestamp: iso(601), logName: "projects/prod-1/logs/cloudaudit.googleapis.com%2Factivity", severity: "NOTICE" }]);
assert.equal(gcpAudit.events[0].format, "gcp-audit");
const deceptiveGcpAudit = parseTelemetryPayload([{ timestamp: iso(602), logName: "https://attacker.example/cloudaudit.googleapis.com", action: "connect" }]);
assert.equal(deceptiveGcpAudit.events[0].format, "generic");

const findings = correlateTelemetry(normalized.events, { windowMinutes: 60 });
assert.ok(findings.some((finding) => finding.ruleId === "SP-CORR-001"), "authentication spray should correlate");
assert.ok(findings.some((finding) => finding.ruleId === "SP-CORR-002"), "privilege and network activity should correlate");
assert.ok(findings.some((finding) => finding.ruleId === "SP-CORR-003"), "GuardDuty should be corroborated");
assert.ok(findings.some((finding) => finding.ruleId === "SP-CORR-004"), "DNS tunneling pattern should correlate");
assert.ok(findings.every((finding) => finding.evidenceIds.length > 0 && finding.technique), "findings must be explainable and evidence-linked");

console.log("enterprise contract checks passed");
