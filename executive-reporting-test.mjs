import assert from "node:assert/strict";
import {
  advanceReportSchedule,
  buildExecutiveBrief,
  buildTopFindings,
  executiveReportCsv,
  validateReportSchedule
} from "./src/executive-reporting.mjs";

const now = Date.parse("2026-07-17T12:00:00Z");
const current = {
  start: now - 60 * 60 * 1000,
  source: "203.0.113.50",
  destination: "10.0.1.12",
  srcPort: 51234,
  dstPort: 22,
  protocol: "TCP",
  action: "ACCEPT",
  evidenceSourceId: "source-vpc",
  evidenceSource: "Production VPC"
};
const previous = { ...current, start: now - 26 * 60 * 60 * 1000 };
const detection = {
  id: "NDR-001",
  title: "Public SSH access accepted",
  severity: "high",
  confidence: 0.9,
  tactic: "Initial Access",
  technique: "External Remote Services",
  entity: "10.0.1.12",
  copy: "A public source reached an internal administrative service.",
  response: ["Restrict the security group and verify the workload owner."],
  tags: ["Public source", "SSH"],
  records: [current, previous]
};
const assets = {
  "10.0.1.12": { key: "10.0.1.12", asset: "prod-api-01", owner: "Payments", criticality: "critical", environment: "production" }
};
const threatIntel = { "203.0.113.50": { label: "Known scanner", severity: "high" } };
const cases = [{ id: "case-1", linkedDetection: "NDR-001", status: "Open", severity: "high", assignee: "", createdAt: "2026-07-16T00:00:00Z" }];

const findings = buildTopFindings({
  detections: [detection, { ...detection, id: "NDR-002", confidence: 0.7 }],
  records: [current, previous],
  assets,
  threatIntel,
  cases,
  filters: { period: "24h", source: "source-vpc", environment: "production" },
  now
});

assert.equal(findings.length, 1, "equivalent detections should consolidate into one ranked finding");
assert.equal(findings[0].currentCount, 1, "consolidated detections deduplicate current evidence volume");
assert.equal(findings[0].previousCount, 1, "consolidated detections deduplicate prior evidence volume");
assert.equal(findings[0].assets[0].asset, "prod-api-01");
assert.equal(findings[0].owner, "Payments");
assert.equal(findings[0].threatIntelMatches[0], "203.0.113.50");
assert.ok(findings[0].urgency >= 70, "critical public access with threat intelligence should be high urgency");
assert.equal(findings[0].factors.find((factor) => factor.label === "Case and SLA").score, 5);

const unknownContext = buildTopFindings({ detections: [detection], records: [current], filters: { period: "evidence" }, now });
assert.equal(unknownContext[0].factors.find((factor) => factor.label === "Asset criticality").score, 0);
assert.equal(unknownContext[0].factors.find((factor) => factor.label === "Asset criticality").evidence, "Unknown");

const report = buildExecutiveBrief({
  detections: [detection],
  records: [current, previous],
  assets,
  threatIntel,
  cases,
  sourceHealth: [{ title: "Production VPC", tone: "ok" }, { title: "CloudTrail", tone: "warn" }],
  period: "24h",
  tenant: { tenantId: "tenant-a", name: "Example Corp" },
  classification: "Restricted",
  generatedAt: new Date(now).toISOString()
});

assert.equal(report.tenantId, "tenant-a");
assert.equal(report.classification, "Restricted");
assert.equal(report.metrics.find((metric) => metric.id === "telemetryCoverage").current, 50);
assert.match(report.narrative, /\[F1\]/);
assert.equal(report.findings[0].records, undefined, "raw evidence is not embedded in an executive report");
assert.ok(report.integrity.contentFingerprint.startsWith("exec-"));

const csv = executiveReportCsv({ ...report, organization: "=WEBSERVICE(\"https://example.invalid\")" });
assert.match(csv, /'=WEBSERVICE/, "CSV formula-like values should be neutralized");
assert.match(csv, /Top findings/);

const schedule = validateReportSchedule({
  name: "Weekly executive brief",
  frequency: "weekly",
  period: "7d",
  format: "pdf",
  recipients: "ciso@example.com, soc@example.com",
  now: "2026-07-17T12:00:00Z"
}, [
  { email: "ciso@example.com", status: "active" },
  { email: "soc@example.com", status: "active" }
]);
assert.equal(schedule.destination, "tenant-inbox");
assert.equal(schedule.recipients.length, 2);
assert.ok(Date.parse(schedule.nextRunAt) > now);
assert.ok(Date.parse(advanceReportSchedule(schedule, new Date(now)).nextRunAt) > now);
assert.throws(() => validateReportSchedule({ name: "Weekly brief", recipients: "outsider@example.com" }, [{ email: "ciso@example.com", status: "active" }]), /active tenant users/);

console.log("Executive reporting tests passed.");
