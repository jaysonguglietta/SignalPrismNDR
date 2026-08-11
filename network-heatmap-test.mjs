import assert from "node:assert/strict";
import {
  buildActivityHeatmap,
  buildCommunicationMatrix,
  buildGeographicHeatmap,
  eventEvidenceKey,
  recordEvidenceKey,
  recordMatchesHeatmapSelection,
  renderActivityHeatmap,
  renderCommunicationMatrix,
  renderGeographicHeatmap
} from "./src/network-heatmap.mjs";

const base = Date.parse("2026-07-17T12:00:00Z");
const records = [
  { source: "10.0.1.10", destination: "198.51.100.20", srcPort: 50000, dstPort: 443, protocol: "TCP", action: "ACCEPT", bytes: 2_000_000, start: base, accountId: "111111111111", evidenceSource: "vpc.log" },
  { source: "198.51.100.44", destination: "10.0.1.10", srcPort: 54000, dstPort: 22, protocol: "TCP", action: "REJECT", bytes: 80, start: base + 60_000, accountId: "111111111111", evidenceSource: "vpc.log" },
  { source: "10.0.1.10", destination: "203.0.113.8", srcPort: 50001, dstPort: 8443, protocol: "TCP", action: "ACCEPT", bytes: 4_000_000, start: base + 120_000, accountId: "111111111111", evidenceSource: "cloudwatch" }
];
const detectionKeys = new Set([recordEvidenceKey(records[1])]);
const stitchedKeys = new Set([recordEvidenceKey(records[0]), recordEvidenceKey(records[2])]);

const activity = buildActivityHeatmap(records, { metric: "bytes", groupBy: "entity", columns: 12, detectionKeys });
assert.equal(activity.kind, "activity");
assert.equal(activity.columns.length, 12);
assert(activity.rows.some((row) => row.key === "10.0.1.10"));
assert(activity.maxValue >= 4_000_000);
assert.match(renderActivityHeatmap(activity), /data-heat-kind="activity"/);

const detectionActivity = buildActivityHeatmap(records, { evidenceFilter: "detections", detectionKeys, columns: 12 });
assert.equal(detectionActivity.matchedRecordCount, 1);
assert(detectionActivity.rows.some((row) => row.key === "198.51.100.44"));
assert.equal(detectionActivity.maxValue, 1);

const stitchedActivity = buildActivityHeatmap(records, { evidenceFilter: "stitched", stitchedKeys, columns: 12 });
assert.equal(stitchedActivity.matchedRecordCount, 2);

const matrix = buildCommunicationMatrix(records, { metric: "events", groupBy: "subnet", detectionKeys });
assert.equal(matrix.kind, "matrix");
assert(matrix.cells.some((cell) => cell.sourceKey === "10.0.1.0/24" && cell.destinationKey === "198.51.100.0/24"));
assert.match(renderCommunicationMatrix(matrix), /Source \/ destination/);

const geographic = buildGeographicHeatmap(records, { metric: "risk", detectionKeys });
assert.equal(geographic.points.length, 2);
assert.equal(geographic.mappedEndpointCount, 3);
assert(geographic.points.every((point) => point.approximate));
assert.match(renderGeographicHeatmap(geographic), /Geographic network activity heatmap/);

const importedGeo = buildGeographicHeatmap(records, {
  enrichment: { "198.51.100.20": { latitude: 35.2, longitude: -80.8, city: "Charlotte", country: "US", geoPrecision: "exact" } },
  allowDemoCoordinates: false
});
assert.equal(importedGeo.points.length, 1);
assert.equal(importedGeo.points[0].city, "Charlotte");
assert.equal(importedGeo.points[0].approximate, false);

assert(recordMatchesHeatmapSelection(records[0], { type: "activity", rowKey: "10.0.1.10", groupBy: "entity", start: base - 1, end: base + 1 }));
assert(recordMatchesHeatmapSelection(records[0], { type: "matrix", sourceKey: "10.0.1.0/24", destinationKey: "198.51.100.0/24", groupBy: "subnet" }));
assert(recordMatchesHeatmapSelection(records[2], { type: "geographic", ip: "203.0.113.8" }));
assert(recordMatchesHeatmapSelection(records[0], { type: "geographic", ips: ["198.51.100.20", "198.51.100.44"] }));
assert.equal(eventEvidenceKey({ sourceIp: records[0].source, destinationIp: records[0].destination, sourcePort: records[0].srcPort, destinationPort: records[0].dstPort, timestamp: new Date(base).toISOString() }), recordEvidenceKey(records[0]));

console.log("Network heatmap tests passed");
