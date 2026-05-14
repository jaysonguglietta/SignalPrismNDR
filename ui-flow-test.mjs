import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const {
  SAMPLE_LOG,
  analyzeRecords,
  buildAiEvidenceContextModel,
  buildInvestigationPackageModel,
  buildTopologyReplaySnapshot,
  parseVpcFlowLog,
  tuneAnalysisForProfile
} = require("./app.js");

const html = await readFile(new URL("./index.html", import.meta.url), "utf8");

assertIncludes(html, 'id="fileInput"', "upload control should exist");
assertIncludes(html, 'id="loadDemoButton"', "guided demo button should exist");
assertIncludes(html, 'id="ruleProfileSelect"', "rule tuning select should exist");
assertIncludes(html, 'id="summarizeAiButton"', "AI summary button should exist");
assertIncludes(html, 'id="exportInvestigationPackageButton"', "investigation export button should exist");
assertIncludes(html, 'id="playReplayButton"', "topology replay play button should exist");
assertIncludes(html, 'id="replayEventList"', "topology replay event list should exist");
assertIncludes(html, 'id="adminTab"', "tenant admin tab should exist");
assertIncludes(html, 'id="saveTenantUserButton"', "tenant user save control should exist");
assertIncludes(html, 'id="assignSourceOwnerButton"', "source ownership assignment should exist");
assertIncludes(html, 'id="backendJobRunsList"', "async job run status list should exist");

const parsed = parseVpcFlowLog(SAMPLE_LOG);
const analysis = analyzeRecords(parsed.records, parsed.errors);
assert.equal(parsed.records.length, 11, "upload/analyze flow should parse the demo evidence");
assert.ok(analysis.detections.length > 0, "demo flow should produce detections");

const focused = tuneAnalysisForProfile(structuredCloneSafe(analysis), "focused", parsed.records);
assert.ok(focused.detections.length <= analysis.detections.length, "focused tuning should not increase detections");
assert.equal(focused.ruleProfile, "focused", "tuning should stamp the active rule profile");

const context = buildAiEvidenceContextModel({
  analysis,
  records: parsed.records,
  filtered: parsed.records.slice(0, 4),
  source: "ui-flow-test",
  workspaceName: "Demo - Public admin access",
  sources: [{ name: "Prod VPC", type: "AWS VPC", region: "us-east-1" }],
  ruleProfile: "balanced"
});
assert.equal(context.workspace, "Demo - Public admin access", "AI context should include workspace identity");
assert.equal(context.sources.length, 1, "AI context should include managed source inventory");
assert.ok(context.sampleRecords.length > 0, "AI context should include bounded evidence samples");

const exported = buildInvestigationPackageModel({
  analysis,
  records: parsed.records,
  filtered: parsed.records,
  workspace: { id: "workspace-demo", name: "Demo", evidenceText: "raw evidence should be omitted" },
  source: "ui-flow-test",
  sources: context.sources,
  hunts: ["action:REJECT"],
  cases: [{ id: "case-1", title: "Public admin access", severity: "high" }],
  analystSummary: "Executive summary",
  aiAnswer: "AI summary"
});
assert.equal(exported.product, "SignalPrism NDR", "export should identify the product");
assert.equal(exported.workspace.evidenceText, undefined, "export should omit raw workspace evidence text");
assert.ok(exported.records.length <= 500, "export should cap record evidence");

const replay = buildTopologyReplaySnapshot(parsed.records, 50);
assert.ok(replay.includedRecords.length > 0, "replay should include records at midpoint");
assert.ok(replay.includedRecords.length <= parsed.records.length, "replay should not exceed source records");
assert.ok(replay.recentRecords.length > 0, "replay should expose recent timeline events");

console.log("ui flow checks passed");

function assertIncludes(text, needle, message) {
  assert.ok(text.includes(needle), message);
}

function structuredCloneSafe(value) {
  return JSON.parse(JSON.stringify(value));
}
