import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const {
  SAMPLE_LOG,
  analyzeRecords,
  buildAiEvidenceContextModel,
  buildCitedInvestigationAnswer,
  buildDetectionAsCodeBundle,
  buildEntityRiskScores,
  buildEvidenceVaultManifest,
  buildEnterpriseReport,
  buildInvestigationPackageModel,
  buildOcsfFindings,
  buildOcsfNetworkActivity,
  buildPolicyFindings,
  buildPlaybookSteps,
  buildReplayTimeline,
  buildSourceHealth,
  buildTopologyReplaySnapshot,
  csvValue,
  parseVpcFlowLog,
  parseThreatIntel,
  scoreDetectionRuleQuality,
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
assertIncludes(html, 'id="enterpriseTab"', "enterprise command center tab should exist");
assertIncludes(html, 'id="generateCitedCopilotButton"', "cited copilot workflow should exist");
assertIncludes(html, 'id="discoverSourcesButton"', "source discovery workflow should exist");
assertIncludes(html, 'id="applyThreatIntelButton"', "threat intelligence enrichment should exist");
assertIncludes(html, 'id="saveDetectionRuleButton"', "detection rule lifecycle should exist");
assertIncludes(html, 'id="exportDetectionAsCodeButton"', "detection-as-code export should exist");
assertIncludes(html, 'id="exportSecurityLakeButton"', "Security Lake export should exist");
assertIncludes(html, 'id="applyAssetContextButton"', "asset context workflow should exist");
assertIncludes(html, 'id="exportReplayTimelineButton"', "investigation replay export should exist");
assertIncludes(html, 'id="analyzePolicyButton"', "policy exposure workflow should exist");
assertIncludes(html, 'id="createPlaybookRunButton"', "response playbook workflow should exist");
assertIncludes(html, 'id="createEvidenceVaultButton"', "evidence vault workflow should exist");
assertIncludes(html, 'id="generateEnterpriseReportButton"', "enterprise reporting workflow should exist");
assertIncludes(html, 'id="ingestTelemetryButton"', "enterprise telemetry ingest should exist");
assertIncludes(html, 'id="correlateTelemetryButton"', "cross-source correlation should exist");
assertIncludes(html, 'id="requestResponseActionButton"', "governed response request should exist");
assertIncludes(html, 'id="verifyDetectionContentButton"', "signed detection content verification should exist");
assertIncludes(html, 'id="platformTab"', "enterprise platform workspace should exist");
assertIncludes(html, 'id="runBehaviorButton"', "behavior analytics workflow should exist");
assertIncludes(html, 'id="buildCampaignsButton"', "campaign assembly workflow should exist");
assertIncludes(html, 'id="runRetrospectiveHuntButton"', "retrospective hunt workflow should exist");
assertIncludes(html, 'id="runAiInvestigationButton"', "AI investigation agent workflow should exist");
assertIncludes(html, 'id="publishOcsfButton"', "continuous OCSF publishing workflow should exist");
assertIncludes(html, 'id="saveConnectorButton"', "governed connector workflow should exist");
assertIncludes(html, 'id="discoverOrganizationButton"', "AWS Organizations discovery workflow should exist");
assertIncludes(html, 'id="directEvidenceUploadButton"', "direct immutable evidence upload should exist");
assertIncludes(html, 'id="saveCustomRoleButton"', "custom tenant role workflow should exist");
assertIncludes(html, 'id="createServiceAccountButton"', "service account workflow should exist");

const parsed = parseVpcFlowLog(SAMPLE_LOG);
assert.equal(csvValue("=HYPERLINK(\"https://attacker.example\")"), "\"'=HYPERLINK(\"\"https://attacker.example\"\")\"", "CSV exports must neutralize spreadsheet formulas");
assert.equal(csvValue("  +cmd|' /C calc'!A0"), "'  +cmd|' /C calc'!A0", "CSV exports must neutralize formulas after leading whitespace");
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

const ocsfNetwork = buildOcsfNetworkActivity(parsed.records);
assert.equal(ocsfNetwork[0].class_name, "Network Activity", "Security Lake export should include OCSF network activity");

const ocsfFindings = buildOcsfFindings(analysis.detections);
assert.equal(ocsfFindings[0].class_name, "Security Finding", "Security Lake export should include OCSF findings");

const policyFindings = buildPolicyFindings([{ source: "0.0.0.0/0", port: 22, action: "allow", resource: "sg-admin" }]);
assert.ok(policyFindings.some((finding) => finding.severity === "high"), "policy analysis should flag public sensitive services");

const intel = parseThreatIntel('indicator,severity,label,source,confidence\n203.0.113.82,high,possible C2,UnitTest,91');
assert.equal(intel["203.0.113.82"].severity, "high", "threat intel parser should normalize CSV indicators");

const riskScores = buildEntityRiskScores(parsed.records, analysis, { "10.0.1.15": { key: "10.0.1.15", criticality: "high" } }, intel);
assert.ok(riskScores.some((item) => item.score > 0), "entity risk scoring should produce prioritized entities");

const cited = buildCitedInvestigationAnswer({ question: "Why suspicious?", analysis, records: parsed.records, cases: [], assets: {}, threatIntel: intel });
assert.ok(cited.citations.length > 0, "cited copilot should provide evidence references");

const quality = scoreDetectionRuleQuality({ name: "Rule", query: "action:ACCEPT", description: "Detects accepted traffic for a meaningful test fixture.", attackId: "T1021", owner: "Security", testCount: 3, status: "production" });
assert.ok(quality.score >= 70, "detection quality scoring should reward production-ready rules");

const detectionBundle = buildDetectionAsCodeBundle([{ id: "rule-1", name: "Rule", query: "action:ACCEPT", severity: "medium", status: "production" }]);
assert.equal(detectionBundle.schema, "signalprism.detections.v1", "detection-as-code export should include schema identity");

const replayTimeline = buildReplayTimeline(parsed.records, analysis.detections);
assert.ok(replayTimeline.some((event) => event.type === "detection"), "timeline replay should overlay detections");

const playbookSteps = buildPlaybookSteps("contain-public-admin", { title: "Case", assignee: "Analyst" });
assert.ok(playbookSteps.length >= 3, "playbooks should create actionable response steps");

const vaultManifest = await buildEvidenceVaultManifest({ records: parsed.records, analysis, cases: [], settings: { governance: { evidenceRetentionDays: 30 } }, source: "unit" });
assert.ok(vaultManifest.evidenceHash, "vault manifest should include chain-of-custody hash");
assert.equal(vaultManifest.evidenceHashAlgorithm, "SHA-256", "vault manifest should use a cryptographic evidence hash");

const sourceHealth = buildSourceHealth([{ id: "source-1", name: "Prod", scope: ["eni-0a1b2c3d"] }], [], parsed.records, []);
assert.equal(sourceHealth[0].title, "Prod", "source health should evaluate managed sources");

const enterpriseReport = buildEnterpriseReport({ mode: "executive", analysis, records: parsed.records, cases: [], settings: { securityLake: { bucket: "" }, governance: {} }, riskScores, sourceHealth });
assert.equal(enterpriseReport.mode, "executive", "enterprise report should preserve selected report mode");

console.log("ui flow checks passed");

function assertIncludes(text, needle, message) {
  assert.ok(text.includes(needle), message);
}

function structuredCloneSafe(value) {
  return JSON.parse(JSON.stringify(value));
}
