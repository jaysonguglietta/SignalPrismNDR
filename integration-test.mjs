import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createSignedAwsRequest } from "./src/aws-sigv4.mjs";
import { createHash, generateKeyPairSync, sign } from "node:crypto";

const root = dirname(fileURLToPath(import.meta.url));

await runIntegrationCheck("API authentication and governance", testApiAuth);
await runIntegrationCheck("cookie session revocation", testCookieSessionAuth);
await runIntegrationCheck("tenant RBAC and approvals", testTenantScopedRbac);
await runIntegrationCheck("privileged MFA step-up", testPrivilegedStepUp);
await runIntegrationCheck("enterprise telemetry, response, and signed content", testEnterpriseSecurityOperations);
await runIntegrationCheck("rate limiting", testRateLimit);
await runIntegrationCheck("request body validation", testRequestBodyLimit);
await runIntegrationCheck("production startup fail-closed controls", testProductionStartupControls);
testAwsSigning();

console.log("integration checks passed");

async function runIntegrationCheck(name, check) {
  process.stdout.write(`- ${name}... `);
  await check();
  console.log("ok");
}

async function testApiAuth() {
  const dataDir = await mkdtemp(join(tmpdir(), "ndr-auth-"));
  const server = await startServer({
    PORT: "4191",
    NDR_DATA_DIR: dataDir,
    NDR_API_KEY: "integration-key",
    NDR_RATE_LIMIT_MAX: "2000",
    NDR_STORE: "local"
  });
  const base = "http://127.0.0.1:4191";
  try {
    const healthResponse = await fetch(`${base}/api/health`, { headers: { "x-request-id": "integration-request-0001", traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01" } });
    assert.equal(healthResponse.status, 200);
    assert.equal(healthResponse.headers.get("x-request-id"), "integration-request-0001");
    assert.match(healthResponse.headers.get("traceparent") || "", /^00-0123456789abcdef0123456789abcdef-[a-f0-9]{16}-01$/);
    assert.equal((await healthResponse.json()).authMode, undefined, "public health must not disclose deployment posture");
    assert.equal((await fetch(`${base}/api/status`)).status, 401);
    assert.equal((await fetch(`${base}/app.js`)).status, 200);
    for (const sensitivePath of ["/server.mjs", "/package.json", "/.git/config", "/.env", "/.ndr-data/sessions.json", "/.ndr-data/cases.json", "/src/aws-sigv4.mjs"]) {
      assert.equal((await fetch(`${base}${sensitivePath}`)).status, 404, `${sensitivePath} must not be served`);
    }
    assert.equal((await fetch(`${base}/api/ready`)).status, 401);
    assert.equal((await fetch(`${base}/api/metrics`)).status, 401);
    const aiConfig = await (await fetch(`${base}/api/ai/config`)).json();
    assert.equal(aiConfig.enabled, false);
    assert.equal((await fetch(`${base}/api/jobs`)).status, 401);
    assert.equal((await fetch(`${base}/api/jobs`, { headers: { "x-ndr-api-key": "wrong" } })).status, 401);

    const jobsResponse = await fetch(`${base}/api/jobs`, { headers: { "x-ndr-api-key": "integration-key" } });
    assert.equal(jobsResponse.status, 200);
    assert.deepEqual(await jobsResponse.json(), []);

    const disabledAiResponse = await fetch(`${base}/api/ai/ask`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ question: "What is risky?", context: { records: 0 } })
    });
    assert.equal(disabledAiResponse.status, 403);

    const directJobResponse = await fetch(`${base}/api/jobs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({
        type: "cloudwatch",
        config: { region: "us-east-1", logGroupName: "/aws/vpc/flowlogs/prod" }
      })
    });
    assert.equal(directJobResponse.status, 403);

    const workspaceResponse = await fetch(`${base}/api/workspaces`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ name: "Integration workspace", records: 3, detections: 1, evidenceText: "sample" })
    });
    assert.equal(workspaceResponse.status, 201);
    assert.equal((await workspaceResponse.json()).tenantId, "default");

    const sourceResponse = await fetch(`${base}/api/sources`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ name: "Prod Flow Logs", type: "CloudWatch Log Group", region: "us-east-1", scope: ["/aws/vpc/flowlogs/prod"] })
    });
    assert.equal(sourceResponse.status, 201);
    const source = await sourceResponse.json();

    const directIngestResponse = await fetch(`${base}/api/ingest/cloudwatch`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ region: "us-east-1", logGroupName: "/aws/vpc/flowlogs/prod" })
    });
    assert.equal(directIngestResponse.status, 403);

    const createJobResponse = await fetch(`${base}/api/sources/${encodeURIComponent(source.id)}/jobs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ name: "Integration CloudWatch import", intervalMinutes: 5, enabled: false })
    });
    assert.equal(createJobResponse.status, 201);
    const job = await createJobResponse.json();
    assert.equal(job.name, "Integration CloudWatch import");
    assert.equal(job.sourceId, source.id);

    const viewerDelete = await fetch(`${base}/api/jobs/${job.id}`, { method: "DELETE" });
    assert.equal(viewerDelete.status, 401);

    const deleteResponse = await fetch(`${base}/api/jobs/${job.id}`, {
      method: "DELETE",
      headers: { "x-ndr-api-key": "integration-key" }
    });
    assert.equal(deleteResponse.status, 200);

    const readyResponse = await fetch(`${base}/api/ready`, { headers: { "x-ndr-api-key": "integration-key" } });
    assert.equal(readyResponse.status, 200);
    assert.equal((await readyResponse.json()).dataDir, undefined);
    assert.equal((await fetch(`${base}/api/metrics`, { headers: { "x-ndr-api-key": "integration-key" } })).status, 200);

    const userResponse = await fetch(`${base}/api/admin/users`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ name: "Integration Analyst", email: "analyst@example.com", role: "analyst", sourceIds: [source.id] })
    });
    assert.equal(userResponse.status, 201);
    const user = await userResponse.json();

    const ownerResponse = await fetch(`${base}/api/admin/source-owners`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ sourceId: source.id, ownerId: user.id })
    });
    assert.equal(ownerResponse.status, 200);
    assert.equal((await ownerResponse.json()).ownerUserId, user.id);

    const settingsResponse = await fetch(`${base}/api/enterprise/settings`, { headers: { "x-ndr-api-key": "integration-key" } });
    assert.equal(settingsResponse.status, 200);
    assert.equal((await settingsResponse.json()).id, "default");

    const saveSettingsResponse = await fetch(`${base}/api/enterprise/settings`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ securityLake: { bucket: "security-lake-test", prefix: "custom/SignalPrismNDR", region: "us-east-1" }, governance: { evidenceRetentionDays: 365, exportApprovalRequired: false } })
    });
    assert.equal(saveSettingsResponse.status, 200);
    assert.equal((await saveSettingsResponse.json()).securityLake.bucket, "security-lake-test");

    const ruleResponse = await fetch(`${base}/api/detection-rules`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ name: "Integration lateral access", query: "action:ACCEPT AND destinationPort:5432", severity: "medium", tactic: "Lateral Movement", attackId: "T1021" })
    });
    assert.equal(ruleResponse.status, 201);
    const rule = await ruleResponse.json();
    assert.equal(rule.name, "Integration lateral access");

    const rulesListResponse = await fetch(`${base}/api/detection-rules`, { headers: { "x-ndr-api-key": "integration-key" } });
    assert.equal(rulesListResponse.status, 200);
    assert.equal((await rulesListResponse.json()).length, 1);

    const caseResponse = await fetch(`${base}/api/cases`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ title: "Integration case", severity: "high", status: "New" })
    });
    assert.equal(caseResponse.status, 201);

    const evidenceResponse = await fetch(`${base}/api/evidence-runs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({
        fileName: "integration.log",
        recordCount: 1,
        rawEvidenceText: "2 1 eni-1 10.0.0.1 8.8.8.8 1 53 17 1 1 1 2 ACCEPT OK",
        records: [{ source: "10.0.0.1", destination: "8.8.8.8" }]
      })
    });
    assert.equal(evidenceResponse.status, 201);
    const evidence = await evidenceResponse.json();
    assert.equal(evidence.package.mode, "local");
    assert.equal(evidence.package.rawEvidenceStored, true);

    const packageResponse = await fetch(`${base}/api/evidence-runs/${encodeURIComponent(evidence.id)}/package`, { headers: { "x-ndr-api-key": "integration-key" } });
    assert.equal(packageResponse.status, 200);
    assert.equal((await packageResponse.json()).rawEvidenceStored, true);

    const jobRunsResponse = await fetch(`${base}/api/job-runs`, { headers: { "x-ndr-api-key": "integration-key" } });
    assert.equal(jobRunsResponse.status, 200);
    assert.deepEqual(await jobRunsResponse.json(), []);

    const exportResponse = await fetch(`${base}/api/exports/investigation`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ product: "SignalPrism NDR", source: "integration" })
    });
    assert.equal(exportResponse.status, 200);
    assert.equal((await exportResponse.json()).tenantId, "default");

    const securityLakeResponse = await fetch(`${base}/api/exports/security-lake`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ recordCount: 12, findingCount: 2, destination: "s3://security-lake-test/custom/SignalPrismNDR", format: "ocsf-ndjson" })
    });
    assert.equal(securityLakeResponse.status, 200);
    assert.equal((await securityLakeResponse.json()).schema, "OCSF");

    const artifactResponse = await fetch(`${base}/api/enterprise/artifacts`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ type: "PLAYBOOK_RUN", title: "Integration playbook", payload: { steps: 3 } })
    });
    assert.equal(artifactResponse.status, 201);
    assert.equal((await artifactResponse.json()).type, "PLAYBOOK_RUN");

    const artifactsList = await fetch(`${base}/api/enterprise/artifacts?type=PLAYBOOK_RUN`, { headers: { "x-ndr-api-key": "integration-key" } });
    assert.equal(artifactsList.status, 200);
    assert.equal((await artifactsList.json()).length, 1);

    const auditEventsResponse = await fetch(`${base}/api/audit/events?limit=50&action=case`, { headers: { "x-ndr-api-key": "integration-key" } });
    assert.equal(auditEventsResponse.status, 200);
    const auditEvents = await auditEventsResponse.json();
    assert.ok(auditEvents.events.some((entry) => entry.action === "case.created"));
    assert.equal(auditEvents.tenantId, "default");

    const auditExportResponse = await fetch(`${base}/api/audit/export`, { headers: { "x-ndr-api-key": "integration-key" } });
    assert.equal(auditExportResponse.status, 200);
    assert.match(await auditExportResponse.text(), /case\.created/);
  } finally {
    await stopServer(server);
    await rm(dataDir, { recursive: true, force: true });
  }
}

async function testCookieSessionAuth() {
  const dataDir = await mkdtemp(join(tmpdir(), "ndr-session-"));
  const server = await startServer({
    PORT: "4195",
    NDR_DATA_DIR: dataDir,
    NDR_API_KEY: "integration-key",
    NDR_RATE_LIMIT_MAX: "100",
    NDR_STORE: "local",
    NDR_SESSION_COOKIE_SECURE: "false"
  });
  const base = "http://127.0.0.1:4195";
  try {
    const login = await fetch(`${base}/api/auth/api-key-session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ apiKey: "integration-key" })
    });
    assert.equal(login.status, 200);
    const setCookie = login.headers.get("set-cookie") || "";
    assert.match(setCookie, /signalprism_session=/);
    assert.match(setCookie, /HttpOnly/i);
    assert.match(setCookie, /SameSite=Strict/i);
    assert.doesNotMatch(setCookie, /integration-key/);
    const opaqueCookieValue = setCookie.split(";")[0].split("=").slice(1).join("=");
    assert.match(decodeURIComponent(opaqueCookieValue), /^[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/);
    assert.ok(setCookie.length < 256, "session cookie must not embed the tenant principal");
    const session = await login.json();
    assert.equal(session.principal.authType, "api-key-session");
    assert.ok(session.csrf);
    const cookie = setCookie.split(";")[0];

    const me = await fetch(`${base}/api/auth/me`, { headers: { cookie } });
    assert.equal(me.status, 200);
    assert.equal((await me.json()).principal.authType, "api-key-session");

    const writeWithoutCsrf = await fetch(`${base}/api/workspaces`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie },
      body: JSON.stringify({ name: "Missing CSRF" })
    });
    assert.equal(writeWithoutCsrf.status, 403);

    const writeWithCsrf = await fetch(`${base}/api/workspaces`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie, "x-ndr-csrf": session.csrf },
      body: JSON.stringify({ name: "Cookie session workspace" })
    });
    assert.equal(writeWithCsrf.status, 201);

    const logout = await fetch(`${base}/api/auth/logout`, { method: "POST", headers: { cookie, "x-ndr-csrf": session.csrf } });
    assert.equal(logout.status, 200);
    assert.match(logout.headers.get("set-cookie") || "", /Max-Age=0/);
    assert.equal((await fetch(`${base}/api/auth/me`, { headers: { cookie } })).status, 401);
  } finally {
    await stopServer(server);
    await rm(dataDir, { recursive: true, force: true });
  }
}

async function testTenantScopedRbac() {
  const dataDir = await mkdtemp(join(tmpdir(), "ndr-tenant-"));
  const server = await startServer({
    PORT: "4193",
    NDR_DATA_DIR: dataDir,
    NDR_TEST_AUTH_ENABLED: "true",
    NDR_RATE_LIMIT_MAX: "2000",
    NDR_MAX_PENDING_EXPORT_APPROVALS: "2",
    NDR_STORE: "local"
  });
  const base = "http://127.0.0.1:4193";
  const analyst = testPrincipal({ subject: "analyst-a", roles: ["analyst"], tenantId: "tenant-a" });
  const analystOther = testPrincipal({ subject: "analyst-other", roles: ["analyst"], tenantId: "tenant-a", sourceAccessMode: "assigned", sourceIds: [] });
  const admin = testPrincipal({ subject: "admin-a", email: "admin-a@example.com", roles: ["admin"], tenantId: "tenant-a" });
  const viewer = testPrincipal({ subject: "viewer-a", roles: ["viewer"], tenantId: "tenant-a" });
  const analystB = testPrincipal({ subject: "analyst-b", roles: ["analyst"], tenantId: "tenant-b" });
  try {
    const createCase = await fetch(`${base}/api/cases`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ title: "Tenant A case", severity: "medium" })
    });
    assert.equal(createCase.status, 201);
    const createdCase = await createCase.json();

    const updatedCase = await fetch(`${base}/api/cases`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ ...createdCase, status: "Triaged", revision: createdCase.revision })
    });
    assert.equal(updatedCase.status, 200);
    assert.equal((await updatedCase.json()).revision, createdCase.revision + 1);
    const staleCaseUpdate = await fetch(`${base}/api/cases`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ ...createdCase, status: "Closed", revision: createdCase.revision })
    });
    assert.equal(staleCaseUpdate.status, 409);

    const raceCaseResponse = await fetch(`${base}/api/cases`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ title: "Atomic case update", severity: "high" }) });
    const raceCase = await raceCaseResponse.json();
    const concurrentCaseUpdates = await Promise.all([
      fetch(`${base}/api/cases`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ ...raceCase, notes: "first", revision: raceCase.revision }) }),
      fetch(`${base}/api/cases`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ ...raceCase, notes: "second", revision: raceCase.revision }) })
    ]);
    assert.deepEqual(concurrentCaseUpdates.map((response) => response.status).sort(), [200, 409]);

    const viewerCreate = await fetch(`${base}/api/cases`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": viewer },
      body: JSON.stringify({ title: "Viewer should not write" })
    });
    assert.equal(viewerCreate.status, 403);

    const tenantAList = await fetch(`${base}/api/cases`, { headers: { "x-ndr-test-principal": viewer } });
    assert.equal((await tenantAList.json()).length, 2);

    const tenantBList = await fetch(`${base}/api/cases`, { headers: { "x-ndr-test-principal": analystB } });
    assert.equal((await tenantBList.json()).length, 0);

    const customReadOnly = testPrincipal({ subject: "custom-reader", roles: ["analyst"], tenantId: "tenant-a", permissionMode: "custom", permissions: ["cases:read"] });
    assert.equal((await fetch(`${base}/api/cases`, { headers: { "x-ndr-test-principal": customReadOnly } })).status, 200);
    assert.equal((await fetch(`${base}/api/cases`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": customReadOnly }, body: JSON.stringify({ title: "Custom role must not inherit analyst writes" }) })).status, 403);
    assert.equal((await fetch(`${base}/api/ai/ask`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": customReadOnly }, body: JSON.stringify({ question: "summarize", context: {} }) })).status, 403);

    const unscopedService = testPrincipal({ subject: "service-unscoped", roles: ["viewer"], authType: "service-account", tenantId: "tenant-a", permissionMode: "custom", permissions: ["sources:read"], sourceIds: [] });
    const unscopedSources = await fetch(`${base}/api/sources`, { headers: { "x-ndr-test-principal": unscopedService } });
    assert.equal(unscopedSources.status, 200);
    assert.deepEqual(await unscopedSources.json(), []);

    const viewerScan = await fetch(`${base}/api/evidence-uploads/missing/scan`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": viewer }, body: JSON.stringify({ outcome: "clean" }) });
    assert.equal(viewerScan.status, 403);
    const scannerPrincipal = testPrincipal({ subject: "scanner", roles: ["viewer"], authType: "service-account", tenantId: "tenant-a", permissionMode: "custom", permissions: ["evidence:scan"] });
    const scannerAuthorized = await fetch(`${base}/api/evidence-uploads/missing/scan`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": scannerPrincipal }, body: JSON.stringify({ outcome: "clean" }) });
    assert.equal(scannerAuthorized.status, 404);

    const collidingTenant = testPrincipal({ subject: "collision-a", roles: ["analyst"], tenantId: "Acme Inc" });
    const safeTenant = testPrincipal({ subject: "collision-b", roles: ["analyst"], tenantId: "acme-inc" });
    assert.equal((await fetch(`${base}/api/cases`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": collidingTenant }, body: JSON.stringify({ title: "Hashed tenant namespace" }) })).status, 201);
    const safeTenantCases = await fetch(`${base}/api/cases`, { headers: { "x-ndr-test-principal": safeTenant } });
    assert.deepEqual(await safeTenantCases.json(), []);

    const viewerExport = await fetch(`${base}/api/exports/investigation`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": viewer },
      body: JSON.stringify({ product: "SignalPrism NDR" })
    });
    assert.equal(viewerExport.status, 403);

    const viewerAi = await fetch(`${base}/api/ai/ask`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": viewer },
      body: JSON.stringify({ question: "summarize", context: {} })
    });
    assert.equal(viewerAi.status, 403);

    const viewerUsers = await fetch(`${base}/api/admin/users`, { headers: { "x-ndr-test-principal": viewer } });
    assert.equal(viewerUsers.status, 403);

    const viewerAudit = await fetch(`${base}/api/audit/events`, { headers: { "x-ndr-test-principal": viewer } });
    assert.equal(viewerAudit.status, 403);

    const viewerSettingsSave = await fetch(`${base}/api/enterprise/settings`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": viewer },
      body: JSON.stringify({ governance: { exportApprovalRequired: false } })
    });
    assert.equal(viewerSettingsSave.status, 403);

    const viewerArtifactSave = await fetch(`${base}/api/enterprise/artifacts`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": viewer },
      body: JSON.stringify({ type: "COPILOT_NOTE", title: "Viewer write", payload: {} })
    });
    assert.equal(viewerArtifactSave.status, 403);

    const analystScheduleSave = await fetch(`${base}/api/enterprise/artifacts`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ id: "report-schedule-governed", type: "REPORT_SCHEDULE", title: "Weekly leadership brief", payload: { name: "Weekly leadership brief", frequency: "weekly", period: "7d", format: "pdf", recipients: ["ciso@example.com"] } })
    });
    assert.equal(analystScheduleSave.status, 403);

    const adminScheduleSave = await fetch(`${base}/api/enterprise/artifacts`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": admin },
      body: JSON.stringify({ id: "report-schedule-governed", type: "REPORT_SCHEDULE", title: "Weekly leadership brief", payload: { name: "Weekly leadership brief", frequency: "weekly", period: "7d", format: "pdf", classification: "Confidential", recipients: ["ciso@example.com"] } })
    });
    assert.equal(adminScheduleSave.status, 200);
    const viewerSchedules = await fetch(`${base}/api/enterprise/artifacts?type=REPORT_SCHEDULE`, { headers: { "x-ndr-test-principal": viewer } });
    assert.deepEqual(await viewerSchedules.json(), [], "report schedule recipients must not be exposed to viewers");

    const ownedSource = await fetch(`${base}/api/sources`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ name: "Owned source", type: "CloudWatch Log Group", region: "us-east-1", scope: ["/aws/vpc/flowlogs/owned"], ownerUserId: "other@example.com", ownerName: "Other User" })
    });
    assert.equal(ownedSource.status, 201);
    const ownedSourceBody = await ownedSource.json();
    assert.equal(ownedSourceBody.ownerUserId, "analyst-a");
    assert.equal(ownedSourceBody.ownerName, "analyst-a");

    const unownedSource = await fetch(`${base}/api/sources`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": admin },
      body: JSON.stringify({ name: "Admin pool source", type: "CloudWatch Log Group", region: "us-east-1", scope: ["/aws/vpc/flowlogs/admin-pool"] })
    });
    assert.equal(unownedSource.status, 201);
    const unassignedAnalystSources = await fetch(`${base}/api/sources`, { headers: { "x-ndr-test-principal": analystOther } });
    assert.deepEqual(await unassignedAnalystSources.json(), [], "empty source assignments must deny access for non-admin identities");

    const unownedSourceBody = await unownedSource.json();
    const ownedOnly = testPrincipal({ subject: "owned-only", roles: ["analyst"], tenantId: "tenant-a", sourceAccessMode: "assigned", sourceIds: [ownedSourceBody.id] });
    const adminOnly = testPrincipal({ subject: "admin-pool-only", roles: ["analyst"], tenantId: "tenant-a", sourceAccessMode: "assigned", sourceIds: [unownedSourceBody.id] });
    for (const [sourceId, eventID, sourceIPAddress] of [[ownedSourceBody.id, "owned-event", "10.0.0.10"], [unownedSourceBody.id, "admin-event", "10.0.0.20"]]) {
      const response = await fetch(`${base}/api/telemetry/events`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-ndr-test-principal": admin },
        body: JSON.stringify({ sourceId, format: "cloudtrail", payload: [{ eventID, eventVersion: "1.09", eventTime: "2026-07-16T12:00:00Z", eventSource: "ec2.amazonaws.com", eventName: "DescribeInstances", sourceIPAddress }] })
      });
      assert.equal(response.status, 201);
    }
    const ownedOnlyEvents = await (await fetch(`${base}/api/telemetry/events`, { headers: { "x-ndr-test-principal": ownedOnly } })).json();
    const adminOnlyEvents = await (await fetch(`${base}/api/telemetry/events`, { headers: { "x-ndr-test-principal": adminOnly } })).json();
    assert.deepEqual(ownedOnlyEvents.map((event) => event.sourceId), [ownedSourceBody.id]);
    assert.deepEqual(adminOnlyEvents.map((event) => event.sourceId), [unownedSourceBody.id]);

    const ownershipRewriteDenied = await fetch(`${base}/api/sources`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analystOther },
      body: JSON.stringify({ ...ownedSourceBody, ownerUserId: "", ownerName: "" })
    });
    assert.equal(ownershipRewriteDenied.status, 403);

    const ownershipDenied = await fetch(`${base}/api/sources/${encodeURIComponent(ownedSourceBody.id)}/ingest-async`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analystOther },
      body: JSON.stringify({})
    });
    assert.equal(ownershipDenied.status, 403);

    const shortSchedule = await fetch(`${base}/api/sources/${encodeURIComponent(ownedSourceBody.id)}/jobs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ intervalMinutes: 1 })
    });
    assert.equal(shortSchedule.status, 400);

    const invalidSchedule = await fetch(`${base}/api/sources/${encodeURIComponent(ownedSourceBody.id)}/jobs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ intervalMinutes: "NaN" })
    });
    assert.equal(invalidSchedule.status, 400);

    const maliciousRegion = await fetch(`${base}/api/sources`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ name: "Injected region", type: "CloudWatch Log Group", region: "us-east-1.example.com", scope: ["/aws/vpc/flowlogs/test"] })
    });
    assert.equal(maliciousRegion.status, 400);

    const exportRequest = await fetch(`${base}/api/exports/investigation`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ product: "SignalPrism NDR", source: "tenant-a" })
    });
    assert.equal(exportRequest.status, 202);
    const exportApprovalId = (await exportRequest.json()).approval.id;

    const selfApproval = await fetch(`${base}/api/export-approvals/${exportApprovalId}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: "{}"
    });
    assert.equal(selfApproval.status, 403);

    const crossTenantApproval = await fetch(`${base}/api/export-approvals/${exportApprovalId}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": testPrincipal({ subject: "admin-b", roles: ["admin"], tenantId: "tenant-b" }) },
      body: "{}"
    });
    assert.equal(crossTenantApproval.status, 404);

    const approval = await fetch(`${base}/api/export-approvals/${exportApprovalId}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": admin },
      body: "{}"
    });
    assert.equal(approval.status, 200);

    const approvedExport = await fetch(`${base}/api/exports/investigation`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ approvalId: exportApprovalId })
    });
    assert.equal(approvedExport.status, 200);
    assert.equal((await approvedExport.json()).source, "tenant-a");

    const executiveRequest = await fetch(`${base}/api/exports/investigation`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ reportType: "executive-brief", format: "pdf", report: { id: "executive-1", title: "Executive Security Brief", tenantId: "tenant-a" } })
    });
    assert.equal(executiveRequest.status, 202);
    const executiveApproval = (await executiveRequest.json()).approval;
    assert.equal(executiveApproval.label, "Executive security brief");
    assert.equal(executiveApproval.format, "pdf");
    assert.equal(executiveApproval.payload, undefined, "approval metadata must not disclose report content");
    assert.equal((await fetch(`${base}/api/export-approvals/${executiveApproval.id}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": admin },
      body: "{}"
    })).status, 200);
    const executiveExport = await fetch(`${base}/api/exports/investigation`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ approvalId: executiveApproval.id })
    });
    assert.equal(executiveExport.status, 200);
    const executiveExportBody = await executiveExport.json();
    assert.equal(executiveExportBody.reportType, "executive-brief");
    assert.equal(executiveExportBody.format, "pdf");
    assert.equal(executiveExportBody.report.id, "executive-1");

    const replayedExport = await fetch(`${base}/api/exports/investigation`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ approvalId: exportApprovalId })
    });
    assert.equal(replayedExport.status, 409);

    const lakeHash = "a".repeat(64);
    const lakeRequest = await fetch(`${base}/api/exports/security-lake`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ recordCount: 1, contentSha256: lakeHash })
    });
    assert.equal(lakeRequest.status, 202);
    const lakeApprovalId = (await lakeRequest.json()).approval.id;
    assert.equal((await fetch(`${base}/api/export-approvals/${lakeApprovalId}/approve`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: "{}" })).status, 200);
    const wrongLakeHash = await fetch(`${base}/api/exports/security-lake`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ approvalId: lakeApprovalId, contentSha256: "b".repeat(64) })
    });
    assert.equal(wrongLakeHash.status, 409);
    const approvedLake = await fetch(`${base}/api/exports/security-lake`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ approvalId: lakeApprovalId, contentSha256: lakeHash })
    });
    assert.equal(approvedLake.status, 200);
    assert.equal((await approvedLake.json()).contentSha256, lakeHash);

    const raceRequest = await fetch(`${base}/api/exports/investigation`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ product: "SignalPrism NDR", source: "approval-race" })
    });
    assert.equal(raceRequest.status, 202);
    const raceApprovalId = (await raceRequest.json()).approval.id;
    const concurrentApprovals = await Promise.all([
      fetch(`${base}/api/export-approvals/${raceApprovalId}/approve`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: "{}" }),
      fetch(`${base}/api/export-approvals/${raceApprovalId}/approve`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: "{}" })
    ]);
    assert.deepEqual(concurrentApprovals.map((response) => response.status).sort(), [200, 409]);

    for (const source of ["quota-one", "quota-two"]) {
      const pending = await fetch(`${base}/api/exports/investigation`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
        body: JSON.stringify({ product: "SignalPrism NDR", source })
      });
      assert.equal(pending.status, 202);
    }
    const overQuota = await fetch(`${base}/api/exports/investigation`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ product: "SignalPrism NDR", source: "quota-three" })
    });
    assert.equal(overQuota.status, 429);

    const ruleCreate = await fetch(`${base}/api/detection-rules`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ name: "Governed database path", query: "destinationPort:5432", description: "Detects accepted database traffic across a sensitive trust boundary.", attackId: "T1021", status: "test", testCount: 2 })
    });
    assert.equal(ruleCreate.status, 201);
    const governedRule = await ruleCreate.json();
    assert.equal((await fetch(`${base}/api/detection-rules/${governedRule.id}/promote`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ status: "production" }) })).status, 403);
    const forgedPromotion = await fetch(`${base}/api/detection-rules/${governedRule.id}/promote`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": admin },
      body: JSON.stringify({ status: "production" })
    });
    assert.equal(forgedPromotion.status, 409, "client-supplied testCount must not satisfy the production gate");
    const detectionFixture = await fetch(`${base}/api/telemetry/events`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ events: Array.from({ length: 5 }, (_, index) => ({ id: `rule-fixture-${index}`, timestamp: new Date(Date.parse("2026-07-16T12:00:00Z") + index * 60_000).toISOString(), sourceIp: "10.0.0.10", destinationIp: "10.0.0.20", destinationPort: index === 0 ? 5432 : 443, action: "connect" })) })
    });
    const detectionFixtureBody = await detectionFixture.json();
    assert.equal(detectionFixture.status, 201, detectionFixtureBody.error);
    const backtestRule = await fetch(`${base}/api/detection-rules/${governedRule.id}/backtest`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ labels: { maliciousEventIds: ["rule-fixture-0"], benignEventIds: ["rule-fixture-1", "rule-fixture-2", "rule-fixture-3", "rule-fixture-4"] } })
    });
    const backtestBody = await backtestRule.json();
    assert.equal(backtestRule.status, 200, backtestBody.error);
    assert.equal(backtestBody.qualityGate, "pass");
    const promoteRule = await fetch(`${base}/api/detection-rules/${governedRule.id}/promote`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": admin },
      body: JSON.stringify({ status: "production" })
    });
    assert.equal(promoteRule.status, 200);
    assert.equal((await promoteRule.json()).status, "production");
  } finally {
    await stopServer(server);
    await rm(dataDir, { recursive: true, force: true });
  }
}

async function testPrivilegedStepUp() {
  const dataDir = await mkdtemp(join(tmpdir(), "ndr-step-up-"));
  const server = await startServer({ PORT: "4196", NDR_DATA_DIR: dataDir, NDR_TEST_AUTH_ENABLED: "true", NDR_STEP_UP_REQUIRED: "true", NDR_RATE_LIMIT_MAX: "100", NDR_STORE: "local" });
  const base = "http://127.0.0.1:4196";
  const analyst = testPrincipal({ subject: "step-up-analyst", email: "analyst@example.com", roles: ["analyst"], tenantId: "tenant-a" });
  const adminWithoutMfa = testPrincipal({ subject: "step-up-admin", email: "admin@example.com", roles: ["admin"], authType: "oidc", tenantId: "tenant-a", authenticationMethods: ["pwd"], authenticatedAt: Math.floor(Date.now() / 1000) });
  const adminWithMfa = testPrincipal({ subject: "step-up-admin", email: "admin@example.com", roles: ["admin"], authType: "oidc", tenantId: "tenant-a", authenticationMethods: ["pwd", "mfa"], authenticationContext: "urn:example:aal2", authenticatedAt: Math.floor(Date.now() / 1000) });
  try {
    const request = await fetch(`${base}/api/exports/investigation`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ source: "step-up-test" }) });
    assert.equal(request.status, 202);
    const approvalId = (await request.json()).approval.id;
    const denied = await fetch(`${base}/api/export-approvals/${approvalId}/approve`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": adminWithoutMfa }, body: "{}" });
    assert.equal(denied.status, 403);
    assert.match((await denied.json()).error, /MFA step-up/);
    const approved = await fetch(`${base}/api/export-approvals/${approvalId}/approve`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": adminWithMfa }, body: "{}" });
    assert.equal(approved.status, 200);
  } finally {
    await stopServer(server);
    await rm(dataDir, { recursive: true, force: true });
  }
}

async function testEnterpriseSecurityOperations() {
  const dataDir = await mkdtemp(join(tmpdir(), "ndr-enterprise-"));
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyB64 = publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const server = await startServer({
    PORT: "4195",
    NDR_DATA_DIR: dataDir,
    NDR_TEST_AUTH_ENABLED: "true",
    NDR_RATE_LIMIT_MAX: "5000",
    NDR_STORE: "local",
    NDR_DETECTION_CONTENT_PUBLIC_KEY_B64: publicKeyB64,
    NDR_PACKET_ALLOWED_BUCKETS: "integration-evidence",
    NDR_PACKET_ALLOWED_PREFIXES: "tenant-a",
    NDR_PACKET_OBJECT_VERIFICATION_REQUIRED: "false",
    NDR_SCIM_BEARER_TOKEN: "integration-scim-token-with-more-than-32-characters",
    NDR_SCIM_TENANT_ID: "tenant-a",
    NDR_SERVICE_ACCOUNT_PEPPER: "integration-service-account-pepper-more-than-32-chars"
  });
  const base = "http://127.0.0.1:4195";
  const analyst = testPrincipal({ subject: "analyst-a", email: "analyst-a@example.com", roles: ["analyst"], tenantId: "tenant-a" });
  const admin = testPrincipal({ subject: "admin-a", email: "admin-a@example.com", roles: ["admin"], tenantId: "tenant-a" });
  const verifierAdmin = testPrincipal({ subject: "verifier-a", email: "verifier-a@example.com", roles: ["admin"], tenantId: "tenant-a" });
  const viewer = testPrincipal({ subject: "viewer-a", email: "viewer-a@example.com", roles: ["viewer"], tenantId: "tenant-a" });
  const otherAdmin = testPrincipal({ subject: "admin-b", email: "admin-b@example.com", roles: ["admin"], tenantId: "tenant-b" });
  try {
    const telemetry = [];
    for (let index = 0; index < 6; index += 1) {
      telemetry.push({ eventVersion: "1.09", eventTime: new Date(Date.parse("2026-07-16T12:00:00Z") + index * 30_000).toISOString(), eventSource: "sts.amazonaws.com", eventName: "AssumeRole", sourceIPAddress: "203.0.113.90", errorCode: "AccessDenied", userIdentity: { arn: `arn:aws:iam::123456789012:user/test-${index}` } });
    }
    const ingest = await fetch(`${base}/api/telemetry/events`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ format: "auto", payload: telemetry })
    });
    assert.equal(ingest.status, 201);
    assert.equal((await ingest.json()).accepted, 6);

    const tenantEvents = await fetch(`${base}/api/telemetry/events`, { headers: { "x-ndr-test-principal": viewer } });
    assert.equal(tenantEvents.status, 200);
    assert.equal((await tenantEvents.json()).length, 6);
    const isolatedEvents = await fetch(`${base}/api/telemetry/events`, { headers: { "x-ndr-test-principal": otherAdmin } });
    assert.equal((await isolatedEvents.json()).length, 0);

    const correlation = await fetch(`${base}/api/telemetry/correlate`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ windowMinutes: 60 })
    });
    assert.equal(correlation.status, 200);
    assert.ok((await correlation.json()).findingCount >= 1);

    const behavior = await fetch(`${base}/api/analytics/behavior`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ compareToBaseline: true }) });
    assert.equal(behavior.status, 200);
    assert.ok((await behavior.json()).findings.some((finding) => finding.ruleId === "SP-UEBA-006"));

    const campaigns = await fetch(`${base}/api/campaigns/build`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ windowMinutes: 60 }) });
    assert.equal(campaigns.status, 200);
    assert.ok((await campaigns.json()).campaignCount >= 1);

    const hunt = await fetch(`${base}/api/hunts/retrospective`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ query: "provider:aws AND outcome:failure" }) });
    assert.equal(hunt.status, 200);
    assert.equal((await hunt.json()).matchCount, 6);

    const stream = await fetch(`${base}/api/stream/events`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ format: "generic", events: [{ id: "stream-1", timestamp: "2026-07-16T12:10:00Z", sourceIp: "10.0.0.8", destinationIp: "198.51.100.8", destinationPort: 443, protocol: "tcp", action: "connect", outcome: "success" }] }) });
    assert.equal(stream.status, 202);
    const streamBody = await stream.json();
    assert.equal(streamBody.delivery.mode, "preview");
    const streamRetry = await fetch(`${base}/api/stream/events`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ format: "generic", events: [{ id: "stream-1", timestamp: "2026-07-16T12:10:00Z", sourceIp: "10.0.0.8", destinationIp: "198.51.100.8", destinationPort: 443, protocol: "tcp", action: "connect", outcome: "success" }] }) });
    const streamRetryBody = await streamRetry.json();
    assert.equal(streamRetry.status, 202);
    assert.equal(streamRetryBody.delivery.id, streamBody.delivery.id);
    assert.equal(streamRetryBody.newlyStored, 0);
    const streamDeliveries = await fetch(`${base}/api/stream/deliveries`, { headers: { "x-ndr-test-principal": viewer } });
    assert.equal(streamDeliveries.status, 200);
    assert.equal((await streamDeliveries.json()).filter((delivery) => delivery.id === streamBody.delivery.id).length, 1);

    const posture = await fetch(`${base}/api/governance/traffic-posture`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ aiPolicy: { sanctionedProviders: ["AWS Bedrock"] } }) });
    assert.equal(posture.status, 200);
    assert.ok((await posture.json()).crypto);

    const securityLakePublish = await fetch(`${base}/api/security-lake/publish`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ limit: 100 }) });
    assert.equal(securityLakePublish.status, 202);
    const securityLakeApproval = await securityLakePublish.json();
    assert.equal(securityLakeApproval.approvalRequired, true);
    assert.match(securityLakeApproval.contentSha256, /^[a-f0-9]{64}$/);

    const aiInvestigation = await fetch(`${base}/api/ai/investigate`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ objective: "Explain the authentication failures and cite the source evidence.", huntQuery: "outcome:failure", useBedrock: false }) });
    assert.equal(aiInvestigation.status, 200);
    const aiRun = await aiInvestigation.json();
    assert.equal(aiRun.mode, "deterministic");
    assert.ok(aiRun.citations.length >= 1);

    const connectorCatalogResponse = await fetch(`${base}/api/connectors/catalog`, { headers: { "x-ndr-test-principal": viewer } });
    assert.equal(connectorCatalogResponse.status, 200);
    assert.ok((await connectorCatalogResponse.json()).some((connector) => connector.id === "splunk-hec"));
    const forbiddenConnector = await fetch(`${base}/api/connectors`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ catalogId: "splunk-hec", name: "Forbidden", format: "hec", endpoint: "https://splunk.example.com/services/collector" }) });
    assert.equal(forbiddenConnector.status, 403);
    const savedConnectorResponse = await fetch(`${base}/api/connectors`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: JSON.stringify({ catalogId: "splunk-hec", name: "Production Splunk", format: "hec", endpoint: "https://splunk.example.com/services/collector", secretRef: "arn:aws:secretsmanager:us-east-1:123456789012:secret:signalprism/splunk" }) });
    assert.equal(savedConnectorResponse.status, 201);
    const savedConnector = await savedConnectorResponse.json();
    assert.equal(savedConnector.secretConfigured, true);
    assert.doesNotMatch(savedConnector.secretRef, /signalprism\/splunk$/);
    const connectorTest = await fetch(`${base}/api/connectors/${savedConnector.id}/test`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: "{}" });
    assert.equal(connectorTest.status, 200);
    assert.equal((await connectorTest.json()).delivery.mode, "validation-only");

    const roleCreate = await fetch(`${base}/api/admin/roles`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: JSON.stringify({ name: "Threat Hunter", baseRole: "viewer", permissions: ["hunts:run", "detections:read"] }) });
    assert.equal(roleCreate.status, 201);
    assert.ok((await roleCreate.json()).permissions.includes("hunts:run"));

    const serviceAccountCreate = await fetch(`${base}/api/admin/service-accounts`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: JSON.stringify({ name: "SIEM reader", baseRole: "viewer" }) });
    assert.equal(serviceAccountCreate.status, 201);
    const serviceAccount = await serviceAccountCreate.json();
    assert.match(serviceAccount.token, /^spn_/);
    const serviceAccountRead = await fetch(`${base}/api/telemetry/events`, { headers: { authorization: `Bearer ${serviceAccount.token}` } });
    assert.equal(serviceAccountRead.status, 200);
    assert.equal((await serviceAccountRead.json()).length, 0, "new service accounts must fail closed until sources are assigned");

    const scimUnauthorized = await fetch(`${base}/scim/v2/Users`);
    assert.equal(scimUnauthorized.status, 401);
    const scimCreate = await fetch(`${base}/scim/v2/Users`, { method: "POST", headers: { authorization: "Bearer integration-scim-token-with-more-than-32-characters", "content-type": "application/json" }, body: JSON.stringify({ externalId: "scim-analyst-1", userName: "scim-analyst@example.com", displayName: "SCIM Analyst", active: true, roles: [{ value: "analyst" }] }) });
    assert.equal(scimCreate.status, 201);
    assert.equal((await scimCreate.json()).active, true);

    const evidenceUploadUnavailable = await fetch(`${base}/api/evidence-uploads`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ fileName: "evidence.log", contentLength: 100, sha256: "a".repeat(64) }) });
    assert.equal(evidenceUploadUnavailable.status, 503);

    const organizationUnavailable = await fetch(`${base}/api/organization/discover`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: "{}" });
    assert.equal(organizationUnavailable.status, 503);

    const readiness = await fetch(`${base}/api/enterprise/readiness`, { headers: { "x-ndr-test-principal": viewer } });
    assert.equal(readiness.status, 200);
    const readinessBody = await readiness.json();
    assert.ok(readinessBody.checks.some((check) => check.name === "Durable ingest queue" && check.status === "action-required"));

    const operations = await fetch(`${base}/api/operations/summary`, { headers: { "x-ndr-test-principal": viewer } });
    assert.equal(operations.status, 200);
    const operationsBody = await operations.json();
    assert.equal(operationsBody.inputCounts.events, 7);
    assert.ok(operationsBody.entityGraph.nodes.length > 0);

    const advancedAnalysis = await fetch(`${base}/api/operations/analyze`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: "{}" });
    assert.equal(advancedAnalysis.status, 200);
    assert.ok((await advancedAnalysis.json()).behavior.governance.approvalRequired);

    const schemaValidation = await fetch(`${base}/api/schema/validate`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ profile: "security-lake-1.3", limit: 100 }) });
    assert.equal(schemaValidation.status, 200);
    const schemaValidationBody = await schemaValidation.json();
    assert.equal(schemaValidationBody.ocsfVersion, "1.3.0");
    assert.equal(schemaValidationBody.compression, "zstd");
    assert.ok(schemaValidationBody.eventClassBatches.every((batch) => batch.records === undefined));

    const lakeSources = await fetch(`${base}/api/security-lake/sources/register`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: JSON.stringify({ assignedPrefix: "ext/security-lake-assigned/signalprism", providerAccountId: "123456789012", externalId: "signalprism-integration-external-id" }) });
    assert.equal(lakeSources.status, 201);
    const lakeSourcesBody = await lakeSources.json();
    assert.equal(lakeSourcesBody.sources.length, 2);
    assert.equal(new Set(lakeSourcesBody.sources.map((source) => source.classUid)).size, 2);

    const sensorResponse = await fetch(`${base}/api/sensors`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: JSON.stringify({ name: "Integration Zeek sensor", type: "zeek", region: "us-east-1", status: "healthy" }) });
    assert.equal(sensorResponse.status, 201);
    assert.equal((await sensorResponse.json()).type, "zeek");

    const replayResponse = await fetch(`${base}/api/streams/replay`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ start: "2026-07-16T11:00:00Z", end: "2026-07-16T13:00:00Z", profile: "native-current", dispatch: false }) });
    assert.equal(replayResponse.status, 200);
    assert.equal((await replayResponse.json()).ordered, true);

    const searchJobResponse = await fetch(`${base}/api/search/jobs`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ query: "outcome:failure", limit: 100 }) });
    assert.equal(searchJobResponse.status, 201);
    assert.equal((await searchJobResponse.json()).status, "completed");

    const packetManifestResponse = await fetch(`${base}/api/packet-manifests`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ objectUri: "s3://integration-evidence/tenant-a/capture.pcap", sha256: "b".repeat(64), bytes: 1024, packetCount: 12 }) });
    assert.equal(packetManifestResponse.status, 201);
    const packetManifest = await packetManifestResponse.json();
    const packetGrantResponse = await fetch(`${base}/api/packet-manifests/${packetManifest.id}/authorize`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: JSON.stringify({ reason: "Validate the evidence-linked command-and-control network session.", minutes: 10 }) });
    assert.equal(packetGrantResponse.status, 201);
    assert.equal((await packetGrantResponse.json()).scope, "read-capture");

    const manifestRaceBody = JSON.stringify({ objectUri: "s3://integration-evidence/tenant-a/race.pcap", sha256: "c".repeat(64), bytes: 2048, packetCount: 24 });
    const manifestRace = await Promise.all([
      fetch(`${base}/api/packet-manifests`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: manifestRaceBody }),
      fetch(`${base}/api/packet-manifests`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: manifestRaceBody })
    ]);
    assert.deepEqual(manifestRace.map((response) => response.status).sort(), [201, 409]);

    const responsePolicyResponse = await fetch(`${base}/api/response-policy`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: JSON.stringify({ mode: "approve", killSwitch: false, requireCase: false, rollbackRequired: true }) });
    assert.equal(responsePolicyResponse.status, 200);
    assert.equal((await responsePolicyResponse.json()).mode, "approve");

    const threatFeedResponse = await fetch(`${base}/api/threat-intel/feeds`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ name: "Integration feed", tlp: "AMBER", indicators: [{ id: "ioc-1", type: "ipv4", value: "198.51.100.8", confidence: 90 }] }) });
    assert.equal(threatFeedResponse.status, 201);
    const retromatchResponse = await fetch(`${base}/api/threat-intel/retromatch`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: "{}" });
    assert.equal(retromatchResponse.status, 200);
    assert.ok((await retromatchResponse.json()).sightingCount >= 1);

    const regionPolicyResponse = await fetch(`${base}/api/regional-cells`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: JSON.stringify({ name: "US East primary", status: "active", payload: { region: "us-east-1", residency: "US", recoveryPointMinutes: 5 } }) });
    assert.equal(regionPolicyResponse.status, 201);
    assert.equal((await regionPolicyResponse.json()).payload.region, "us-east-1");

    const inlineAgentEvaluation = await fetch(`${base}/api/agent/evaluations`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ run: { id: "inline-agent-run", citations: [{ id: "evidence-1" }] } }) });
    assert.equal(inlineAgentEvaluation.status, 400);
    const agentEvaluationResponse = await fetch(`${base}/api/agent/evaluations`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ runId: aiRun.id }) });
    assert.equal(agentEvaluationResponse.status, 201);
    assert.equal((await agentEvaluationResponse.json()).passed, true);

    const responseAdapters = await fetch(`${base}/api/response-adapters`, { headers: { "x-ndr-test-principal": viewer } });
    assert.equal(responseAdapters.status, 200);
    assert.ok((await responseAdapters.json()).some((adapter) => adapter.id === "sensor-capture" && adapter.actions.includes("capture-packets")));
    const captureRequest = await fetch(`${base}/api/response-actions`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ type: "capture-packets", target: "sensor/us-east-1/vpc-0abc123", reason: "Capture a five-minute evidence window for the corroborated command-and-control path.", expiresInMinutes: 5 })
    });
    assert.equal(captureRequest.status, 201);
    const captureAction = await captureRequest.json();
    assert.equal(captureAction.adapter, "sensor-capture");
    assert.match(captureAction.rollbackPlan, /expire/);

    const responseRequest = await fetch(`${base}/api/response-actions`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ type: "block-ip", target: "203.0.113.90", reason: "Block the observed authentication spray while the case is investigated." })
    });
    assert.equal(responseRequest.status, 201);
    const responseAction = await responseRequest.json();
    const crossTenantApprove = await fetch(`${base}/api/response-actions/${responseAction.id}/approve`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": otherAdmin }, body: "{}" });
    assert.equal(crossTenantApprove.status, 404);
    const approve = await fetch(`${base}/api/response-actions/${responseAction.id}/approve`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: "{}" });
    assert.equal(approve.status, 200);
    assert.equal((await approve.json()).status, "approved");
    const requesterVerify = await fetch(`${base}/api/response-actions/${responseAction.id}/verify`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ successful: true, evidence: "Self-attested result" }) });
    assert.equal(requesterVerify.status, 403);
    const approverVerify = await fetch(`${base}/api/response-actions/${responseAction.id}/verify`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: JSON.stringify({ successful: true, evidence: "Approver-attested result" }) });
    assert.equal(approverVerify.status, 403);
    const verifyResponse = await fetch(`${base}/api/response-actions/${responseAction.id}/verify`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": verifierAdmin }, body: JSON.stringify({ successful: true, evidence: "No additional authentication attempts were observed after the dry run." }) });
    assert.equal(verifyResponse.status, 200);
    assert.equal((await verifyResponse.json()).status, "verified");
    const rollbackResponse = await fetch(`${base}/api/response-actions/${responseAction.id}/rollback`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: JSON.stringify({ reason: "Restore the managed block list after successful validation." }) });
    assert.equal(rollbackResponse.status, 201);
    assert.equal((await rollbackResponse.json()).type, "rollback-action");

    const selfRequest = await fetch(`${base}/api/response-actions`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": admin },
      body: JSON.stringify({ type: "notify-soc", target: "primary-soc", reason: "Notify the primary SOC about the validated cross-source finding." })
    });
    const selfAction = await selfRequest.json();
    const selfApprove = await fetch(`${base}/api/response-actions/${selfAction.id}/approve`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: "{}" });
    assert.equal(selfApprove.status, 403);

    const rules = [{ id: "signed-rule-1", name: "Signed authentication spray", query: "category:authentication AND outcome:failure", description: "Detects repeated failed cloud authentication events linked to a single source.", severity: "high", tactic: "Credential Access", technique: "Brute Force", attackId: "T1110" }];
    const manifest = { id: "signalprism-integration", name: "SignalPrism integration pack", publisher: "Integration Test", version: "1.0.0", contentHash: createHash("sha256").update(canonicalJson(rules)).digest("hex") };
    const signature = sign(null, Buffer.from(canonicalJson({ manifest, rules })), privateKey).toString("base64");
    const bundle = { manifest, rules, signature };
    const verify = await fetch(`${base}/api/detection-content/verify`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ bundle }) });
    assert.equal(verify.status, 200);
    assert.equal((await verify.json()).verified, true);
    const analystImport = await fetch(`${base}/api/detection-content/import`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ bundle }) });
    assert.equal(analystImport.status, 403);
    const imported = await fetch(`${base}/api/detection-content/import`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": admin }, body: JSON.stringify({ bundle }) });
    assert.equal(imported.status, 201);
    const importedBody = await imported.json();
    assert.equal(importedBody.rules[0].status, "test");
    assert.equal(importedBody.rules[0].testCount, 0);
    const backtest = await fetch(`${base}/api/detection-rules/${importedBody.rules[0].id}/backtest`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ labels: { maliciousEventIds: telemetry.slice(0, 2).map((event, index) => `missing-${index}`) } }) });
    assert.equal(backtest.status, 200);
    assert.equal((await backtest.json()).matched, 6);

    const tampered = structuredClone(bundle);
    tampered.rules[0].query = "action:any";
    const tamperedVerify = await fetch(`${base}/api/detection-content/verify`, { method: "POST", headers: { "content-type": "application/json", "x-ndr-test-principal": analyst }, body: JSON.stringify({ bundle: tampered }) });
    assert.equal(tamperedVerify.status, 400);
  } finally {
    await stopServer(server);
    await rm(dataDir, { recursive: true, force: true });
  }
}

async function testRateLimit() {
  const dataDir = await mkdtemp(join(tmpdir(), "ndr-rate-"));
  const server = await startServer({
    PORT: "4192",
    NDR_DATA_DIR: dataDir,
    NDR_RATE_LIMIT_MAX: "2",
    NDR_RATE_LIMIT_WINDOW_MS: "60000",
    NDR_STORE: "local"
  });
  const base = "http://127.0.0.1:4192";
  try {
    assert.equal((await fetch(`${base}/api/health`)).status, 200);
    assert.equal((await fetch(`${base}/api/health`)).status, 200);
    const limited = await fetch(`${base}/api/health`);
    assert.equal(limited.status, 429);
    assert.ok(limited.headers.get("retry-after"));
  } finally {
    await stopServer(server);
    await rm(dataDir, { recursive: true, force: true });
  }
}

async function testRequestBodyLimit() {
  const dataDir = await mkdtemp(join(tmpdir(), "ndr-body-"));
  const server = await startServer({
    PORT: "4194",
    NDR_DATA_DIR: dataDir,
    NDR_API_KEY: "integration-key",
    NDR_MAX_BODY_BYTES: "32",
    NDR_RATE_LIMIT_MAX: "100",
    NDR_STORE: "local"
  });
  const base = "http://127.0.0.1:4194";
  try {
    const oversized = await fetch(`${base}/api/workspaces`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ name: "x".repeat(64) })
    });
    assert.equal(oversized.status, 413);

    const malformed = await fetch(`${base}/api/workspaces`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: "{"
    });
    assert.equal(malformed.status, 400);

    const wrongType = await fetch(`${base}/api/workspaces`, {
      method: "POST",
      headers: { "content-type": "text/plain", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ name: "wrong content type" })
    });
    assert.equal(wrongType.status, 415);
  } finally {
    await stopServer(server);
    await rm(dataDir, { recursive: true, force: true });
  }
}

async function testProductionStartupControls() {
  const productionStorage = {
    NDR_STORE: "dynamodb",
    NDR_DDB_TABLE: "signalprism-integration",
    NDR_AUDIT_BUCKET: "signalprism-audit-integration",
    NDR_AUDIT_OBJECT_STORAGE_REQUIRED: "true",
    NDR_EXPORT_PAYLOAD_BUCKET: "signalprism-staging-integration"
  };
  const testAuthFailure = await runRejectedServer({
    NODE_ENV: "production",
    NDR_TEST_AUTH_ENABLED: "true"
  });
  assert.match(testAuthFailure, /NDR_TEST_AUTH_ENABLED cannot be enabled/);

  const evidenceScanFailure = await runRejectedServer({
    NODE_ENV: "production",
    NDR_PRODUCTION_HARDENING: "true",
    NDR_EVIDENCE_BUCKET: "signalprism-evidence-prod",
    NDR_EVIDENCE_STAGING_BUCKET: "",
    NDR_EVIDENCE_SCAN_REQUIRED: "false"
  });
  assert.match(evidenceScanFailure, /require NDR_EVIDENCE_STAGING_BUCKET/);

  const weakSecretFailure = await runRejectedServer({
    ...productionStorage,
    NODE_ENV: "production",
    NDR_PRODUCTION_HARDENING: "true",
    NDR_API_KEY: "a-secure-api-key-value-123456",
    NDR_SESSION_SECRET: "short",
    NDR_EVIDENCE_ATTESTATION_SECRET: "evidence-attestation-key-material-123456",
    NDR_SESSION_COOKIE_SECURE: "true"
  });
  assert.match(weakSecretFailure, /NDR_SESSION_SECRET must contain at least 32 characters/);

  const localStoreFailure = await runRejectedServer({
    NODE_ENV: "production",
    NDR_PRODUCTION_HARDENING: "true",
    NDR_API_KEY: "a-secure-api-key-value-123456",
    NDR_SESSION_SECRET: "session-signing-key-material-1234567890",
    NDR_EVIDENCE_ATTESTATION_SECRET: "evidence-attestation-key-material-123456",
    NDR_SESSION_COOKIE_SECURE: "true",
    NDR_STORE: "local"
  });
  assert.match(localStoreFailure, /requires NDR_STORE=dynamodb/);

  const queueFailure = await runRejectedServer({
    ...productionStorage,
    NODE_ENV: "production",
    NDR_PRODUCTION_HARDENING: "true",
    NDR_API_KEY: "a-secure-api-key-value-123456",
    NDR_SESSION_SECRET: "session-signing-key-material-1234567890",
    NDR_EVIDENCE_ATTESTATION_SECRET: "evidence-attestation-key-material-123456",
    NDR_SESSION_COOKIE_SECURE: "true",
    NDR_QUEUE_URL: ""
  });
  assert.match(queueFailure, /requires NDR_QUEUE_URL/);

  const schedulerFailure = await runRejectedServer({
    ...productionStorage,
    NODE_ENV: "production",
    NDR_PRODUCTION_HARDENING: "true",
    NDR_API_KEY: "a-secure-api-key-value-123456",
    NDR_SESSION_SECRET: "session-signing-key-material-1234567890",
    NDR_EVIDENCE_ATTESTATION_SECRET: "evidence-attestation-key-material-123456",
    NDR_SESSION_COOKIE_SECURE: "true",
    NDR_QUEUE_URL: "https://sqs.us-east-1.amazonaws.com/123456789012/signalprism-ingest",
    NDR_QUEUE_REGION: "us-east-1",
    NDR_SCHEDULER_MODE: "local"
  });
  assert.match(schedulerFailure, /requires EventBridge Scheduler/);
}

function runRejectedServer(overrides) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["server.mjs"], {
      cwd: root,
      env: {
        ...process.env,
        HOST: "127.0.0.1",
        PORT: "4199",
        NDR_TEST_AUTH_ENABLED: "false",
        NDR_PRODUCTION_HARDENING: "false",
        NDR_API_KEY: "",
        NDR_OIDC_ISSUER: "",
        NDR_QUEUE_URL: "",
        ...overrides
      },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let output = "";
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`Expected startup rejection but server remained active:\n${output}`));
    }, 3000);
    child.stdout.on("data", (chunk) => { output += chunk.toString(); });
    child.stderr.on("data", (chunk) => { output += chunk.toString(); });
    child.once("exit", (code) => {
      clearTimeout(timer);
      if (code === 0) reject(new Error(`Expected non-zero startup rejection:\n${output}`));
      else resolve(output);
    });
  });
}

function testAwsSigning() {
  const signed = createSignedAwsRequest({
    accessKeyId: "AKIDEXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    service: "dynamodb",
    region: "us-east-1",
    method: "POST",
    host: "dynamodb.us-east-1.amazonaws.com",
    path: "/",
    headers: {
      "content-type": "application/x-amz-json-1.1",
      "x-amz-target": "DynamoDB_20120810.Query"
    },
    body: JSON.stringify({ TableName: "ndr-flow-console-dev" }),
    date: new Date("2026-05-05T12:00:00Z")
  });

  assert.equal(signed.url, "https://dynamodb.us-east-1.amazonaws.com/");
  assert.equal(signed.signedHeaderNames, "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-target");
  assert.match(signed.signature, /^[a-f0-9]{64}$/);
  assert.ok(signed.canonicalRequest.includes("content-type:application/x-amz-json-1.1\n"));
  assert.ok(signed.canonicalRequest.includes("x-amz-target:DynamoDB_20120810.Query\n"));
  assert.ok(signed.headers.authorization.includes("Credential=AKIDEXAMPLE/20260505/us-east-1/dynamodb/aws4_request"));
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

async function startServer(env) {
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: root,
    env: { ...process.env, HOST: "127.0.0.1", NDR_TEST_AUTH_ENABLED: "false", ...env, AWS_ACCESS_KEY_ID: "", AWS_SECRET_ACCESS_KEY: "", NDR_OIDC_ISSUER: "" },
    stdio: ["ignore", "pipe", "pipe"]
  });
  await waitForStartup(child);
  return child;
}

function waitForStartup(child) {
  return new Promise((resolve, reject) => {
    let output = "";
    const timeout = setTimeout(() => reject(new Error(`Server did not start:\n${output}`)), 5000);
    child.stdout.on("data", (chunk) => {
      output += chunk.toString();
      if (output.includes("server_started")) {
        clearTimeout(timeout);
        resolve();
      }
    });
    child.stderr.on("data", (chunk) => {
      output += chunk.toString();
    });
    child.on("exit", (code) => {
      clearTimeout(timeout);
      reject(new Error(`Server exited with ${code}:\n${output}`));
    });
  });
}

function stopServer(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
      return;
    }
    child.once("exit", resolve);
    child.kill("SIGTERM");
  });
}

function testPrincipal(principal) {
  const hasSourcePolicy = principal.sourceAccessMode || Array.isArray(principal.sourceIds) || Array.isArray(principal.sourceGroupIds);
  return JSON.stringify(hasSourcePolicy || (principal.roles || []).includes("admin") ? principal : { ...principal, sourceAccessMode: "all" });
}
