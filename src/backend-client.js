export async function backendHealth() {
  const health = await apiGet("/api/health");
  try {
    return { ...(await apiGet("/api/status")), ...health };
  } catch {
    return health;
  }
}

export async function authConfig() {
  return apiGet("/api/auth/config");
}

export async function currentPrincipal() {
  return apiGet("/api/auth/me");
}

export async function aiConfig() {
  return apiGet("/api/ai/config");
}

export async function askAi(payload) {
  return apiPost("/api/ai/ask", payload);
}

export async function listWorkspaces() {
  return apiGet("/api/workspaces");
}

export async function saveWorkspace(workspace) {
  return apiPost("/api/workspaces", workspace);
}

export async function deleteWorkspace(id) {
  return apiDelete(`/api/workspaces/${encodeURIComponent(id)}`);
}

export async function listEvidenceRuns() {
  return apiGet("/api/evidence-runs");
}

export async function saveEvidenceRun(run) {
  return apiPost("/api/evidence-runs", run);
}

export async function listSources() {
  return apiGet("/api/sources");
}

export async function saveSource(source) {
  return apiPost("/api/sources", source);
}

export async function deleteSource(id) {
  return apiDelete(`/api/sources/${encodeURIComponent(id)}`);
}

export async function ingestManagedSource(id) {
  return apiPost(`/api/sources/${encodeURIComponent(id)}/ingest`, {});
}

export async function ingestManagedSourceAsync(id) {
  return apiPost(`/api/sources/${encodeURIComponent(id)}/ingest-async`, {});
}

export async function scheduleManagedSource(id, job) {
  return apiPost(`/api/sources/${encodeURIComponent(id)}/jobs`, job);
}

export async function listTenantUsers() {
  return apiGet("/api/admin/users");
}

export async function saveTenantUser(user) {
  return apiPost("/api/admin/users", user);
}

export async function deleteTenantUser(id) {
  return apiDelete(`/api/admin/users/${encodeURIComponent(id)}`);
}

export async function assignSourceOwner(sourceId, ownerId) {
  return apiPost("/api/admin/source-owners", { sourceId, ownerId });
}

export async function enterpriseSettings() {
  return apiGet("/api/enterprise/settings");
}

export async function saveEnterpriseSettings(settings) {
  return apiPost("/api/enterprise/settings", settings);
}

export async function enterpriseReadiness() {
  return apiGet("/api/enterprise/readiness");
}

export async function operationsSummary() {
  return apiGet("/api/operations/summary");
}

export async function runOperationsAnalysis(options = {}) {
  return apiPost("/api/operations/analyze", options);
}

export async function schemaProfiles() {
  return apiGet("/api/schema/profiles");
}

export async function validateSchemaProfile(profile, limit = 1000) {
  return apiPost("/api/schema/validate", { profile, limit });
}

export async function listSecurityLakeSources() {
  return apiGet("/api/security-lake/sources");
}

export async function configureSecurityLakeSources(config) {
  return apiPost("/api/security-lake/sources/register", config);
}

export async function streamControl() {
  return apiGet("/api/streams/control");
}

export async function replayStream(config) {
  return apiPost("/api/streams/replay", config);
}

export async function createSearchJob(query, limit = 500) {
  return apiPost("/api/search/jobs", { query, limit });
}

export async function listSensors() {
  return apiGet("/api/sensors");
}

export async function saveSensor(sensor) {
  return apiPost("/api/sensors", sensor);
}

export async function listPacketManifests() {
  return apiGet("/api/packet-manifests");
}

export async function savePacketManifest(manifest) {
  return apiPost("/api/packet-manifests", manifest);
}

export async function authorizePacketAccess(id, reason, minutes = 15) {
  return apiPost(`/api/packet-manifests/${encodeURIComponent(id)}/authorize`, { reason, minutes });
}

export async function responsePolicy() {
  return apiGet("/api/response-policy");
}

export async function saveResponsePolicy(policy) {
  return apiPost("/api/response-policy", policy);
}

export async function setResponseKillSwitch(enabled) {
  return apiPost("/api/response-policy/kill-switch", { enabled });
}

export async function listThreatIntelFeeds() {
  return apiGet("/api/threat-intel/feeds");
}

export async function saveThreatIntelFeed(feed) {
  return apiPost("/api/threat-intel/feeds", feed);
}

export async function runThreatIntelRetromatch() {
  return apiPost("/api/threat-intel/retromatch", {});
}

export async function listCaseTasks(caseId = "") {
  return apiGet(`/api/case-tasks${caseId ? `?caseId=${encodeURIComponent(caseId)}` : ""}`);
}

export async function saveCaseTask(task) {
  return apiPost("/api/case-tasks", task);
}

export async function deleteCaseTask(id) {
  return apiDelete(`/api/case-tasks/${encodeURIComponent(id)}`);
}

export async function listGovernanceResources(path) {
  const allowed = new Set(["pipeline-policy", "exposure-context", "regional-cells", "provider-workspaces", "notification-policies", "agent/evaluations"]);
  if (!allowed.has(path)) throw new Error("Unsupported governance resource");
  return apiGet(`/api/${path}`);
}

export async function saveGovernanceResource(path, record) {
  const allowed = new Set(["pipeline-policy", "exposure-context", "regional-cells", "provider-workspaces", "notification-policies"]);
  if (!allowed.has(path)) throw new Error("Unsupported governance resource");
  return apiPost(`/api/${path}`, record);
}

export async function evaluateAgent(payload) {
  return apiPost("/api/agent/evaluations", payload);
}

export async function listTelemetryEvents(format = "") {
  return apiGet(`/api/telemetry/events${format ? `?format=${encodeURIComponent(format)}` : ""}`);
}

export async function ingestTelemetry(format, payload) {
  return apiPost("/api/telemetry/events", { format, payload });
}

export async function runTelemetryCorrelation(windowMinutes = 60) {
  return apiPost("/api/telemetry/correlate", { windowMinutes });
}

export async function listCorrelations() {
  return apiGet("/api/correlations");
}

export async function streamStatus() {
  return apiGet("/api/stream/status");
}

export async function streamTelemetry(format, payload) {
  return apiPost("/api/stream/events", { format, payload });
}

export async function behaviorAnalytics() {
  return apiGet("/api/analytics/behavior");
}

export async function runBehaviorAnalytics(options = {}) {
  return apiPost("/api/analytics/behavior", options);
}

export async function listCampaigns() {
  return apiGet("/api/campaigns");
}

export async function buildCampaigns(options = {}) {
  return apiPost("/api/campaigns/build", options);
}

export async function listRetrospectiveHunts() {
  return apiGet("/api/hunts/retrospective");
}

export async function runRetrospectiveHunt(query, limit = 500) {
  return apiPost("/api/hunts/retrospective", { query, limit });
}

export async function trafficPosture() {
  return apiGet("/api/governance/traffic-posture");
}

export async function runTrafficPosture(aiPolicy = {}) {
  return apiPost("/api/governance/traffic-posture", { aiPolicy });
}

export async function listResponseActions() {
  return apiGet("/api/response-actions");
}

export async function requestResponseAction(action) {
  return apiPost("/api/response-actions", action);
}

export async function approveResponseAction(id) {
  return apiPost(`/api/response-actions/${encodeURIComponent(id)}/approve`, {});
}

export async function responseAdapters() {
  return apiGet("/api/response-adapters");
}

export async function verifyResponseAction(id, successful, evidence) {
  return apiPost(`/api/response-actions/${encodeURIComponent(id)}/verify`, { successful, evidence });
}

export async function rollbackResponseAction(id, reason, executionMode = "dry-run") {
  return apiPost(`/api/response-actions/${encodeURIComponent(id)}/rollback`, { reason, executionMode });
}

export async function listDetectionContentBundles() {
  return apiGet("/api/detection-content/bundles");
}

export async function verifyDetectionContent(bundle) {
  return apiPost("/api/detection-content/verify", { bundle });
}

export async function importDetectionContent(bundle) {
  return apiPost("/api/detection-content/import", { bundle });
}

export async function listExportApprovals() {
  return apiGet("/api/export-approvals");
}

export async function approveExport(id) {
  return apiPost(`/api/export-approvals/${encodeURIComponent(id)}/approve`, {});
}

export async function listEnterpriseArtifacts(type = "") {
  return apiGet(`/api/enterprise/artifacts${type ? `?type=${encodeURIComponent(type)}` : ""}`);
}

export async function saveEnterpriseArtifact(artifact) {
  return apiPost("/api/enterprise/artifacts", artifact);
}

export async function deleteEnterpriseArtifact(id) {
  return apiDelete(`/api/enterprise/artifacts/${encodeURIComponent(id)}`);
}

export async function listDetectionRules() {
  return apiGet("/api/detection-rules");
}

export async function saveDetectionRule(rule) {
  return apiPost("/api/detection-rules", rule);
}

export async function promoteDetectionRule(id, status = "production") {
  return apiPost(`/api/detection-rules/${encodeURIComponent(id)}/promote`, { status });
}

export async function backtestDetectionRule(id, labels = {}) {
  return apiPost(`/api/detection-rules/${encodeURIComponent(id)}/backtest`, { labels });
}

export async function deleteDetectionRule(id) {
  return apiDelete(`/api/detection-rules/${encodeURIComponent(id)}`);
}

export async function listCases() {
  return apiGet("/api/cases");
}

export async function saveCase(caseRecord) {
  return apiPost("/api/cases", caseRecord);
}

export async function deleteCase(id) {
  return apiDelete(`/api/cases/${encodeURIComponent(id)}`);
}

export async function listCaseAudit(id) {
  return apiGet(`/api/cases/${encodeURIComponent(id)}/audit`);
}

export async function exportInvestigationPackage(payload) {
  return apiPost("/api/exports/investigation", payload);
}

export async function exportSecurityLakeManifest(payload) {
  return apiPost("/api/exports/security-lake", payload);
}

export async function publishSecurityLake(payload = {}) {
  return apiPost("/api/security-lake/publish", payload);
}

export async function connectorCatalog() {
  return apiGet("/api/connectors/catalog");
}

export async function listConnectors() {
  return apiGet("/api/connectors");
}

export async function saveConnector(connector) {
  return apiPost("/api/connectors", connector);
}

export async function testConnector(id) {
  return apiPost(`/api/connectors/${encodeURIComponent(id)}/test`, {});
}

export async function deleteConnector(id) {
  return apiDelete(`/api/connectors/${encodeURIComponent(id)}`);
}

export async function listOrganizationAccounts() {
  return apiGet("/api/organization/accounts");
}

export async function discoverOrganizationAccounts() {
  return apiPost("/api/organization/discover", {});
}

export async function onboardOrganizationAccount(id, config) {
  return apiPost(`/api/organization/accounts/${encodeURIComponent(id)}/onboard`, config);
}

export async function listEvidenceUploads() {
  return apiGet("/api/evidence-uploads");
}

export async function createEvidenceUpload(metadata) {
  return apiPost("/api/evidence-uploads", metadata);
}

export async function completeEvidenceUpload(id, sha256) {
  return apiPost(`/api/evidence-uploads/${encodeURIComponent(id)}/complete`, { sha256 });
}

export async function uploadEvidenceFile(file, onProgress) {
  const sha256 = await browserSha256(file);
  const session = await createEvidenceUpload({ fileName: file.name, contentType: file.type || "application/octet-stream", contentLength: file.size, sha256 });
  if (onProgress) onProgress({ phase: "uploading", loaded: 0, total: file.size });
  const response = await fetch(session.uploadUrl, { method: "PUT", headers: session.requiredHeaders, body: file, mode: "cors" });
  if (!response.ok) throw new Error(`Evidence object upload failed (${response.status})`);
  if (onProgress) onProgress({ phase: "verifying", loaded: file.size, total: file.size });
  return completeEvidenceUpload(session.id, sha256);
}

export async function listAiInvestigations() {
  return apiGet("/api/ai/investigations");
}

export async function runAiInvestigation(payload) {
  return apiPost("/api/ai/investigate", payload);
}

export async function saveAiInvestigationFeedback(id, rating, comment = "") {
  return apiPost(`/api/ai/investigations/${encodeURIComponent(id)}/feedback`, { rating, comment });
}

export async function listRoleDefinitions() {
  return apiGet("/api/admin/roles");
}

export async function saveRoleDefinition(role) {
  return apiPost("/api/admin/roles", role);
}

export async function deleteRoleDefinition(id) {
  return apiDelete(`/api/admin/roles/${encodeURIComponent(id)}`);
}

export async function listServiceAccounts() {
  return apiGet("/api/admin/service-accounts");
}

export async function createServiceAccount(account) {
  return apiPost("/api/admin/service-accounts", account);
}

export async function rotateServiceAccount(id) {
  return apiPost(`/api/admin/service-accounts/${encodeURIComponent(id)}/rotate`, {});
}

export async function revokeServiceAccount(id) {
  return apiDelete(`/api/admin/service-accounts/${encodeURIComponent(id)}`);
}

export async function ingestS3(config) {
  return apiPost("/api/ingest/s3", config);
}

export async function ingestCloudWatch(config) {
  return apiPost("/api/ingest/cloudwatch", config);
}

export async function listJobs() {
  return apiGet("/api/jobs");
}

export async function createJob(job) {
  return apiPost("/api/jobs", job);
}

export async function runJob(id) {
  return apiPost(`/api/jobs/${encodeURIComponent(id)}/run`, {});
}

export async function runJobAsync(id) {
  return apiPost(`/api/jobs/${encodeURIComponent(id)}/run-async`, {});
}

export async function deleteJob(id) {
  return apiDelete(`/api/jobs/${encodeURIComponent(id)}`);
}

export async function listJobRuns() {
  return apiGet("/api/job-runs");
}

export async function listBackendRuns() {
  return apiGet("/api/runs");
}

export async function exportAuditNdjson() {
  const response = await fetch("/api/audit/export", { headers: authHeaders(), credentials: "same-origin" });
  if (!response.ok) throw new Error(await errorText(response));
  return response.text();
}

export async function listAuditEvents({ limit = 100, action = "", actor = "" } = {}) {
  const params = new URLSearchParams();
  params.set("limit", String(limit));
  if (action) params.set("action", action);
  if (actor) params.set("actor", actor);
  return apiGet(`/api/audit/events?${params.toString()}`);
}

export async function saveApiKey(key) {
  const value = String(key || "").trim();
  if (!value) {
    await clearCredentials();
    return null;
  }
  const response = await fetch("/api/auth/api-key-session", {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ apiKey: value })
  });
  if (!response.ok) throw new Error(await errorText(response));
  const session = await response.json();
  saveSessionMetadata(session);
  return session;
}

export function getApiKey() {
  return "";
}

export function storageSessionBinding() {
  const csrf = sessionStorage.getItem("ndrFlowConsole.csrf") || "";
  const expiresAt = sessionStorage.getItem("ndrFlowConsole.sessionExpiresAt") || "";
  return csrf && expiresAt ? `${csrf}.${expiresAt}` : "";
}

export async function clearCredentials() {
  await fetch("/api/auth/logout", { method: "POST", headers: authHeaders(), credentials: "same-origin" }).catch(() => {});
  localStorage.removeItem("ndrFlowConsole.apiKey");
  localStorage.removeItem("ndrFlowConsole.oidcToken");
  localStorage.removeItem("ndrFlowConsole.oidcExpiresAt");
  localStorage.removeItem("ndrFlowConsole.oidcState");
  localStorage.removeItem("ndrFlowConsole.oidcVerifier");
  sessionStorage.removeItem("ndrFlowConsole.csrf");
  sessionStorage.removeItem("ndrFlowConsole.sessionExpiresAt");
  sessionStorage.removeItem("ndrFlowConsole.oidcToken");
  sessionStorage.removeItem("ndrFlowConsole.oidcExpiresAt");
  sessionStorage.removeItem("ndrFlowConsole.oidcState");
  sessionStorage.removeItem("ndrFlowConsole.oidcVerifier");
}

export async function beginSsoLogin(config) {
  if (!config?.enabled || !config.authorizationEndpoint || !config.clientId) {
    throw new Error("SSO is not configured on this backend.");
  }
  const redirectUri = config.redirectUri || `${window.location.origin}${window.location.pathname}`;
  const state = randomString();
  const verifier = randomString(64);
  const challenge = await pkceChallenge(verifier);
  sessionStorage.setItem("ndrFlowConsole.oidcState", state);
  sessionStorage.setItem("ndrFlowConsole.oidcVerifier", verifier);
  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: redirectUri,
    scope: config.scopes || "openid profile email",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });
  window.location.assign(`${config.authorizationEndpoint}?${params.toString()}`);
}

export async function completeSsoCallback() {
  const url = new URL(window.location.href);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code) return null;
  const expectedState = sessionStorage.getItem("ndrFlowConsole.oidcState") || localStorage.getItem("ndrFlowConsole.oidcState");
  const verifier = sessionStorage.getItem("ndrFlowConsole.oidcVerifier") || localStorage.getItem("ndrFlowConsole.oidcVerifier");
  if (!state || state !== expectedState || !verifier) {
    throw new Error("SSO callback validation failed.");
  }
  const redirectUri = `${window.location.origin}${window.location.pathname}`;
  const response = await fetch("/api/auth/token", {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ code, codeVerifier: verifier, redirectUri })
  });
  if (!response.ok) throw new Error(await errorText(response));
  const session = await response.json();
  saveSessionMetadata(session);
  localStorage.removeItem("ndrFlowConsole.oidcToken");
  localStorage.removeItem("ndrFlowConsole.oidcExpiresAt");
  sessionStorage.removeItem("ndrFlowConsole.oidcState");
  sessionStorage.removeItem("ndrFlowConsole.oidcVerifier");
  localStorage.removeItem("ndrFlowConsole.oidcState");
  localStorage.removeItem("ndrFlowConsole.oidcVerifier");
  url.searchParams.delete("code");
  url.searchParams.delete("state");
  url.searchParams.delete("session_state");
  window.history.replaceState({}, document.title, `${url.pathname}${url.search}${url.hash}`);
  return session;
}

async function apiGet(path) {
  const response = await fetch(path, { headers: authHeaders(), credentials: "same-origin" });
  if (!response.ok) throw new Error(await errorText(response));
  return response.json();
}

async function apiPost(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...authHeaders() },
    credentials: "same-origin",
    body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error(await errorText(response));
  return response.json();
}

async function apiDelete(path) {
  const response = await fetch(path, { method: "DELETE", headers: authHeaders(), credentials: "same-origin" });
  if (!response.ok) throw new Error(await errorText(response));
  return response.json();
}

function authHeaders() {
  const csrf = sessionStorage.getItem("ndrFlowConsole.csrf");
  return csrf ? { "x-ndr-csrf": csrf } : {};
}

async function browserSha256(file) {
  const bytes = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function saveSessionMetadata(session) {
  if (session?.csrf) sessionStorage.setItem("ndrFlowConsole.csrf", session.csrf);
  if (session?.expiresAt) sessionStorage.setItem("ndrFlowConsole.sessionExpiresAt", session.expiresAt);
}

function randomString(bytes = 32) {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  return base64Url(buffer);
}

async function pkceChallenge(verifier) {
  const bytes = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return base64Url(new Uint8Array(digest));
}

function base64Url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function errorText(response) {
  try {
    const body = await response.json();
    return body.error || response.statusText;
  } catch {
    return response.statusText;
  }
}
