import { createVerify, createPublicKey } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { createServer } from "node:http";
import { mkdir, readFile, writeFile, stat } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { extname, join, resolve } from "node:path";
import { createSignedAwsRequest } from "./src/aws-sigv4.mjs";

const PORT = Number(process.env.PORT || 4173);
const HOST = process.env.HOST || "0.0.0.0";
const ROOT = resolve(".");
const DATA_DIR = resolve(process.env.NDR_DATA_DIR || join(ROOT, ".ndr-data"));
const JOBS_FILE = join(DATA_DIR, "jobs.json");
const RUNS_FILE = join(DATA_DIR, "ingest-runs.json");
const WORKSPACES_FILE = join(DATA_DIR, "workspaces.json");
const CASES_FILE = join(DATA_DIR, "cases.json");
const EVIDENCE_FILE = join(DATA_DIR, "evidence-runs.json");
const SOURCES_FILE = join(DATA_DIR, "sources.json");
const AUDIT_FILE = join(DATA_DIR, "audit.ndjson");
const MAX_BODY_BYTES = Number(process.env.NDR_MAX_BODY_BYTES || 1024 * 1024);
const RATE_LIMIT_WINDOW_MS = Number(process.env.NDR_RATE_LIMIT_WINDOW_MS || 60_000);
const RATE_LIMIT_MAX = Number(process.env.NDR_RATE_LIMIT_MAX || 120);
const API_KEY = process.env.NDR_API_KEY || "";
const RETAIN_RUNS = Number(process.env.NDR_RETAIN_RUNS || 50);
const STORE_MODE = process.env.NDR_STORE || "local";
const DDB_TABLE = process.env.NDR_DDB_TABLE || "";
const DDB_REGION = process.env.NDR_DDB_REGION || process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || "us-east-1";
const AUDIT_RETENTION_DAYS = Number(process.env.NDR_AUDIT_RETENTION_DAYS || 2555);
const BEDROCK_ENABLED = process.env.NDR_BEDROCK_ENABLED === "true";
const BEDROCK_REGION = process.env.NDR_BEDROCK_REGION || process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || "us-east-1";
const BEDROCK_MODEL_ID = process.env.NDR_BEDROCK_MODEL_ID || "anthropic.claude-3-haiku-20240307-v1:0";
const BEDROCK_MAX_TOKENS = Number(process.env.NDR_BEDROCK_MAX_TOKENS || 900);
const BEDROCK_TEMPERATURE = Number(process.env.NDR_BEDROCK_TEMPERATURE || 0.2);
const BEDROCK_MAX_CONTEXT_CHARS = Number(process.env.NDR_BEDROCK_MAX_CONTEXT_CHARS || 24000);
const OIDC_ISSUER = process.env.NDR_OIDC_ISSUER || "";
const OIDC_AUDIENCE = process.env.NDR_OIDC_AUDIENCE || "";
const OIDC_JWKS_URI = process.env.NDR_OIDC_JWKS_URI || "";
const OIDC_CLIENT_ID = process.env.NDR_OIDC_CLIENT_ID || "";
const OIDC_CLIENT_SECRET = process.env.NDR_OIDC_CLIENT_SECRET || "";
const OIDC_REDIRECT_URI = process.env.NDR_OIDC_REDIRECT_URI || "";
const OIDC_SCOPES = process.env.NDR_OIDC_SCOPES || "openid profile email groups";
const ADMIN_GROUP = process.env.NDR_ADMIN_GROUP || "ndr-admin";
const ANALYST_GROUP = process.env.NDR_ANALYST_GROUP || "ndr-analyst";
const VIEWER_GROUP = process.env.NDR_VIEWER_GROUP || "ndr-viewer";
const DEFAULT_TENANT = process.env.NDR_DEFAULT_TENANT || "default";
const TENANT_CLAIM = process.env.NDR_TENANT_CLAIM || "tenant_id";
const TEST_AUTH_ENABLED = process.env.NDR_TEST_AUTH_ENABLED === "true";
const PUBLIC_API_PATHS = new Set(["/api/health", "/api/ready", "/api/metrics", "/api/auth/config", "/api/auth/token", "/api/ai/config"]);
const METRICS = {
  startedAt: new Date().toISOString(),
  requests: 0,
  errors: 0,
  ingestRuns: 0,
  jobsRun: 0
};

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png"
};

const activeIntervals = new Map();
const rateBuckets = new Map();
let jwksCache = { expiresAt: 0, keys: [] };
let oidcDiscoveryCache = { expiresAt: 0, value: null };

await mkdir(DATA_DIR, { recursive: true });
if (STORE_MODE === "local") {
  await ensureJsonFile(JOBS_FILE, []);
  await ensureJsonFile(RUNS_FILE, []);
  await ensureJsonFile(WORKSPACES_FILE, []);
  await ensureJsonFile(CASES_FILE, []);
  await ensureJsonFile(EVIDENCE_FILE, []);
  await ensureJsonFile(SOURCES_FILE, []);
  await ensureTextFile(AUDIT_FILE, "");
}
await restoreSchedules();

createServer(async (req, res) => {
  const started = Date.now();
  try {
    applySecurityHeaders(res);
    if (!checkRateLimit(req, res)) return;
    if (req.url.startsWith("/api/")) {
      if (!(await authorize(req, res))) return;
      await routeApi(req, res);
    } else {
      await serveStatic(req, res);
    }
  } catch (error) {
    METRICS.errors += 1;
    sendJson(res, 500, { error: error.message || "Server error" });
  } finally {
    METRICS.requests += 1;
    logRequest(req, res, Date.now() - started);
  }
}).listen(PORT, HOST, () => {
  logInfo("server_started", { host: HOST, port: PORT, dataDir: DATA_DIR, apiKeyRequired: Boolean(API_KEY) });
});

async function routeApi(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (req.method === "GET" && url.pathname === "/api/health") {
    sendJson(res, 200, {
      ok: true,
      authMode: OIDC_ISSUER ? "oidc" : API_KEY ? "api-key" : "none",
      oidcConfigured: Boolean(OIDC_ISSUER && OIDC_CLIENT_ID),
      awsConfigured: hasAwsCredentialProvider(),
      bedrockEnabled: BEDROCK_ENABLED,
      storeMode: STORE_MODE,
      tenantDefault: DEFAULT_TENANT,
      time: new Date().toISOString()
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/ready") {
    sendJson(res, 200, {
      ok: true,
      dataDir: DATA_DIR,
      storeMode: STORE_MODE,
      jobsFile: STORE_MODE === "local" ? await fileExists(JOBS_FILE) : undefined,
      runsFile: STORE_MODE === "local" ? await fileExists(RUNS_FILE) : undefined,
      dynamoConfigured: STORE_MODE === "dynamodb" ? Boolean(DDB_TABLE) : undefined,
      auditRetentionDays: AUDIT_RETENTION_DAYS,
      oidcEnabled: Boolean(OIDC_ISSUER && OIDC_CLIENT_ID),
      bedrockEnabled: BEDROCK_ENABLED,
      bedrockModelId: BEDROCK_ENABLED ? BEDROCK_MODEL_ID : undefined,
      tenantClaim: TENANT_CLAIM
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/metrics") {
    sendMetrics(res);
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/auth/config") {
    sendJson(res, 200, await authConfig());
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/auth/token") {
    const body = await readJson(req);
    const result = await exchangeOidcCode(body);
    sendJson(res, 200, result);
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/auth/me") {
    sendJson(res, 200, { principal: req.principal });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/workspaces") {
    if (!requireRole(req, res, ["admin", "analyst", "viewer"])) return;
    sendJson(res, 200, await listTenantObjects("WORKSPACE", req.principal.tenantId, WORKSPACES_FILE));
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/workspaces") {
    if (!requireRole(req, res, ["admin", "analyst"])) return;
    const body = await readJson(req);
    const workspace = normalizeWorkspace(body, req.principal);
    await putTenantObject("WORKSPACE", workspace.id, workspace, req.principal.tenantId, WORKSPACES_FILE);
    await appendAudit("workspace.saved", { workspaceId: workspace.id, name: workspace.name, tenantId: req.principal.tenantId }, req.principal);
    sendJson(res, body.id ? 200 : 201, workspace);
    return;
  }

  if (req.method === "DELETE" && url.pathname.startsWith("/api/workspaces/")) {
    if (!requireRole(req, res, ["admin"])) return;
    const id = decodeURIComponent(url.pathname.split("/").pop());
    await deleteTenantObject("WORKSPACE", id, req.principal.tenantId, WORKSPACES_FILE);
    await appendAudit("workspace.deleted", { workspaceId: id, tenantId: req.principal.tenantId }, req.principal);
    sendJson(res, 200, { ok: true });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/evidence-runs") {
    if (!requireRole(req, res, ["admin", "analyst", "viewer"])) return;
    sendJson(res, 200, await listTenantObjects("EVIDENCE", req.principal.tenantId, EVIDENCE_FILE, 50));
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/evidence-runs") {
    if (!requireRole(req, res, ["admin", "analyst"])) return;
    const body = await readJson(req);
    const run = normalizeEvidenceRun(body, req.principal);
    await putTenantObject("EVIDENCE", run.id, run, req.principal.tenantId, EVIDENCE_FILE);
    await appendAudit("evidence.saved", { evidenceRunId: run.id, fileName: run.fileName, records: run.recordCount, tenantId: req.principal.tenantId }, req.principal);
    sendJson(res, 201, run);
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/sources") {
    if (!requireRole(req, res, ["admin", "analyst", "viewer"])) return;
    sendJson(res, 200, await listTenantObjects("SOURCE", req.principal.tenantId, SOURCES_FILE));
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/sources") {
    if (!requireRole(req, res, ["admin", "analyst"])) return;
    const body = await readJson(req);
    const source = normalizeSource(body, req.principal);
    await putTenantObject("SOURCE", source.id, source, req.principal.tenantId, SOURCES_FILE);
    await appendAudit("source.saved", { sourceId: source.id, name: source.name, type: source.type, tenantId: req.principal.tenantId }, req.principal);
    sendJson(res, body.id ? 200 : 201, source);
    return;
  }

  if (req.method === "DELETE" && url.pathname.startsWith("/api/sources/")) {
    if (!requireRole(req, res, ["admin"])) return;
    const id = decodeURIComponent(url.pathname.split("/").pop());
    await deleteTenantObject("SOURCE", id, req.principal.tenantId, SOURCES_FILE);
    await appendAudit("source.deleted", { sourceId: id, tenantId: req.principal.tenantId }, req.principal);
    sendJson(res, 200, { ok: true });
    return;
  }

  if (req.method === "POST" && url.pathname.startsWith("/api/sources/") && url.pathname.endsWith("/ingest")) {
    if (!requireRole(req, res, ["admin", "analyst"])) return;
    const id = decodeURIComponent(url.pathname.split("/").at(-2));
    const source = await getTenantObject("SOURCE", id, req.principal.tenantId, SOURCES_FILE);
    if (!source) {
      sendJson(res, 404, { error: "Managed source not found" });
      return;
    }
    const result = await ingestManagedSource(source);
    await appendRun({ ...result, tenantId: req.principal.tenantId, sourceId: source.id, sourceName: source.name });
    await appendAudit("source.ingest.completed", { sourceId: source.id, name: source.name, source: result.source, tenantId: req.principal.tenantId }, req.principal);
    sendJson(res, 200, result);
    return;
  }

  if (req.method === "POST" && url.pathname.startsWith("/api/sources/") && url.pathname.endsWith("/jobs")) {
    if (!requireRole(req, res, ["admin", "analyst"])) return;
    const id = decodeURIComponent(url.pathname.split("/").at(-2));
    const body = await readJson(req);
    const source = await getTenantObject("SOURCE", id, req.principal.tenantId, SOURCES_FILE);
    if (!source) {
      sendJson(res, 404, { error: "Managed source not found" });
      return;
    }
    const ingestConfig = managedSourceIngestConfig(source);
    const job = {
      id: String(Date.now()),
      tenantId: req.principal.tenantId,
      sourceId: source.id,
      name: body.name || `${source.name} ingest`,
      type: ingestConfig.type,
      intervalMinutes: Math.max(5, Number(body.intervalMinutes || source.intervalMinutes || 15)),
      enabled: body.enabled !== false,
      config: ingestConfig.config,
      lastRun: null,
      lastStatus: "never",
      createdAt: new Date().toISOString()
    };
    await putJob(job);
    await appendAudit("source.job.created", { jobId: job.id, sourceId: source.id, type: job.type, tenantId: req.principal.tenantId }, req.principal);
    scheduleJob(job);
    sendJson(res, 201, job);
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/cases") {
    if (!requireRole(req, res, ["admin", "analyst", "viewer"])) return;
    sendJson(res, 200, await listTenantObjects("CASE", req.principal.tenantId, CASES_FILE));
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/cases") {
    if (!requireRole(req, res, ["admin", "analyst"])) return;
    const body = await readJson(req);
    const caseRecord = await normalizeCase(body, req.principal);
    await putTenantObject("CASE", caseRecord.id, caseRecord, req.principal.tenantId, CASES_FILE);
    await appendAudit(body.id ? "case.updated" : "case.created", { caseId: caseRecord.id, title: caseRecord.title, tenantId: req.principal.tenantId }, req.principal);
    sendJson(res, body.id ? 200 : 201, caseRecord);
    return;
  }

  if (req.method === "GET" && url.pathname.startsWith("/api/cases/") && url.pathname.endsWith("/audit")) {
    if (!requireRole(req, res, ["admin", "analyst", "viewer"])) return;
    const id = decodeURIComponent(url.pathname.split("/").at(-2));
    const caseRecord = await getTenantObject("CASE", id, req.principal.tenantId, CASES_FILE);
    if (!caseRecord) {
      sendJson(res, 404, { error: "Case not found" });
      return;
    }
    sendJson(res, 200, caseRecord.audit || []);
    return;
  }

  if (req.method === "DELETE" && url.pathname.startsWith("/api/cases/")) {
    if (!requireRole(req, res, ["admin"])) return;
    const id = decodeURIComponent(url.pathname.split("/").pop());
    await deleteTenantObject("CASE", id, req.principal.tenantId, CASES_FILE);
    await appendAudit("case.deleted", { caseId: id, tenantId: req.principal.tenantId }, req.principal);
    sendJson(res, 200, { ok: true });
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/exports/investigation") {
    if (!requireRole(req, res, ["admin", "analyst"])) return;
    const body = await readJson(req);
    const exported = {
      ...body,
      tenantId: req.principal.tenantId,
      exportedBy: req.principal.email || req.principal.name || req.principal.subject || "unknown",
      exportedAt: new Date().toISOString()
    };
    await appendAudit("investigation.exported", { workspace: body.workspace?.name || body.source || "current", tenantId: req.principal.tenantId }, req.principal);
    sendJson(res, 200, exported);
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/ai/config") {
    sendJson(res, 200, aiConfig());
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/ai/ask") {
    if (!requireRole(req, res, ["admin", "analyst"])) return;
    if (!BEDROCK_ENABLED) {
      sendJson(res, 403, { error: "AWS Bedrock AI is disabled. Set NDR_BEDROCK_ENABLED=true on the backend to enable it." });
      return;
    }
    const body = await readJson(req);
    const result = await askBedrock(body);
    await appendAudit("ai.bedrock.invoked", { mode: body.mode || "answer", modelId: BEDROCK_MODEL_ID, tenantId: req.principal.tenantId }, req.principal);
    sendJson(res, 200, result);
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/ingest/s3") {
    if (!requireRole(req, res, ["admin", "analyst"])) return;
    const body = await readJson(req);
    const result = await ingestS3(body);
    await appendRun({ ...result, tenantId: req.principal.tenantId });
    await appendAudit("ingest.s3.completed", { sourceLabel: result.sourceLabel, objectCount: result.objectCount, tenantId: req.principal.tenantId }, req.principal);
    sendJson(res, 200, result);
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/ingest/cloudwatch") {
    if (!requireRole(req, res, ["admin", "analyst"])) return;
    const body = await readJson(req);
    const result = await ingestCloudWatch(body);
    await appendRun({ ...result, tenantId: req.principal.tenantId });
    await appendAudit("ingest.cloudwatch.completed", { sourceLabel: result.sourceLabel, eventCount: result.eventCount, tenantId: req.principal.tenantId }, req.principal);
    sendJson(res, 200, result);
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/jobs") {
    if (!requireRole(req, res, ["admin", "analyst", "viewer"])) return;
    sendJson(res, 200, filterTenant(await listJobs(), req.principal.tenantId));
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/jobs") {
    if (!requireRole(req, res, ["admin", "analyst"])) return;
    const body = await readJson(req);
    const job = {
      id: String(Date.now()),
      tenantId: req.principal.tenantId,
      name: body.name || `${body.type || "ingest"} job`,
      type: body.type,
      intervalMinutes: Math.max(5, Number(body.intervalMinutes || 15)),
      enabled: body.enabled !== false,
      config: body.config || {},
      lastRun: null,
      lastStatus: "never",
      createdAt: new Date().toISOString()
    };
    await putJob(job);
    await appendAudit("job.created", { jobId: job.id, name: job.name, type: job.type }, req.principal);
    scheduleJob(job);
    sendJson(res, 201, job);
    return;
  }

  if (req.method === "DELETE" && url.pathname.startsWith("/api/jobs/")) {
    if (!requireRole(req, res, ["admin"])) return;
    const id = decodeURIComponent(url.pathname.split("/").pop());
    const job = (await listJobs()).find((item) => item.id === id && sameTenant(item, req.principal.tenantId));
    if (!job) {
      sendJson(res, 404, { error: "Job not found" });
      return;
    }
    await deleteJob(id);
    await appendAudit("job.deleted", { jobId: id, tenantId: req.principal.tenantId }, req.principal);
    clearInterval(activeIntervals.get(id));
    activeIntervals.delete(id);
    sendJson(res, 200, { ok: true });
    return;
  }

  if (req.method === "POST" && url.pathname.startsWith("/api/jobs/") && url.pathname.endsWith("/run")) {
    if (!requireRole(req, res, ["admin", "analyst"])) return;
    const id = decodeURIComponent(url.pathname.split("/").at(-2));
    const jobs = await listJobs();
    const job = jobs.find((item) => item.id === id && sameTenant(item, req.principal.tenantId));
    if (!job) {
      sendJson(res, 404, { error: "Job not found" });
      return;
    }
    const result = await runJob(job);
    sendJson(res, 200, result);
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/runs") {
    if (!requireRole(req, res, ["admin", "analyst", "viewer"])) return;
    sendJson(res, 200, filterTenant(await listRuns(), req.principal.tenantId));
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/audit/export") {
    if (!requireRole(req, res, ["admin"])) return;
    await appendAudit("audit.exported", { format: "ndjson" }, req.principal);
    const audit = filterTenant(await listAudit(), req.principal.tenantId);
    res.statusCode = 200;
    res.writeHead(200, {
      "content-type": "application/x-ndjson; charset=utf-8",
      "content-disposition": `attachment; filename="ndr-audit-${new Date().toISOString().slice(0, 10)}.ndjson"`
    });
    res.end(audit.map((entry) => JSON.stringify(entry)).join("\n") + "\n");
    return;
  }

  sendJson(res, 404, { error: "Not found" });
}

function applySecurityHeaders(res) {
  res.setHeader("x-content-type-options", "nosniff");
  res.setHeader("x-frame-options", "DENY");
  res.setHeader("referrer-policy", "no-referrer");
  res.setHeader("permissions-policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("content-security-policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
}

async function authorize(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (PUBLIC_API_PATHS.has(url.pathname)) {
    req.principal = { subject: "public", roles: ["viewer"], authType: "public", tenantId: DEFAULT_TENANT };
    return true;
  }
  if (TEST_AUTH_ENABLED && req.headers["x-ndr-test-principal"]) {
    req.principal = normalizePrincipal(JSON.parse(String(req.headers["x-ndr-test-principal"])), "test");
    return true;
  }
  if (API_KEY && req.headers["x-ndr-api-key"] === API_KEY) {
    req.principal = { subject: "api-key", roles: ["admin"], authType: "api-key", tenantId: DEFAULT_TENANT };
    return true;
  }
  const bearer = parseBearer(req.headers.authorization);
  if (bearer && OIDC_ISSUER) {
    try {
      req.principal = await verifyOidcToken(bearer);
      return true;
    } catch (error) {
      sendJson(res, 401, { error: `Invalid OIDC token: ${error.message}` });
      return false;
    }
  }
  if (!API_KEY && !OIDC_ISSUER) {
    req.principal = { subject: "local-dev", roles: ["admin"], authType: "none", tenantId: DEFAULT_TENANT };
    return true;
  }
  sendJson(res, 401, { error: OIDC_ISSUER ? "Bearer token required" : "API key required" });
  return false;
}

async function authConfig() {
  if (!OIDC_ISSUER || !OIDC_CLIENT_ID) {
    return {
      enabled: false,
      authMode: API_KEY ? "api-key" : "local-dev",
      roles: { admin: ADMIN_GROUP, analyst: ANALYST_GROUP, viewer: VIEWER_GROUP },
      defaultTenant: DEFAULT_TENANT,
      tenantClaim: TENANT_CLAIM
    };
  }
  const discovery = await getOidcDiscovery();
  return {
    enabled: true,
    authMode: "oidc",
    issuer: OIDC_ISSUER,
    audience: OIDC_AUDIENCE,
    clientId: OIDC_CLIENT_ID,
    redirectUri: OIDC_REDIRECT_URI,
    scopes: OIDC_SCOPES,
    authorizationEndpoint: discovery.authorization_endpoint,
    tokenEndpoint: "/api/auth/token",
    roles: { admin: ADMIN_GROUP, analyst: ANALYST_GROUP, viewer: VIEWER_GROUP },
    defaultTenant: DEFAULT_TENANT,
    tenantClaim: TENANT_CLAIM
  };
}

async function exchangeOidcCode({ code, codeVerifier, redirectUri }) {
  if (!OIDC_ISSUER || !OIDC_CLIENT_ID) {
    throw new Error("OIDC login is not configured");
  }
  if (!code || !codeVerifier) {
    throw new Error("Authorization code and PKCE verifier are required");
  }
  const discovery = await getOidcDiscovery();
  const tokenRedirectUri = redirectUri || OIDC_REDIRECT_URI;
  if (!tokenRedirectUri) throw new Error("OIDC redirect URI is required");
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: tokenRedirectUri,
    client_id: OIDC_CLIENT_ID,
    code_verifier: codeVerifier
  });
  const headers = { "content-type": "application/x-www-form-urlencoded" };
  if (OIDC_CLIENT_SECRET) {
    headers.authorization = `Basic ${Buffer.from(`${OIDC_CLIENT_ID}:${OIDC_CLIENT_SECRET}`).toString("base64")}`;
  }
  const response = await fetch(discovery.token_endpoint, { method: "POST", headers, body: form });
  const tokens = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(tokens.error_description || tokens.error || `OIDC token exchange failed ${response.status}`);
  }
  const tokenForPrincipal = tokens.id_token || tokens.access_token;
  const principal = tokenForPrincipal ? await verifyOidcToken(tokenForPrincipal) : null;
  await appendAudit("auth.login", { authType: "oidc" }, principal || { subject: "oidc-user", roles: ["viewer"], tenantId: DEFAULT_TENANT });
  return {
    accessToken: tokens.access_token || "",
    idToken: tokens.id_token || "",
    tokenType: tokens.token_type || "Bearer",
    expiresIn: tokens.expires_in || 3600,
    principal
  };
}

async function getOidcDiscovery() {
  if (!OIDC_ISSUER) throw new Error("OIDC issuer is not configured");
  if (Date.now() < oidcDiscoveryCache.expiresAt && oidcDiscoveryCache.value) return oidcDiscoveryCache.value;
  const response = await fetch(`${OIDC_ISSUER.replace(/\/$/, "")}/.well-known/openid-configuration`);
  if (!response.ok) throw new Error(`OIDC discovery failed ${response.status}`);
  const value = await response.json();
  oidcDiscoveryCache = { expiresAt: Date.now() + 10 * 60 * 1000, value };
  return value;
}

function aiConfig() {
  return {
    enabled: BEDROCK_ENABLED,
    provider: "aws-bedrock",
    region: BEDROCK_REGION,
    modelId: BEDROCK_ENABLED ? BEDROCK_MODEL_ID : "",
    maxTokens: BEDROCK_MAX_TOKENS,
    maxContextChars: BEDROCK_MAX_CONTEXT_CHARS,
    modes: ["answer", "summary"]
  };
}

async function askBedrock({ question = "", mode = "answer", context = {} }) {
  const normalizedMode = mode === "summary" ? "summary" : "answer";
  const normalizedQuestion = String(question || "").trim();
  if (normalizedMode === "answer" && normalizedQuestion.length < 3) {
    throw new Error("Ask a question with at least 3 characters.");
  }
  if (normalizedQuestion.length > 2000) {
    throw new Error("Question is too long. Keep it under 2,000 characters.");
  }
  requireAws(BEDROCK_REGION);
  const evidenceContext = truncateText(JSON.stringify(context || {}, null, 2), BEDROCK_MAX_CONTEXT_CHARS);
  const prompt =
    normalizedMode === "summary"
      ? `Create a concise NDR investigation summary from this evidence. Include: executive readout, highest-risk entities, likely tactics, analyst next actions, and caveats. Evidence JSON:\n${evidenceContext}`
      : `Answer the analyst question using only the provided NDR evidence. If the evidence is insufficient, say what is missing and suggest the next query or ingest action.\n\nQuestion:\n${normalizedQuestion}\n\nEvidence JSON:\n${evidenceContext}`;
  const payload = {
    system: [
      {
        text: "You are an expert Network Detection and Response analyst. Be concise, evidence-grounded, and operational. Do not invent facts, identities, malware names, or cloud resources not present in evidence. Use markdown bullets when useful."
      }
    ],
    messages: [
      {
        role: "user",
        content: [{ text: prompt }]
      }
    ],
    inferenceConfig: {
      maxTokens: BEDROCK_MAX_TOKENS,
      temperature: BEDROCK_TEMPERATURE
    }
  };
  const response = await awsRequest({
    service: "bedrock",
    region: BEDROCK_REGION,
    method: "POST",
    host: `bedrock-runtime.${BEDROCK_REGION}.amazonaws.com`,
    path: `/model/${encodeURIComponent(BEDROCK_MODEL_ID)}/converse`,
    headers: {
      accept: "application/json",
      "content-type": "application/json"
    },
    body: JSON.stringify(payload)
  });
  const body = JSON.parse(response.body || "{}");
  const answer = (body.output?.message?.content || [])
    .map((item) => item.text || "")
    .filter(Boolean)
    .join("\n")
    .trim();
  if (!answer) throw new Error("Bedrock returned an empty response.");
  return {
    answer,
    mode: normalizedMode,
    modelId: BEDROCK_MODEL_ID,
    region: BEDROCK_REGION,
    stopReason: body.stopReason || "",
    usage: body.usage || {}
  };
}

function truncateText(text, maxChars) {
  const value = String(text || "");
  if (value.length <= maxChars) return value;
  return `${value.slice(0, maxChars)}\n...truncated to ${maxChars} characters...`;
}

function requireRole(req, res, allowed) {
  const roles = req.principal?.roles || [];
  if (allowed.some((role) => roles.includes(role))) {
    return true;
  }
  sendJson(res, 403, { error: "Insufficient role", required: allowed, roles });
  return false;
}

function parseBearer(header = "") {
  const match = String(header).match(/^Bearer\s+(.+)$/i);
  return match?.[1] || "";
}

async function verifyOidcToken(token) {
  const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
  if (!encodedHeader || !encodedPayload || !encodedSignature) throw new Error("Malformed token");
  const header = JSON.parse(base64UrlDecode(encodedHeader).toString("utf8"));
  const payload = JSON.parse(base64UrlDecode(encodedPayload).toString("utf8"));
  if (header.alg !== "RS256") throw new Error("Only RS256 is supported");
  if (OIDC_ISSUER && payload.iss !== OIDC_ISSUER) throw new Error("Issuer mismatch");
  if (OIDC_AUDIENCE) {
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!audiences.includes(OIDC_AUDIENCE)) throw new Error("Audience mismatch");
  }
  if (payload.exp && Date.now() >= payload.exp * 1000) throw new Error("Token expired");
  if (payload.nbf && Date.now() < payload.nbf * 1000) throw new Error("Token not active");
  const jwk = (await getJwks()).find((key) => key.kid === header.kid);
  if (!jwk) throw new Error("Signing key not found");
  const publicKey = createPublicKey({ key: jwk, format: "jwk" });
  const verifier = createVerify("RSA-SHA256");
  verifier.update(`${encodedHeader}.${encodedPayload}`);
  verifier.end();
  if (!verifier.verify(publicKey, base64UrlDecode(encodedSignature))) throw new Error("Signature mismatch");
  return {
    subject: payload.sub,
    email: payload.email,
    name: payload.name || payload.preferred_username || payload.email || payload.sub,
    roles: rolesFromClaims(payload),
    authType: "oidc",
    tenantId: tenantFromClaims(payload)
  };
}

function normalizePrincipal(value = {}, authType = "test") {
  const roles = Array.isArray(value.roles) && value.roles.length ? value.roles : ["viewer"];
  return {
    subject: value.subject || value.sub || "test-user",
    email: value.email || "",
    name: value.name || value.email || value.subject || "Test User",
    roles,
    authType: value.authType || authType,
    tenantId: sanitizeTenantId(value.tenantId || value.tenant || DEFAULT_TENANT)
  };
}

function tenantFromClaims(payload) {
  return sanitizeTenantId(
    payload[TENANT_CLAIM] ||
      payload.tenant_id ||
      payload.org_id ||
      payload.organization ||
      payload["custom:tenant_id"] ||
      DEFAULT_TENANT
  );
}

function sanitizeTenantId(value) {
  return String(value || DEFAULT_TENANT)
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || DEFAULT_TENANT;
}

async function getJwks() {
  if (Date.now() < jwksCache.expiresAt && jwksCache.keys.length) return jwksCache.keys;
  const jwksUri = OIDC_JWKS_URI || (await getOidcDiscovery()).jwks_uri;
  if (!jwksUri) throw new Error("JWKS URI not configured");
  const response = await fetch(jwksUri);
  if (!response.ok) throw new Error(`JWKS fetch failed ${response.status}`);
  const body = await response.json();
  jwksCache = { expiresAt: Date.now() + 10 * 60 * 1000, keys: body.keys || [] };
  return jwksCache.keys;
}

function rolesFromClaims(payload) {
  const raw = new Set([
    ...claimValues(payload.groups),
    ...claimValues(payload.roles),
    ...claimValues(payload["cognito:groups"]),
    ...claimValues(payload.realm_access?.roles)
  ]);
  const roles = new Set();
  if (raw.has(ADMIN_GROUP)) roles.add("admin");
  if (raw.has(ANALYST_GROUP)) roles.add("analyst");
  if (raw.has(VIEWER_GROUP)) roles.add("viewer");
  if (!roles.size) roles.add("viewer");
  return [...roles];
}

function claimValues(value) {
  if (Array.isArray(value)) return value;
  if (typeof value === "string") return [value];
  return [];
}

function base64UrlDecode(value) {
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function checkRateLimit(req, res) {
  const key = req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const bucket = rateBuckets.get(key) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
  if (now > bucket.resetAt) {
    bucket.count = 0;
    bucket.resetAt = now + RATE_LIMIT_WINDOW_MS;
  }
  bucket.count += 1;
  rateBuckets.set(key, bucket);
  if (bucket.count > RATE_LIMIT_MAX) {
    sendJson(res, 429, { error: "Rate limit exceeded" });
    return false;
  }
  return true;
}

async function ingestS3({ region, bucket, prefix = "", maxObjects = 10 }) {
  requireAws(region);
  if (!bucket) throw new Error("S3 bucket is required");
  const listed = await awsRequest({
    service: "s3",
    region,
    method: "GET",
    host: `${bucket}.s3.${region}.amazonaws.com`,
    path: "/",
    query: { "list-type": "2", prefix, "max-keys": String(Math.min(Number(maxObjects) || 10, 50)) }
  });
  const keys = [...listed.body.matchAll(/<Key>(.*?)<\/Key>/g)].map((match) => decodeXml(match[1]));
  const texts = [];
  for (const key of keys) {
    const object = await awsRequest({
      service: "s3",
      region,
      method: "GET",
      host: `${bucket}.s3.${region}.amazonaws.com`,
      path: `/${encodePath(key)}`
    });
    const raw = Buffer.from(object.raw);
    const text = key.endsWith(".gz") ? await gunzipText(raw) : raw.toString("utf8");
    texts.push(text);
  }
  return {
    source: "s3",
    sourceLabel: `s3://${bucket}/${prefix}`,
    objectCount: keys.length,
    text: texts.join("\n"),
    importedAt: new Date().toISOString()
  };
}

async function ingestCloudWatch({ region, logGroupName, filterPattern = "", startTime, endTime, limit = 1000 }) {
  requireAws(region);
  if (!logGroupName) throw new Error("CloudWatch log group is required");
  const payload = {
    logGroupName,
    filterPattern,
    limit: Math.min(Number(limit) || 1000, 10000)
  };
  if (startTime) payload.startTime = Number(startTime);
  if (endTime) payload.endTime = Number(endTime);
  const result = await awsJsonRequest({
    service: "logs",
    region,
    target: "Logs_20140328.FilterLogEvents",
    payload
  });
  return {
    source: "cloudwatch",
    sourceLabel: logGroupName,
    eventCount: result.events?.length || 0,
    text: (result.events || []).map((event) => event.message).join("\n"),
    importedAt: new Date().toISOString()
  };
}

async function runJob(job) {
  let result;
  try {
    result = job.type === "s3" ? await ingestS3(job.config) : await ingestCloudWatch(job.config);
    METRICS.jobsRun += 1;
    await appendRun({ ...result, tenantId: job.tenantId || DEFAULT_TENANT, jobId: job.id, jobName: job.name });
    await updateJob(job.id, { lastRun: new Date().toISOString(), lastStatus: "ok", lastError: "" });
    await appendAudit("job.run.completed", { jobId: job.id, jobName: job.name, source: result.source, tenantId: job.tenantId || DEFAULT_TENANT }, { subject: "scheduler", roles: ["admin"], tenantId: job.tenantId || DEFAULT_TENANT });
    return result;
  } catch (error) {
    await updateJob(job.id, { lastRun: new Date().toISOString(), lastStatus: "error", lastError: error.message });
    await appendAudit("job.run.failed", { jobId: job.id, jobName: job.name, error: error.message, tenantId: job.tenantId || DEFAULT_TENANT }, { subject: "scheduler", roles: ["admin"], tenantId: job.tenantId || DEFAULT_TENANT });
    throw error;
  }
}

async function restoreSchedules() {
  const jobs = await listJobs();
  jobs.forEach(scheduleJob);
}

async function listTenantObjects(kind, tenantId, file, limit = 100) {
  if (STORE_MODE === "dynamodb") return ddbListScoped(kind, tenantId, limit);
  const records = await readJsonFile(file, []);
  return filterTenant(records, tenantId)
    .sort((a, b) => String(b.updatedAt || b.createdAt || "").localeCompare(String(a.updatedAt || a.createdAt || "")))
    .slice(0, limit);
}

async function getTenantObject(kind, id, tenantId, file) {
  const records = await listTenantObjects(kind, tenantId, file, 500);
  return records.find((item) => String(item.id) === String(id)) || null;
}

async function putTenantObject(kind, id, value, tenantId, file) {
  const record = { ...value, tenantId: sanitizeTenantId(tenantId) };
  if (STORE_MODE === "dynamodb") return ddbPutScoped(kind, tenantId, id, record);
  const records = await readJsonFile(file, []);
  const index = records.findIndex((item) => sameTenant(item, tenantId) && String(item.id) === String(id));
  if (index >= 0) records.splice(index, 1, record);
  else records.unshift(record);
  await writeJsonFile(file, records);
  return record;
}

async function deleteTenantObject(kind, id, tenantId, file) {
  if (STORE_MODE === "dynamodb") return ddbDeleteScoped(kind, tenantId, id);
  const records = (await readJsonFile(file, [])).filter((item) => !(sameTenant(item, tenantId) && String(item.id) === String(id)));
  await writeJsonFile(file, records);
}

function filterTenant(records, tenantId) {
  return (records || []).filter((item) => sameTenant(item, tenantId));
}

function sameTenant(item, tenantId) {
  return sanitizeTenantId(item?.tenantId || DEFAULT_TENANT) === sanitizeTenantId(tenantId || DEFAULT_TENANT);
}

function normalizeWorkspace(body = {}, principal = {}) {
  const now = new Date().toISOString();
  const name = String(body.name || "").trim();
  if (!name) throw new Error("Workspace name is required");
  return {
    id: String(body.id || `workspace-${Date.now()}`),
    tenantId: principal.tenantId || DEFAULT_TENANT,
    name,
    createdAt: body.createdAt || now,
    updatedAt: now,
    fileName: String(body.fileName || ""),
    evidenceText: truncateText(body.evidenceText || "", 200000),
    records: Number(body.records || 0),
    detections: Number(body.detections || 0),
    high: Number(body.high || 0),
    entities: Number(body.entities || 0),
    bytes: Number(body.bytes || 0),
    sourceCount: Number(body.sourceCount || 0),
    sources: Array.isArray(body.sources) ? body.sources.slice(0, 100) : [],
    hunts: Array.isArray(body.hunts) ? body.hunts.slice(0, 50) : [],
    enrichment: body.enrichment && typeof body.enrichment === "object" ? body.enrichment : {},
    ruleProfile: ["strict", "balanced", "focused"].includes(body.ruleProfile) ? body.ruleProfile : "balanced",
    signatures: body.signatures || null
  };
}

function normalizeEvidenceRun(body = {}, principal = {}) {
  const now = new Date().toISOString();
  const records = Array.isArray(body.records) ? body.records.slice(0, 500) : [];
  const analysis = body.analysis || {};
  return {
    id: String(body.id || `run-${Date.now()}`),
    tenantId: principal.tenantId || DEFAULT_TENANT,
    fileName: String(body.fileName || "Evidence run"),
    createdAt: body.createdAt || now,
    recordCount: Number(body.recordCount || records.length || 0),
    detectionCount: Number(body.detectionCount || analysis.detections?.length || 0),
    highCount: Number(body.highCount || (analysis.detections || []).filter((item) => item.severity === "high").length || 0),
    bytes: Number(body.bytes || analysis.totals?.bytes || 0),
    sourceLabel: String(body.sourceLabel || body.fileName || ""),
    recordsSample: records,
    analysisSummary: {
      detections: (analysis.detections || []).slice(0, 25).map((item) => ({
        id: item.id,
        severity: item.severity,
        title: item.title,
        entity: item.entity,
        confidence: item.confidence
      })),
      entityRisk: (analysis.entityRisk || []).slice(0, 25),
      timeRange: analysis.timeRange || null
    }
  };
}

function normalizeSource(body = {}, principal = {}) {
  const now = new Date().toISOString();
  const name = String(body.name || "").trim();
  const scope = Array.isArray(body.scope)
    ? body.scope.map(String).map((item) => item.trim()).filter(Boolean)
    : String(body.scope || "").split(/\s+/).map((item) => item.trim()).filter(Boolean);
  if (!name) throw new Error("Source name is required");
  if (!scope.length) throw new Error("Source scope is required");
  return {
    id: String(body.id || `source-${Date.now()}`),
    tenantId: principal.tenantId || DEFAULT_TENANT,
    name,
    type: String(body.type || "AWS VPC"),
    account: String(body.account || ""),
    region: String(body.region || ""),
    scope,
    createdAt: body.createdAt || now,
    updatedAt: now
  };
}

async function normalizeCase(body = {}, principal = {}) {
  const now = new Date().toISOString();
  const title = String(body.title || "").trim();
  if (!title) throw new Error("Case title is required");
  const existing = body.id ? await getTenantObject("CASE", body.id, principal.tenantId, CASES_FILE) : null;
  const audit = existing?.audit || [];
  const action = existing ? "Case updated" : "Case created";
  return {
    id: String(body.id || `case-${Date.now()}`),
    tenantId: principal.tenantId || DEFAULT_TENANT,
    title,
    assignee: String(body.assignee || "Unassigned"),
    status: String(body.status || "New"),
    severity: ["high", "medium", "low"].includes(body.severity) ? body.severity : "medium",
    notes: String(body.notes || ""),
    linkedDetection: String(body.linkedDetection || ""),
    createdAt: existing?.createdAt || body.createdAt || now,
    updatedAt: now,
    createdBy: existing?.createdBy || principal.email || principal.name || principal.subject || "unknown",
    audit: [
      {
        id: `case-audit-${Date.now()}`,
        action,
        detail: title,
        actor: principal.email || principal.name || principal.subject || "unknown",
        roles: principal.roles || [],
        createdAt: now
      },
      ...audit
    ].slice(0, 100)
  };
}

async function ingestManagedSource(source) {
  const ingestConfig = managedSourceIngestConfig(source);
  const result = ingestConfig.type === "s3" ? await ingestS3(ingestConfig.config) : await ingestCloudWatch(ingestConfig.config);
  return {
    ...result,
    managedSourceId: source.id,
    managedSourceName: source.name
  };
}

function managedSourceIngestConfig(source) {
  const scope = source.scope || [];
  const type = String(source.type || "").toLowerCase();
  const region = source.region || DDB_REGION;
  if (type.includes("s3") || scope.some((item) => String(item).startsWith("s3://"))) {
    const reference = scope.find((item) => String(item).startsWith("s3://")) || scope.find((item) => !String(item).startsWith("/"));
    const parsed = parseS3Reference(reference || "");
    if (!parsed.bucket) throw new Error("Managed S3 sources need a scope like s3://bucket/prefix.");
    return { type: "s3", config: { region, bucket: parsed.bucket, prefix: parsed.prefix, maxObjects: 20 } };
  }
  if (type.includes("cloudwatch") || scope.some((item) => String(item).startsWith("/aws/"))) {
    const logGroupName = scope.find((item) => String(item).startsWith("/aws/"));
    if (!logGroupName) throw new Error("Managed CloudWatch sources need a /aws/... log group scope.");
    return { type: "cloudwatch", config: { region, logGroupName, filterPattern: "", limit: 2000 } };
  }
  throw new Error("Managed source cannot be ingested directly. Add an S3 prefix or CloudWatch log group scope.");
}

function parseS3Reference(reference) {
  const value = String(reference || "").trim();
  const stripped = value.startsWith("s3://") ? value.slice(5) : value;
  const slash = stripped.indexOf("/");
  if (slash < 0) return { bucket: stripped, prefix: "" };
  return { bucket: stripped.slice(0, slash), prefix: stripped.slice(slash + 1) };
}

function scheduleJob(job) {
  clearInterval(activeIntervals.get(job.id));
  activeIntervals.delete(job.id);
  if (!job.enabled) return;
  const interval = setInterval(() => runJob(job).catch((error) => console.error(`Job ${job.id} failed:`, error.message)), job.intervalMinutes * 60 * 1000);
  activeIntervals.set(job.id, interval);
}

async function updateJob(id, patch) {
  const jobs = await listJobs();
  const index = jobs.findIndex((job) => job.id === id);
  if (index >= 0) {
    jobs[index] = { ...jobs[index], ...patch };
    await putJob(jobs[index]);
  }
}

async function appendRun(run) {
  const runRecord = { id: String(Date.now()), tenantId: run.tenantId || DEFAULT_TENANT, ...run, text: undefined, createdAt: new Date().toISOString() };
  await putRun(runRecord);
  METRICS.ingestRuns += 1;
}

async function listJobs() {
  return STORE_MODE === "dynamodb" ? ddbList("JOB") : readJsonFile(JOBS_FILE, []);
}

async function putJob(job) {
  if (STORE_MODE === "dynamodb") return ddbPut("JOB", job.id, job);
  const jobs = await readJsonFile(JOBS_FILE, []);
  const index = jobs.findIndex((item) => item.id === job.id);
  if (index >= 0) jobs.splice(index, 1, job);
  else jobs.unshift(job);
  await writeJsonFile(JOBS_FILE, jobs);
}

async function deleteJob(id) {
  if (STORE_MODE === "dynamodb") return ddbDelete("JOB", id);
  const jobs = (await readJsonFile(JOBS_FILE, [])).filter((job) => job.id !== id);
  await writeJsonFile(JOBS_FILE, jobs);
}

async function listRuns() {
  if (STORE_MODE === "dynamodb") return ddbList("RUN", RETAIN_RUNS);
  return readJsonFile(RUNS_FILE, []);
}

async function putRun(run) {
  if (STORE_MODE === "dynamodb") return ddbPut("RUN", run.id, run);
  const runs = await readJsonFile(RUNS_FILE, []);
  runs.unshift(run);
  await writeJsonFile(RUNS_FILE, runs.slice(0, RETAIN_RUNS));
}

async function appendAudit(action, details = {}, principal = {}) {
  const entry = {
    id: String(Date.now()) + "-" + Math.random().toString(16).slice(2),
    createdAt: new Date().toISOString(),
    retentionUntil: new Date(Date.now() + AUDIT_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString(),
    action,
    actor: principal.email || principal.name || principal.subject || "system",
    roles: principal.roles || [],
    tenantId: principal.tenantId || details.tenantId || DEFAULT_TENANT,
    details
  };
  if (STORE_MODE === "dynamodb") return ddbPut("AUDIT", entry.id, entry);
  await writeFile(AUDIT_FILE, `${JSON.stringify(entry)}\n`, { flag: "a" });
}

async function listAudit() {
  if (STORE_MODE === "dynamodb") return ddbList("AUDIT", 1000);
  try {
    const text = await readFile(AUDIT_FILE, "utf8");
    return text
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}

async function ddbPut(kind, id, value) {
  requireDynamo();
  const now = value.createdAt || new Date().toISOString();
  await awsJsonRequest({
    service: "dynamodb",
    region: DDB_REGION,
    target: "DynamoDB_20120810.PutItem",
    payload: {
      TableName: DDB_TABLE,
      Item: {
        pk: { S: kind },
        sk: { S: id },
        createdAt: { S: now },
        payload: { S: JSON.stringify(value) }
      }
    }
  });
}

async function ddbDelete(kind, id) {
  requireDynamo();
  await awsJsonRequest({
    service: "dynamodb",
    region: DDB_REGION,
    target: "DynamoDB_20120810.DeleteItem",
    payload: {
      TableName: DDB_TABLE,
      Key: { pk: { S: kind }, sk: { S: id } }
    }
  });
}

async function ddbList(kind, limit = 100) {
  requireDynamo();
  const result = await awsJsonRequest({
    service: "dynamodb",
    region: DDB_REGION,
    target: "DynamoDB_20120810.Query",
    payload: {
      TableName: DDB_TABLE,
      KeyConditionExpression: "pk = :pk",
      ExpressionAttributeValues: { ":pk": { S: kind } },
      ScanIndexForward: false,
      Limit: limit
    }
  });
  return (result.Items || []).map((item) => JSON.parse(item.payload.S));
}

async function ddbPutScoped(kind, tenantId, id, value) {
  requireDynamo();
  const now = value.createdAt || new Date().toISOString();
  await awsJsonRequest({
    service: "dynamodb",
    region: DDB_REGION,
    target: "DynamoDB_20120810.PutItem",
    payload: {
      TableName: DDB_TABLE,
      Item: {
        pk: { S: tenantPartition(kind, tenantId) },
        sk: { S: id },
        tenantId: { S: sanitizeTenantId(tenantId) },
        kind: { S: kind },
        createdAt: { S: now },
        payload: { S: JSON.stringify(value) }
      }
    }
  });
}

async function ddbDeleteScoped(kind, tenantId, id) {
  requireDynamo();
  await awsJsonRequest({
    service: "dynamodb",
    region: DDB_REGION,
    target: "DynamoDB_20120810.DeleteItem",
    payload: {
      TableName: DDB_TABLE,
      Key: { pk: { S: tenantPartition(kind, tenantId) }, sk: { S: id } }
    }
  });
}

async function ddbListScoped(kind, tenantId, limit = 100) {
  requireDynamo();
  const result = await awsJsonRequest({
    service: "dynamodb",
    region: DDB_REGION,
    target: "DynamoDB_20120810.Query",
    payload: {
      TableName: DDB_TABLE,
      KeyConditionExpression: "pk = :pk",
      ExpressionAttributeValues: { ":pk": { S: tenantPartition(kind, tenantId) } },
      ScanIndexForward: false,
      Limit: limit
    }
  });
  return (result.Items || []).map((item) => JSON.parse(item.payload.S));
}

function tenantPartition(kind, tenantId) {
  return `TENANT#${sanitizeTenantId(tenantId)}#${kind}`;
}

function requireDynamo() {
  if (!DDB_TABLE) throw new Error("NDR_DDB_TABLE is required when NDR_STORE=dynamodb");
  requireAws(DDB_REGION);
}

function requireAws(region) {
  if (!region) throw new Error("AWS region is required");
  if (!hasAwsCredentialProvider()) throw new Error("Configure AWS credentials or an ECS task role before using AWS-backed features.");
}

async function awsJsonRequest({ service, region, target, payload }) {
  const body = JSON.stringify(payload);
  const response = await awsRequest({
    service,
    region,
    method: "POST",
    host: `${service}.${region}.amazonaws.com`,
    path: "/",
    headers: {
      "content-type": "application/x-amz-json-1.1",
      "x-amz-target": target
    },
    body
  });
  return JSON.parse(response.body || "{}");
}

async function awsRequest({ service, region, method, host, path, query = {}, headers = {}, body = "" }) {
  const bodyBuffer = Buffer.isBuffer(body) ? body : Buffer.from(body);
  const credentials = await getAwsCredentials();
  const signed = createSignedAwsRequest({
    accessKeyId: credentials.accessKeyId,
    secretAccessKey: credentials.secretAccessKey,
    sessionToken: credentials.sessionToken,
    service,
    region,
    method,
    host,
    path,
    query,
    headers,
    body: bodyBuffer
  });
  const response = await fetch(signed.url, {
    method,
    headers: signed.headers,
    body: method === "GET" ? undefined : bodyBuffer
  });
  const arrayBuffer = await response.arrayBuffer();
  const raw = Buffer.from(arrayBuffer);
  const text = raw.toString("utf8");
  if (!response.ok) {
    throw new Error(`${service} request failed ${response.status}: ${text.slice(0, 500)}`);
  }
  return { raw, body: text, headers: response.headers };
}

function hasAwsCredentialProvider() {
  return Boolean(
    (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) ||
      process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI ||
      process.env.AWS_CONTAINER_CREDENTIALS_FULL_URI
  );
}

async function getAwsCredentials() {
  if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
    return {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      sessionToken: process.env.AWS_SESSION_TOKEN || ""
    };
  }
  const credentialsUri = process.env.AWS_CONTAINER_CREDENTIALS_FULL_URI || (process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI ? `http://169.254.170.2${process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}` : "");
  if (!credentialsUri) {
    throw new Error("Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY locally or run with an ECS task role.");
  }
  const headers = {};
  if (process.env.AWS_CONTAINER_AUTHORIZATION_TOKEN) headers.authorization = process.env.AWS_CONTAINER_AUTHORIZATION_TOKEN;
  const response = await fetch(credentialsUri, { headers, signal: AbortSignal.timeout(3000) });
  if (!response.ok) throw new Error(`ECS credential provider failed ${response.status}`);
  const body = await response.json();
  return {
    accessKeyId: body.AccessKeyId,
    secretAccessKey: body.SecretAccessKey,
    sessionToken: body.Token || ""
  };
}

function gunzipText(buffer) {
  return Promise.resolve(gunzipSync(buffer).toString("utf8"));
}

function encodePath(key) {
  return key.split("/").map(encodeURIComponent).join("/");
}

function decodeXml(value) {
  return value.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&apos;/g, "'");
}

async function serveStatic(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const safePath = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
  const filePath = resolve(ROOT, `.${safePath}`);
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }
  try {
    const info = await stat(filePath);
    if (!info.isFile()) throw new Error("Not a file");
    res.writeHead(200, { "content-type": MIME[extname(filePath)] || "application/octet-stream" });
    createReadStream(filePath).pipe(res);
  } catch {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("Not found");
  }
}

async function readJson(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) chunks.push(chunk);
  for (const chunk of chunks) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      throw new Error(`Request body exceeds ${MAX_BODY_BYTES} bytes`);
    }
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? JSON.parse(text) : {};
}

function sendJson(res, status, payload) {
  res.statusCode = status;
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload));
}

function sendMetrics(res) {
  const uptime = Math.floor((Date.now() - Date.parse(METRICS.startedAt)) / 1000);
  const body = [
    "# HELP ndr_requests_total Total HTTP requests",
    "# TYPE ndr_requests_total counter",
    `ndr_requests_total ${METRICS.requests}`,
    "# HELP ndr_errors_total Total server errors",
    "# TYPE ndr_errors_total counter",
    `ndr_errors_total ${METRICS.errors}`,
    "# HELP ndr_ingest_runs_total Total completed ingest runs",
    "# TYPE ndr_ingest_runs_total counter",
    `ndr_ingest_runs_total ${METRICS.ingestRuns}`,
    "# HELP ndr_jobs_run_total Total scheduled/manual job runs",
    "# TYPE ndr_jobs_run_total counter",
    `ndr_jobs_run_total ${METRICS.jobsRun}`,
    "# HELP ndr_uptime_seconds Process uptime",
    "# TYPE ndr_uptime_seconds gauge",
    `ndr_uptime_seconds ${uptime}`
  ].join("\n");
  res.statusCode = 200;
  res.writeHead(200, { "content-type": "text/plain; version=0.0.4; charset=utf-8" });
  res.end(`${body}\n`);
}

async function fileExists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

function logRequest(req, res, durationMs) {
  logInfo("request", {
    method: req.method,
    path: req.url,
    status: res.statusCode || 200,
    durationMs,
    remoteAddress: req.socket.remoteAddress
  });
}

function logInfo(event, fields = {}) {
  console.log(JSON.stringify({ level: "info", event, time: new Date().toISOString(), ...fields }));
}

async function ensureJsonFile(path, fallback) {
  try {
    await readFile(path, "utf8");
  } catch {
    await writeJsonFile(path, fallback);
  }
}

async function ensureTextFile(path, fallback) {
  try {
    await readFile(path, "utf8");
  } catch {
    await mkdir(DATA_DIR, { recursive: true });
    await writeFile(path, fallback);
  }
}

async function readJsonFile(path, fallback) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    return fallback;
  }
}

async function writeJsonFile(path, value) {
  await mkdir(DATA_DIR, { recursive: true });
  await writeFile(path, JSON.stringify(value, null, 2));
}
