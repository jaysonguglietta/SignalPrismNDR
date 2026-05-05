export async function backendHealth() {
  return apiGet("/api/health");
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

export async function deleteJob(id) {
  const response = await fetch(`/api/jobs/${encodeURIComponent(id)}`, { method: "DELETE", headers: authHeaders() });
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

export async function listBackendRuns() {
  return apiGet("/api/runs");
}

export async function exportAuditNdjson() {
  const response = await fetch("/api/audit/export", { headers: authHeaders() });
  if (!response.ok) throw new Error(await errorText(response));
  return response.text();
}

export function saveApiKey(key) {
  if (key) localStorage.setItem("ndrFlowConsole.apiKey", key);
  else localStorage.removeItem("ndrFlowConsole.apiKey");
}

export function getApiKey() {
  return localStorage.getItem("ndrFlowConsole.apiKey") || "";
}

export function clearCredentials() {
  localStorage.removeItem("ndrFlowConsole.apiKey");
  localStorage.removeItem("ndrFlowConsole.oidcToken");
  localStorage.removeItem("ndrFlowConsole.oidcExpiresAt");
  localStorage.removeItem("ndrFlowConsole.oidcState");
  localStorage.removeItem("ndrFlowConsole.oidcVerifier");
}

export async function beginSsoLogin(config) {
  if (!config?.enabled || !config.authorizationEndpoint || !config.clientId) {
    throw new Error("SSO is not configured on this backend.");
  }
  const redirectUri = config.redirectUri || `${window.location.origin}${window.location.pathname}`;
  const state = randomString();
  const verifier = randomString(64);
  const challenge = await pkceChallenge(verifier);
  localStorage.setItem("ndrFlowConsole.oidcState", state);
  localStorage.setItem("ndrFlowConsole.oidcVerifier", verifier);
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
  const expectedState = localStorage.getItem("ndrFlowConsole.oidcState");
  const verifier = localStorage.getItem("ndrFlowConsole.oidcVerifier");
  if (!state || state !== expectedState || !verifier) {
    throw new Error("SSO callback validation failed.");
  }
  const redirectUri = `${window.location.origin}${window.location.pathname}`;
  const response = await fetch("/api/auth/token", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ code, codeVerifier: verifier, redirectUri })
  });
  if (!response.ok) throw new Error(await errorText(response));
  const token = await response.json();
  const bearer = token.idToken || token.accessToken;
  if (!bearer) throw new Error("SSO provider did not return a usable token.");
  localStorage.setItem("ndrFlowConsole.oidcToken", bearer);
  localStorage.setItem("ndrFlowConsole.oidcExpiresAt", String(Date.now() + Number(token.expiresIn || 3600) * 1000));
  localStorage.removeItem("ndrFlowConsole.oidcState");
  localStorage.removeItem("ndrFlowConsole.oidcVerifier");
  url.searchParams.delete("code");
  url.searchParams.delete("state");
  url.searchParams.delete("session_state");
  window.history.replaceState({}, document.title, `${url.pathname}${url.search}${url.hash}`);
  return token;
}

async function apiGet(path) {
  const response = await fetch(path, { headers: authHeaders() });
  if (!response.ok) throw new Error(await errorText(response));
  return response.json();
}

async function apiPost(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...authHeaders() },
    body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error(await errorText(response));
  return response.json();
}

function authHeaders() {
  const oidcToken = localStorage.getItem("ndrFlowConsole.oidcToken");
  const expiresAt = Number(localStorage.getItem("ndrFlowConsole.oidcExpiresAt") || 0);
  if (oidcToken && (!expiresAt || Date.now() < expiresAt)) {
    return { authorization: `Bearer ${oidcToken}` };
  }
  const key = localStorage.getItem("ndrFlowConsole.apiKey");
  return key ? { "x-ndr-api-key": key } : {};
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
