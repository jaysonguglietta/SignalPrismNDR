export function createPlatformController({ backendApi, notify = () => {} }) {
  const state = {
    initialized: false,
    loading: false,
    stream: null,
    behavior: { profiles: [], findings: [] },
    campaigns: [],
    hunts: [],
    posture: [],
    connectors: [],
    catalog: [],
    accounts: [],
    uploads: [],
    roles: [],
    serviceAccounts: [],
    aiRuns: []
  };
  const element = (id) => document.getElementById(id);

  function init() {
    if (state.initialized) return;
    state.initialized = true;
    wire("platformRefreshButton", "click", () => refresh(true));
    wire("runBehaviorButton", "click", runBehavior);
    wire("buildCampaignsButton", "click", buildCampaigns);
    wire("runPostureButton", "click", runPosture);
    wire("publishOcsfButton", "click", publishOcsf);
    wire("runRetrospectiveHuntButton", "click", runHunt);
    wire("retrospectiveHuntInput", "keydown", (event) => { if (event.key === "Enter") runHunt(); });
    wire("runAiInvestigationButton", "click", runAiInvestigation);
    wire("saveConnectorButton", "click", saveConnector);
    wire("connectorList", "click", connectorAction);
    wire("discoverOrganizationButton", "click", discoverAccounts);
    wire("onboardOrganizationAccountButton", "click", onboardAccount);
    wire("directEvidenceUploadButton", "click", uploadEvidence);
    wire("saveCustomRoleButton", "click", saveRole);
    wire("createServiceAccountButton", "click", createServiceAccount);
    wire("platformAccessList", "click", accessAction);
    renderAll();
  }

  async function refresh(announce = false) {
    if (state.loading) return;
    state.loading = true;
    setMessage("Refreshing tenant platform state...", "info");
    const requests = [
      ["stream", backendApi.streamStatus],
      ["behavior", backendApi.behaviorAnalytics],
      ["campaigns", backendApi.listCampaigns],
      ["hunts", backendApi.listRetrospectiveHunts],
      ["posture", backendApi.trafficPosture],
      ["catalog", backendApi.connectorCatalog],
      ["connectors", backendApi.listConnectors],
      ["accounts", backendApi.listOrganizationAccounts],
      ["uploads", backendApi.listEvidenceUploads],
      ["roles", backendApi.listRoleDefinitions],
      ["serviceAccounts", backendApi.listServiceAccounts],
      ["aiRuns", backendApi.listAiInvestigations]
    ];
    const results = await Promise.allSettled(requests.map(([, request]) => request()));
    const errors = [];
    results.forEach((result, index) => {
      const key = requests[index][0];
      if (result.status === "fulfilled") state[key] = result.value;
      else errors.push(result.reason?.message || `${key} unavailable`);
    });
    state.loading = false;
    renderAll();
    if (errors.length) setMessage(`${errors.length} platform service${errors.length === 1 ? " is" : "s are"} unavailable for this identity or environment.`, "warn");
    else setMessage("Platform state is current.", "success");
    if (announce) notify(errors.length ? "Platform refreshed with limited services." : "Platform state refreshed.", errors.length ? "warn" : "success");
  }

  async function runBehavior() {
    await withBusy("runBehaviorButton", "Running...", async () => {
      state.behavior = await backendApi.runBehaviorAnalytics({ compareToBaseline: true, businessHourStart: 6, businessHourEnd: 20 });
      renderBehavior();
      renderMetrics();
      notify(`${state.behavior.findings.length} behavior finding${state.behavior.findings.length === 1 ? "" : "s"} produced.`);
    });
  }

  async function buildCampaigns() {
    await withBusy("buildCampaignsButton", "Building...", async () => {
      const result = await backendApi.buildCampaigns({ windowMinutes: 240 });
      state.campaigns = result.campaigns || [];
      renderCampaigns();
      renderMetrics();
      notify(`${state.campaigns.length} linked campaign${state.campaigns.length === 1 ? "" : "s"} assembled.`);
    });
  }

  async function runPosture() {
    await withBusy("runPostureButton", "Assessing...", async () => {
      const sanctionedProviders = splitComma(element("sanctionedAiProvidersInput").value);
      const result = await backendApi.runTrafficPosture({ sanctionedProviders });
      state.posture = [result, ...state.posture.filter((item) => item.id !== result.id)];
      renderPosture();
      renderMetrics();
      notify("AI usage and cryptography posture assessed.");
    });
  }

  async function publishOcsf() {
    await withBusy("publishOcsfButton", "Publishing...", async () => {
      const result = await backendApi.publishSecurityLake({ limit: 5000 });
      if (result.approvalRequired) {
        setMessage(`OCSF publication ${result.approval?.id || ""} is waiting for an independent export approval.`, "warn");
        notify("OCSF publication is waiting for approval.", "warn");
      } else {
        setMessage(`${formatNumber(result.recordCount)} OCSF records validated; ${formatNumber(result.delivery?.published || 0)} dispatched.`, "success");
        notify("OCSF publication completed.");
      }
    });
  }

  async function runHunt() {
    const query = element("retrospectiveHuntInput").value.trim();
    if (!query) return setMessage("Enter a retrospective hunt query.", "warn");
    await withBusy("runRetrospectiveHuntButton", "Searching...", async () => {
      const result = await backendApi.runRetrospectiveHunt(query, 500);
      state.hunts = [result, ...state.hunts.filter((item) => item.id !== result.id)];
      renderHunts();
      renderMetrics();
      notify(`${formatNumber(result.matchCount)} historical event${result.matchCount === 1 ? "" : "s"} matched.`);
    });
  }

  async function runAiInvestigation() {
    const objective = element("aiInvestigationObjectiveInput").value.trim();
    if (objective.length < 5) return setMessage("Describe an investigation objective with at least five characters.", "warn");
    await withBusy("runAiInvestigationButton", "Investigating...", async () => {
      const result = await backendApi.runAiInvestigation({
        objective,
        huntQuery: element("aiInvestigationHuntInput").value.trim(),
        useBedrock: element("aiInvestigationBedrockInput").checked
      });
      state.aiRuns = [result, ...state.aiRuns.filter((item) => item.id !== result.id)];
      renderAiRun(result);
      renderMetrics();
      notify(`Investigation completed with ${result.citations.length} evidence citation${result.citations.length === 1 ? "" : "s"}.`);
    });
  }

  async function saveConnector() {
    const catalogId = element("connectorCatalogInput").value;
    const catalog = state.catalog.find((item) => item.id === catalogId);
    if (!catalog) return setMessage("Select a connector type.", "warn");
    await withBusy("saveConnectorButton", "Saving...", async () => {
      const streamValue = element("connectorStreamInput").value.trim();
      const connector = await backendApi.saveConnector({
        catalogId,
        name: element("connectorNameInput").value.trim() || catalog.name,
        format: catalog.formats[0],
        endpoint: element("connectorEndpointInput").value.trim(),
        secretRef: element("connectorSecretRefInput").value.trim(),
        region: element("connectorRegionInput").value.trim(),
        streamName: streamValue,
        sourceId: streamValue
      });
      state.connectors = [connector, ...state.connectors.filter((item) => item.id !== connector.id)];
      renderConnectors();
      renderMetrics();
      element("connectorNameInput").value = "";
      element("connectorEndpointInput").value = "";
      element("connectorSecretRefInput").value = "";
      notify(`${connector.name} saved.`);
    });
  }

  async function connectorAction(event) {
    const test = event.target.closest("[data-test-connector]");
    const remove = event.target.closest("[data-delete-connector]");
    if (test) {
      await withBusyElement(test, "Testing...", async () => {
        const result = await backendApi.testConnector(test.dataset.testConnector);
        state.connectors = state.connectors.map((item) => item.id === result.connector.id ? result.connector : item);
        renderConnectors();
        notify(`Connector test ${result.delivery.mode === "eventbridge" ? "dispatched" : "validated"}.`);
      });
    }
    if (remove && window.confirm("Delete this connector configuration?")) {
      await backendApi.deleteConnector(remove.dataset.deleteConnector);
      state.connectors = state.connectors.filter((item) => item.id !== remove.dataset.deleteConnector);
      renderConnectors();
      renderMetrics();
      notify("Connector deleted.");
    }
  }

  async function discoverAccounts() {
    await withBusy("discoverOrganizationButton", "Discovering...", async () => {
      const result = await backendApi.discoverOrganizationAccounts();
      state.accounts = result.accounts || [];
      renderAccounts();
      renderMetrics();
      notify(`${state.accounts.length} AWS account${state.accounts.length === 1 ? "" : "s"} discovered.`);
    });
  }

  async function onboardAccount() {
    const accountId = element("organizationAccountInput").value;
    if (!accountId) return setMessage("Select a discovered AWS account.", "warn");
    await withBusy("onboardOrganizationAccountButton", "Creating...", async () => {
      const result = await backendApi.onboardOrganizationAccount(accountId, {
        region: element("organizationRegionInput").value.trim(),
        s3Prefixes: splitLines(element("organizationS3Input").value),
        cloudWatchLogGroups: splitLines(element("organizationCloudWatchInput").value)
      });
      state.accounts = state.accounts.map((item) => item.id === result.account.id ? result.account : item);
      renderAccounts();
      notify(`${result.sources.length} managed source${result.sources.length === 1 ? "" : "s"} created.`);
    });
  }

  async function uploadEvidence() {
    const file = element("directEvidenceFileInput").files[0];
    if (!file) return setMessage("Select an evidence package to upload.", "warn");
    await withBusy("directEvidenceUploadButton", "Uploading...", async () => {
      const status = element("directEvidenceUploadStatus");
      const upload = await backendApi.uploadEvidenceFile(file, (progress) => {
        status.textContent = progress.phase === "uploading" ? `Uploading ${formatNumber(progress.loaded)} of ${formatNumber(progress.total)} bytes...` : "Verifying checksum and Object Lock metadata...";
      });
      state.uploads = [upload, ...state.uploads.filter((item) => item.id !== upload.id)];
      renderUploads();
      status.textContent = `${file.name} is retained until ${formatDate(upload.retentionUntil)}.`;
      element("directEvidenceFileInput").value = "";
      notify("Immutable evidence upload verified.");
    });
  }

  async function saveRole() {
    const name = element("customRoleNameInput").value.trim();
    if (!name) return setMessage("Enter a custom role name.", "warn");
    await withBusy("saveCustomRoleButton", "Creating...", async () => {
      const role = await backendApi.saveRoleDefinition({
        name,
        baseRole: element("customRoleBaseInput").value,
        permissions: splitComma(element("customRolePermissionsInput").value),
        description: `${name} tenant role created from the Platform workspace.`
      });
      state.roles = [...state.roles.filter((item) => item.id !== role.id), role];
      element("customRoleNameInput").value = "";
      renderAccess();
      notify(`${role.name} role created.`);
    });
  }

  async function createServiceAccount() {
    const name = element("serviceAccountNameInput").value.trim();
    if (!name) return setMessage("Enter a service account name.", "warn");
    await withBusy("createServiceAccountButton", "Creating...", async () => {
      const account = await backendApi.createServiceAccount({ name, baseRole: element("serviceAccountRoleInput").value });
      state.serviceAccounts = [account, ...state.serviceAccounts.filter((item) => item.id !== account.id)];
      const output = element("serviceAccountTokenOutput");
      output.hidden = false;
      output.innerHTML = `<strong>One-time token</strong><code>${escapeHtml(account.token)}</code><span>Store this token now. SignalPrism retains only its HMAC digest.</span>`;
      element("serviceAccountNameInput").value = "";
      renderAccess();
      notify("Service account created. Its token is shown once.", "warn");
    });
  }

  async function accessAction(event) {
    const rotate = event.target.closest("[data-rotate-service-account]");
    const revoke = event.target.closest("[data-revoke-service-account]");
    const removeRole = event.target.closest("[data-delete-role]");
    if (rotate) {
      const account = await backendApi.rotateServiceAccount(rotate.dataset.rotateServiceAccount);
      state.serviceAccounts = state.serviceAccounts.map((item) => item.id === account.id ? account : item);
      const output = element("serviceAccountTokenOutput");
      output.hidden = false;
      output.innerHTML = `<strong>Rotated one-time token</strong><code>${escapeHtml(account.token)}</code><span>The previous token is invalid.</span>`;
      renderAccess();
    }
    if (revoke && window.confirm("Revoke this service account token immediately?")) {
      const account = await backendApi.revokeServiceAccount(revoke.dataset.revokeServiceAccount);
      state.serviceAccounts = state.serviceAccounts.map((item) => item.id === account.id ? account : item);
      renderAccess();
      notify("Service account revoked.");
    }
    if (removeRole && window.confirm("Delete this unassigned custom role?")) {
      await backendApi.deleteRoleDefinition(removeRole.dataset.deleteRole);
      state.roles = state.roles.filter((item) => item.id !== removeRole.dataset.deleteRole);
      renderAccess();
      notify("Custom role deleted.");
    }
  }

  function renderAll() {
    renderCatalog();
    renderMetrics();
    renderBehavior();
    renderCampaigns();
    renderHunts();
    renderAiRun(state.aiRuns[0]);
    renderConnectors();
    renderAccounts();
    renderUploads();
    renderPosture();
    renderAccess();
  }

  function renderMetrics() {
    const posture = state.posture[0];
    const metrics = [
      ["Stream", state.stream?.mode || "Unknown", state.stream?.configured ? state.stream.streamName : "Validated local path"],
      ["Behavior findings", formatNumber(state.behavior.findings?.length || 0), `${formatNumber(state.behavior.profiles?.length || 0)} entity profiles`],
      ["Campaigns", formatNumber(state.campaigns.length), state.campaigns[0]?.severity ? `${state.campaigns[0].severity} highest severity` : "No linked campaign"],
      ["Historical hunts", formatNumber(state.hunts.length), state.hunts[0] ? `${formatNumber(state.hunts[0].matchCount)} latest matches` : "No run yet"],
      ["Connectors", formatNumber(state.connectors.length), `${state.connectors.filter((item) => item.status === "healthy").length} healthy`],
      ["Governance", formatNumber((posture?.ai?.unsanctionedEvents || 0) + (posture?.crypto?.findings?.length || 0)), "AI and crypto exceptions"]
    ];
    element("platformMetricGrid").innerHTML = metrics.map(([label, value, detail]) => `<article class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><em>${escapeHtml(detail)}</em></article>`).join("");
  }

  function renderBehavior() {
    const findings = state.behavior.findings || [];
    element("behaviorFindingCount").textContent = String(findings.length);
    element("behaviorFindingList").innerHTML = findings.length ? findings.slice(0, 20).map((finding) => findingRow(finding)).join("") : empty("Run behavior analytics after telemetry ingest to learn entity deviations.");
  }

  function renderCampaigns() {
    element("campaignCount").textContent = String(state.campaigns.length);
    element("campaignList").innerHTML = state.campaigns.length ? state.campaigns.slice(0, 20).map((campaign) => `<div class="finding ${severityClass(campaign.severity)}"><span class="severity"></span><div><strong>${escapeHtml(campaign.title)}</strong><p>${escapeHtml(campaign.narrative)}</p><small>${escapeHtml((campaign.stages || []).join(" -> "))} · ${formatNumber(campaign.blastRadius?.entityCount || 0)} entities · score ${formatNumber(campaign.score)}</small></div></div>`).join("") : empty("Campaigns appear when correlations or behavior findings share entities and time windows.");
  }

  function renderHunts() {
    const run = state.hunts[0];
    element("retrospectiveHuntResults").innerHTML = run ? `<div class="issue-item"><strong>${formatNumber(run.matchCount)} matches from ${formatNumber(run.scanned)} events</strong>${escapeHtml(run.normalizedQuery)}</div>${(run.matches || []).slice(0, 12).map((event) => `<div class="issue-item"><strong>${escapeHtml(event.sourceIp || event.identity || "Unknown entity")} to ${escapeHtml(event.destinationIp || event.resource || "Unknown target")}</strong>${escapeHtml(event.action || event.category)} · ${escapeHtml(event.format)} · ${formatDate(event.timestamp)}</div>`).join("")}` : empty("Run a safe fielded query across normalized telemetry.");
  }

  function renderAiRun(run) {
    const target = element("aiInvestigationResult");
    if (!run) {
      target.innerHTML = empty("Set an objective to run a bounded, tenant-scoped investigation with evidence citations.");
      return;
    }
    target.innerHTML = `<p>${escapeHtml(run.answer)}</p><ul>${(run.steps || []).map((step) => `<li>${escapeHtml(step.name)}: ${escapeHtml(step.status)} (${formatNumber(step.count)})</li>`).join("")}</ul><p><strong>${formatNumber(run.citations?.length || 0)} evidence citations</strong></p>${(run.citations || []).slice(0, 8).map((citation) => `<div class="issue-item"><strong>${escapeHtml(citation.eventId)}</strong>${escapeHtml(citation.sourceIp || "unknown")} to ${escapeHtml(citation.destinationIp || "unknown")} · ${formatDate(citation.timestamp)}</div>`).join("")}`;
  }

  function renderCatalog() {
    const select = element("connectorCatalogInput");
    const current = select.value;
    select.innerHTML = state.catalog.length ? state.catalog.map((item) => `<option value="${escapeAttr(item.id)}">${escapeHtml(item.name)} · ${escapeHtml(item.direction)}</option>`).join("") : `<option value="">Catalog unavailable</option>`;
    if (state.catalog.some((item) => item.id === current)) select.value = current;
  }

  function renderConnectors() {
    element("connectorList").innerHTML = state.connectors.length ? state.connectors.map((connector) => `<div class="issue-item"><strong>${escapeHtml(connector.name)} · ${escapeHtml(connector.status)}</strong>${escapeHtml(connector.catalogId)} · ${escapeHtml(connector.format)} · ${connector.secretConfigured ? "secret configured" : "no secret"}<div class="inline-action"><button class="mini-button" type="button" data-test-connector="${escapeAttr(connector.id)}">Test</button><button class="mini-button" type="button" data-delete-connector="${escapeAttr(connector.id)}">Delete</button></div></div>`).join("") : empty("Configure a governed integration. Delivery is mediated by an EventBridge adapter boundary.");
  }

  function renderAccounts() {
    const select = element("organizationAccountInput");
    const current = select.value;
    select.innerHTML = state.accounts.length ? `<option value="">Select account</option>${state.accounts.map((account) => `<option value="${escapeAttr(account.id)}">${escapeHtml(account.name)} · ${escapeHtml(account.accountId)}</option>`).join("")}` : `<option value="">No discovered accounts</option>`;
    if (state.accounts.some((item) => item.id === current)) select.value = current;
    element("organizationAccountList").innerHTML = state.accounts.length ? state.accounts.slice(0, 50).map((account) => `<div class="issue-item"><strong>${escapeHtml(account.name)} · ${escapeHtml(account.onboardingStatus)}</strong>${escapeHtml(account.accountId)} · ${escapeHtml(account.status)} · ${formatNumber(account.sourceIds?.length || 0)} sources</div>`).join("") : empty("Enable Organizations discovery to inventory and onboard member accounts.");
  }

  function renderUploads() {
    element("directEvidenceUploadList").innerHTML = state.uploads.length ? state.uploads.slice(0, 20).map((upload) => `<div class="issue-item"><strong>${escapeHtml(upload.fileName)} · ${escapeHtml(upload.status)}</strong>${formatNumber(upload.contentLength)} bytes · retain until ${formatDate(upload.retentionUntil)}</div>`).join("") : empty("No direct evidence packages have been uploaded.");
  }

  function renderPosture() {
    const result = state.posture[0];
    element("trafficPostureList").innerHTML = result ? [
      `<div class="issue-item ${result.ai.unsanctionedEvents ? "warning" : ""}"><strong>${formatNumber(result.ai.unsanctionedEvents)} unsanctioned AI events</strong>${formatNumber(result.ai.observedEvents)} AI service observations · ${formatNumber(result.ai.totalBytes)} bytes</div>`,
      `<div class="issue-item ${result.crypto.findings.length ? "warning" : ""}"><strong>${formatNumber(result.crypto.findings.length)} cryptography findings</strong>${formatNumber(result.crypto.observedSessions)} TLS sessions · ${Math.round((result.crypto.pqcCoverage || 0) * 100)}% PQC observed</div>`,
      ...result.crypto.findings.slice(0, 8).map((finding) => `<div class="issue-item warning"><strong>${escapeHtml(finding.title)}</strong>${escapeHtml(finding.summary)}</div>`)
    ].join("") : empty("Assess normalized TLS metadata and enterprise AI service usage.");
  }

  function renderAccess() {
    const customRoles = state.roles.filter((role) => !role.builtIn);
    const roleRows = customRoles.map((role) => `<div class="issue-item"><strong>${escapeHtml(role.name)} · ${escapeHtml(role.baseRole)}</strong>${escapeHtml((role.permissions || []).join(", ") || "Base permissions only")}<div class="inline-action"><button class="mini-button" type="button" data-delete-role="${escapeAttr(role.id)}">Delete</button></div></div>`);
    const accountRows = state.serviceAccounts.map((account) => `<div class="issue-item ${account.status !== "active" ? "warning" : ""}"><strong>${escapeHtml(account.name)} · ${escapeHtml(account.status)}</strong>${escapeHtml(account.baseRole)} · expires ${formatDate(account.expiresAt)}<div class="inline-action">${account.status === "active" ? `<button class="mini-button" type="button" data-rotate-service-account="${escapeAttr(account.id)}">Rotate</button><button class="mini-button" type="button" data-revoke-service-account="${escapeAttr(account.id)}">Revoke</button>` : ""}</div></div>`);
    element("platformAccessList").innerHTML = [...roleRows, ...accountRows].join("") || empty("Create scoped identities for integrations and specialist teams.");
  }

  function findingRow(finding) {
    return `<div class="finding ${severityClass(finding.severity)}"><span class="severity"></span><div><strong>${escapeHtml(finding.title)}</strong><p>${escapeHtml(finding.summary)}</p><small>${escapeHtml(finding.entity)} · ${escapeHtml(finding.explanation?.reason || finding.ruleId)} · score ${formatNumber(finding.score)}</small></div></div>`;
  }

  function setMessage(message, kind = "info") {
    const target = element("platformActionMessage");
    target.hidden = false;
    target.dataset.kind = kind;
    target.textContent = message;
  }

  async function withBusy(id, label, operation) {
    const button = element(id);
    return withBusyElement(button, label, operation);
  }

  async function withBusyElement(button, label, operation) {
    const previous = button.textContent;
    button.disabled = true;
    button.textContent = label;
    try {
      setMessage(label, "info");
      const result = await operation();
      setMessage("Operation completed.", "success");
      return result;
    } catch (error) {
      setMessage(error.message, "error");
      notify(error.message, "error");
      return null;
    } finally {
      button.disabled = false;
      button.textContent = previous;
    }
  }

  function wire(id, eventName, handler) {
    const target = element(id);
    if (target) target.addEventListener(eventName, handler);
  }

  function empty(message) {
    return `<div class="issue-item"><strong>No results</strong>${escapeHtml(message)}</div>`;
  }

  init();
  return { refresh, render: renderAll, state };
}

function splitComma(value) {
  return [...new Set(String(value || "").split(",").map((item) => item.trim()).filter(Boolean))].slice(0, 100);
}

function splitLines(value) {
  return [...new Set(String(value || "").split(/\r?\n/).map((item) => item.trim()).filter(Boolean))].slice(0, 100);
}

function severityClass(value) {
  return ["critical", "high", "medium", "low"].includes(value) ? value : "low";
}

function formatNumber(value) {
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 }).format(Number(value || 0));
}

function formatDate(value) {
  const parsed = Date.parse(value || "");
  return Number.isFinite(parsed) ? new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "short" }).format(parsed) : "unknown";
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/`/g, "&#96;");
}
