export function createOperationsController({ backendApi, notify = () => {} }) {
  const state = { initialized: false, loading: false, snapshot: null, sensors: [], lakeSources: [], responsePolicy: null, cases: [], caseTasks: [], packetManifests: [] };
  const byId = (id) => document.getElementById(id);

  function init() {
    if (state.initialized) return;
    state.initialized = true;
    byId("refreshOperationsButton")?.addEventListener("click", () => refresh(true));
    byId("runOperationsAnalysisButton")?.addEventListener("click", analyze);
    byId("validateOperationsSchemaButton")?.addEventListener("click", validateSchema);
    byId("configureSecurityLakeButton")?.addEventListener("click", configureSecurityLake);
    byId("previewStreamReplayButton")?.addEventListener("click", previewReplay);
    byId("saveSensorButton")?.addEventListener("click", saveSensor);
    byId("saveResponsePolicyButton")?.addEventListener("click", saveResponsePolicy);
    byId("saveThreatFeedButton")?.addEventListener("click", saveThreatFeed);
    byId("runThreatRetromatchButton")?.addEventListener("click", runRetromatch);
    byId("saveCaseTaskButton")?.addEventListener("click", saveCaseTask);
    byId("caseTaskList")?.addEventListener("click", manageCaseTask);
    byId("savePacketManifestButton")?.addEventListener("click", savePacketManifest);
    byId("packetManifestList")?.addEventListener("click", authorizePacketAccess);
    byId("operationsUrgencyQueue")?.addEventListener("click", (event) => {
      const button = event.target.closest("[data-open-detections]");
      if (button) document.getElementById("detectionsTab")?.click();
    });
  }

  async function refreshCaseTasks() {
    if (!backendApi?.listCaseTasks) return;
    try {
      const [cases, tasks] = await Promise.all([backendApi.listCases(), backendApi.listCaseTasks()]);
      state.cases = cases;
      state.caseTasks = tasks;
      renderCaseTasks();
    } catch (error) {
      const list = byId("caseTaskList");
      if (list) list.innerHTML = empty(error.message || "Case tasks are unavailable.");
    }
  }

  async function saveCaseTask() {
    const caseId = byId("caseTaskCaseInput")?.value || "";
    const title = byId("caseTaskTitleInput")?.value.trim() || "";
    if (!caseId || !title) return notify("Select a case and enter a task title.", "warn");
    setButtonBusy("saveCaseTaskButton", true, "Adding...");
    try {
      const dueValue = byId("caseTaskDueInput")?.value;
      const task = await backendApi.saveCaseTask({ caseId, title, assignee: byId("caseTaskAssigneeInput")?.value.trim(), watchers: (byId("caseTaskWatchersInput")?.value || "").split(",").map((value) => value.trim()).filter(Boolean), dueAt: dueValue ? new Date(dueValue).toISOString() : undefined, status: "todo" });
      state.caseTasks = [task, ...state.caseTasks.filter((item) => item.id !== task.id)];
      byId("caseTaskTitleInput").value = "";
      byId("caseTaskAssigneeInput").value = "";
      byId("caseTaskWatchersInput").value = "";
      renderCaseTasks();
      notify("Case task added with SLA tracking.");
      await refresh(false);
    } catch (error) {
      notify(error.message || "Case task could not be saved.", "warn");
    } finally {
      setButtonBusy("saveCaseTaskButton", false, "Add task");
    }
  }

  async function manageCaseTask(event) {
    const complete = event.target.closest("[data-complete-task]");
    const reopen = event.target.closest("[data-reopen-task]");
    const remove = event.target.closest("[data-delete-task]");
    const id = complete?.dataset.completeTask || reopen?.dataset.reopenTask || remove?.dataset.deleteTask;
    if (!id) return;
    const task = state.caseTasks.find((item) => item.id === id);
    if (!task) return;
    if (remove && !window.confirm(`Delete task "${task.title}"?`)) return;
    try {
      if (remove) {
        await backendApi.deleteCaseTask(id);
        state.caseTasks = state.caseTasks.filter((item) => item.id !== id);
      } else {
        const updated = await backendApi.saveCaseTask({ ...task, status: complete ? "done" : "todo" });
        state.caseTasks = state.caseTasks.map((item) => item.id === id ? updated : item);
      }
      renderCaseTasks();
      notify(remove ? "Case task deleted." : complete ? "Case task completed." : "Case task reopened.");
      await refresh(false);
    } catch (error) {
      notify(error.message || "Case task could not be updated.", "warn");
    }
  }

  async function refreshPlatformControls() {
    if (!backendApi?.listSensors) return;
    try {
      const [sensors, lakeSources, policy, packetManifests] = await Promise.all([backendApi.listSensors(), backendApi.listSecurityLakeSources(), backendApi.responsePolicy(), backendApi.listPacketManifests()]);
      state.sensors = sensors;
      state.lakeSources = lakeSources;
      state.responsePolicy = policy;
      state.packetManifests = packetManifests;
      renderPlatformControls();
    } catch (error) {
      setPlatformStatus("responsePolicyStatus", error.message || "Advanced platform controls are unavailable.");
    }
  }

  async function savePacketManifest() {
    const objectUri = byId("packetObjectUriInput")?.value.trim() || "";
    const sha256 = byId("packetSha256Input")?.value.trim() || "";
    if (!objectUri || !sha256) return notify("Packet object URI and SHA-256 are required.", "warn");
    setButtonBusy("savePacketManifestButton", true, "Creating...");
    try {
      const manifest = await backendApi.savePacketManifest({ objectUri, sha256, caseId: byId("packetCaseIdInput")?.value.trim(), classification: "restricted" });
      state.packetManifests = [manifest, ...state.packetManifests];
      byId("packetObjectUriInput").value = "";
      byId("packetSha256Input").value = "";
      renderPlatformControls();
      notify("Immutable packet manifest created.");
    } catch (error) {
      notify(error.message || "Packet manifest could not be created.", "warn");
    } finally {
      setButtonBusy("savePacketManifestButton", false, "Create manifest");
    }
  }

  async function authorizePacketAccess(event) {
    const button = event.target.closest("[data-authorize-packet]");
    if (!button) return;
    const reason = byId("packetAccessReasonInput")?.value.trim() || "";
    if (reason.length < 10) return notify("Enter a substantive packet access reason first.", "warn");
    button.disabled = true;
    try {
      const grant = await backendApi.authorizePacketAccess(button.dataset.authorizePacket, reason, 15);
      button.textContent = `Authorized until ${formatTime(grant.expiresAt)}`;
      notify("Scoped packet access grant created.");
    } catch (error) {
      button.disabled = false;
      notify(error.message || "Packet access could not be authorized.", "warn");
    }
  }

  async function configureSecurityLake() {
    const assignedPrefix = byId("securityLakePrefixInput")?.value.trim() || "";
    const providerAccountId = byId("securityLakeProviderAccountInput")?.value.trim() || "";
    const externalId = byId("securityLakeExternalIdInput")?.value.trim() || "";
    setButtonBusy("configureSecurityLakeButton", true, "Configuring...");
    try {
      const result = await backendApi.configureSecurityLakeSources({ assignedPrefix, providerAccountId, externalId });
      state.lakeSources = result.sources;
      renderPlatformControls();
      notify(result.status === "draft" ? "Security Lake draft saved. Provider identity is still required." : "Class-specific Security Lake sources are ready to register.", result.status === "draft" ? "warn" : "success");
    } catch (error) {
      notify(error.message || "Security Lake configuration failed.", "warn");
    } finally {
      setButtonBusy("configureSecurityLakeButton", false, "Configure sources");
    }
  }

  async function previewReplay() {
    const startValue = byId("streamReplayStartInput")?.value;
    const endValue = byId("streamReplayEndInput")?.value;
    setButtonBusy("previewStreamReplayButton", true, "Building...");
    try {
      const result = await backendApi.replayStream({ start: startValue ? new Date(startValue).toISOString() : undefined, end: endValue ? new Date(endValue).toISOString() : undefined, profile: byId("streamReplayProfileInput")?.value || "native-current", limit: 1000, dispatch: false });
      setPlatformStatus("streamReplayStatus", `${formatNumber(result.eventCount)} ordered event(s) / ${result.profile} / ${result.firstEventTime ? `${formatTime(result.firstEventTime)} to ${formatTime(result.lastEventTime)}` : "empty window"}.`);
      notify("Stream replay preview completed.");
    } catch (error) {
      setPlatformStatus("streamReplayStatus", error.message || "Replay preview failed.");
    } finally {
      setButtonBusy("previewStreamReplayButton", false, "Preview replay");
    }
  }

  async function saveSensor() {
    const name = byId("sensorNameInput")?.value.trim() || "";
    if (!name) return notify("Enter a sensor name.", "warn");
    setButtonBusy("saveSensorButton", true, "Adding...");
    try {
      const sensor = await backendApi.saveSensor({ name, type: byId("sensorTypeInput")?.value, region: byId("sensorRegionInput")?.value.trim(), status: "healthy", coveragePercent: 100 });
      state.sensors = [sensor, ...state.sensors.filter((item) => item.id !== sensor.id)];
      byId("sensorNameInput").value = "";
      renderPlatformControls();
      notify(`${sensor.name} added to sensor health monitoring.`);
      await refresh(false);
    } catch (error) {
      notify(error.message || "Sensor registration failed.", "warn");
    } finally {
      setButtonBusy("saveSensorButton", false, "Add sensor");
    }
  }

  async function saveResponsePolicy() {
    setButtonBusy("saveResponsePolicyButton", true, "Saving...");
    try {
      const policy = await backendApi.saveResponsePolicy({
        mode: byId("responsePolicyModeInput")?.value,
        killSwitch: Boolean(byId("responseKillSwitchInput")?.checked),
        requireCase: Boolean(byId("responseRequireCaseInput")?.checked),
        rollbackRequired: Boolean(byId("responseRollbackRequiredInput")?.checked),
        requireSeparateApprover: true
      });
      state.responsePolicy = policy;
      renderPlatformControls();
      notify(policy.killSwitch ? "Response kill switch enabled." : "Response policy saved.", policy.killSwitch ? "warn" : "success");
    } catch (error) {
      setPlatformStatus("responsePolicyStatus", error.message || "Response policy could not be saved.");
    } finally {
      setButtonBusy("saveResponsePolicyButton", false, "Save policy");
    }
  }

  async function saveThreatFeed() {
    const name = byId("threatFeedNameInput")?.value.trim() || "";
    const values = (byId("threatFeedIndicatorsInput")?.value || "").split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
    if (!name || !values.length) return setPlatformStatus("threatIntelStatus", "Enter a feed name and at least one indicator.");
    setButtonBusy("saveThreatFeedButton", true, "Saving...");
    try {
      const feed = await backendApi.saveThreatIntelFeed({ name, provider: "Tenant intelligence", tlp: "AMBER", indicators: values.map((value) => ({ value, type: value.includes(".") && /^\d/.test(value) ? "ipv4" : "domain", confidence: 70 })) });
      setPlatformStatus("threatIntelStatus", `${feed.name}: ${formatNumber(feed.indicators.length)} indicator(s), ${feed.tlp}.`);
      byId("threatFeedNameInput").value = "";
      byId("threatFeedIndicatorsInput").value = "";
      notify("Threat intelligence feed saved.");
    } catch (error) {
      setPlatformStatus("threatIntelStatus", error.message || "Threat intelligence feed could not be saved.");
    } finally {
      setButtonBusy("saveThreatFeedButton", false, "Save feed");
    }
  }

  async function runRetromatch() {
    setButtonBusy("runThreatRetromatchButton", true, "Matching...");
    try {
      const result = await backendApi.runThreatIntelRetromatch();
      setPlatformStatus("threatIntelStatus", `${formatNumber(result.sightingCount)} sighting(s) across ${formatNumber(result.eventCount)} historical event(s) and ${formatNumber(result.feedCount)} feed(s).`);
      notify(`Threat intelligence retromatch found ${result.sightingCount} sighting(s).`);
    } catch (error) {
      setPlatformStatus("threatIntelStatus", error.message || "Threat intelligence retromatch failed.");
    } finally {
      setButtonBusy("runThreatRetromatchButton", false, "Retromatch");
    }
  }

  async function refresh(announce = false) {
    if (state.loading || !backendApi?.operationsSummary) return;
    state.loading = true;
    setStatus("Refreshing source health, detections, entities, and model posture...");
    setButtonBusy("refreshOperationsButton", true);
    try {
      state.snapshot = await backendApi.operationsSummary();
      render();
      setStatus(`Operational posture refreshed at ${formatTime(state.snapshot.generatedAt)}.`, "success");
      if (announce) notify("Detection operations refreshed.");
    } catch (error) {
      renderUnavailable(error.message);
      setStatus(error.message || "Detection operations are unavailable.", "error");
    } finally {
      state.loading = false;
      setButtonBusy("refreshOperationsButton", false);
    }
  }

  async function analyze() {
    if (state.loading) return;
    state.loading = true;
    setButtonBusy("runOperationsAnalysisButton", true, "Analyzing...");
    setStatus("Building entity claims, seasonal baselines, protocol findings, attack urgency, and exposure paths...");
    try {
      state.snapshot = await backendApi.runOperationsAnalysis({});
      render();
      setStatus(`Analysis completed at ${formatTime(state.snapshot.generatedAt)} with ${formatNumber(state.snapshot.metrics.urgentSignals)} urgent signal(s).`, "success");
      notify("Advanced detection analysis completed.");
    } catch (error) {
      setStatus(error.message || "Advanced analysis failed.", "error");
      notify(error.message || "Advanced analysis failed.", "warn");
    } finally {
      state.loading = false;
      setButtonBusy("runOperationsAnalysisButton", false, "Run analysis");
    }
  }

  async function validateSchema() {
    const profile = byId("operationsSchemaProfile")?.value || "native-current";
    setButtonBusy("validateOperationsSchemaButton", true, "Validating...");
    try {
      const result = await backendApi.validateSchemaProfile(profile, 1000);
      const classes = (result.eventClassBatches || []).map((item) => `${item.className}: ${formatNumber(item.recordCount)}`).join("; ") || "no records";
      setStatus(`${result.profile} validated ${formatNumber(result.recordCount)} record(s), rejected ${formatNumber(result.rejectedCount)}. ${classes}.`, result.rejectedCount ? "warn" : "success");
      notify(`${result.profile} schema validation completed.`);
    } catch (error) {
      setStatus(error.message || "Schema validation failed.", "error");
    } finally {
      setButtonBusy("validateOperationsSchemaButton", false, "Validate schema");
    }
  }

  function render() {
    const snapshot = state.snapshot;
    if (!snapshot) return;
    const criticalHealth = snapshot.sourceHealth.filter((item) => item.state === "critical").length;
    const degradedHealth = snapshot.sourceHealth.filter((item) => item.state === "degraded").length;
    const indicator = byId("operationsLiveIndicator");
    indicator.className = `live-indicator${criticalHealth ? " critical" : degradedHealth ? " degraded" : ""}`;
    byId("operationsUpdatedLabel").textContent = `Updated ${formatTime(snapshot.generatedAt)}`;
    byId("operationsRegionLabel").textContent = snapshot.deployment.regions.length ? `${snapshot.deployment.regions.length} regional cells` : "Single region";
    byId("operationsTenantLabel").textContent = `${snapshot.inputCounts.events.toLocaleString()} events in scope`;
    byId("operationsStreamMode").textContent = `${label(snapshot.deployment.streamMode)} / ${label(snapshot.deployment.hotSearchMode)} hunt`;
    renderKpis(snapshot);
    renderUrgency(snapshot.urgentFindings);
    renderHealth(snapshot.sourceHealth);
    renderPaths(snapshot.exposurePaths);
    renderModelHealth(snapshot.behavior);
    renderEncrypted(snapshot.encryptedTraffic, snapshot.protocolAnalytics);
    renderEconomics(snapshot.dataEconomics);
  }

  function renderPlatformControls() {
    if (byId("sensorInventoryList")) byId("sensorInventoryList").innerHTML = state.sensors.slice(0, 6).map((sensor) => `<div class="quality-item"><strong>${escapeHtml(sensor.name)}</strong><span>${escapeHtml(label(sensor.type))} / ${escapeHtml(sensor.region)} / ${escapeHtml(label(sensor.status))}</span></div>`).join("") || empty("No registered packet or protocol sensors.");
    if (byId("securityLakeSourceList")) byId("securityLakeSourceList").innerHTML = state.lakeSources.map((source) => `<div class="quality-item"><strong>${escapeHtml(source.eventClass)}</strong><span>OCSF ${escapeHtml(source.schemaVersion)} / ${escapeHtml(label(source.status))} / ${escapeHtml(source.compression)}</span></div>`).join("") || empty("No class-specific Security Lake source configuration exists.");
    if (state.responsePolicy) {
      byId("responsePolicyModeInput").value = state.responsePolicy.mode;
      byId("responseKillSwitchInput").checked = Boolean(state.responsePolicy.killSwitch);
      byId("responseRequireCaseInput").checked = Boolean(state.responsePolicy.requireCase);
      byId("responseRollbackRequiredInput").checked = Boolean(state.responsePolicy.rollbackRequired);
      setPlatformStatus("responsePolicyStatus", `${label(state.responsePolicy.mode)} mode / ${state.responsePolicy.killSwitch ? "kill switch active" : "dispatch available after approval"} / ${state.responsePolicy.verificationMinutes}m verification window.`);
    }
    if (byId("packetManifestList")) byId("packetManifestList").innerHTML = state.packetManifests.slice(0, 8).map((manifest) => `<div class="quality-item"><strong>${escapeHtml(manifest.objectUri.split("/").pop() || manifest.id)}</strong><span>${formatNumber(manifest.packetCount)} packets / ${escapeHtml(manifest.classification)} / hash ${escapeHtml(manifest.sha256.slice(0, 12))}...</span><button class="ghost-button compact" type="button" data-authorize-packet="${escapeHtml(manifest.id)}">Authorize access</button></div>`).join("") || empty("No immutable packet manifests have been registered.");
  }

  function renderCaseTasks() {
    const select = byId("caseTaskCaseInput");
    if (select) {
      const current = select.value;
      select.innerHTML = state.cases.length ? state.cases.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.title)}</option>`).join("") : '<option value="">No cases available</option>';
      if (state.cases.some((item) => item.id === current)) select.value = current;
    }
    const list = byId("caseTaskList");
    if (list) list.innerHTML = state.caseTasks.slice(0, 12).map((task) => {
      const caseRecord = state.cases.find((item) => item.id === task.caseId);
      const breached = !["done", "closed"].includes(String(task.status).toLowerCase()) && Date.parse(task.dueAt || 0) < Date.now();
      const closed = ["done", "closed"].includes(String(task.status).toLowerCase());
      return `<div class="quality-item"><strong>${escapeHtml(task.title)}</strong><span>${escapeHtml(caseRecord?.title || task.caseId)} / ${escapeHtml(task.assignee)} / ${closed ? "completed" : breached ? "SLA breached" : `due ${formatTime(task.dueAt)}`} / ${formatNumber(task.watchers?.length || 0)} watcher(s)</span><div class="inline-actions"><button class="mini-button" type="button" ${closed ? `data-reopen-task="${escapeHtml(task.id)}"` : `data-complete-task="${escapeHtml(task.id)}"`}>${closed ? "Reopen" : "Complete"}</button><button class="mini-button danger" type="button" data-delete-task="${escapeHtml(task.id)}">Delete</button></div></div>`;
    }).join("") || empty("No case tasks have been assigned.");
  }

  function renderKpis(snapshot) {
    const metrics = snapshot.metrics;
    const items = [
      { label: "Urgent signals", value: metrics.urgentSignals, note: "Urgency 70 or higher", tone: metrics.urgentSignals ? "critical" : "" },
      { label: "Active campaigns", value: metrics.activeCampaigns, note: "Correlated attack stories", tone: metrics.activeCampaigns ? "warn" : "" },
      { label: "Unhealthy sources", value: metrics.unhealthySources, note: `${snapshot.sourceHealth.length} monitored`, tone: metrics.unhealthySources ? "warn" : "" },
      { label: "Open cases", value: metrics.openCases, note: `${metrics.slaBreaches} SLA breach${metrics.slaBreaches === 1 ? "" : "es"}`, tone: metrics.slaBreaches ? "critical" : "info" },
      { label: "Resolved entities", value: metrics.entityCount, note: `${snapshot.entityGraph.edges.length} temporal edges`, tone: "info" },
      { label: "Daily telemetry", value: currency(metrics.estimatedDailyCostUsd), note: `${snapshot.dataEconomics.projectedDailyGb} GB projected`, tone: "" }
    ];
    byId("operationsKpis").innerHTML = items.map((item) => `<div class="operations-kpi ${item.tone}"><span>${escapeHtml(item.label)}</span><strong>${escapeHtml(String(item.value))}</strong><small>${escapeHtml(item.note)}</small></div>`).join("");
  }

  function renderUrgency(findings) {
    const items = findings.slice(0, 7);
    byId("operationsQueueCount").textContent = `${findings.length} signal${findings.length === 1 ? "" : "s"}`;
    byId("operationsUrgencyQueue").innerHTML = items.length ? items.map((finding) => {
      const scoring = finding.scoring || {};
      return `<div class="operations-queue-item">
        <span class="urgency-score ${escapeHtml(finding.urgencyBand)}" aria-label="Urgency ${formatNumber(finding.urgency)}">${formatNumber(finding.urgency)}</span>
        <div class="operations-item-copy"><strong>${escapeHtml(finding.title || finding.ruleId || "Network detection")}</strong><span>${escapeHtml((finding.entities || [finding.entity]).filter(Boolean).slice(0, 3).join(" / ") || finding.summary || "Evidence-linked signal")}</span></div>
        <div class="score-components" aria-label="Urgency factors"><span>Velocity<b>${formatNumber(scoring.velocity)}</b></span><span>Privilege<b>${formatNumber(scoring.privilege)}</b></span><span>Impact<b>${formatNumber(scoring.impact)}</b></span><span>Confidence<b>${formatNumber(scoring.confidence)}</b></span><span>Breadth<b>${formatNumber(scoring.breadth)}</b></span><span>Blast<b>${formatNumber(scoring.blastRadius)}</b></span></div>
        <button class="ghost-button compact" type="button" data-open-detections="${escapeHtml(finding.id || "")}">Open</button>
      </div>`;
    }).join("") : empty("No advanced findings yet. Run correlation or advanced analysis after telemetry is ingested.");
  }

  function renderHealth(health) {
    const items = health.slice(0, 8);
    byId("operationsSourceHealth").innerHTML = items.length ? items.map((item) => `<div class="operations-health-row">
      <span class="health-state ${escapeHtml(item.state)}" aria-label="${escapeHtml(item.state)}"></span>
      <div class="operations-item-copy"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.reasons[0] || `${label(item.kind)} reporting normally`)} / ${escapeHtml(item.region)}</small></div>
      <span>${item.ageMinutes === null ? "No heartbeat" : `${formatNumber(item.ageMinutes)}m ago`}</span>
    </div>`).join("") : empty("No managed sources or sensors are registered for this tenant.");
  }

  function renderPaths(paths) {
    byId("operationsExposurePaths").innerHTML = paths.slice(0, 5).map((path) => `<div class="operations-path-row">
      <span class="health-state ${path.risk >= 80 ? "critical" : "degraded"}" aria-hidden="true"></span>
      <div class="operations-item-copy"><strong>${escapeHtml(path.from)} &rarr; ${escapeHtml(path.to)}</strong><small>${escapeHtml(label(path.relation))} / ${path.internetOrigin ? "internet origin" : "internal path"} / ${formatTime(path.observedAt)}</small></div>
      <span class="operations-path-risk">${formatNumber(path.risk)}</span>
    </div>`).join("") || empty("No high-risk observed exposure paths in the current evidence window.");
  }

  function renderModelHealth(behavior) {
    byId("operationsModelHealth").innerHTML = [
      stat("Models", behavior.models.length),
      stat("Stable", behavior.models.filter((item) => item.state === "stable").length),
      stat("Drifted", behavior.drifted),
      stat("Learning", behavior.learning),
      `<p class="operations-summary-note">Peer-group and hour-of-week baselines use median absolute deviation. Model promotion is approval-gated with poisoning exclusions and rollback snapshots.</p>`
    ].join("");
  }

  function renderEncrypted(encrypted, protocols) {
    byId("operationsEncryptedTraffic").innerHTML = [
      stat("Encrypted sessions", encrypted.observed),
      stat("Fingerprint coverage", `${encrypted.fingerprintCoveragePercent}%`),
      stat("QUIC", encrypted.quic),
      stat("Protocol findings", protocols.findings.length),
      `<p class="operations-summary-note">${escapeHtml(encrypted.licensePolicy)} Community ID coverage: ${formatNumber(protocols.communityIdCoveragePercent)}%.</p>`
    ].join("");
  }

  function renderEconomics(economics) {
    byId("operationsDataEconomics").innerHTML = [
      stat("Projected / day", `${economics.projectedDailyGb} GB`),
      stat("Estimated cost", currency(economics.estimatedDailyCostUsd)),
      stat("Duplicates", `${economics.duplicatePercent}%`),
      stat("Hot retention", `${economics.hotRetentionDays} days`),
      `<p class="operations-summary-note">${escapeHtml(economics.recommendations[0] || "Telemetry routing and masking policies are within the configured baseline.")}</p>`
    ].join("");
  }

  function renderUnavailable(message) {
    byId("operationsKpis").innerHTML = "";
    ["operationsUrgencyQueue", "operationsSourceHealth", "operationsExposurePaths", "operationsModelHealth", "operationsEncryptedTraffic", "operationsDataEconomics"].forEach((id) => { const element = byId(id); if (element) element.innerHTML = empty(message || "Operational posture is unavailable."); });
  }

  function setStatus(message, tone = "") {
    const element = byId("operationsStatus");
    if (!element) return;
    element.className = `operations-status ${tone}`.trim();
    element.textContent = message;
  }

  function setButtonBusy(id, busy, busyText = "") {
    const button = byId(id);
    if (!button) return;
    if (!button.dataset.defaultText) button.dataset.defaultText = button.textContent;
    button.disabled = busy;
    if (busyText) button.textContent = busy ? busyText : button.dataset.defaultText;
    button.setAttribute("aria-busy", String(busy));
  }

  function setPlatformStatus(id, message) { const element = byId(id); if (element) element.textContent = message; }

  return { init, refresh, refreshPlatformControls, refreshCaseTasks, getState: () => state };
}

function stat(labelText, value) { return `<div class="operations-summary-stat"><span>${escapeHtml(labelText)}</span><strong>${escapeHtml(String(value))}</strong></div>`; }
function empty(message) { return `<div class="operations-empty">${escapeHtml(message)}</div>`; }
function label(value) { return String(value || "").replaceAll("-", " ").replace(/\b\w/g, (character) => character.toUpperCase()); }
function formatNumber(value) { return new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 }).format(Number(value || 0)); }
function currency(value) { return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 2 }).format(Number(value || 0)); }
function formatTime(value) { const date = new Date(value); return Number.isFinite(date.getTime()) ? date.toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }) : "Unknown"; }
function escapeHtml(value) { return String(value ?? "").replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", "\"": "&quot;" })[character]); }
