const DEFAULT_FIELDS = [
  "version",
  "account-id",
  "interface-id",
  "srcaddr",
  "dstaddr",
  "srcport",
  "dstport",
  "protocol",
  "packets",
  "bytes",
  "start",
  "end",
  "action",
  "log-status"
];

const KNOWN_FIELDS = new Set([
  "version",
  "account-id",
  "interface-id",
  "srcaddr",
  "dstaddr",
  "srcport",
  "dstport",
  "protocol",
  "packets",
  "bytes",
  "start",
  "end",
  "action",
  "log-status",
  "flow-direction",
  "traffic-path",
  "pkt-srcaddr",
  "pkt-dstaddr",
  "pkt-src-aws-service",
  "pkt-dst-aws-service",
  "sublocation-type",
  "sublocation-id",
  "tcp-flags",
  "type",
  "region",
  "az-id",
  "subnet-id",
  "instance-id"
]);

const PROTOCOLS = {
  "1": "ICMP",
  "2": "IGMP",
  "6": "TCP",
  "17": "UDP",
  "41": "IPv6",
  "47": "GRE",
  "50": "ESP",
  "51": "AH",
  "58": "ICMPv6",
  "89": "OSPF",
  "132": "SCTP"
};

const SENSITIVE_PORTS = new Map([
  [21, "FTP"],
  [22, "SSH"],
  [23, "Telnet"],
  [25, "SMTP"],
  [53, "DNS"],
  [110, "POP3"],
  [135, "RPC"],
  [139, "NetBIOS"],
  [143, "IMAP"],
  [389, "LDAP"],
  [445, "SMB"],
  [1433, "SQL Server"],
  [1521, "Oracle"],
  [2049, "NFS"],
  [2375, "Docker"],
  [3306, "MySQL"],
  [3389, "RDP"],
  [5432, "PostgreSQL"],
  [5900, "VNC"],
  [6379, "Redis"],
  [9200, "Elasticsearch"],
  [11211, "Memcached"],
  [27017, "MongoDB"]
]);

const SERVICE_PORTS = new Map([
  ...SENSITIVE_PORTS,
  [20, "FTP Data"],
  [80, "HTTP"],
  [123, "NTP"],
  [161, "SNMP"],
  [443, "HTTPS"],
  [465, "SMTPS"],
  [514, "Syslog"],
  [587, "SMTP Submission"],
  [636, "LDAPS"],
  [993, "IMAPS"],
  [995, "POP3S"],
  [1194, "OpenVPN"],
  [1900, "SSDP"],
  [5353, "mDNS"],
  [5601, "Kibana"],
  [8080, "HTTP Alt"],
  [8443, "HTTPS Alt"],
  [9300, "Elasticsearch Transport"]
]);

const AI_DOMAIN_HINTS = [
  "openai.com",
  "chatgpt.com",
  "anthropic.com",
  "claude.ai",
  "gemini.google.com",
  "generativelanguage.googleapis.com",
  "cohere.ai",
  "perplexity.ai",
  "mistral.ai",
  "huggingface.co"
];

const STORAGE_KEYS = {
  history: "ndrFlowConsole.history.v1",
  baseline: "ndrFlowConsole.baseline.v1",
  hunts: "ndrFlowConsole.hunts.v1",
  sources: "ndrFlowConsole.sources.v1",
  enrichment: "ndrFlowConsole.enrichment.v1"
};

const SAMPLE_LOG = `#Fields: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
2 123456789012 eni-0a1b2c3d 198.51.100.10 10.0.1.15 52511 22 6 3 180 1714771200 1714771260 REJECT OK
2 123456789012 eni-0a1b2c3d 203.0.113.24 10.0.1.15 52122 3389 6 2 128 1714771260 1714771320 REJECT OK
2 123456789012 eni-0a1b2c3d 10.0.1.15 10.0.2.28 44312 5432 6 48 39032 1714771320 1714771380 ACCEPT OK
2 123456789012 eni-0e4f5a6b 10.0.2.28 52.95.110.1 49320 443 6 204 982044 1714771380 1714771440 ACCEPT OK
2 123456789012 eni-0e4f5a6b 10.0.2.28 8.8.8.8 53422 53 17 16 1280 1714771440 1714771500 ACCEPT OK
2 123456789012 eni-0c7d8e9f 198.51.100.88 10.0.3.44 53300 445 6 1 64 1714771500 1714771560 REJECT OK
2 123456789012 eni-0c7d8e9f 198.51.100.88 10.0.3.44 53301 1433 6 1 64 1714771560 1714771620 REJECT OK
2 123456789012 eni-0c7d8e9f 198.51.100.88 10.0.3.44 53302 3306 6 1 64 1714771620 1714771680 REJECT OK
2 123456789012 eni-0a1b2c3d 10.0.1.15 172.31.4.50 50220 443 6 99 142002 1714771680 1714771740 ACCEPT OK
2 123456789012 eni-0a1b2c3d 10.0.1.15 203.0.113.82 50221 8443 6 320 14502000 1714771740 1714771800 ACCEPT OK
2 123456789012 eni-0a1b2c3d - - - - - - - 1714771800 1714771860 - NODATA`;

const state = {
  records: [],
  filtered: [],
  analysis: null,
  fields: [],
  errors: [],
  fileName: "",
  enrichment: {},
  selectedEntity: null,
  huntResults: [],
  sort: { field: "start", direction: "desc" },
  pendingConfirm: null
};

const els = {};
let idbApi = null;
let backendApi = null;
let topologyApi = null;

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    cacheElements();
    initializePersistentData();
    wireEvents();
    renderEmptyDashboard();
  });
}

function cacheElements() {
  [
    "statusPill",
    "statusText",
    "dropZone",
    "fileInput",
    "fileMeta",
    "pasteInput",
    "analyzeButton",
    "sampleButton",
    "clearButton",
    "inputMessage",
    "resetFiltersButton",
    "searchInput",
    "actionFilter",
    "protocolFilter",
    "parseIssueCount",
    "parseIssueList",
    "metricGrid",
    "timelineChart",
    "timeRangeLabel",
    "priorityEntities",
    "topPorts",
    "findingCount",
    "findingList",
    "severityFilter",
    "exportDetectionsButton",
    "topRejected",
    "protocolMix",
    "entityCountLabel",
    "entityRiskList",
    "internalPaths",
    "externalPaths",
    "recordCountLabel",
    "recordsTableHead",
    "recordsTable",
    "exportButton",
    "createCaseFromTopDetectionButton",
    "caseQuickTitleInput",
    "caseQuickAssigneeInput",
    "entityDetailTitle",
    "entityDetailMeta",
    "entityDetail",
    "huntInput",
    "runHuntButton",
    "saveHuntButton",
    "clearHuntsButton",
    "huntResultsTable",
    "savedHuntsList",
    "observationCount",
    "observationList",
    "coverageScoreLabel",
    "coverageGrid",
    "sourceNameInput",
    "sourceScopeInput",
    "saveSourceButton",
    "clearSourcesButton",
    "sourceWatchlist",
    "saveBaselineButton",
    "deleteBaselineButton",
    "clearHistoryButton",
    "historyList",
    "enrichmentInput",
    "applyEnrichmentButton",
    "backendStatusLabel",
    "authStatusLabel",
    "authRoleLabel",
    "apiKeyInput",
    "saveApiKeyButton",
    "ssoLoginButton",
    "ssoLogoutButton",
    "s3RegionInput",
    "s3BucketInput",
    "s3PrefixInput",
    "ingestS3Button",
    "cwRegionInput",
    "cwGroupInput",
    "cwFilterInput",
    "ingestCloudWatchButton",
    "jobNameInput",
    "jobTypeInput",
    "jobIntervalInput",
    "createJobButton",
    "backendJobsList",
    "applicationMix",
    "dropAcceptedDns",
    "dropNoData",
    "dedupeFlows",
    "sampleRateInput",
    "optimizationResult",
    "aiStatusLabel",
    "aiQuestionInput",
    "askAiButton",
    "summarizeAiButton",
    "clearAiButton",
    "aiAnswerPanel",
    "analystSummary",
    "copySummaryButton",
    "exportJsonButton",
    "exportOcsfButton",
    "exportCefButton",
    "policyRecommendations",
    "exportRedactedButton",
    "maskIps",
    "maskAccounts",
    "maskDomains",
    "caseIdInput",
    "caseTitleInput",
    "caseAssigneeInput",
    "caseStatusInput",
    "caseSeverityInput",
    "caseNotesInput",
    "saveCaseButton",
    "caseCountLabel",
    "caseList",
    "caseAuditTitle",
    "caseAuditList",
    "topologyCanvas",
    "replayRangeInput",
    "replayTimeLabel",
    "toastRegion",
    "confirmDialog",
    "confirmTitle",
    "confirmBody",
    "acceptConfirmButton",
    "cancelConfirmButton",
    "emptyStateTemplate"
  ].forEach((id) => {
    els[id] = document.getElementById(id);
  });
}

function wireEvents() {
  els.fileInput.addEventListener("change", (event) => {
    const file = event.target.files[0];
    if (file) {
      readFile(file);
    }
  });

  ["dragenter", "dragover"].forEach((type) => {
    els.dropZone.addEventListener(type, (event) => {
      event.preventDefault();
      els.dropZone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach((type) => {
    els.dropZone.addEventListener(type, (event) => {
      event.preventDefault();
      els.dropZone.classList.remove("dragover");
    });
  });

  els.dropZone.addEventListener("drop", (event) => {
    const file = event.dataTransfer.files[0];
    if (file) {
      readFile(file);
    } else {
      setInputMessage("Drop a .log, .txt, .csv, .json, .jsonl, or .gz file.");
    }
  });

  els.analyzeButton.addEventListener("click", () => {
    runAnalysis(els.pasteInput.value, "Pasted log");
  });

  els.sampleButton.addEventListener("click", () => {
    els.pasteInput.value = SAMPLE_LOG;
    runAnalysis(SAMPLE_LOG, "Sample log");
  });

  els.clearButton.addEventListener("click", () => {
    if (!state.records.length && !els.pasteInput.value.trim()) {
      clearCurrentEvidence();
      return;
    }
    confirmAction({
      title: "Clear current evidence?",
      body: "This clears the loaded records, filters, pasted text, and current analysis from the screen. Saved hunts, baselines, and history remain untouched.",
      confirmLabel: "Clear Evidence",
      onConfirm: clearCurrentEvidence
    });
  });

  els.resetFiltersButton.addEventListener("click", () => {
    els.searchInput.value = "";
    els.actionFilter.value = "all";
    els.protocolFilter.value = "all";
    applyFilters();
  });

  [els.searchInput, els.actionFilter, els.protocolFilter].forEach((input) => {
    input.addEventListener("input", applyFilters);
  });

  els.recordsTableHead.addEventListener("click", (event) => {
    const button = event.target.closest("[data-sort]");
    if (button) {
      setRecordSort(button.dataset.sort);
    }
  });

  els.severityFilter.addEventListener("input", () => {
    renderFindings(state.analysis?.detections || []);
  });

  els.findingList.addEventListener("click", (event) => {
    const button = event.target.closest("[data-filter-entity]");
    if (!button) {
      return;
    }
    els.searchInput.value = button.dataset.filterEntity;
    applyFilters();
    activateTab("records");
  });

  els.entityRiskList.addEventListener("click", (event) => {
    const card = event.target.closest("[data-entity]");
    if (card) {
      selectEntity(card.dataset.entity);
    }
  });
  els.entityRiskList.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const card = event.target.closest("[data-entity]");
    if (card) {
      event.preventDefault();
      selectEntity(card.dataset.entity);
    }
  });

  els.runHuntButton.addEventListener("click", runAdvancedHunt);
  els.huntInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") runAdvancedHunt();
  });
  els.saveHuntButton.addEventListener("click", saveCurrentHunt);
  els.savedHuntsList.addEventListener("click", (event) => {
    const deleteButton = event.target.closest("[data-delete-hunt]");
    if (deleteButton) {
      deleteSavedHunt(deleteButton.dataset.deleteHunt);
      return;
    }
    const item = event.target.closest("[data-hunt]");
    if (item) {
      els.huntInput.value = item.dataset.hunt;
      runAdvancedHunt();
    }
  });
  els.clearHuntsButton.addEventListener("click", clearSavedHunts);
  els.saveSourceButton.addEventListener("click", saveSourceConfig);
  els.clearSourcesButton.addEventListener("click", clearSourceConfigs);
  els.sourceWatchlist.addEventListener("click", (event) => {
    const button = event.target.closest("[data-delete-source]");
    if (button) deleteSourceConfig(button.dataset.deleteSource);
  });
  els.saveBaselineButton.addEventListener("click", saveCurrentBaseline);
  els.deleteBaselineButton.addEventListener("click", deleteBaseline);
  els.clearHistoryButton.addEventListener("click", clearHistory);
  els.applyEnrichmentButton.addEventListener("click", applyEnrichmentInput);
  [els.dropAcceptedDns, els.dropNoData, els.dedupeFlows, els.sampleRateInput].forEach((input) => {
    input.addEventListener("input", renderOptimization);
  });
  els.copySummaryButton.addEventListener("click", copyAnalystSummary);
  els.exportJsonButton.addEventListener("click", () => exportDetectionsStructured("json"));
  els.exportOcsfButton.addEventListener("click", () => exportDetectionsStructured("ocsf"));
  els.exportCefButton.addEventListener("click", exportDetectionsCef);
  els.exportRedactedButton.addEventListener("click", exportRedactedRecords);

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      activateTab(tab.dataset.tab);
    });
  });

  els.exportButton.addEventListener("click", exportFilteredCsv);
  els.exportDetectionsButton.addEventListener("click", exportDetectionsCsv);
  els.saveApiKeyButton.addEventListener("click", saveBackendApiKey);
  els.ssoLoginButton.addEventListener("click", startSsoLogin);
  els.ssoLogoutButton.addEventListener("click", signOutBackend);
  els.askAiButton.addEventListener("click", () => askBedrockAssistant("answer"));
  els.summarizeAiButton.addEventListener("click", () => askBedrockAssistant("summary"));
  els.clearAiButton.addEventListener("click", clearAiAssistant);
  els.ingestS3Button.addEventListener("click", ingestFromS3);
  els.ingestCloudWatchButton.addEventListener("click", ingestFromCloudWatch);
  els.createJobButton.addEventListener("click", createIngestJob);
  els.backendJobsList.addEventListener("click", (event) => {
    const run = event.target.closest("[data-run-job]");
    const del = event.target.closest("[data-delete-job]");
    if (run) runBackendJob(run.dataset.runJob);
    if (del) deleteBackendJob(del.dataset.deleteJob);
  });
  els.createCaseFromTopDetectionButton.addEventListener("click", createCaseFromTopDetection);
  els.saveCaseButton.addEventListener("click", saveCaseForm);
  els.caseList.addEventListener("click", (event) => {
    const edit = event.target.closest("[data-edit-case]");
    const del = event.target.closest("[data-delete-case]");
    if (edit) editCase(edit.dataset.editCase);
    if (del) deleteCaseById(del.dataset.deleteCase);
  });
  els.replayRangeInput.addEventListener("input", renderTopology);
  els.confirmDialog.addEventListener("close", () => {
    if (els.confirmDialog.returnValue === "confirm" && state.pendingConfirm) {
      state.pendingConfirm();
    }
    state.pendingConfirm = null;
  });
}

function activateTab(tabName) {
  document.querySelectorAll(".tab").forEach((tab) => {
    const isActive = tab.dataset.tab === tabName;
    tab.classList.toggle("active", isActive);
    tab.setAttribute("aria-selected", String(isActive));
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    const isActive = panel.id === `${tabName}Panel`;
    panel.classList.toggle("active", isActive);
    panel.hidden = !isActive;
  });
}

function clearCurrentEvidence() {
  state.records = [];
  state.filtered = [];
  state.analysis = null;
  state.fields = [];
  state.errors = [];
  state.fileName = "";
  state.selectedEntity = null;
  state.huntResults = [];
  els.fileInput.value = "";
  els.pasteInput.value = "";
  els.severityFilter.value = "all";
  els.searchInput.value = "";
  els.actionFilter.value = "all";
  els.protocolFilter.value = "all";
  els.fileMeta.textContent = ".log, .txt, .csv, .gz, or JSON";
  clearInputMessage();
  renderEmptyDashboard();
  showToast("Current evidence cleared.");
}

function setBusy(isBusy, label = "Working") {
  [
    els.analyzeButton,
    els.sampleButton,
    els.clearButton,
    els.exportButton,
    els.exportDetectionsButton,
    els.runHuntButton,
    els.saveHuntButton,
    els.applyEnrichmentButton
  ].forEach((button) => {
    if (button) button.disabled = isBusy;
  });
  els.dropZone.classList.toggle("loading", isBusy);
  if (isBusy) {
    setStatus(label, "ready");
  }
}

function setInputMessage(message) {
  els.inputMessage.textContent = message;
  els.inputMessage.hidden = false;
  showToast(message, "warn");
}

function clearInputMessage() {
  els.inputMessage.textContent = "";
  els.inputMessage.hidden = true;
}

async function initializePersistentData() {
  state.enrichment = loadJson(STORAGE_KEYS.enrichment, {});
  try {
    [idbApi, backendApi, topologyApi] = await Promise.all([
      import("./src/idb-store.js"),
      import("./src/backend-client.js"),
      import("./src/topology.js")
    ]);
    const loginResult = await backendApi.completeSsoCallback();
    if (loginResult?.principal) showToast(`Signed in as ${loginResult.principal.name || loginResult.principal.subject}.`);
    await refreshCases();
    await refreshBackendStatus();
  } catch (error) {
    showToast(`Module initialization warning: ${error.message}`, "warn");
  }
}

function loadJson(key, fallback) {
  if (typeof localStorage === "undefined") {
    return fallback;
  }
  try {
    return JSON.parse(localStorage.getItem(key)) ?? fallback;
  } catch {
    return fallback;
  }
}

function saveJson(key, value) {
  if (typeof localStorage === "undefined") {
    return;
  }
  localStorage.setItem(key, JSON.stringify(value));
}

function removeJson(key) {
  if (typeof localStorage === "undefined") {
    return;
  }
  localStorage.removeItem(key);
}

function showToast(message, tone = "success") {
  if (!els.toastRegion || !message) return;
  const toast = document.createElement("div");
  toast.className = `toast ${tone === "success" ? "" : tone}`;
  toast.textContent = message;
  els.toastRegion.appendChild(toast);
  window.setTimeout(() => {
    toast.remove();
  }, 3600);
}

function confirmAction({ title, body, confirmLabel = "Confirm", onConfirm }) {
  if (!els.confirmDialog?.showModal) {
    if (window.confirm(`${title}\n\n${body}`)) onConfirm();
    return;
  }
  els.confirmTitle.textContent = title;
  els.confirmBody.textContent = body;
  els.acceptConfirmButton.textContent = confirmLabel;
  state.pendingConfirm = onConfirm;
  els.confirmDialog.returnValue = "";
  els.confirmDialog.showModal();
}

async function readFile(file) {
  setBusy(true, `Reading ${file.name}`);
  clearInputMessage();
  try {
    const text = await readFileText(file);
    els.pasteInput.value = text.slice(0, 70000);
    els.fileMeta.textContent = `${file.name} - ${formatBytes(file.size)}`;
    runAnalysis(text, file.name);
  } catch (error) {
    setStatus(error.message || "File could not be read", "warn");
    setInputMessage(error.message || "File could not be read.");
  } finally {
    setBusy(false);
  }
}

async function readFileText(file) {
  if (file.name.toLowerCase().endsWith(".gz")) {
    if (typeof DecompressionStream === "undefined") {
      throw new Error("This browser cannot decompress .gz files");
    }
    const stream = file.stream().pipeThrough(new DecompressionStream("gzip"));
    return new Response(stream).text();
  }
  return file.text();
}

function runAnalysis(text, fileName) {
  if (!String(text || "").trim()) {
    setStatus("No log text to analyze", "warn");
    setInputMessage("Paste flow log text or upload a supported evidence file first.");
    return;
  }

  setBusy(true, "Analyzing evidence");
  clearInputMessage();
  try {
    const parsed = parseVpcFlowLog(text);
    state.records = parsed.records;
    state.filtered = parsed.records;
    state.fields = parsed.fields;
    state.errors = parsed.errors;
    state.fileName = fileName;
    state.analysis = analyzeRecords(parsed.records, parsed.errors);
    enrichAnalysis(state.analysis);
    applyBaselineObservations(state.analysis);
    persistHistory(fileName, state.analysis);
    persistEvidenceIndexedDb(fileName, parsed.records, state.analysis);

    refreshProtocolFilter(parsed.records);
    applyFilters();
    renderDashboard();
    updateStatus();
    if (!parsed.records.length) {
      setInputMessage("No records were parsed. Check the field order, delimiter, or pasted text.");
    } else {
      showToast(`${formatNumber(parsed.records.length)} records analyzed from ${fileName}.`);
    }
  } catch (error) {
    setStatus("Analysis failed", "warn");
    setInputMessage(error.message || "Analysis failed.");
  } finally {
    setBusy(false);
  }
}

function parseVpcFlowLog(text) {
  const structured = parseStructuredCloudLogs(text);
  if (structured) {
    return structured;
  }

  const lines = unwrapLogText(text)
    .replace(/\u0000/g, "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  let fields = null;
  let delimiter = "space";
  const records = [];
  const errors = [];

  lines.forEach((line, index) => {
    const fieldsMatch = line.match(/^#?\s*Fields:\s*(.+)$/i);
    if (fieldsMatch) {
      fields = normalizeFields(splitFields(fieldsMatch[1]));
      delimiter = detectDelimiter(fieldsMatch[1]);
      return;
    }

    if (line.startsWith("#")) {
      return;
    }

    if (!fields) {
      const candidateDelimiter = detectDelimiter(line);
      const possibleHeader = normalizeFields(splitLine(line, candidateDelimiter));
      if (looksLikeHeader(possibleHeader)) {
        fields = possibleHeader;
        delimiter = candidateDelimiter;
        return;
      }

      fields = DEFAULT_FIELDS;
      delimiter = candidateDelimiter === "comma" ? "comma" : "space";
    }

    let values = splitLine(line, delimiter);
    if (values.length !== fields.length && delimiter === "space" && line.includes(",")) {
      values = splitLine(line, "comma");
    }
    if (values.length !== fields.length && delimiter === "comma") {
      values = splitLine(line, "space");
    }

    if (looksLikeHeader(normalizeFields(values))) {
      return;
    }

    if (values.length < Math.min(8, fields.length)) {
      errors.push({ line: index + 1, message: "Too few columns" });
      return;
    }

    const raw = {};
    fields.forEach((field, fieldIndex) => {
      raw[field] = cleanValue(values[fieldIndex]);
    });
    records.push(normalizeRecord(raw, index + 1));
  });

  return {
    records,
    fields: fields || DEFAULT_FIELDS,
    errors
  };
}

function parseStructuredCloudLogs(text) {
  const trimmed = String(text || "").trim();
  if (!trimmed || (!trimmed.startsWith("{") && !trimmed.startsWith("["))) {
    return null;
  }
  try {
    const parsed = JSON.parse(trimmed);
    const azure = parseAzureNsgFlowLogs(parsed);
    if (azure.records.length) return azure;
    const gcp = parseGcpVpcFlowLogs(parsed);
    if (gcp.records.length) return gcp;
  } catch {
    return null;
  }
  return null;
}

function parseAzureNsgFlowLogs(parsed) {
  const records = [];
  const items = Array.isArray(parsed) ? parsed : parsed.records || [];
  items.forEach((item) => {
    const ruleFlows = item.properties?.flows || item.flows || [];
    ruleFlows.forEach((rule) => {
      (rule.flows || []).forEach((flow) => {
        (flow.flowTuples || []).forEach((tuple, index) => {
          const [timestamp, source, destination, srcPort, dstPort, protocol, direction, decision] = String(tuple).split(",");
          records.push(
            normalizeRecord(
              {
                version: "azure-nsg",
                "account-id": item.resourceId || "-",
                "interface-id": rule.rule || item.resourceId || "azure-nsg",
                srcaddr: source,
                dstaddr: destination,
                srcport: srcPort,
                dstport: dstPort,
                protocol: protocol === "T" ? "6" : protocol === "U" ? "17" : protocol,
                packets: "0",
                bytes: "0",
                start: timestamp,
                end: timestamp,
                action: decision === "A" ? "ACCEPT" : decision === "D" ? "REJECT" : decision,
                "log-status": "OK",
                "flow-direction": direction
              },
              index + 1
            )
          );
        });
      });
    });
  });
  return { records, fields: ["azure-nsg"], errors: [] };
}

function parseGcpVpcFlowLogs(parsed) {
  const rows = Array.isArray(parsed) ? parsed : parsed.entries || parsed.logs || [];
  const records = [];
  rows.forEach((row, index) => {
    const payload = row.jsonPayload || row;
    const connection = payload.connection || payload;
    const source = connection.src_ip || connection.srcIp || connection.srcaddr;
    const destination = connection.dest_ip || connection.destIp || connection.dstaddr;
    if (!source || !destination) return;
    records.push(
      normalizeRecord(
        {
          version: "gcp-vpc",
          "account-id": row.resource?.labels?.project_id || payload.project_id || "-",
          "interface-id": row.resource?.labels?.subnetwork_name || payload.vpc || "gcp-vpc",
          srcaddr: source,
          dstaddr: destination,
          srcport: connection.src_port || connection.srcPort || "-",
          dstport: connection.dest_port || connection.destPort || "-",
          protocol: connection.protocol || payload.protocol || "-",
          packets: payload.packets_sent || payload.packets || "0",
          bytes: payload.bytes_sent || payload.bytes || "0",
          start: payload.start_time || row.timestamp || payload.start || "-",
          end: payload.end_time || row.receiveTimestamp || payload.end || "-",
          action: payload.disposition === "DENIED" ? "REJECT" : "ACCEPT",
          "log-status": "OK"
        },
        index + 1
      )
    );
  });
  return { records, fields: ["gcp-vpc"], errors: [] };
}

function unwrapLogText(text) {
  const source = String(text || "");
  const trimmed = source.trim();
  if (!trimmed) {
    return "";
  }

  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed);
      const messages = collectMessages(parsed);
      if (messages.length) {
        return messages.join("\n");
      }
    } catch {
      return unwrapJsonLines(source);
    }
  }

  return unwrapJsonLines(source);
}

function unwrapJsonLines(text) {
  const messages = [];
  let sawJson = false;
  const lines = String(text || "").split(/\r?\n/);

  lines.forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) {
      if (trimmed) {
        messages.push(line);
      }
      return;
    }

    try {
      const parsed = JSON.parse(trimmed);
      const extracted = collectMessages(parsed);
      if (extracted.length) {
        sawJson = true;
        messages.push(...extracted);
        return;
      }
    } catch {
      // Keep the original line if it is not a complete JSON record.
    }

    messages.push(line);
  });

  return sawJson ? messages.join("\n") : String(text || "");
}

function collectMessages(value) {
  if (!value) {
    return [];
  }
  if (typeof value === "string") {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.flatMap(collectMessages);
  }
  if (typeof value === "object") {
    if (typeof value.message === "string") {
      return [value.message];
    }
    if (Array.isArray(value.logEvents)) {
      return value.logEvents.flatMap(collectMessages);
    }
    if (value.event) {
      return collectMessages(value.event);
    }
    if (value.record) {
      return collectMessages(value.record);
    }
  }
  return [];
}

function splitFields(input) {
  return String(input)
    .replace(/,/g, " ")
    .split(/\s+/)
    .filter(Boolean);
}

function normalizeFields(fields) {
  return fields
    .map((field) => String(field).trim().replace(/^[$#]+/, "").toLowerCase())
    .filter(Boolean);
}

function looksLikeHeader(fields) {
  const knownCount = fields.filter((field) => KNOWN_FIELDS.has(field)).length;
  return knownCount >= 3 && fields.some((field) => field === "srcaddr" || field === "dstaddr" || field === "interface-id");
}

function detectDelimiter(line) {
  return line.includes(",") && line.split(",").length > line.trim().split(/\s+/).length ? "comma" : "space";
}

function splitLine(line, delimiter) {
  if (delimiter === "comma") {
    return parseCsvLine(line).map(cleanValue);
  }
  return line.split(/\s+/).map(cleanValue);
}

function parseCsvLine(line) {
  const result = [];
  let value = "";
  let quoted = false;

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    const next = line[i + 1];
    if (char === "\"" && quoted && next === "\"") {
      value += "\"";
      i += 1;
    } else if (char === "\"") {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      result.push(value);
      value = "";
    } else {
      value += char;
    }
  }

  result.push(value);
  return result;
}

function cleanValue(value) {
  const cleaned = String(value ?? "").trim();
  if (!cleaned || cleaned === "-") {
    return "-";
  }
  return cleaned.replace(/^"|"$/g, "");
}

function normalizeRecord(raw, lineNumber) {
  const source = firstValue(raw, ["srcaddr", "pkt-srcaddr"]);
  const destination = firstValue(raw, ["dstaddr", "pkt-dstaddr"]);
  const srcPort = toNumber(firstValue(raw, ["srcport"]));
  const dstPort = toNumber(firstValue(raw, ["dstport"]));
  const protocolValue = firstValue(raw, ["protocol"]);
  const protocol = normalizeProtocol(protocolValue);
  const start = toTimestamp(firstValue(raw, ["start"]));
  const end = toTimestamp(firstValue(raw, ["end"]));
  const packets = toNumber(firstValue(raw, ["packets"])) || 0;
  const bytes = toNumber(firstValue(raw, ["bytes"])) || 0;
  const action = normalizeAction(firstValue(raw, ["action"]));
  const logStatus = firstValue(raw, ["log-status"]) || "-";

  return {
    raw,
    lineNumber,
    accountId: firstValue(raw, ["account-id"]),
    interfaceId: firstValue(raw, ["interface-id"]),
    source,
    destination,
    srcPort,
    dstPort,
    protocolValue,
    protocol,
    packets,
    bytes,
    start,
    end,
    action,
    logStatus,
    flowDirection: firstValue(raw, ["flow-direction"]),
    trafficPath: firstValue(raw, ["traffic-path"])
  };
}

function firstValue(raw, names) {
  for (const name of names) {
    if (raw[name] && raw[name] !== "-") {
      return raw[name];
    }
  }
  return "-";
}

function toNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function toTimestamp(value) {
  if (!value || value === "-") {
    return null;
  }
  const numeric = Number(value);
  if (Number.isFinite(numeric)) {
    return numeric > 9999999999 ? numeric : numeric * 1000;
  }
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function normalizeProtocol(value) {
  if (!value || value === "-") {
    return "-";
  }
  const key = String(value).toUpperCase();
  return PROTOCOLS[key] || key;
}

function normalizeAction(value) {
  const upper = String(value || "-").toUpperCase();
  if (upper === "ACCEPT" || upper === "REJECT") {
    return upper;
  }
  return "-";
}

function classifyApplication(record) {
  const enriched = lookupEnrichment(record.destination) || lookupEnrichment(record.source);
  if (enriched?.app) return enriched.app;
  if (enriched?.category) return enriched.category;
  if (record.protocol === "ICMP" || record.protocol === "ICMPv6") return record.protocol;
  if (record.dstPort && SERVICE_PORTS.has(record.dstPort)) return SERVICE_PORTS.get(record.dstPort);
  if (record.dstPort) return `${record.protocol}/${record.dstPort}`;
  return record.protocol || "Unknown";
}

function analyzeRecords(records, errors) {
  const totals = records.reduce(
    (acc, record) => {
      acc.bytes += record.bytes;
      acc.packets += record.packets;
      if (record.action === "ACCEPT") acc.accepted += 1;
      if (record.action === "REJECT") acc.rejected += 1;
      if (record.logStatus === "NODATA") acc.noData += 1;
      if (record.logStatus === "SKIPDATA") acc.skipData += 1;
      if (record.source !== "-") acc.sources.add(record.source);
      if (record.destination !== "-") acc.destinations.add(record.destination);
      return acc;
    },
    {
      bytes: 0,
      packets: 0,
      accepted: 0,
      rejected: 0,
      noData: 0,
      skipData: 0,
      sources: new Set(),
      destinations: new Set()
    }
  );

  const acceptedBytes = sumBy(records.filter((record) => record.action === "ACCEPT"), "bytes");
  const rejectedBytes = sumBy(records.filter((record) => record.action === "REJECT"), "bytes");
  const minStart = minTimestamp(records.map((record) => record.start));
  const maxEnd = maxTimestamp(records.map((record) => record.end || record.start));
  const findings = buildFindings(records, errors);
  const detections = findings.filter((detection) => detection.severity !== "low");
  const observations = findings.filter((detection) => detection.severity === "low");
  const entityRisk = buildEntityRisk(records, findings);

  return {
    totals,
    acceptedBytes,
    rejectedBytes,
    timeRange: { start: minStart, end: maxEnd },
    topSources: rank(records, (record) => record.source, "bytes"),
    topDestinations: rank(records, (record) => record.destination, "bytes"),
    topPorts: rank(records.filter((record) => record.dstPort), (record) => String(record.dstPort), "bytes"),
    applicationMix: rank(records, (record) => classifyApplication(record), "bytes"),
    protocolMix: rank(records, (record) => record.protocol, "bytes"),
    topRejected: rank(
      records.filter((record) => record.action === "REJECT"),
      (record) => `${record.destination}:${record.dstPort || "*"}`,
      "count"
    ),
    internalPaths: rank(
      records.filter((record) => isPrivateIp(record.source) && isPrivateIp(record.destination)),
      (record) => `${record.source} -> ${record.destination}:${record.dstPort || "*"}`,
      "bytes"
    ),
    externalPaths: rank(
      records.filter(
        (record) =>
          (isPrivateIp(record.source) && isPublicIp(record.destination)) ||
          (isPublicIp(record.source) && isPrivateIp(record.destination))
      ),
      (record) => `${record.source} -> ${record.destination}:${record.dstPort || "*"}`,
      "bytes"
    ),
    timeline: buildTimeline(records),
    entityRisk,
    observations,
    detections,
    findings
  };
}

function sumBy(records, field) {
  return records.reduce((total, record) => total + (record[field] || 0), 0);
}

function minTimestamp(values) {
  const filtered = values.filter((value) => Number.isFinite(value));
  return filtered.length ? Math.min(...filtered) : null;
}

function maxTimestamp(values) {
  const filtered = values.filter((value) => Number.isFinite(value));
  return filtered.length ? Math.max(...filtered) : null;
}

function rank(records, keyFn, valueField) {
  const buckets = new Map();
  records.forEach((record) => {
    const key = keyFn(record);
    if (!key || key === "-" || key === "-:*") {
      return;
    }
    if (!buckets.has(key)) {
      buckets.set(key, { key, count: 0, bytes: 0, packets: 0, rejects: 0 });
    }
    const bucket = buckets.get(key);
    bucket.count += 1;
    bucket.bytes += record.bytes;
    bucket.packets += record.packets;
    if (record.action === "REJECT") bucket.rejects += 1;
  });

  return [...buckets.values()]
    .sort((a, b) => (b[valueField] || b.bytes || b.count) - (a[valueField] || a.bytes || a.count))
    .slice(0, 10);
}

function buildTimeline(records) {
  const timed = records.filter((record) => Number.isFinite(record.start));
  if (!timed.length) {
    return [];
  }

  const start = Math.min(...timed.map((record) => record.start));
  const end = Math.max(...timed.map((record) => record.end || record.start));
  const bucketCount = Math.min(18, Math.max(6, Math.ceil(Math.sqrt(timed.length))));
  const span = Math.max(1, end - start);
  const size = Math.max(1, Math.ceil(span / bucketCount));
  const buckets = Array.from({ length: bucketCount }, (_, index) => ({
    start: start + index * size,
    bytes: 0,
    rejects: 0,
    count: 0
  }));

  timed.forEach((record) => {
    const index = Math.min(bucketCount - 1, Math.floor((record.start - start) / size));
    buckets[index].bytes += record.bytes;
    buckets[index].count += 1;
    if (record.action === "REJECT") {
      buckets[index].rejects += 1;
    }
  });

  return buckets;
}

function buildFindings(records, errors) {
  const findings = [];
  const total = records.length;
  const rejected = records.filter((record) => record.action === "REJECT");
  const rejectedRate = total ? rejected.length / total : 0;
  const skipData = records.filter((record) => record.logStatus === "SKIPDATA").length;
  const noData = records.filter((record) => record.logStatus === "NODATA").length;

  if (!total) {
    findings.push(createDetection({
      severity: "medium",
      title: "No flow records parsed",
      copy: "The input did not produce VPC flow records. Check whether the file includes a field header or the default VPC Flow Logs field order.",
      tactic: "Telemetry Quality",
      technique: "Parser coverage",
      entity: "Input source",
      confidence: 0.9,
      response: ["Confirm the export format and include a #Fields header when using custom VPC Flow Log formats."],
      tags: ["Parser"]
    }));
    return findings;
  }

  if (errors.length) {
    findings.push(createDetection({
      severity: "medium",
      title: "Some lines were skipped",
      copy: `${errors.length} line${errors.length === 1 ? "" : "s"} had fewer columns than expected.`,
      tactic: "Telemetry Quality",
      technique: "Collection gap",
      entity: "Input source",
      confidence: 0.85,
      response: ["Review skipped lines before relying on detection counts for incident scope."],
      tags: ["Parser"]
    }));
  }

  if (rejectedRate >= 0.35 && rejected.length >= 5) {
    findings.push(createDetection({
      severity: "high",
      title: "High rejection rate",
      copy: `${formatPercent(rejectedRate)} of parsed records were rejected. This can indicate blocked scans, misrouted traffic, or restrictive security group changes.`,
      tactic: "Reconnaissance",
      technique: "Network Service Discovery",
      entity: "Environment",
      confidence: 0.72,
      response: ["Pivot to rejected targets and validate whether one source is sweeping multiple services or hosts."],
      tags: ["REJECT", `${rejected.length} records`],
      records: rejected
    }));
  }

  if (skipData > 0) {
    findings.push(createDetection({
      severity: "high",
      title: "Skipped log data",
      copy: `${skipData} record${skipData === 1 ? "" : "s"} reported SKIPDATA, so the analysis may be missing traffic during those intervals.`,
      tactic: "Telemetry Quality",
      technique: "Visibility gap",
      entity: "Collector",
      confidence: 0.95,
      response: ["Treat this as an NDR blind spot and validate CloudWatch delivery or S3 export health."],
      tags: ["Log status"]
    }));
  }

  if (noData > 0) {
    findings.push(createDetection({
      severity: "low",
      title: "No-data intervals present",
      copy: `${noData} interval${noData === 1 ? "" : "s"} had NODATA status. This is normal for quiet ENIs but useful when validating collection coverage.`,
      tactic: "Telemetry Quality",
      technique: "Quiet interval",
      entity: "Collector",
      confidence: 0.9,
      response: ["Confirm the affected ENIs are expected to be idle during the analyzed period."],
      tags: ["Log status"]
    }));
  }

  findings.push(...findSensitiveRejects(rejected));
  findings.push(...findPortFanOut(records));
  findings.push(...findLateralAdminAccess(records));
  findings.push(...findBeaconing(records));
  findings.push(...findDnsExfiltration(records));
  findings.push(...findLargeTransfers(records));
  findings.push(...findPublicAdminAccepts(records));
  findings.push(...findUnusualProtocols(records));

  if (!findings.length) {
    findings.push(createDetection({
      severity: "low",
      title: "No obvious NDR detections",
      copy: "The parsed records do not show high rejection rates, sensitive-port probing, lateral access, beaconing, public admin access, or unusually large transfers.",
      tactic: "Baseline",
      technique: "No notable behavior",
      entity: "Environment",
      confidence: 0.65,
      response: ["Use the entity leaderboard and filtered records to validate expected application paths."],
      tags: ["Baseline"]
    }));
  }

  return findings
    .sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity) || b.confidence - a.confidence)
    .map((finding, index) => ({ ...finding, id: `NDR-${String(index + 1).padStart(3, "0")}` }));
}

function createDetection({
  severity,
  title,
  copy,
  tactic,
  technique,
  entity,
  confidence = 0.7,
  response = [],
  tags = [],
  records = []
}) {
  return {
    severity,
    title,
    copy,
    tactic,
    technique,
    entity,
    confidence,
    response,
    tags,
    records
  };
}

function findSensitiveRejects(rejected) {
  const groups = new Map();
  rejected.forEach((record) => {
    if (!SENSITIVE_PORTS.has(record.dstPort)) {
      return;
    }
    const key = `${record.source}->${record.destination}:${record.dstPort}`;
    if (!groups.has(key)) {
      groups.set(key, {
        source: record.source,
        destination: record.destination,
        port: record.dstPort,
        service: SENSITIVE_PORTS.get(record.dstPort),
        count: 0
      });
    }
    groups.get(key).count += 1;
  });

  return [...groups.values()]
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
    .map((group) => createDetection({
      severity: group.count >= 3 ? "high" : "medium",
      title: `Rejected ${group.service} traffic`,
      copy: `${group.source} hit ${group.destination}:${group.port} ${group.count} time${group.count === 1 ? "" : "s"}.`,
      tactic: "Reconnaissance",
      technique: "Service probing",
      entity: group.source,
      confidence: group.count >= 3 ? 0.78 : 0.62,
      response: ["Check whether the source attempted adjacent ports or other destinations in the same time window."],
      tags: ["Sensitive port", "REJECT", group.service]
    }));
}

function findPortFanOut(records) {
  const bySource = new Map();
  records.forEach((record) => {
    if (record.source === "-" || !record.dstPort) {
      return;
    }
    if (!bySource.has(record.source)) {
      bySource.set(record.source, { ports: new Set(), destinations: new Set(), count: 0, rejects: 0 });
    }
    const item = bySource.get(record.source);
    item.ports.add(record.dstPort);
    item.destinations.add(record.destination);
    item.count += 1;
    if (record.action === "REJECT") item.rejects += 1;
  });

  return [...bySource.entries()]
    .filter(([, item]) => item.ports.size >= 15 || item.destinations.size >= 25)
    .sort((a, b) => b[1].ports.size + b[1].destinations.size - (a[1].ports.size + a[1].destinations.size))
    .slice(0, 4)
    .map(([source, item]) => createDetection({
      severity: item.rejects / item.count > 0.5 ? "high" : "medium",
      title: "Source fan-out detected",
      copy: `${source} contacted ${item.destinations.size} destination${item.destinations.size === 1 ? "" : "s"} across ${item.ports.size} port${item.ports.size === 1 ? "" : "s"}.`,
      tactic: "Discovery",
      technique: "Network scanning",
      entity: source,
      confidence: item.ports.size >= 25 || item.destinations.size >= 50 ? 0.86 : 0.7,
      response: ["Contain or investigate the source if this pattern is not produced by a scanner, load balancer, or approved monitoring job."],
      tags: ["Scanning pattern", `${item.count} records`]
    }));
}

function findLateralAdminAccess(records) {
  const groups = new Map();
  records.forEach((record) => {
    if (
      record.action !== "ACCEPT" ||
      !SENSITIVE_PORTS.has(record.dstPort) ||
      !isPrivateIp(record.source) ||
      !isPrivateIp(record.destination) ||
      record.source === record.destination
    ) {
      return;
    }
    const key = `${record.source}->${record.destination}:${record.dstPort}`;
    if (!groups.has(key)) {
      groups.set(key, { source: record.source, destination: record.destination, port: record.dstPort, bytes: 0, count: 0, records: [] });
    }
    const group = groups.get(key);
    group.bytes += record.bytes;
    group.count += 1;
    group.records.push(record);
  });

  return [...groups.values()]
    .sort((a, b) => b.count - a.count || b.bytes - a.bytes)
    .slice(0, 5)
    .map((group) => createDetection({
      severity: "medium",
      title: `Internal ${SENSITIVE_PORTS.get(group.port)} access`,
      copy: `${group.source} reached ${group.destination}:${group.port} inside the private address space.`,
      tactic: "Lateral Movement",
      technique: "Remote Services",
      entity: group.source,
      confidence: 0.68,
      response: ["Validate the source workload identity and confirm this internal service path is expected."],
      tags: ["East-West", "ACCEPT", SENSITIVE_PORTS.get(group.port)],
      records: group.records
    }));
}

function findBeaconing(records) {
  const groups = new Map();
  records.forEach((record) => {
    if (
      record.action !== "ACCEPT" ||
      !Number.isFinite(record.start) ||
      !isPrivateIp(record.source) ||
      !isPublicIp(record.destination) ||
      record.protocol === "ICMP"
    ) {
      return;
    }
    const key = `${record.source}->${record.destination}:${record.dstPort || "*"}:${record.protocol}`;
    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key).push(record);
  });

  return [...groups.entries()]
    .map(([key, group]) => ({ key, group: group.sort((a, b) => a.start - b.start), score: beaconScore(group) }))
    .filter((item) => item.group.length >= 4 && item.score >= 0.72)
    .sort((a, b) => b.score - a.score)
    .slice(0, 4)
    .map((item) => createDetection({
      severity: item.score >= 0.86 ? "high" : "medium",
      title: "Periodic outbound connection pattern",
      copy: `${item.key} produced ${item.group.length} accepted connections on a regular cadence.`,
      tactic: "Command and Control",
      technique: "Beaconing",
      entity: item.group[0].source,
      confidence: item.score,
      response: ["Inspect the destination reputation and compare the cadence against known agent, update, or telemetry schedules."],
      tags: ["Beaconing", "Outbound"],
      records: item.group
    }));
}

function beaconScore(records) {
  const intervals = [];
  const sorted = records.slice().sort((a, b) => a.start - b.start);
  for (let index = 1; index < sorted.length; index += 1) {
    intervals.push(sorted[index].start - sorted[index - 1].start);
  }
  if (intervals.length < 3) {
    return 0;
  }
  const average = intervals.reduce((total, value) => total + value, 0) / intervals.length;
  if (average < 30000) {
    return 0;
  }
  const variance = intervals.reduce((total, value) => total + (value - average) ** 2, 0) / intervals.length;
  const deviation = Math.sqrt(variance);
  const regularity = Math.max(0, 1 - deviation / average);
  const volumeConsistency = byteConsistency(sorted);
  return Math.max(0, Math.min(0.95, regularity * 0.8 + volumeConsistency * 0.15));
}

function byteConsistency(records) {
  const values = records.map((record) => record.bytes);
  const average = values.reduce((total, value) => total + value, 0) / values.length;
  if (!average) {
    return 1;
  }
  return 1 - Math.min(1, (Math.max(...values) - Math.min(...values)) / average);
}

function findDnsExfiltration(records) {
  const groups = new Map();
  records.forEach((record) => {
    if (
      record.action !== "ACCEPT" ||
      record.dstPort !== 53 ||
      !isPrivateIp(record.source) ||
      !isPublicIp(record.destination)
    ) {
      return;
    }
    const key = `${record.source}->${record.destination}`;
    if (!groups.has(key)) {
      groups.set(key, { source: record.source, destination: record.destination, bytes: 0, count: 0, records: [] });
    }
    const group = groups.get(key);
    group.bytes += record.bytes;
    group.count += 1;
    group.records.push(record);
  });

  return [...groups.values()]
    .filter((group) => group.count >= 200 || group.bytes >= 5 * 1024 * 1024 || (group.count >= 5 && group.bytes / group.count >= 1200))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 4)
    .map((group) => createDetection({
      severity: group.bytes >= 20 * 1024 * 1024 || group.count >= 1000 ? "high" : "medium",
      title: "Suspicious DNS volume",
      copy: `${group.source} sent ${formatBytes(group.bytes)} across ${formatNumber(group.count)} DNS flow${group.count === 1 ? "" : "s"} to ${group.destination}.`,
      tactic: "Exfiltration",
      technique: "Exfiltration Over Alternative Protocol",
      entity: group.source,
      confidence: 0.66,
      response: ["Inspect DNS query logs for long labels, high entropy domains, and unusual resolver destinations."],
      tags: ["DNS", "Outbound"],
      records: group.records
    }));
}

function findLargeTransfers(records) {
  const accepted = records.filter((record) => record.action === "ACCEPT" && record.bytes > 0);
  if (accepted.length < 5) {
    return [];
  }
  const sorted = accepted.map((record) => record.bytes).sort((a, b) => a - b);
  const p95 = sorted[Math.floor(sorted.length * 0.95)] || sorted[sorted.length - 1];
  const threshold = Math.max(p95, 10 * 1024 * 1024);

  return accepted
    .filter((record) => record.bytes >= threshold)
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 3)
    .map((record) => createDetection({
      severity: isPrivateIp(record.source) && isPublicIp(record.destination) ? "high" : isPublicIp(record.destination) ? "medium" : "low",
      title: "Large accepted transfer",
      copy: `${record.source}:${record.srcPort || "*"} sent ${formatBytes(record.bytes)} to ${record.destination}:${record.dstPort || "*"}.`,
      tactic: isPrivateIp(record.source) && isPublicIp(record.destination) ? "Exfiltration" : "Impact",
      technique: "High-volume flow",
      entity: record.source,
      confidence: isPrivateIp(record.source) && isPublicIp(record.destination) ? 0.72 : 0.58,
      response: ["Validate the destination owner, expected data volume, and whether the source normally sends traffic to this service."],
      tags: ["ACCEPT", record.protocol],
      records: [record]
    }));
}

function findPublicAdminAccepts(records) {
  return records
    .filter(
      (record) =>
        record.action === "ACCEPT" &&
        SENSITIVE_PORTS.has(record.dstPort) &&
        isPublicIp(record.source) &&
        isPrivateIp(record.destination)
    )
    .slice(0, 5)
    .map((record) => createDetection({
      severity: "high",
      title: `Public ${SENSITIVE_PORTS.get(record.dstPort)} access accepted`,
      copy: `${record.source} reached ${record.destination}:${record.dstPort}. Verify this is expected and tightly scoped.`,
      tactic: "Initial Access",
      technique: "External Remote Services",
      entity: record.destination,
      confidence: 0.84,
      response: ["Confirm the security group scope, source ownership, authentication strength, and whether this service should be publicly reachable."],
      tags: ["Public source", "ACCEPT", SENSITIVE_PORTS.get(record.dstPort)],
      records: [record]
    }));
}

function findUnusualProtocols(records) {
  const allowed = new Set(["TCP", "UDP", "ICMP", "ICMPV6", "-"]);
  const groups = new Map();
  records.forEach((record) => {
    if (record.action !== "ACCEPT" || allowed.has(record.protocol)) {
      return;
    }
    const key = `${record.protocol}:${record.source}->${record.destination}`;
    if (!groups.has(key)) {
      groups.set(key, { protocol: record.protocol, source: record.source, destination: record.destination, count: 0, bytes: 0, records: [] });
    }
    const group = groups.get(key);
    group.count += 1;
    group.bytes += record.bytes;
    group.records.push(record);
  });

  return [...groups.values()]
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 4)
    .map((group) => createDetection({
      severity: isPublicIp(group.destination) || isPublicIp(group.source) ? "medium" : "low",
      title: `Unusual accepted protocol ${group.protocol}`,
      copy: `${group.source} communicated with ${group.destination} using ${group.protocol} across ${group.count} flow${group.count === 1 ? "" : "s"}.`,
      tactic: "Defense Evasion",
      technique: "Non-standard network protocol",
      entity: group.source,
      confidence: 0.55,
      response: ["Validate this protocol against approved network architecture and expected workload behavior."],
      tags: ["Protocol", group.protocol],
      records: group.records
    }));
}

function buildEntityRisk(records, detections) {
  const entities = new Map();

  records.forEach((record) => {
    updateEntity(entities, record.source, record, "source");
    updateEntity(entities, record.destination, record, "destination");
  });

  detections.forEach((detection) => {
    const related = detection.records && detection.records.length ? detection.records : [];
    const entityKeys = new Set([detection.entity, ...related.flatMap((record) => [record.source, record.destination])]);
    entityKeys.forEach((key) => {
      if (!key || key === "-" || key === "Environment" || key === "Collector" || key === "Input source") {
        return;
      }
      if (!entities.has(key)) {
        entities.set(key, createEntity(key));
      }
      const entity = entities.get(key);
      entity.risk += severityWeight(detection.severity) * 12 + Math.round((detection.confidence || 0.5) * 8);
      entity.detections += 1;
      entity.tags.add(detection.tactic || "Detection");
      if (detection.severity === "high") {
        entity.high += 1;
      }
    });
  });

  return [...entities.values()]
    .map((entity) => ({
      ...entity,
      risk: Math.min(100, Math.round(entity.risk)),
      ports: entity.ports.size,
      peers: entity.peers.size,
      tags: [...entity.tags].slice(0, 5)
    }))
    .sort((a, b) => b.risk - a.risk || b.bytes - a.bytes)
    .slice(0, 15);
}

function createEntity(key) {
  return {
    key,
    risk: isPublicIp(key) ? 4 : isPrivateIp(key) ? 2 : 0,
    bytes: 0,
    packets: 0,
    accepted: 0,
    rejected: 0,
    detections: 0,
    high: 0,
    ports: new Set(),
    peers: new Set(),
    tags: new Set(isPublicIp(key) ? ["Public"] : isPrivateIp(key) ? ["Private"] : [])
  };
}

function updateEntity(entities, key, record, side) {
  if (!key || key === "-") {
    return;
  }
  if (!entities.has(key)) {
    entities.set(key, createEntity(key));
  }
  const entity = entities.get(key);
  entity.bytes += record.bytes;
  entity.packets += record.packets;
  if (record.action === "ACCEPT") {
    entity.accepted += 1;
  }
  if (record.action === "REJECT") {
    entity.rejected += 1;
    entity.risk += side === "source" ? 2 : 1;
  }
  if (record.dstPort) {
    entity.ports.add(record.dstPort);
  }
  const peer = side === "source" ? record.destination : record.source;
  if (peer && peer !== "-") {
    entity.peers.add(peer);
  }
  if (SENSITIVE_PORTS.has(record.dstPort)) {
    entity.tags.add(SENSITIVE_PORTS.get(record.dstPort));
  }
}

function severityWeight(severity) {
  return { high: 3, medium: 2, low: 1 }[severity] || 0;
}

function applyFilters() {
  const query = els.searchInput.value.trim().toLowerCase();
  const action = els.actionFilter.value;
  const protocol = els.protocolFilter.value;

  state.filtered = state.records.filter((record) => {
    const matchesAction = action === "all" || record.action === action;
    const matchesProtocol = protocol === "all" || record.protocol === protocol;
    const haystack = [
      record.interfaceId,
      record.source,
      record.destination,
      record.srcPort,
      record.dstPort,
      record.protocol,
      record.action,
      record.logStatus
    ]
      .join(" ")
      .toLowerCase();
    const matchesSearch = !query || haystack.includes(query);
    return matchesAction && matchesProtocol && matchesSearch;
  });

  renderRecordsTable();
}

function refreshProtocolFilter(records) {
  const current = els.protocolFilter.value;
  const protocols = [...new Set(records.map((record) => record.protocol).filter((protocol) => protocol !== "-"))].sort();
  els.protocolFilter.innerHTML = `<option value="all">All protocols</option>${protocols
    .map((protocol) => `<option value="${escapeHtml(protocol)}">${escapeHtml(protocol)}</option>`)
    .join("")}`;
  if (protocols.includes(current)) {
    els.protocolFilter.value = current;
  }
}

function renderDashboard() {
  if (!state.analysis) {
    renderEmptyDashboard();
    return;
  }

  const { analysis } = state;
  const total = state.records.length;
  const rejectRate = total ? analysis.totals.rejected / total : 0;
  const highDetections = analysis.detections.filter((detection) => detection.severity === "high").length;
  const maxRisk = analysis.entityRisk[0]?.risk || 0;

  els.metricGrid.innerHTML = [
    metricTemplate("NDR risk", String(maxRisk), `${highDetections} high severity`),
    metricTemplate("Detections", formatNumber(analysis.detections.length), "investigation queue"),
    metricTemplate("Entities", formatNumber(analysis.entityRisk.length), `${formatNumber(analysis.totals.sources.size)} sources`),
    metricTemplate("Rejected", formatNumber(analysis.totals.rejected), formatPercent(rejectRate)),
    metricTemplate("Data volume", formatBytes(analysis.totals.bytes), `${formatNumber(analysis.totals.packets)} packets`)
  ].join("");

  els.timeRangeLabel.textContent = formatRange(analysis.timeRange.start, analysis.timeRange.end);
  renderTimeline(analysis.timeline);
  renderPriorityEntities(els.priorityEntities, analysis.entityRisk);
  renderRankList(els.topPorts, analysis.topPorts, "bytes");
  renderRankList(els.topRejected, analysis.topRejected, "count");
  renderRankList(els.protocolMix, analysis.protocolMix, "bytes");
  renderRankList(els.internalPaths, analysis.internalPaths, "bytes");
  renderRankList(els.externalPaths, analysis.externalPaths, "bytes");
  renderEntityRisk(analysis.entityRisk);
  renderFindings(analysis.detections);
  renderObservations(analysis.observations || []);
  renderApplicationMix();
  renderCoverage();
  renderHistory();
  renderSavedHunts();
  renderOptimization();
  renderAnalystSummary();
  renderPolicyRecommendations();
  renderTopology();
  if (!state.selectedEntity && analysis.entityRisk[0]) {
    selectEntity(analysis.entityRisk[0].key, false);
  } else {
    renderEntityDetail();
  }
  renderImportQuality();
}

function renderEmptyDashboard() {
  setStatus("No log loaded", "");
  els.metricGrid.innerHTML = [
    metricTemplate("NDR risk", "0", "No source data"),
    metricTemplate("Detections", "0", "investigation queue"),
    metricTemplate("Entities", "0", "0 sources"),
    metricTemplate("Rejected", "0", "0%"),
    metricTemplate("Data volume", "0 B", "0 packets")
  ].join("");
  els.timelineChart.style.setProperty("--bucket-count", 1);
  els.timelineChart.innerHTML = emptyState();
  els.timeRangeLabel.textContent = "-";
  [els.priorityEntities, els.topPorts, els.topRejected, els.protocolMix, els.findingList, els.entityRiskList, els.internalPaths, els.externalPaths].forEach((el) => {
    el.innerHTML = emptyState();
  });
  [
    els.observationList,
    els.savedHuntsList,
    els.coverageGrid,
    els.sourceWatchlist,
    els.historyList,
    els.applicationMix,
    els.aiAnswerPanel,
    els.analystSummary,
    els.policyRecommendations,
    els.entityDetail,
    els.topologyCanvas
  ].forEach((el) => {
    if (el) el.innerHTML = emptyState();
  });
  els.findingCount.textContent = "0";
  els.entityCountLabel.textContent = "0 entities";
  els.observationCount.textContent = "0";
  els.coverageScoreLabel.textContent = "0% covered";
  els.entityDetailTitle.textContent = "Select an entity";
  els.entityDetailMeta.textContent = "No entity selected";
  els.replayTimeLabel.textContent = "All evidence";
  state.huntResults = [];
  renderHuntResults();
  renderSavedHunts();
  renderCoverage();
  renderHistory();
  renderOptimization();
  renderImportQuality();
  renderRecordsTable();
}

function metricTemplate(label, value, detail) {
  return `<article class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><em>${escapeHtml(detail)}</em></article>`;
}

function renderImportQuality() {
  const issues = state.errors || [];
  els.parseIssueCount.textContent = String(issues.length);

  if (!state.records.length && !issues.length) {
    els.parseIssueList.innerHTML = `<div class="issue-item"><strong>Waiting for evidence</strong>Upload or paste flow records to validate import quality.</div>`;
    return;
  }

  if (!issues.length) {
    els.parseIssueList.innerHTML = `<div class="issue-item"><strong>No parser issues</strong>${escapeHtml(formatNumber(state.records.length))} records parsed using ${escapeHtml(formatNumber(state.fields.length))} fields.</div>`;
    return;
  }

  els.parseIssueList.innerHTML = issues
    .slice(0, 5)
    .map((issue) => `<div class="issue-item"><strong>Line ${escapeHtml(issue.line)}</strong>${escapeHtml(issue.message)}</div>`)
    .join("");
}

function renderTimeline(buckets) {
  if (!buckets.length) {
    els.timelineChart.style.setProperty("--bucket-count", 1);
    els.timelineChart.innerHTML = emptyState();
    return;
  }

  const maxBytes = Math.max(...buckets.map((bucket) => bucket.bytes), 1);
  const maxRejects = Math.max(...buckets.map((bucket) => bucket.rejects), 1);
  els.timelineChart.style.setProperty("--bucket-count", buckets.length);
  els.timelineChart.innerHTML = buckets
    .map((bucket) => {
      const bytesHeight = Math.max(2, Math.round((bucket.bytes / maxBytes) * 155));
      const rejectHeight = bucket.rejects ? Math.max(4, Math.round((bucket.rejects / maxRejects) * 55)) : 0;
      return `<div class="bar-stack" title="${escapeHtml(formatDate(bucket.start))}: ${formatBytes(bucket.bytes)}, ${bucket.rejects} rejects">
        <div class="bar" style="height:${bytesHeight}px"></div>
        ${rejectHeight ? `<div class="bar rejects" style="height:${rejectHeight}px"></div>` : ""}
        <div class="bar-label">${escapeHtml(formatShortTime(bucket.start))}</div>
      </div>`;
    })
    .join("");
}

function renderRankList(container, rows, valueField) {
  if (!rows.length) {
    container.innerHTML = emptyState();
    return;
  }
  const max = Math.max(...rows.map((row) => row[valueField] || row.bytes || row.count), 1);
  container.innerHTML = rows
    .map((row) => {
      const value = row[valueField] || row.bytes || row.count;
      const label = valueField === "bytes" ? formatBytes(value) : formatNumber(value);
      return `<div class="rank-item">
        <span class="rank-label" title="${escapeHtml(row.key)}">${escapeHtml(row.key)}</span>
        <span class="rank-value">${escapeHtml(label)}</span>
        <div class="rank-bar"><span style="width:${Math.max(3, Math.round((value / max) * 100))}%"></span></div>
      </div>`;
    })
    .join("");
}

function renderPriorityEntities(container, rows) {
  if (!rows.length) {
    container.innerHTML = emptyState();
    return;
  }
  const max = Math.max(...rows.slice(0, 8).map((row) => row.risk), 1);
  container.innerHTML = rows
    .slice(0, 8)
    .map(
      (row) => `<div class="rank-item">
        <span class="rank-label" title="${escapeHtml(row.key)}">${escapeHtml(row.key)}</span>
        <span class="rank-value">${escapeHtml(String(row.risk))}</span>
        <div class="rank-bar"><span style="width:${Math.max(4, Math.round((row.risk / max) * 100))}%"></span></div>
      </div>`
    )
    .join("");
}

function renderEntityRisk(rows) {
  els.entityCountLabel.textContent = `${formatNumber(rows.length)} entit${rows.length === 1 ? "y" : "ies"}`;
  if (!rows.length) {
    els.entityRiskList.innerHTML = emptyState();
    return;
  }
  els.entityRiskList.innerHTML = rows
    .map(
      (entity) => `<article class="entity-card" data-entity="${escapeHtml(entity.key)}" tabindex="0">
        <div class="entity-name" title="${escapeHtml(entity.key)}">${escapeHtml(entity.key)}</div>
        <div class="risk-score ${riskClass(entity.risk)}">${escapeHtml(String(entity.risk))}</div>
        <div class="entity-meta">
          <span class="tag">${escapeHtml(formatBytes(entity.bytes))}</span>
          <span class="tag">${escapeHtml(formatNumber(entity.peers))} peers</span>
          <span class="tag">${escapeHtml(formatNumber(entity.ports))} ports</span>
          <span class="tag ${entity.rejected ? "red" : "green"}">${escapeHtml(formatNumber(entity.rejected))} rejects</span>
          <span class="tag ${entity.high ? "red" : "green"}">${escapeHtml(formatNumber(entity.detections))} detections</span>
          ${entity.tags.map((tag) => `<span class="tag">${escapeHtml(tag)}</span>`).join("")}
        </div>
      </article>`
    )
    .join("");
}

function selectEntity(entityKey, switchTab = true) {
  state.selectedEntity = entityKey;
  renderEntityDetail();
  if (switchTab) activateTab("entities");
}

function renderEntityDetail() {
  const entityKey = state.selectedEntity;
  const records = state.records.filter((record) => record.source === entityKey || record.destination === entityKey);
  const detections = (state.analysis?.detections || []).filter(
    (detection) =>
      detection.entity === entityKey ||
      (detection.records || []).some((record) => record.source === entityKey || record.destination === entityKey)
  );

  if (!entityKey || !records.length) {
    els.entityDetailTitle.textContent = "Select an entity";
    els.entityDetailMeta.textContent = "No entity selected";
    els.entityDetail.innerHTML = emptyState();
    return;
  }

  const peers = new Set(records.flatMap((record) => [record.source, record.destination]).filter((value) => value && value !== entityKey && value !== "-"));
  const ports = new Set(records.map((record) => record.dstPort).filter(Boolean));
  const bytes = sumBy(records, "bytes");
  const rejects = records.filter((record) => record.action === "REJECT").length;
  const first = minTimestamp(records.map((record) => record.start));
  const last = maxTimestamp(records.map((record) => record.end || record.start));

  els.entityDetailTitle.textContent = entityKey;
  els.entityDetailMeta.textContent = `${formatRange(first, last)}`;
  els.entityDetail.innerHTML = `<div class="entity-detail-grid">
    <div class="detail-tile"><span>Traffic</span><strong>${escapeHtml(formatBytes(bytes))}</strong></div>
    <div class="detail-tile"><span>Peers</span><strong>${escapeHtml(formatNumber(peers.size))}</strong></div>
    <div class="detail-tile"><span>Ports</span><strong>${escapeHtml(formatNumber(ports.size))}</strong></div>
    <div class="detail-tile"><span>Detections</span><strong>${escapeHtml(formatNumber(detections.length))}</strong></div>
    <div class="detail-tile"><span>Rejected flows</span><strong>${escapeHtml(formatNumber(rejects))}</strong></div>
  </div>
  <div class="rank-list">
    ${rank(records, (record) => (record.source === entityKey ? record.destination : record.source), "bytes")
      .slice(0, 6)
      .map(
        (peer) => `<div class="rank-item">
          <span class="rank-label">${escapeHtml(peer.key)}</span>
          <span class="rank-value">${escapeHtml(formatBytes(peer.bytes))}</span>
          <div class="rank-bar"><span style="width:${Math.max(4, Math.round((peer.bytes / Math.max(bytes, 1)) * 100))}%"></span></div>
        </div>`
      )
      .join("")}
  </div>`;
}

function renderObservations(observations) {
  els.observationCount.textContent = String(observations.length);
  if (!observations.length) {
    els.observationList.innerHTML = emptyState();
    return;
  }
  els.observationList.innerHTML = observations
    .slice(0, 8)
    .map(
      (observation) => `<article class="finding ${escapeHtml(observation.severity)}">
        <span class="severity"></span>
        <div>
          <div class="finding-title">${escapeHtml(observation.title)}</div>
          <p class="finding-copy">${escapeHtml(observation.copy)}</p>
          <div class="finding-meta">
            ${observation.tactic ? `<span class="tag">${escapeHtml(observation.tactic)}</span>` : ""}
            ${observation.entity ? `<span class="tag">${escapeHtml(observation.entity)}</span>` : ""}
            ${(observation.tags || []).map((tag) => `<span class="tag">${escapeHtml(tag)}</span>`).join("")}
          </div>
        </div>
      </article>`
    )
    .join("");
}

function renderFindings(findings) {
  const severity = els.severityFilter?.value || "all";
  const visible = severity === "all" ? findings : findings.filter((finding) => finding.severity === severity);
  els.findingCount.textContent = severity === "all" ? String(findings.length) : `${visible.length}/${findings.length}`;

  if (!visible.length) {
    els.findingList.innerHTML = emptyState();
    return;
  }

  els.findingList.innerHTML = visible
    .map(
      (finding) => `<article class="finding ${escapeHtml(finding.severity)}">
        <span class="severity"></span>
        <div>
          <div class="finding-head">
            <div class="finding-title">${escapeHtml(finding.id ? `${finding.id} - ${finding.title}` : finding.title)}</div>
            <span class="confidence">${escapeHtml(formatPercent(finding.confidence || 0))}</span>
          </div>
          <p class="finding-copy">${escapeHtml(finding.copy)}</p>
          <div class="finding-meta">
            <span class="tag ${tagClass(finding.severity)}">${escapeHtml(finding.severity.toUpperCase())}</span>
            ${finding.tactic ? `<span class="tag">${escapeHtml(finding.tactic)}</span>` : ""}
            ${finding.technique ? `<span class="tag">${escapeHtml(finding.technique)}</span>` : ""}
            ${finding.entity ? `<span class="tag">${escapeHtml(finding.entity)}</span>` : ""}
            ${finding.tags.map((tag) => `<span class="tag">${escapeHtml(tag)}</span>`).join("")}
          </div>
          ${finding.response?.length ? `<div class="response-list"><strong>Response:</strong> ${escapeHtml(finding.response[0])}</div>` : ""}
          <div class="evidence-row">
            <span>${escapeHtml(detectionEvidenceText(finding))}</span>
            ${isSearchableEntity(finding.entity) ? `<button class="mini-button" type="button" data-filter-entity="${escapeHtml(finding.entity)}">Evidence</button>` : ""}
          </div>
        </div>
      </article>`
    )
    .join("");
}

function detectionEvidenceText(finding) {
  const records = finding.records || [];
  if (!records.length) {
    return "No linked record sample";
  }
  const starts = records.map((record) => record.start).filter((value) => Number.isFinite(value));
  const range = starts.length ? `${formatShortTime(Math.min(...starts))} to ${formatShortTime(Math.max(...starts))}` : "time unknown";
  return `${formatNumber(records.length)} evidence record${records.length === 1 ? "" : "s"} - ${range}`;
}

function isSearchableEntity(entity) {
  return Boolean(entity && entity !== "-" && entity !== "Environment" && entity !== "Collector" && entity !== "Input source");
}

function renderRecordsTable() {
  els.recordCountLabel.textContent = `${formatNumber(state.filtered.length)} record${state.filtered.length === 1 ? "" : "s"}`;
  if (!state.filtered.length) {
    els.recordsTable.innerHTML = `<tr><td colspan="8">${emptyState()}</td></tr>`;
    renderSortState();
    return;
  }

  const sorted = sortedRecords(state.filtered);
  els.recordsTable.innerHTML = sorted
    .slice(0, 500)
    .map(
      (record) => `<tr>
        <td>${escapeHtml(formatDate(record.start))}</td>
        <td><span class="action ${record.action === "REJECT" ? "reject" : ""}">${escapeHtml(record.action)}</span></td>
        <td class="mono">${escapeHtml(formatEndpoint(record.source, record.srcPort))}</td>
        <td class="mono">${escapeHtml(formatEndpoint(record.destination, record.dstPort))}</td>
        <td>${escapeHtml(record.protocol)}</td>
        <td>${escapeHtml(formatNumber(record.packets))}</td>
        <td>${escapeHtml(formatBytes(record.bytes))}</td>
        <td>${escapeHtml(record.logStatus)}</td>
      </tr>`
    )
    .join("");
  renderSortState();
}

function setRecordSort(field) {
  if (state.sort.field === field) {
    state.sort.direction = state.sort.direction === "asc" ? "desc" : "asc";
  } else {
    state.sort = { field, direction: field === "start" || field === "bytes" || field === "packets" ? "desc" : "asc" };
  }
  renderRecordsTable();
}

function sortedRecords(records) {
  const { field, direction } = state.sort;
  const modifier = direction === "asc" ? 1 : -1;
  return records.slice().sort((a, b) => {
    const left = sortValue(a, field);
    const right = sortValue(b, field);
    if (typeof left === "number" && typeof right === "number") {
      return (left - right) * modifier;
    }
    return String(left).localeCompare(String(right)) * modifier;
  });
}

function sortValue(record, field) {
  const value = record[field];
  if (field === "start") return Number.isFinite(value) ? value : 0;
  if (field === "bytes" || field === "packets") return value || 0;
  return value || "";
}

function renderSortState() {
  document.querySelectorAll("[data-sort]").forEach((button) => {
    const isActive = button.dataset.sort === state.sort.field;
    button.classList.toggle("active", isActive);
    button.classList.toggle("asc", isActive && state.sort.direction === "asc");
    button.setAttribute("aria-sort", isActive ? (state.sort.direction === "asc" ? "ascending" : "descending") : "none");
  });
}

function runAdvancedHunt() {
  const query = els.huntInput.value.trim();
  state.huntResults = query ? state.records.filter((record) => matchesHunt(record, query)) : state.records.slice();
  renderHuntResults();
}

function matchesHunt(record, query) {
  const risk = entityRiskFor(record.source) + entityRiskFor(record.destination);
  const app = classifyApplication(record).toLowerCase();
  return query
    .split(/\s+/)
    .filter(Boolean)
    .every((token) => {
      const lower = token.toLowerCase();
      const comparison = lower.match(/^(bytes|packets|risk)([<>]=?)(\d+)$/);
      if (comparison) {
        const value = comparison[1] === "risk" ? risk : record[comparison[1]];
        return compareNumber(value, comparison[2], Number(comparison[3]));
      }
      const field = lower.match(/^([a-z]+):(.+)$/);
      if (!field) {
        return [record.source, record.destination, record.interfaceId, record.action, record.protocol, record.logStatus, app].join(" ").toLowerCase().includes(lower);
      }
      const [, key, value] = field;
      const target = {
        src: record.source,
        source: record.source,
        dst: record.destination,
        dest: record.destination,
        destination: record.destination,
        port: String(record.dstPort || record.srcPort || ""),
        action: record.action,
        proto: record.protocol,
        protocol: record.protocol,
        status: record.logStatus,
        eni: record.interfaceId,
        app
      }[key];
      return String(target || "").toLowerCase().includes(value);
    });
}

function compareNumber(left, operator, right) {
  if (operator === ">") return left > right;
  if (operator === ">=") return left >= right;
  if (operator === "<") return left < right;
  if (operator === "<=") return left <= right;
  return false;
}

function entityRiskFor(entity) {
  return state.analysis?.entityRisk.find((item) => item.key === entity)?.risk || 0;
}

function renderHuntResults() {
  const rows = state.huntResults.length ? state.huntResults : [];
  if (!rows.length) {
    els.huntResultsTable.innerHTML = `<tr><td colspan="6">${emptyState()}</td></tr>`;
    return;
  }
  els.huntResultsTable.innerHTML = rows
    .slice(0, 300)
    .map(
      (record) => `<tr>
        <td>${escapeHtml(formatDate(record.start))}</td>
        <td class="mono">${escapeHtml(formatEndpoint(record.source, record.srcPort))}</td>
        <td class="mono">${escapeHtml(formatEndpoint(record.destination, record.dstPort))}</td>
        <td><span class="action ${record.action === "REJECT" ? "reject" : ""}">${escapeHtml(record.action)}</span></td>
        <td>${escapeHtml(classifyApplication(record))}</td>
        <td>${escapeHtml(formatBytes(record.bytes))}</td>
      </tr>`
    )
    .join("");
}

function saveCurrentHunt() {
  const query = els.huntInput.value.trim();
  if (!query) {
    setInputMessage("Enter a hunt query before saving it.");
    return;
  }
  const hunts = loadJson(STORAGE_KEYS.hunts, []);
  if (!hunts.includes(query)) {
    hunts.unshift(query);
    saveJson(STORAGE_KEYS.hunts, hunts.slice(0, 20));
    showToast("Hunt saved.");
  } else {
    showToast("That hunt is already saved.", "warn");
  }
  renderSavedHunts();
}

function renderSavedHunts() {
  const hunts = loadJson(STORAGE_KEYS.hunts, []);
  if (!hunts.length) {
    els.savedHuntsList.innerHTML = emptyState();
    return;
  }
  els.savedHuntsList.innerHTML = hunts
    .map((hunt) => `<div class="rank-item clickable" data-hunt="${escapeHtml(hunt)}">
      <span class="rank-label">${escapeHtml(hunt)}</span>
      <span class="rank-value">
        <button class="mini-button" type="button" data-hunt="${escapeHtml(hunt)}">Run</button>
        <button class="mini-button danger" type="button" data-delete-hunt="${escapeHtml(hunt)}">Delete</button>
      </span>
    </div>`)
    .join("");
}

function deleteSavedHunt(query) {
  confirmAction({
    title: "Delete saved hunt?",
    body: `This removes the saved query "${query}" from this browser.`,
    confirmLabel: "Delete Hunt",
    onConfirm: () => {
      const hunts = loadJson(STORAGE_KEYS.hunts, []).filter((hunt) => hunt !== query);
      saveJson(STORAGE_KEYS.hunts, hunts);
      renderSavedHunts();
      showToast("Saved hunt deleted.");
    }
  });
}

function clearSavedHunts() {
  const hunts = loadJson(STORAGE_KEYS.hunts, []);
  if (!hunts.length) {
    showToast("No saved hunts to clear.", "warn");
    return;
  }
  confirmAction({
    title: "Clear all saved hunts?",
    body: "This removes every saved hunt query stored in this browser.",
    confirmLabel: "Clear Hunts",
    onConfirm: () => {
      saveJson(STORAGE_KEYS.hunts, []);
      renderSavedHunts();
      showToast("Saved hunts cleared.");
    }
  });
}

function renderCoverage() {
  const sources = loadJson(STORAGE_KEYS.sources, []);
  renderSourceWatchlist(sources);
  const interfaces = new Set(state.records.map((record) => record.interfaceId).filter((value) => value && value !== "-"));
  const expected = new Set(sources.flatMap((source) => source.scope).filter((value) => value.startsWith("eni-")));
  const missing = [...expected].filter((eni) => !interfaces.has(eni));
  const skipData = state.records.filter((record) => record.logStatus === "SKIPDATA").length;
  const noData = state.records.filter((record) => record.logStatus === "NODATA").length;
  const covered = expected.size ? Math.round(((expected.size - missing.length) / expected.size) * 100) : interfaces.size ? 100 : 0;
  els.coverageScoreLabel.textContent = `${covered}% covered`;
  els.coverageGrid.innerHTML = [
    coverageTile("Observed ENIs", formatNumber(interfaces.size), "Current evidence"),
    coverageTile("Expected ENIs", formatNumber(expected.size), "Source watchlist"),
    coverageTile("Missing ENIs", formatNumber(missing.length), missing.slice(0, 3).join(", ") || "None"),
    coverageTile("NODATA / SKIPDATA", `${formatNumber(noData)} / ${formatNumber(skipData)}`, "Collector quality"),
    coverageTile("Accounts", formatNumber(uniqueRawValues("account-id").size), "Parsed fields"),
    coverageTile("Regions", formatNumber(uniqueRawValues("region").size), "Requires custom fields")
  ].join("");
}

function coverageTile(label, value, detail) {
  return `<div class="coverage-tile"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><span>${escapeHtml(detail)}</span></div>`;
}

function uniqueRawValues(field) {
  return new Set(state.records.map((record) => record.raw?.[field]).filter((value) => value && value !== "-"));
}

function saveSourceConfig() {
  const name = els.sourceNameInput.value.trim();
  const scope = els.sourceScopeInput.value.split(/\s+/).map((value) => value.trim()).filter(Boolean);
  if (!name || !scope.length) {
    setInputMessage("Add a source name and at least one expected ENI or CIDR.");
    return;
  }
  const invalid = scope.filter((value) => !isValidScopeValue(value));
  if (invalid.length) {
    setInputMessage(`Invalid source scope: ${invalid.slice(0, 3).join(", ")}. Use ENI IDs, IPv4 CIDRs, or IP addresses.`);
    return;
  }
  const sources = loadJson(STORAGE_KEYS.sources, []);
  const existingIndex = sources.findIndex((source) => source.name.toLowerCase() === name.toLowerCase());
  const item = { id: existingIndex >= 0 ? sources[existingIndex].id : Date.now(), name, scope };
  if (existingIndex >= 0) {
    sources.splice(existingIndex, 1, item);
  } else {
    sources.unshift(item);
  }
  saveJson(STORAGE_KEYS.sources, sources.slice(0, 20));
  els.sourceNameInput.value = "";
  els.sourceScopeInput.value = "";
  renderCoverage();
  showToast(existingIndex >= 0 ? "Source watchlist updated." : "Source watchlist saved.");
}

function isValidScopeValue(value) {
  return /^eni-[a-z0-9]+$/i.test(value) || /^(\d{1,3}\.){3}\d{1,3}(\/([0-9]|[12][0-9]|3[0-2]))?$/.test(value);
}

function renderSourceWatchlist(sources) {
  if (!sources.length) {
    els.sourceWatchlist.innerHTML = `<div class="issue-item"><strong>No expected sources</strong>Add ENIs or CIDRs to measure blind spots.</div>`;
    return;
  }
  els.sourceWatchlist.innerHTML = sources
    .slice(0, 6)
    .map((source) => `<div class="issue-item">
      <strong>${escapeHtml(source.name)}</strong>
      <span>${escapeHtml(source.scope.join(", "))}</span>
      <button class="mini-button danger inline-action" type="button" data-delete-source="${escapeHtml(source.id)}">Delete</button>
    </div>`)
    .join("");
}

function deleteSourceConfig(id) {
  const sources = loadJson(STORAGE_KEYS.sources, []);
  const source = sources.find((item) => String(item.id) === String(id));
  if (!source) return;
  confirmAction({
    title: "Delete source watchlist entry?",
    body: `This removes "${source.name}" from coverage scoring in this browser.`,
    confirmLabel: "Delete Source",
    onConfirm: () => {
      saveJson(STORAGE_KEYS.sources, sources.filter((item) => String(item.id) !== String(id)));
      renderCoverage();
      showToast("Source watchlist entry deleted.");
    }
  });
}

function clearSourceConfigs() {
  const sources = loadJson(STORAGE_KEYS.sources, []);
  if (!sources.length) {
    showToast("No source watchlist entries to clear.", "warn");
    return;
  }
  confirmAction({
    title: "Clear source watchlist?",
    body: "This removes all expected source definitions used for blind-spot scoring.",
    confirmLabel: "Clear Sources",
    onConfirm: () => {
      saveJson(STORAGE_KEYS.sources, []);
      renderCoverage();
      showToast("Source watchlist cleared.");
    }
  });
}

function persistHistory(fileName, analysis) {
  const history = loadJson(STORAGE_KEYS.history, []);
  history.unshift({
    id: Date.now(),
    fileName,
    createdAt: new Date().toISOString(),
    records: state.records.length,
    detections: analysis.detections.length,
    high: analysis.detections.filter((detection) => detection.severity === "high").length,
    entities: analysis.entityRisk.length,
    bytes: analysis.totals.bytes,
    signatures: buildBaselineSignature(analysis)
  });
  saveJson(STORAGE_KEYS.history, history.slice(0, 30));
}

function renderHistory() {
  const history = loadJson(STORAGE_KEYS.history, []);
  if (!history.length) {
    els.historyList.innerHTML = emptyState();
    return;
  }
  els.historyList.innerHTML = history
    .slice(0, 8)
    .map(
      (item) => `<div class="rank-item">
        <span class="rank-label">${escapeHtml(item.fileName || "Evidence run")}</span>
        <span class="rank-value">${escapeHtml(formatNumber(item.detections))} det.</span>
        <div class="rank-bar"><span style="width:${Math.max(4, Math.min(100, item.high * 30 + 5))}%"></span></div>
      </div>`
    )
    .join("");
}

function clearHistory() {
  const history = loadJson(STORAGE_KEYS.history, []);
  if (!history.length) {
    showToast("No ingest history to clear.", "warn");
    return;
  }
  confirmAction({
    title: "Clear ingest history?",
    body: "This removes the stored list of previous analysis runs from this browser. It does not clear the current evidence.",
    confirmLabel: "Clear History",
    onConfirm: () => {
      saveJson(STORAGE_KEYS.history, []);
      renderHistory();
      showToast("Ingest history cleared.");
    }
  });
}

function saveCurrentBaseline() {
  if (!state.analysis) {
    setInputMessage("Analyze evidence before saving a baseline.");
    return;
  }
  saveJson(STORAGE_KEYS.baseline, {
    createdAt: new Date().toISOString(),
    records: state.records.length,
    signatures: buildBaselineSignature(state.analysis)
  });
  showToast("Baseline saved. Future imports will flag new peers, ports, and applications.");
}

function deleteBaseline() {
  const baseline = loadJson(STORAGE_KEYS.baseline, null);
  if (!baseline) {
    showToast("No saved baseline to delete.", "warn");
    return;
  }
  confirmAction({
    title: "Delete saved baseline?",
    body: "This removes baseline comparison data from this browser. Future imports will stop producing baseline-drift observations until you save a new baseline.",
    confirmLabel: "Delete Baseline",
    onConfirm: () => {
      removeJson(STORAGE_KEYS.baseline);
      showToast("Baseline deleted.");
    }
  });
}

function buildBaselineSignature(analysis) {
  return {
    entities: analysis.entityRisk.map((entity) => entity.key),
    ports: analysis.topPorts.map((port) => port.key),
    apps: (analysis.applicationMix || []).map((app) => app.key),
    paths: [...analysis.internalPaths, ...analysis.externalPaths].map((path) => path.key)
  };
}

function applyBaselineObservations(analysis) {
  const baseline = loadJson(STORAGE_KEYS.baseline, null);
  if (!baseline?.signatures) return;
  const additions = [];
  additions.push(...newSetObservations("New entity", analysis.entityRisk.map((entity) => entity.key), baseline.signatures.entities, "Discovery"));
  additions.push(...newSetObservations("New destination port", analysis.topPorts.map((port) => port.key), baseline.signatures.ports, "Application Behavior"));
  additions.push(...newSetObservations("New application", (analysis.applicationMix || []).map((app) => app.key), baseline.signatures.apps, "Application Intelligence"));
  additions.push(...newSetObservations("New path", [...analysis.internalPaths, ...analysis.externalPaths].map((path) => path.key), baseline.signatures.paths, "Traffic Path"));
  analysis.observations = [...(analysis.observations || []), ...additions].slice(0, 30);
  analysis.findings = [...analysis.detections, ...analysis.observations.filter((item) => !analysis.detections.includes(item))];
}

function newSetObservations(title, current, previous = [], tactic) {
  const known = new Set(previous);
  return current
    .filter((item) => item && !known.has(item))
    .slice(0, 5)
    .map((item) =>
      createDetection({
        severity: "low",
        title,
        copy: `${item} was not present in the saved baseline.`,
        tactic,
        technique: "Baseline drift",
        entity: item,
        confidence: 0.6,
        response: ["Validate whether this is expected change or suspicious drift."],
        tags: ["Baseline"]
      })
    );
}

function applyEnrichmentInput() {
  const parsed = parseEnrichment(els.enrichmentInput.value);
  if (!Object.keys(parsed).length) {
    setInputMessage("No enrichment rows were recognized. Use JSONL or CSV with ip/dst/domain/sni/app fields.");
    return;
  }
  state.enrichment = { ...state.enrichment, ...parsed };
  saveJson(STORAGE_KEYS.enrichment, state.enrichment);
  if (state.analysis) {
    enrichAnalysis(state.analysis);
    renderDashboard();
  }
  setInputMessage(`${formatNumber(Object.keys(parsed).length)} enrichment item${Object.keys(parsed).length === 1 ? "" : "s"} applied.`);
}

async function refreshBackendStatus() {
  if (!backendApi) return;
  try {
    const [health, auth, ai] = await Promise.all([backendApi.backendHealth(), backendApi.authConfig(), backendApi.aiConfig()]);
    const store = health.storeMode === "dynamodb" ? "DynamoDB" : "local store";
    els.backendStatusLabel.textContent = health.awsConfigured ? `Backend ready - ${store}, AWS credentials detected` : `Backend ready - ${store}, AWS credentials missing`;
    renderAiStatus(ai, health.awsConfigured);
    await renderBackendAuth(auth);
    await renderBackendJobs();
  } catch {
    els.backendStatusLabel.textContent = "Backend offline - run npm start";
    els.authStatusLabel.textContent = "Backend offline";
    els.authRoleLabel.textContent = "Cloud ingest and schedules are unavailable until the backend starts.";
    els.ssoLoginButton.disabled = true;
    renderAiStatus({ enabled: false }, false);
  }
}

function renderAiStatus(config, awsConfigured) {
  const enabled = Boolean(config?.enabled);
  els.aiStatusLabel.textContent = enabled ? `${config.modelId} in ${config.region}` : "Feature flag off";
  const disabled = !enabled || !awsConfigured;
  els.askAiButton.disabled = disabled;
  els.summarizeAiButton.disabled = disabled;
  els.aiQuestionInput.disabled = disabled;
  if (!enabled) {
    els.aiAnswerPanel.innerHTML = `<div class="empty-state"><strong>Bedrock disabled</strong><span>Set NDR_BEDROCK_ENABLED=true and configure AWS credentials to use AI assistance.</span></div>`;
  } else if (!awsConfigured) {
    els.aiAnswerPanel.innerHTML = `<div class="empty-state"><strong>AWS credentials missing</strong><span>Configure local AWS credentials or run with an ECS task role before asking Bedrock.</span></div>`;
  }
}

async function renderBackendAuth(auth) {
  els.apiKeyInput.value = backendApi.getApiKey();
  els.ssoLoginButton.disabled = !auth.enabled;
  try {
    const { principal } = await backendApi.currentPrincipal();
    const roles = principal?.roles?.length ? principal.roles.join(", ") : "viewer";
    els.authStatusLabel.textContent = principal?.authType === "oidc" ? `Signed in as ${principal.name || principal.subject}` : principal?.authType === "api-key" ? "API key session" : "Local admin session";
    els.authRoleLabel.textContent = `Roles: ${roles}. Admin can delete jobs and export audit; analyst can ingest and run jobs; viewer can inspect.`;
  } catch {
    els.authStatusLabel.textContent = auth.enabled ? "SSO required" : "API key required";
    els.authRoleLabel.textContent = auth.enabled ? `Use ${auth.issuer} and mapped groups for access.` : "Save the backend API key to use cloud ingest and schedules.";
  }
}

async function saveBackendApiKey() {
  if (!backendApi) return;
  backendApi.saveApiKey(els.apiKeyInput.value.trim());
  showToast(els.apiKeyInput.value.trim() ? "API key saved for this browser." : "API key cleared.");
  await refreshBackendStatus();
}

async function startSsoLogin() {
  if (!backendApi) return;
  try {
    const config = await backendApi.authConfig();
    await backendApi.beginSsoLogin(config);
  } catch (error) {
    setInputMessage(error.message);
  }
}

async function signOutBackend() {
  if (!backendApi) return;
  backendApi.clearCredentials();
  els.apiKeyInput.value = "";
  showToast("Signed out of backend access.");
  await refreshBackendStatus();
}

async function ingestFromS3() {
  if (!backendApi) return setInputMessage("Backend module is not available.");
  try {
    setBusy(true, "Ingesting S3");
    const result = await backendApi.ingestS3({
      region: els.s3RegionInput.value.trim(),
      bucket: els.s3BucketInput.value.trim(),
      prefix: els.s3PrefixInput.value.trim(),
      maxObjects: 20
    });
    els.pasteInput.value = result.text;
    runAnalysis(result.text, result.sourceLabel);
    showToast(`Imported ${formatNumber(result.objectCount || 0)} S3 objects.`);
  } catch (error) {
    setInputMessage(error.message);
  } finally {
    setBusy(false);
  }
}

async function ingestFromCloudWatch() {
  if (!backendApi) return setInputMessage("Backend module is not available.");
  try {
    setBusy(true, "Ingesting CloudWatch");
    const result = await backendApi.ingestCloudWatch({
      region: els.cwRegionInput.value.trim(),
      logGroupName: els.cwGroupInput.value.trim(),
      filterPattern: els.cwFilterInput.value.trim(),
      limit: 2000
    });
    els.pasteInput.value = result.text;
    runAnalysis(result.text, result.sourceLabel);
    showToast(`Imported ${formatNumber(result.eventCount || 0)} CloudWatch events.`);
  } catch (error) {
    setInputMessage(error.message);
  } finally {
    setBusy(false);
  }
}

async function createIngestJob() {
  if (!backendApi) return setInputMessage("Backend module is not available.");
  const type = els.jobTypeInput.value;
  const config =
    type === "s3"
      ? { region: els.s3RegionInput.value.trim(), bucket: els.s3BucketInput.value.trim(), prefix: els.s3PrefixInput.value.trim(), maxObjects: 20 }
      : { region: els.cwRegionInput.value.trim(), logGroupName: els.cwGroupInput.value.trim(), filterPattern: els.cwFilterInput.value.trim(), limit: 2000 };
  try {
    await backendApi.createJob({
      name: els.jobNameInput.value.trim() || `${type.toUpperCase()} ingest`,
      type,
      intervalMinutes: Number(els.jobIntervalInput.value || 15),
      config
    });
    showToast("Scheduled ingest job created.");
    await renderBackendJobs();
  } catch (error) {
    setInputMessage(error.message);
  }
}

async function renderBackendJobs() {
  if (!backendApi) return;
  try {
    const jobs = await backendApi.listJobs();
    if (!jobs.length) {
      els.backendJobsList.innerHTML = emptyState();
      return;
    }
    els.backendJobsList.innerHTML = jobs
      .map(
        (job) => `<div class="rank-item">
          <span class="rank-label">${escapeHtml(job.name)} (${escapeHtml(job.type)})</span>
          <span class="rank-value">
            ${escapeHtml(job.lastStatus || "never")}
            <button class="mini-button" type="button" data-run-job="${escapeHtml(job.id)}">Run</button>
            <button class="mini-button danger" type="button" data-delete-job="${escapeHtml(job.id)}">Delete</button>
          </span>
          <div class="rank-bar"><span style="width:${job.enabled ? 100 : 8}%"></span></div>
        </div>`
      )
      .join("");
  } catch {
    els.backendJobsList.innerHTML = emptyState();
  }
}

async function runBackendJob(id) {
  try {
    const result = await backendApi.runJob(id);
    els.pasteInput.value = result.text || "";
    if (result.text) runAnalysis(result.text, result.sourceLabel || "Scheduled ingest");
    await renderBackendJobs();
  } catch (error) {
    setInputMessage(error.message);
  }
}

function deleteBackendJob(id) {
  confirmAction({
    title: "Delete scheduled ingest job?",
    body: "This removes the local schedule. It does not delete cloud data.",
    confirmLabel: "Delete Job",
    onConfirm: async () => {
      try {
        await backendApi.deleteJob(id);
        await renderBackendJobs();
        showToast("Scheduled job deleted.");
      } catch (error) {
        setInputMessage(error.message);
      }
    }
  });
}

async function askBedrockAssistant(mode) {
  if (!backendApi) return setInputMessage("Backend module is not available.");
  if (!state.analysis) return setInputMessage("Analyze evidence before asking the AI assistant.");
  const question = els.aiQuestionInput.value.trim();
  if (mode === "answer" && question.length < 3) {
    setInputMessage("Ask a question before sending it to Bedrock.");
    return;
  }
  try {
    els.aiAnswerPanel.classList.add("loading");
    els.aiAnswerPanel.textContent = mode === "summary" ? "Generating Bedrock summary..." : "Asking Bedrock...";
    const result = await backendApi.askAi({
      mode,
      question,
      context: buildAiEvidenceContext()
    });
    els.aiAnswerPanel.classList.remove("loading");
    els.aiAnswerPanel.innerHTML = renderAiAnswer(result.answer);
    showToast(mode === "summary" ? "Bedrock summary generated." : "Bedrock answer ready.");
  } catch (error) {
    els.aiAnswerPanel.classList.remove("loading");
    els.aiAnswerPanel.innerHTML = `<div class="empty-state"><strong>AI request failed</strong><span>${escapeHtml(error.message)}</span></div>`;
    setInputMessage(error.message);
  }
}

function clearAiAssistant() {
  els.aiQuestionInput.value = "";
  els.aiAnswerPanel.classList.remove("loading");
  els.aiAnswerPanel.innerHTML = `<div class="empty-state"><strong>No AI response yet</strong><span>Ask a question about the current investigation evidence.</span></div>`;
}

function buildAiEvidenceContext() {
  const analysis = state.analysis || {};
  return {
    source: state.fileName || "Current browser evidence",
    generatedAt: new Date().toISOString(),
    metrics: {
      records: state.records.length,
      filteredRecords: state.filtered.length,
      detections: analysis.detections?.length || 0,
      observations: analysis.observations?.length || 0,
      highSeverity: (analysis.detections || []).filter((item) => item.severity === "high").length,
      rejected: state.records.filter((record) => record.action === "REJECT").length,
      bytes: sumBy(state.records, "bytes")
    },
    detections: (analysis.detections || []).slice(0, 10).map((detection) => ({
      severity: detection.severity,
      confidence: detection.confidence,
      title: detection.title,
      entity: detection.entity,
      tactic: detection.tactic,
      technique: detection.technique,
      summary: detection.copy,
      response: detection.response
    })),
    observations: (analysis.observations || []).slice(0, 8).map((item) => ({
      severity: item.severity,
      title: item.title,
      entity: item.entity,
      summary: item.copy
    })),
    priorityEntities: (analysis.entityRisk || []).slice(0, 10).map((entity) => ({
      entity: entity.key,
      risk: entity.risk,
      detections: entity.detections,
      rejects: entity.rejects,
      bytes: entity.bytes,
      ports: entity.ports
    })),
    topApplications: (analysis.applicationMix || []).slice(0, 8),
    topPorts: (analysis.topPorts || []).slice(0, 8),
    internalPaths: (analysis.internalPaths || []).slice(0, 8),
    externalPaths: (analysis.externalPaths || []).slice(0, 8),
    sampleRecords: state.filtered.slice(0, 25).map((record) => ({
      source: record.source,
      destination: record.destination,
      srcPort: record.srcPort,
      dstPort: record.dstPort,
      protocol: record.protocol,
      action: record.action,
      bytes: record.bytes,
      packets: record.packets,
      start: record.start,
      interfaceId: record.interfaceId,
      logStatus: record.logStatus
    }))
  };
}

function renderAiAnswer(answer) {
  const lines = String(answer || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (!lines.length) return emptyState();
  const blocks = [];
  let bulletGroup = [];
  const flushBullets = () => {
    if (bulletGroup.length) {
      blocks.push(`<ul>${bulletGroup.map((line) => `<li>${escapeHtml(line.replace(/^[-*]\s*/, ""))}</li>`).join("")}</ul>`);
      bulletGroup = [];
    }
  };
  lines.forEach((line) => {
    if (/^[-*]\s+/.test(line)) {
      bulletGroup.push(line);
      return;
    }
    flushBullets();
    blocks.push(`<p>${escapeHtml(line)}</p>`);
  });
  flushBullets();
  return blocks.join("");
}

function parseEnrichment(text) {
  const rows = {};
  String(text || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .forEach((line, index) => {
      let item = null;
      if (line.startsWith("{")) {
        try {
          item = JSON.parse(line);
        } catch {
          item = null;
        }
      } else {
        const values = parseCsvLine(line);
        if (index === 0 && values.some((value) => /ip|dst|domain|sni|app/i.test(value))) {
          rows.__header = values.map((value) => value.trim());
          return;
        }
        if (rows.__header) {
          item = {};
          rows.__header.forEach((field, fieldIndex) => {
            item[field] = values[fieldIndex];
          });
        }
      }
      const key = item?.ip || item?.dst || item?.destination || item?.domain || item?.sni || item?.host;
      if (key) {
        rows[key] = normalizeEnrichment(item);
      }
    });
  delete rows.__header;
  return rows;
}

function normalizeEnrichment(item) {
  const domain = item.domain || item.sni || item.host || "";
  return {
    ip: item.ip || item.dst || item.destination || "",
    domain,
    sni: item.sni || "",
    ja3: item.ja3 || "",
    certIssuer: item.certIssuer || item.issuer || "",
    app: item.app || inferAppFromDomain(domain),
    category: item.category || "",
    ai: item.ai === true || item.ai === "true" || AI_DOMAIN_HINTS.some((hint) => domain.includes(hint))
  };
}

function lookupEnrichment(key) {
  if (!key || key === "-") return null;
  return state.enrichment?.[key] || null;
}

function inferAppFromDomain(domain) {
  if (!domain) return "";
  const match = AI_DOMAIN_HINTS.find((hint) => domain.includes(hint));
  if (match) return "AI Service";
  if (/amazonaws|cloudfront|azure|googleapis/.test(domain)) return "Cloud Service";
  return "";
}

function enrichAnalysis(analysis) {
  analysis.applicationMix = rank(state.records, (record) => classifyApplication(record), "bytes");
  const aiRecords = state.records.filter((record) => {
    const enrichment = lookupEnrichment(record.destination) || lookupEnrichment(record.source);
    return enrichment?.ai;
  });
  if (aiRecords.length) {
    const bytes = sumBy(aiRecords, "bytes");
    const detection = createDetection({
      severity: "medium",
      title: "Unapproved AI service traffic candidate",
      copy: `${formatNumber(aiRecords.length)} flow${aiRecords.length === 1 ? "" : "s"} matched AI service enrichment hints totaling ${formatBytes(bytes)}.`,
      tactic: "Data Governance",
      technique: "Shadow AI Usage",
      entity: aiRecords[0].source,
      confidence: 0.7,
      response: ["Validate business approval for the AI destination and review whether sensitive data could be leaving the environment."],
      tags: ["AI", "Application Intelligence"],
      records: aiRecords
    });
    analysis.detections = [detection, ...analysis.detections].map((item, index) => ({ ...item, id: item.id || `NDR-${String(index + 1).padStart(3, "0")}` }));
    analysis.findings = [...analysis.detections, ...(analysis.observations || [])];
    analysis.entityRisk = buildEntityRisk(state.records, analysis.detections);
  }
}

function renderApplicationMix() {
  renderRankList(els.applicationMix, state.analysis?.applicationMix || [], "bytes");
}

function renderOptimization() {
  const records = state.records || [];
  if (!records.length) {
    els.optimizationResult.textContent = "0% reduction";
    return;
  }
  let kept = records.slice();
  if (els.dropAcceptedDns.checked) {
    kept = kept.filter((record) => !(record.action === "ACCEPT" && record.dstPort === 53));
  }
  if (els.dropNoData.checked) {
    kept = kept.filter((record) => record.logStatus !== "NODATA");
  }
  if (els.dedupeFlows.checked) {
    const seen = new Set();
    kept = kept.filter((record) => {
      const key = [record.source, record.destination, record.srcPort, record.dstPort, record.protocol, record.action].join("|");
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
  const sampleRate = Number(els.sampleRateInput.value || 100) / 100;
  const projected = Math.ceil(kept.length * sampleRate);
  const reduction = Math.max(0, Math.round((1 - projected / records.length) * 100));
  els.optimizationResult.textContent = `${reduction}% reduction - ${formatNumber(projected)} projected records`;
}

function renderAnalystSummary() {
  if (!state.analysis) {
    els.analystSummary.innerHTML = emptyState();
    return;
  }
  const high = state.analysis.detections.filter((detection) => detection.severity === "high");
  const topEntity = state.analysis.entityRisk[0];
  const apps = (state.analysis.applicationMix || []).slice(0, 3).map((item) => item.key).join(", ") || "none";
  els.analystSummary.innerHTML = `<h3>Executive Summary</h3>
    <p>${escapeHtml(formatNumber(state.records.length))} flow records produced ${escapeHtml(formatNumber(state.analysis.detections.length))} detections and ${escapeHtml(formatNumber(state.analysis.observations?.length || 0))} observations. ${escapeHtml(formatNumber(high.length))} detections are high severity.</p>
    <h3>Priority Entity</h3>
    <p>${topEntity ? `${escapeHtml(topEntity.key)} has risk ${escapeHtml(topEntity.risk)} with ${escapeHtml(formatNumber(topEntity.detections))} linked detections.` : "No priority entity yet."}</p>
    <h3>Top Applications</h3>
    <p>${escapeHtml(apps)}</p>
    <h3>Recommended Focus</h3>
    <ul>${state.analysis.detections
      .slice(0, 4)
      .map((detection) => `<li>${escapeHtml(detection.title)}: ${escapeHtml(detection.response?.[0] || detection.copy)}</li>`)
      .join("")}</ul>`;
}

function renderPolicyRecommendations() {
  const detections = state.analysis?.detections || [];
  const recommendations = [];
  detections.forEach((detection) => {
    if (/Public .* access accepted/.test(detection.title)) {
      recommendations.push(`Restrict ${detection.entity} security-group ingress to approved source ranges for ${detection.tags.slice(-1)[0] || "admin service"}.`);
    }
    if (/Rejected .* traffic/.test(detection.title)) {
      recommendations.push(`Consider temporary block or WAF rule for ${detection.entity} if probing repeats across multiple services.`);
    }
    if (/Large accepted transfer/.test(detection.title)) {
      recommendations.push(`Review egress policy and destination ownership for ${detection.entity}; require approved data-transfer path.`);
    }
    if (/Internal .* access/.test(detection.title)) {
      recommendations.push(`Validate east-west rule allowing ${detection.entity}; document or restrict lateral remote-service access.`);
    }
  });
  if (!recommendations.length) {
    els.policyRecommendations.innerHTML = emptyState();
    return;
  }
  els.policyRecommendations.innerHTML = [...new Set(recommendations)]
    .slice(0, 8)
    .map((item) => `<article class="finding low"><span class="severity"></span><div><div class="finding-title">Policy recommendation</div><p class="finding-copy">${escapeHtml(item)}</p></div></article>`)
    .join("");
}

async function persistEvidenceIndexedDb(fileName, records, analysis) {
  if (!idbApi?.saveEvidenceRun) return;
  try {
    await idbApi.saveEvidenceRun({ fileName, records, analysis });
  } catch (error) {
    showToast(`IndexedDB persistence failed: ${error.message}`, "warn");
  }
}

function createCaseFromTopDetection() {
  const detection = state.analysis?.detections?.[0];
  if (!detection) {
    setInputMessage("Analyze evidence with at least one detection before creating a case.");
    return;
  }
  els.caseTitleInput.value = els.caseQuickTitleInput.value.trim() || detection.title;
  els.caseAssigneeInput.value = els.caseQuickAssigneeInput.value.trim();
  els.caseSeverityInput.value = detection.severity;
  els.caseStatusInput.value = "New";
  els.caseNotesInput.value = `${detection.copy}\n\nResponse guidance: ${detection.response?.[0] || "Review linked evidence."}`;
  els.caseIdInput.value = "";
  activateTab("cases");
}

async function saveCaseForm() {
  if (!idbApi?.saveCase) return setInputMessage("Case storage is not available in this browser.");
  const title = els.caseTitleInput.value.trim();
  if (!title) return setInputMessage("Case title is required.");
  const record = await idbApi.saveCase({
    id: els.caseIdInput.value || undefined,
    title,
    assignee: els.caseAssigneeInput.value.trim() || "Unassigned",
    status: els.caseStatusInput.value,
    severity: els.caseSeverityInput.value,
    notes: els.caseNotesInput.value.trim(),
    linkedDetection: state.analysis?.detections?.[0]?.id || "",
    auditAction: els.caseIdInput.value ? "Case updated" : "Case created",
    auditDetail: title
  });
  els.caseIdInput.value = record.id;
  await refreshCases(record.id);
  showToast("Case saved.");
}

async function refreshCases(selectedId = "") {
  if (!idbApi?.listCases) return;
  const cases = await idbApi.listCases();
  els.caseCountLabel.textContent = String(cases.length);
  if (!cases.length) {
    els.caseList.innerHTML = emptyState();
    els.caseAuditList.innerHTML = emptyState();
    return;
  }
  els.caseList.innerHTML = cases
    .map(
      (item) => `<article class="entity-card">
        <div class="entity-name">${escapeHtml(item.title)}</div>
        <div class="risk-score ${riskClass(item.severity === "high" ? 85 : item.severity === "medium" ? 45 : 15)}">${escapeHtml(item.severity[0].toUpperCase())}</div>
        <div class="entity-meta">
          <span class="tag">${escapeHtml(item.status)}</span>
          <span class="tag">${escapeHtml(item.assignee || "Unassigned")}</span>
          <button class="mini-button" type="button" data-edit-case="${escapeHtml(item.id)}">Edit</button>
          <button class="mini-button danger" type="button" data-delete-case="${escapeHtml(item.id)}">Delete</button>
        </div>
      </article>`
    )
    .join("");
  await renderCaseAudit(selectedId || cases[0].id);
}

async function editCase(id) {
  const cases = await idbApi.listCases();
  const item = cases.find((caseItem) => caseItem.id === id);
  if (!item) return;
  els.caseIdInput.value = item.id;
  els.caseTitleInput.value = item.title;
  els.caseAssigneeInput.value = item.assignee;
  els.caseStatusInput.value = item.status;
  els.caseSeverityInput.value = item.severity;
  els.caseNotesInput.value = item.notes || "";
  await renderCaseAudit(item.id);
}

function deleteCaseById(id) {
  confirmAction({
    title: "Delete case?",
    body: "This deletes the local case record and appends an audit event. Evidence records are not deleted.",
    confirmLabel: "Delete Case",
    onConfirm: async () => {
      await idbApi.deleteCase(id);
      await refreshCases();
      showToast("Case deleted.");
    }
  });
}

async function renderCaseAudit(caseId) {
  if (!idbApi?.listAudit || !caseId) return;
  els.caseAuditTitle.textContent = `Case audit log`;
  const audit = await idbApi.listAudit(caseId);
  if (!audit.length) {
    els.caseAuditList.innerHTML = emptyState();
    return;
  }
  els.caseAuditList.innerHTML = audit
    .map((entry) => `<div class="issue-item"><strong>${escapeHtml(entry.action)}</strong>${escapeHtml(formatDate(Date.parse(entry.createdAt)))} - ${escapeHtml(entry.detail || "")}</div>`)
    .join("");
}

function renderTopology() {
  if (!topologyApi?.buildTopology) return;
  if (!state.records.length) {
    els.topologyCanvas.innerHTML = emptyState();
    return;
  }
  const times = state.records.map((record) => record.start).filter((value) => Number.isFinite(value)).sort((a, b) => a - b);
  const pct = Number(els.replayRangeInput.value || 100) / 100;
  const cutoff = times.length ? times[Math.min(times.length - 1, Math.floor((times.length - 1) * pct))] : Infinity;
  const topology = topologyApi.buildTopology(state.records, cutoff);
  els.topologyCanvas.innerHTML = topologyApi.renderTopologySvg(topology);
  els.replayTimeLabel.textContent = pct >= 1 ? "All evidence" : `Replay through ${formatDate(cutoff)}`;
}

function updateStatus() {
  const total = state.records.length;
  if (!total) {
    setStatus(state.errors.length ? "No records parsed" : "No log loaded", "warn");
    return;
  }
  const skipped = state.errors.length ? `, ${state.errors.length} skipped` : "";
  setStatus(`${formatNumber(total)} records${skipped}`, "ready");
}

function setStatus(text, className) {
  els.statusPill.className = `status-pill ${className}`;
  els.statusText.textContent = text;
}

function exportFilteredCsv() {
  if (!state.filtered.length) {
    setInputMessage("There are no filtered records to export.");
    return;
  }
  const headers = ["time", "action", "source", "srcport", "destination", "dstport", "protocol", "packets", "bytes", "logStatus", "interfaceId"];
  const lines = [
    headers.join(","),
    ...state.filtered.map((record) =>
      [
        formatDate(record.start),
        record.action,
        record.source,
        record.srcPort || "",
        record.destination,
        record.dstPort || "",
        record.protocol,
        record.packets,
        record.bytes,
        record.logStatus,
        record.interfaceId
      ]
        .map(csvValue)
        .join(",")
    )
  ];

  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "vpc-flow-analysis.csv";
  link.click();
  URL.revokeObjectURL(url);
}

function exportDetectionsCsv() {
  const allDetections = state.analysis?.detections || [];
  const severity = els.severityFilter?.value || "all";
  const detections = severity === "all" ? allDetections : allDetections.filter((detection) => detection.severity === severity);
  if (!detections.length) {
    setInputMessage("There are no detections to export for the current severity filter.");
    return;
  }
  const headers = ["id", "severity", "confidence", "entity", "tactic", "technique", "title", "summary", "response", "tags"];
  const lines = [
    headers.join(","),
    ...detections.map((detection) =>
      [
        detection.id,
        detection.severity,
        formatPercent(detection.confidence || 0),
        detection.entity || "",
        detection.tactic || "",
        detection.technique || "",
        detection.title,
        detection.copy,
        detection.response?.[0] || "",
        detection.tags.join("|")
      ]
        .map(csvValue)
        .join(",")
    )
  ];

  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "ndr-detections.csv";
  link.click();
  URL.revokeObjectURL(url);
}

function exportDetectionsStructured(format) {
  const detections = state.analysis?.detections || [];
  if (!detections.length) {
    setInputMessage("There are no detections to export.");
    return;
  }
  const payload =
    format === "ocsf"
      ? detections.map((detection) => ({
          class_name: "Detection Finding",
          activity_name: detection.title,
          severity: detection.severity,
          confidence: Math.round((detection.confidence || 0) * 100),
          finding_info: {
            uid: detection.id,
            title: detection.title,
            desc: detection.copy
          },
          resources: [{ name: detection.entity || "unknown", type: "network_entity" }],
          metadata: { product: { name: "SignalPrism NDR" }, labels: detection.tags }
        }))
      : detections;
  downloadText(format === "ocsf" ? "ndr-detections-ocsf.json" : "ndr-detections.json", JSON.stringify(payload, null, 2), "application/json");
}

function exportDetectionsCef() {
  const detections = state.analysis?.detections || [];
  if (!detections.length) {
    setInputMessage("There are no detections to export.");
    return;
  }
  const lines = detections.map((detection) => {
    const severity = { high: 8, medium: 5, low: 2 }[detection.severity] || 3;
    return `CEF:0|SignalPrism NDR|Cloud Flow NDR|1.0|${escapeCef(detection.id)}|${escapeCef(detection.title)}|${severity}|src=${escapeCef(detection.entity || "")} msg=${escapeCef(detection.copy)} cs1Label=Tactic cs1=${escapeCef(detection.tactic || "")} cs2Label=Technique cs2=${escapeCef(detection.technique || "")}`;
  });
  downloadText("ndr-detections.cef", lines.join("\n"), "text/plain");
}

function exportRedactedRecords() {
  if (!state.records.length) {
    setInputMessage("Analyze evidence before exporting redacted records.");
    return;
  }
  const rows = state.records.map((record) => ({
    time: formatDate(record.start),
    action: record.action,
    source: redactValue(record.source, "ip"),
    srcport: record.srcPort || "",
    destination: redactValue(record.destination, "ip"),
    dstport: record.dstPort || "",
    protocol: record.protocol,
    packets: record.packets,
    bytes: record.bytes,
    interfaceId: redactValue(record.interfaceId, "account"),
    accountId: redactValue(record.accountId, "account"),
    app: classifyApplication(record)
  }));
  downloadText("ndr-redacted-records.json", JSON.stringify(rows, null, 2), "application/json");
}

function redactValue(value, kind) {
  if (!value || value === "-") return value;
  if (kind === "ip" && els.maskIps.checked) {
    return isPrivateIp(value) || isPublicIp(value) ? `ip-${hashText(value).slice(0, 8)}` : value;
  }
  if (kind === "account" && els.maskAccounts.checked) {
    return String(value).replace(/[a-z0-9-]{6,}/gi, (match) => `id-${hashText(match).slice(0, 8)}`);
  }
  if (kind === "domain" && els.maskDomains.checked) {
    return `domain-${hashText(value).slice(0, 8)}`;
  }
  return value;
}

function hashText(text) {
  let hash = 2166136261;
  for (let index = 0; index < String(text).length; index += 1) {
    hash ^= String(text).charCodeAt(index);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return (hash >>> 0).toString(16);
}

function copyAnalystSummary() {
  const text = els.analystSummary.textContent.trim();
  if (!text) {
    setInputMessage("There is no summary to copy yet.");
    return;
  }
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text);
    setInputMessage("Analyst summary copied.");
  } else {
    setInputMessage("Clipboard API is not available in this browser.");
  }
}

function downloadText(fileName, text, type) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(url);
}

function escapeCef(value) {
  return String(value ?? "").replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/=/g, "\\=");
}

function csvValue(value) {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
}

function emptyState() {
  return els.emptyStateTemplate.innerHTML;
}

function tagClass(severity) {
  return severity === "high" ? "red" : severity === "medium" ? "amber" : "green";
}

function riskClass(risk) {
  if (risk >= 70) return "high";
  if (risk >= 35) return "medium";
  return "";
}

function formatEndpoint(ip, port) {
  return `${ip || "-"}${port ? `:${port}` : ""}`;
}

function formatBytes(bytes) {
  const value = Number(bytes) || 0;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let current = value;
  let index = 0;
  while (current >= 1024 && index < units.length - 1) {
    current /= 1024;
    index += 1;
  }
  const decimals = current >= 10 || index === 0 ? 0 : 1;
  return `${current.toFixed(decimals)} ${units[index]}`;
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value) || 0);
}

function formatPercent(value) {
  return `${Math.round((Number(value) || 0) * 100)}%`;
}

function formatDate(timestamp) {
  if (!Number.isFinite(timestamp)) {
    return "-";
  }
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  }).format(new Date(timestamp));
}

function formatShortTime(timestamp) {
  if (!Number.isFinite(timestamp)) {
    return "-";
  }
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit"
  }).format(new Date(timestamp));
}

function formatRange(start, end) {
  if (!Number.isFinite(start) || !Number.isFinite(end)) {
    return "-";
  }
  return `${formatDate(start)} to ${formatDate(end)}`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function isPrivateIp(ip) {
  if (!ip || ip === "-") {
    return false;
  }
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) {
    return false;
  }
  const [a, b] = parts;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function isPublicIp(ip) {
  if (!ip || ip === "-") {
    return false;
  }
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) {
    return false;
  }
  const [a, b] = parts;
  if (a === 0 || a === 127 || a >= 224) return false;
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return false;
  if (a === 169 && b === 254) return false;
  return true;
}

if (typeof window !== "undefined") {
  window.VpcLogAnalyzer = {
    parseVpcFlowLog,
    analyzeRecords
  };
}

if (typeof module !== "undefined") {
  module.exports = {
    parseVpcFlowLog,
    analyzeRecords,
    SAMPLE_LOG
  };
}
