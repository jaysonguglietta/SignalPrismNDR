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
  workspaces: "ndrFlowConsole.workspaces.v1",
  activeWorkspace: "ndrFlowConsole.activeWorkspace.v1",
  ruleProfile: "ndrFlowConsole.ruleProfile.v1",
  history: "ndrFlowConsole.history.v1",
  baseline: "ndrFlowConsole.baseline.v1",
  hunts: "ndrFlowConsole.hunts.v1",
  sources: "ndrFlowConsole.sources.v1",
  tenantUsers: "ndrFlowConsole.tenantUsers.v1",
  auditEvents: "ndrFlowConsole.auditEvents.v1",
  seenJobRuns: "ndrFlowConsole.seenJobRuns.v1",
  jobRuns: "ndrFlowConsole.jobRuns.v1",
  detectionRules: "ndrFlowConsole.detectionRules.v1",
  enterpriseSettings: "ndrFlowConsole.enterpriseSettings.v1",
  assetContext: "ndrFlowConsole.assetContext.v1",
  policyFindings: "ndrFlowConsole.policyFindings.v1",
  securityLakeManifest: "ndrFlowConsole.securityLakeManifest.v1",
  threatIntel: "ndrFlowConsole.threatIntel.v1",
  copilotNotes: "ndrFlowConsole.copilotNotes.v1",
  playbookRuns: "ndrFlowConsole.playbookRuns.v1",
  evidenceVault: "ndrFlowConsole.evidenceVault.v1",
  enterpriseReports: "ndrFlowConsole.enterpriseReports.v1",
  executiveBriefs: "ndrFlowConsole.executiveBriefs.v1",
  reportSchedules: "ndrFlowConsole.reportSchedules.v1",
  reportDeliveries: "ndrFlowConsole.reportDeliveries.v1",
  enrichment: "ndrFlowConsole.enrichment.v1"
};
const PROTECTED_STORAGE_KEYS = new Set(Object.values(STORAGE_KEYS));
let activeStorageScope = "signed-out";
const MAX_BROWSER_FILE_BYTES = 16 * 1024 * 1024;
const MAX_BROWSER_TEXT_BYTES = 32 * 1024 * 1024;
const MAX_BROWSER_BATCH_FILES = 20;
const MAX_STRUCTURED_MESSAGES = 100000;
const MAX_STRUCTURED_DEPTH = 16;
const STITCHING_FLOW_FORMATS = new Set(["aws-vpc-flow", "azure-nsg", "gcp-vpc-flow"]);
let pseudonymKeyCache = null;

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
  rawEvidenceText: "",
  evidenceSources: [],
  stitching: { events: [], result: null, selectedChainId: "" },
  heatmap: {
    mode: "graph",
    groupBy: "entity",
    metric: "events",
    scale: "log",
    evidenceFilter: "all",
    zoom: 1,
    panRatio: 0,
    panX: 0,
    panY: 0,
    selection: null,
    model: null,
    drag: null
  },
  executive: { topFindings: [], selectedFindingId: "", evidenceRecords: null, currentReport: null, renderToken: 0 },
  enrichment: {},
  activeWorkspaceId: "",
  selectedEntity: null,
  huntResults: [],
  sort: { field: "start", direction: "desc" },
  backend: { online: false, authMode: "local-dev", principal: null },
  enterprise: { telemetryEvents: [], correlations: [], responseActions: [], contentBundles: [], readiness: null, contentVerification: null },
  jobRunPoller: null,
  replayTimer: null,
  pendingConfirm: null,
  busy: false
};

const els = {};
let idbApi = null;
let editingCaseRevision = 0;
let backendApi = null;
let topologyApi = null;
let eventStitchingApi = null;
let eventStitchingPromise = null;
let networkHeatmapApi = null;
let executiveReportingApi = null;
let platformController = null;
let operationsController = null;

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
    "evidenceSourceList",
    "workspaceSelect",
    "workspaceNameInput",
    "newWorkspaceButton",
    "saveWorkspaceButton",
    "exportPackageButton",
    "loadDemoButton",
    "workspaceMeta",
    "pasteInput",
    "analyzeButton",
    "sampleButton",
    "clearButton",
    "inputMessage",
    "resetFiltersButton",
    "searchInput",
    "actionFilter",
    "protocolFilter",
    "evidenceSourceFilter",
    "parseIssueCount",
    "parseIssueList",
    "metricGrid",
    "timelineChart",
    "timeRangeLabel",
    "priorityEntities",
    "topPorts",
    "topFindingsPeriod",
    "topFindingsSource",
    "topFindingsSeverity",
    "topFindingsEnvironment",
    "resetTopFindingsButton",
    "topFindingsStatus",
    "topFindingsTable",
    "topFindingDetail",
    "findingCount",
    "findingList",
    "severityFilter",
    "exportDetectionsButton",
    "ruleProfileSelect",
    "applyRuleProfileButton",
    "ruleProfileDescription",
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
    "sourceTypeInput",
    "sourceAccountInput",
    "sourceRegionInput",
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
    "backendJobRunsList",
    "applicationMix",
    "dropAcceptedDns",
    "dropNoData",
    "dedupeFlows",
    "sampleRateInput",
    "optimizationResult",
    "aiStatusLabel",
    "aiPromptPreset",
    "aiQuestionInput",
    "askAiButton",
    "summarizeAiButton",
    "clearAiButton",
    "aiAnswerPanel",
    "analystSummary",
    "copySummaryButton",
    "exportInvestigationPackageButton",
    "exportJsonButton",
    "exportOcsfButton",
    "exportCefButton",
    "policyRecommendations",
    "exportRedactedButton",
    "maskIps",
    "maskAccounts",
    "maskDomains",
    "executivePeriodSelect",
    "executiveClassificationSelect",
    "executiveNarrativeSelect",
    "executiveOrganizationInput",
    "generateExecutiveBriefButton",
    "exportExecutivePdfButton",
    "exportExecutiveCsvButton",
    "exportExecutiveJsonButton",
    "executiveBriefStatus",
    "executiveBriefOutput",
    "reportScheduleAccessLabel",
    "reportScheduleForm",
    "reportScheduleNameInput",
    "reportScheduleFrequencySelect",
    "reportSchedulePeriodSelect",
    "reportScheduleFormatSelect",
    "reportScheduleClassificationSelect",
    "reportScheduleRecipientsInput",
    "saveReportScheduleButton",
    "reportScheduleMessage",
    "reportScheduleList",
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
    "adminTenantLabel",
    "adminUserIdInput",
    "adminUserNameInput",
    "adminUserEmailInput",
    "adminUserRoleInput",
    "adminUserStatusInput",
    "adminUserSourceInput",
    "saveTenantUserButton",
    "adminUserCountLabel",
    "adminOpsGrid",
    "adminUserList",
    "sourceOwnerSourceInput",
    "sourceOwnerUserInput",
    "assignSourceOwnerButton",
    "sourceOwnershipList",
    "exportAccessReviewButton",
    "accessReviewList",
    "refreshExportApprovalsButton",
    "exportApprovalList",
    "refreshAuditButton",
    "exportAuditButton",
    "auditActionFilterInput",
    "auditActorFilterInput",
    "auditReviewList",
    "stitchWindowSelect",
    "stitchConfidenceSelect",
    "rebuildStitchingButton",
    "exportStitchingButton",
    "stitchStatus",
    "stitchMetricGrid",
    "stitchChainList",
    "stitchDetail",
    "stitchGapList",
    "topologyViewHeading",
    "topologyModeControl",
    "heatmapStatusLabel",
    "heatmapToolbar",
    "heatmapGroupSelect",
    "heatmapMetricSelect",
    "heatmapScaleSelect",
    "heatmapEvidenceFilter",
    "heatmapZoomOutButton",
    "heatmapZoomInButton",
    "heatmapPanLeftButton",
    "heatmapPanRightButton",
    "heatmapPanUpButton",
    "heatmapPanDownButton",
    "heatmapResetViewButton",
    "exportHeatmapButton",
    "heatmapContextBar",
    "heatmapSelectionLabel",
    "clearHeatmapSelectionButton",
    "topologyCanvas",
    "playReplayButton",
    "stepReplayBackButton",
    "stepReplayForwardButton",
    "replayRangeInput",
    "replayTimeLabel",
    "replayEventCountLabel",
    "replayEventList",
    "enterpriseReadinessLabel",
    "enterpriseMetricGrid",
    "detectionOpsLabel",
    "detectionOpsGrid",
    "detectionOpsList",
    "refreshHardeningButton",
    "productionHardeningList",
    "telemetryFormatInput",
    "telemetryPayloadInput",
    "loadTelemetrySampleButton",
    "ingestTelemetryButton",
    "correlateTelemetryButton",
    "telemetryMetricGrid",
    "correlationList",
    "responseActionStatusLabel",
    "responseActionTypeInput",
    "responseExecutionModeInput",
    "responseActionTargetInput",
    "responseCaseInput",
    "responseCorrelationInput",
    "responseActionReasonInput",
    "requestResponseActionButton",
    "responseActionList",
    "detectionContentInput",
    "verifyDetectionContentButton",
    "importDetectionContentButton",
    "detectionContentList",
    "copilotQuestionInput",
    "generateCitedCopilotButton",
    "copilotCitationList",
    "sourceHealthList",
    "discoverSourcesButton",
    "enterpriseCoverageList",
    "threatIntelInput",
    "applyThreatIntelButton",
    "threatIntelList",
    "entityRiskScoringList",
    "detectionRuleIdInput",
    "detectionRuleNameInput",
    "detectionRuleQueryInput",
    "detectionRuleDescriptionInput",
    "detectionRuleSeverityInput",
    "detectionRuleTacticInput",
    "detectionRuleTechniqueInput",
    "detectionRuleAttackInput",
    "testDetectionRuleButton",
    "saveDetectionRuleButton",
    "detectionRuleResultList",
    "detectionRuleCountLabel",
    "detectionRuleList",
    "exportDetectionAsCodeButton",
    "detectionAsCodeList",
    "securityLakeBucketInput",
    "enterpriseSecurityLakePrefixInput",
    "siemTargetInput",
    "siemEndpointInput",
    "saveIntegrationButton",
    "exportSecurityLakeButton",
    "securityLakeManifestList",
    "assetContextInput",
    "applyAssetContextButton",
    "assetContextList",
    "exportGraphButton",
    "investigationGraphList",
    "exportReplayTimelineButton",
    "replayTimelineList",
    "policyInput",
    "analyzePolicyButton",
    "policyFindingList",
    "incidentOpsList",
    "playbookCaseSelect",
    "playbookTemplateSelect",
    "createPlaybookRunButton",
    "playbookRunList",
    "qualityDashboardList",
    "retentionDaysInput",
    "legalHoldInput",
    "exportApprovalInput",
    "analyticsStoreInput",
    "queryEngineInput",
    "saveGovernanceButton",
    "governanceReadinessList",
    "createEvidenceVaultButton",
    "evidenceVaultList",
    "reportModeSelect",
    "generateEnterpriseReportButton",
    "enterpriseReportPanel",
    "enterpriseAdminList",
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
  els.fileInput.addEventListener("change", async (event) => {
    const files = Array.from(event.target.files || []);
    if (files?.length) {
      await readFiles(files);
    }
    event.target.value = "";
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
    const files = event.dataTransfer.files;
    if (files?.length) {
      readFiles(files);
    } else {
      setInputMessage("Drop one or more .log, .txt, .csv, .json, .jsonl, or .gz files.");
    }
  });

  els.analyzeButton.addEventListener("click", () => {
    runAnalysis(els.pasteInput.value, "Pasted log");
  });

  els.sampleButton.addEventListener("click", () => {
    els.pasteInput.value = SAMPLE_LOG;
    runAnalysis(SAMPLE_LOG, "Sample log");
  });
  els.workspaceSelect.addEventListener("change", loadSelectedWorkspace);
  els.newWorkspaceButton.addEventListener("click", createWorkspaceDraft);
  els.saveWorkspaceButton.addEventListener("click", saveWorkspaceSnapshot);
  els.exportPackageButton.addEventListener("click", exportInvestigationPackage);
  els.loadDemoButton.addEventListener("click", loadGuidedDemo);

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
    const hadHeatmapSelection = Boolean(state.heatmap.selection);
    const hadExecutiveSelection = Boolean(state.executive.evidenceRecords);
    state.heatmap.selection = null;
    state.executive.evidenceRecords = null;
    state.executive.selectedFindingId = "";
    els.searchInput.value = "";
    els.actionFilter.value = "all";
    els.protocolFilter.value = "all";
    els.evidenceSourceFilter.value = "all";
    applyFilters();
    if (hadHeatmapSelection || hadExecutiveSelection) {
      renderFindings(state.analysis?.detections || []);
      rebuildEventStitching(false);
      renderTopology();
      renderTopFindings();
    }
  });

  [els.searchInput, els.actionFilter, els.protocolFilter, els.evidenceSourceFilter].forEach((input) => {
    input.addEventListener("input", applyFilters);
  });

  els.recordsTableHead.addEventListener("click", (event) => {
    const button = event.target.closest("[data-sort]");
    if (button) {
      setRecordSort(button.dataset.sort);
    }
  });

  els.severityFilter.addEventListener("input", () => {
    renderFindings(findingsForHeatmapSelection(state.analysis?.detections || []));
  });
  els.ruleProfileSelect.addEventListener("change", updateRuleProfileDescription);
  els.applyRuleProfileButton.addEventListener("click", applyRuleProfile);

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
    const deleteButton = event.target.closest("[data-delete-source]");
    const ingestButton = event.target.closest("[data-ingest-source]");
    const ingestAsyncButton = event.target.closest("[data-ingest-source-async]");
    const scheduleButton = event.target.closest("[data-schedule-source]");
    if (deleteButton) deleteSourceConfig(deleteButton.dataset.deleteSource);
    if (ingestButton) ingestManagedSource(ingestButton.dataset.ingestSource);
    if (ingestAsyncButton) ingestManagedSourceAsync(ingestAsyncButton.dataset.ingestSourceAsync);
    if (scheduleButton) scheduleManagedSourceJob(scheduleButton.dataset.scheduleSource);
  });
  els.saveBaselineButton.addEventListener("click", saveCurrentBaseline);
  els.deleteBaselineButton.addEventListener("click", deleteBaseline);
  els.clearHistoryButton.addEventListener("click", clearHistory);
  els.applyEnrichmentButton.addEventListener("click", applyEnrichmentInput);
  [els.dropAcceptedDns, els.dropNoData, els.dedupeFlows, els.sampleRateInput].forEach((input) => {
    input.addEventListener("input", renderOptimization);
  });
  els.copySummaryButton.addEventListener("click", copyAnalystSummary);
  els.exportInvestigationPackageButton.addEventListener("click", exportInvestigationPackage);
  els.exportJsonButton.addEventListener("click", () => exportDetectionsStructured("json"));
  els.exportOcsfButton.addEventListener("click", () => exportDetectionsStructured("ocsf"));
  els.exportCefButton.addEventListener("click", exportDetectionsCef);
  els.exportRedactedButton.addEventListener("click", exportRedactedRecords);
  [els.topFindingsPeriod, els.topFindingsSource, els.topFindingsSeverity, els.topFindingsEnvironment].forEach((input) => {
    input.addEventListener("input", renderTopFindings);
  });
  els.resetTopFindingsButton.addEventListener("click", resetTopFindingsFilters);
  els.topFindingsTable.addEventListener("click", handleTopFindingAction);
  els.topFindingDetail.addEventListener("click", handleTopFindingAction);
  els.generateExecutiveBriefButton.addEventListener("click", generateExecutiveBrief);
  els.exportExecutivePdfButton.addEventListener("click", () => exportExecutiveBrief("pdf"));
  els.exportExecutiveCsvButton.addEventListener("click", () => exportExecutiveBrief("csv"));
  els.exportExecutiveJsonButton.addEventListener("click", () => exportExecutiveBrief("json"));
  els.reportScheduleForm.addEventListener("submit", saveReportSchedule);
  els.reportScheduleList.addEventListener("click", (event) => {
    const pause = event.target.closest("[data-pause-report-schedule]");
    const remove = event.target.closest("[data-delete-report-schedule]");
    const run = event.target.closest("[data-run-report-schedule]");
    if (pause) toggleReportSchedule(pause.dataset.pauseReportSchedule);
    if (remove) deleteReportSchedule(remove.dataset.deleteReportSchedule);
    if (run) runReportSchedule(run.dataset.runReportSchedule, false);
  });

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      activateTab(tab.dataset.tab);
    });
    tab.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const tabs = [...document.querySelectorAll(".tab")].filter((item) => !item.disabled);
      const current = tabs.indexOf(tab);
      const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (current + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
      tabs[next].focus();
      activateTab(tabs[next].dataset.tab);
    });
  });
  document.querySelectorAll("[data-learn-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (button.dataset.learnDemo === "true") await loadGuidedDemo();
      activateTab(button.dataset.learnTarget);
      document.querySelector(".tabs")?.scrollIntoView({ block: "start" });
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
  els.aiPromptPreset.addEventListener("change", applyAiPromptPreset);
  els.ingestS3Button.addEventListener("click", ingestFromS3);
  els.ingestCloudWatchButton.addEventListener("click", ingestFromCloudWatch);
  els.createJobButton.addEventListener("click", createIngestJob);
  els.backendJobsList.addEventListener("click", (event) => {
    const run = event.target.closest("[data-run-job]");
    const asyncRun = event.target.closest("[data-run-job-async]");
    const del = event.target.closest("[data-delete-job]");
    if (run) runBackendJob(run.dataset.runJob);
    if (asyncRun) runBackendJobAsync(asyncRun.dataset.runJobAsync);
    if (del) deleteBackendJob(del.dataset.deleteJob);
  });
  els.saveTenantUserButton.addEventListener("click", saveTenantUser);
  els.adminUserList.addEventListener("click", (event) => {
    const edit = event.target.closest("[data-edit-tenant-user]");
    const del = event.target.closest("[data-delete-tenant-user]");
    if (edit) editTenantUser(edit.dataset.editTenantUser);
    if (del) deleteTenantUser(del.dataset.deleteTenantUser);
  });
  els.assignSourceOwnerButton.addEventListener("click", assignSourceOwner);
  els.exportAccessReviewButton.addEventListener("click", exportAccessReview);
  els.refreshExportApprovalsButton.addEventListener("click", renderExportApprovals);
  els.exportApprovalList.addEventListener("click", (event) => {
    const approve = event.target.closest("[data-approve-export]");
    const download = event.target.closest("[data-download-export]");
    if (approve) approveExportRequest(approve.dataset.approveExport);
    if (download) downloadApprovedExport(download.dataset.downloadExport, download.dataset.exportKind);
  });
  els.refreshAuditButton.addEventListener("click", () => refreshAuditEventsFromBackend(false));
  els.exportAuditButton.addEventListener("click", exportAuditReviewNdjson);
  [els.auditActionFilterInput, els.auditActorFilterInput].forEach((input) => {
    input.addEventListener("input", renderAuditReview);
  });
  els.generateCitedCopilotButton.addEventListener("click", generateCitedCopilotAnswer);
  els.discoverSourcesButton.addEventListener("click", discoverSourcesFromEvidence);
  els.applyThreatIntelButton.addEventListener("click", applyThreatIntelInput);
  els.testDetectionRuleButton.addEventListener("click", testDetectionRuleForm);
  els.saveDetectionRuleButton.addEventListener("click", saveDetectionRuleForm);
  els.detectionRuleList.addEventListener("click", (event) => {
    const edit = event.target.closest("[data-edit-rule]");
    const test = event.target.closest("[data-test-rule]");
    const del = event.target.closest("[data-delete-rule]");
    const promote = event.target.closest("[data-promote-rule]");
    const clone = event.target.closest("[data-clone-rule]");
    if (edit) editDetectionRule(edit.dataset.editRule);
    if (test) testDetectionRuleById(test.dataset.testRule);
    if (del) deleteDetectionRuleById(del.dataset.deleteRule);
    if (promote) promoteDetectionRule(promote.dataset.promoteRule);
    if (clone) cloneDetectionRule(clone.dataset.cloneRule);
  });
  els.exportDetectionAsCodeButton.addEventListener("click", exportDetectionAsCodeBundle);
  els.saveIntegrationButton.addEventListener("click", saveEnterpriseIntegration);
  els.exportSecurityLakeButton.addEventListener("click", exportSecurityLakeOcsf);
  els.applyAssetContextButton.addEventListener("click", applyAssetContextInput);
  els.exportGraphButton.addEventListener("click", exportInvestigationGraph);
  els.exportReplayTimelineButton.addEventListener("click", exportReplayTimeline);
  els.analyzePolicyButton.addEventListener("click", analyzePolicyInput);
  els.createPlaybookRunButton.addEventListener("click", createPlaybookRun);
  els.saveGovernanceButton.addEventListener("click", saveGovernanceControls);
  els.createEvidenceVaultButton.addEventListener("click", createEvidenceVaultBundle);
  els.generateEnterpriseReportButton.addEventListener("click", generateEnterpriseReport);
  els.refreshHardeningButton.addEventListener("click", () => refreshEnterpriseSecurityOperations(false));
  els.loadTelemetrySampleButton.addEventListener("click", loadEnterpriseTelemetrySample);
  els.ingestTelemetryButton.addEventListener("click", ingestEnterpriseTelemetry);
  els.correlateTelemetryButton.addEventListener("click", correlateEnterpriseTelemetry);
  els.requestResponseActionButton.addEventListener("click", requestEnterpriseResponseAction);
  els.responseActionList.addEventListener("click", (event) => {
    const approve = event.target.closest("[data-approve-response-action]");
    if (approve) approveEnterpriseResponseAction(approve.dataset.approveResponseAction);
  });
  els.verifyDetectionContentButton.addEventListener("click", verifyEnterpriseDetectionContent);
  els.importDetectionContentButton.addEventListener("click", importEnterpriseDetectionContent);
  els.createCaseFromTopDetectionButton.addEventListener("click", createCaseFromTopDetection);
  els.saveCaseButton.addEventListener("click", saveCaseForm);
  els.caseList.addEventListener("click", (event) => {
    const edit = event.target.closest("[data-edit-case]");
    const del = event.target.closest("[data-delete-case]");
    if (edit) editCase(edit.dataset.editCase);
    if (del) deleteCaseById(del.dataset.deleteCase);
  });
  els.playReplayButton.addEventListener("click", toggleTopologyReplay);
  els.stepReplayBackButton.addEventListener("click", () => stepTopologyReplay(-10));
  els.stepReplayForwardButton.addEventListener("click", () => stepTopologyReplay(10));
  els.replayRangeInput.addEventListener("input", renderTopology);
  els.topologyModeControl.addEventListener("click", (event) => {
    const button = event.target.closest("[data-topology-mode]");
    if (!button) return;
    setTopologyMode(button.dataset.topologyMode);
  });
  [els.heatmapGroupSelect, els.heatmapMetricSelect, els.heatmapScaleSelect, els.heatmapEvidenceFilter].forEach((input) => {
    input.addEventListener("change", updateHeatmapOptions);
  });
  els.heatmapZoomOutButton.addEventListener("click", () => zoomHeatmap(-1));
  els.heatmapZoomInButton.addEventListener("click", () => zoomHeatmap(1));
  els.heatmapPanLeftButton.addEventListener("click", () => panHeatmap(-1, 0));
  els.heatmapPanRightButton.addEventListener("click", () => panHeatmap(1, 0));
  els.heatmapPanUpButton.addEventListener("click", () => panHeatmap(0, -1));
  els.heatmapPanDownButton.addEventListener("click", () => panHeatmap(0, 1));
  els.heatmapResetViewButton.addEventListener("click", resetHeatmapView);
  els.clearHeatmapSelectionButton.addEventListener("click", clearHeatmapSelection);
  els.exportHeatmapButton.addEventListener("click", exportHeatmapView);
  els.topologyCanvas.addEventListener("wheel", handleHeatmapWheel, { passive: false });
  els.topologyCanvas.addEventListener("pointerdown", startHeatmapDrag);
  els.topologyCanvas.addEventListener("pointermove", moveHeatmapDrag);
  els.topologyCanvas.addEventListener("pointerup", endHeatmapDrag);
  els.topologyCanvas.addEventListener("pointercancel", endHeatmapDrag);
  els.topologyCanvas.addEventListener("keydown", handleHeatmapKeydown);
  els.rebuildStitchingButton.addEventListener("click", () => rebuildEventStitching(true));
  [els.stitchWindowSelect, els.stitchConfidenceSelect].forEach((input) => input.addEventListener("change", () => rebuildEventStitching(true)));
  els.exportStitchingButton.addEventListener("click", exportStitchedIncidents);
  els.stitchChainList.addEventListener("click", (event) => {
    const chain = event.target.closest("[data-stitch-chain]");
    if (!chain) return;
    state.stitching.selectedChainId = chain.dataset.stitchChain;
    renderEventStitching();
  });
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
    tab.tabIndex = isActive ? 0 : -1;
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    const isActive = panel.id === `${tabName}Panel`;
    panel.classList.toggle("active", isActive);
    panel.hidden = !isActive;
  });
  if (tabName === "admin") renderTenantAdmin();
  if (tabName === "enterprise") renderEnterprise();
  if (tabName === "platform") {
    platformController?.refresh(false);
    operationsController?.refreshPlatformControls();
  }
  if (tabName === "overview") operationsController?.refresh(false);
  if (tabName === "cases") operationsController?.refreshCaseTasks();
  if (tabName === "reports") renderExecutiveReporting();
  if (tabName === "topology") {
    renderTopology();
    renderEventStitching();
  }
}

function clearCurrentEvidence() {
  state.records = [];
  state.filtered = [];
  state.analysis = null;
  state.fields = [];
  state.errors = [];
  state.fileName = "";
  state.rawEvidenceText = "";
  state.evidenceSources = [];
  state.stitching = { events: [], result: null, selectedChainId: "" };
  state.heatmap = { ...state.heatmap, zoom: 1, panRatio: 0, panX: 0, panY: 0, selection: null, model: null, drag: null };
  state.executive = { ...state.executive, topFindings: [], selectedFindingId: "", evidenceRecords: null, currentReport: null };
  state.selectedEntity = null;
  state.huntResults = [];
  els.fileInput.value = "";
  els.pasteInput.value = "";
  els.severityFilter.value = "all";
  els.searchInput.value = "";
  els.actionFilter.value = "all";
  els.protocolFilter.value = "all";
  els.evidenceSourceFilter.innerHTML = `<option value="all">All evidence sources</option>`;
  els.fileMeta.textContent = "Drop one or more log, CSV, gzip, or JSON files";
  renderEvidenceSources();
  clearInputMessage();
  renderEmptyDashboard();
  showToast("Current evidence cleared.");
}

function setBusy(isBusy, label = "Working") {
  state.busy = isBusy;
  els.fileInput.disabled = isBusy;
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

async function loadEventStitchingApi() {
  if (eventStitchingApi) return eventStitchingApi;
  if (!eventStitchingPromise) eventStitchingPromise = import("./src/event-stitching.mjs");
  eventStitchingApi = await eventStitchingPromise;
  return eventStitchingApi;
}

function normalizeEvidenceForStitching(stitching, text, context, flowRecords) {
  const structured = stitching.parseStitchingTelemetry(text, context);
  if (structured.events.length) return structured;
  return stitching.parseStitchingTelemetry(text, { ...context, flowRecords });
}

async function parseEvidenceTelemetry(text, context, flowRecords) {
  try {
    const stitching = await loadEventStitchingApi();
    return normalizeEvidenceForStitching(stitching, text, context, flowRecords);
  } catch (error) {
    return {
      events: [],
      errors: [],
      formats: [],
      unavailable: true,
      message: error.message || "Event stitching module is unavailable"
    };
  }
}

async function initializePersistentData() {
  try {
    purgeLegacyStorageKeys();
    const [loadedIdbApi, loadedBackendApi, loadedTopologyApi, loadedEventStitchingApi, loadedNetworkHeatmapApi, loadedExecutiveReportingApi, platformUiApi, operationsUiApi] = await Promise.all([
      import("./src/idb-store.js"),
      import("./src/backend-client.js"),
      import("./src/topology.js"),
      loadEventStitchingApi(),
      import("./src/network-heatmap.mjs?v=0.3.3"),
      import("./src/executive-reporting.mjs?v=0.4.0"),
      import("./src/platform-ui.mjs"),
      import("./src/operations-ui.mjs")
    ]);
    idbApi = loadedIdbApi;
    backendApi = loadedBackendApi;
    topologyApi = loadedTopologyApi;
    eventStitchingApi = loadedEventStitchingApi;
    networkHeatmapApi = loadedNetworkHeatmapApi;
    executiveReportingApi = loadedExecutiveReportingApi;
    const loginResult = await backendApi.completeSsoCallback();
    if (loginResult?.principal) showToast(`Signed in as ${loginResult.principal.name || loginResult.principal.subject}.`);
    await refreshBackendStatus();
    platformController = platformUiApi.createPlatformController({ backendApi, notify: showToast });
    operationsController = operationsUiApi.createOperationsController({ backendApi, notify: showToast });
    operationsController.init();
    hydrateScopedClientState();
    await refreshServerWorkspaces();
    await refreshManagedSourcesFromBackend();
    await refreshCases();
    await refreshTenantUsersFromBackend();
    await refreshAuditEventsFromBackend(true);
    await refreshEnterpriseFromBackend();
    await platformController.refresh(false);
    await operationsController.refresh(false);
    await operationsController.refreshPlatformControls();
    await operationsController.refreshCaseTasks();
    await refreshJobRuns(true);
    startJobRunPolling();
  } catch (error) {
    await setActiveStorageScope(null, "offline-local");
    hydrateScopedClientState();
    showToast(`Module initialization warning: ${error.message}`, "warn");
  }
}

function hydrateScopedClientState() {
  state.enrichment = loadJson(STORAGE_KEYS.enrichment, {});
  state.activeWorkspaceId = loadJson(STORAGE_KEYS.activeWorkspace, "");
  els.ruleProfileSelect.value = loadJson(STORAGE_KEYS.ruleProfile, "balanced");
  updateRuleProfileDescription();
  renderWorkspaces();
}

function loadJson(key, fallback) {
  if (typeof localStorage === "undefined") {
    return fallback;
  }
  try {
    return JSON.parse(localStorage.getItem(scopedStorageKey(key))) ?? fallback;
  } catch {
    return fallback;
  }
}

function saveJson(key, value) {
  if (typeof localStorage === "undefined") {
    return;
  }
  localStorage.setItem(scopedStorageKey(key), JSON.stringify(value));
}

function removeJson(key) {
  if (typeof localStorage === "undefined") {
    return;
  }
  localStorage.removeItem(scopedStorageKey(key));
}

function scopedStorageKey(key, scope = activeStorageScope) {
  return PROTECTED_STORAGE_KEYS.has(key) ? `${key}.scope.${scope}` : key;
}

function storageScopeForPrincipal(principal, fallback = "signed-out") {
  if (!principal) return fallback;
  const tenant = String(principal.tenantId || "default").toLowerCase().replace(/[^a-z0-9_.-]+/g, "-").slice(0, 80);
  const subject = String(principal.subject || principal.email || "unknown").toLowerCase().replace(/[^a-z0-9_.@-]+/g, "-").slice(0, 120);
  return `${tenant}.${subject}`;
}

async function setActiveStorageScope(principal, fallback = "signed-out") {
  activeStorageScope = storageScopeForPrincipal(principal, fallback);
  pseudonymKeyCache = null;
  if (idbApi?.setStorageScope) await idbApi.setStorageScope(activeStorageScope, principal ? backendApi?.storageSessionBinding?.() || "" : "");
}

function purgeLegacyStorageKeys() {
  if (typeof localStorage === "undefined") return;
  PROTECTED_STORAGE_KEYS.forEach((key) => localStorage.removeItem(key));
}

async function clearActiveClientStorage() {
  if (typeof localStorage !== "undefined") PROTECTED_STORAGE_KEYS.forEach((key) => localStorage.removeItem(scopedStorageKey(key)));
  if (idbApi?.clearStorageScope) await idbApi.clearStorageScope();
  clearCurrentEvidence();
  state.enrichment = {};
  state.activeWorkspaceId = "";
}

function renderWorkspaces() {
  const workspaces = loadJson(STORAGE_KEYS.workspaces, []);
  if (!workspaces.length) {
    els.workspaceSelect.innerHTML = `<option value="">No saved workspaces</option>`;
    els.workspaceNameInput.value = "";
    els.workspaceMeta.textContent = "No workspace saved yet. Analyze evidence, name it, then save.";
    return;
  }
  els.workspaceSelect.innerHTML = workspaces
    .map((workspace) => `<option value="${escapeHtml(workspace.id)}">${escapeHtml(workspace.name)}</option>`)
    .join("");
  const active = workspaces.find((workspace) => workspace.id === state.activeWorkspaceId) || workspaces[0];
  state.activeWorkspaceId = active.id;
  saveJson(STORAGE_KEYS.activeWorkspace, active.id);
  els.workspaceSelect.value = active.id;
  els.workspaceNameInput.value = active.name;
  els.workspaceMeta.textContent = `${formatNumber(active.records || 0)} records, ${formatNumber(active.detections || 0)} detections, updated ${formatDate(Date.parse(active.updatedAt || active.createdAt))}`;
}

function createWorkspaceDraft() {
  state.activeWorkspaceId = "";
  saveJson(STORAGE_KEYS.activeWorkspace, "");
  els.workspaceSelect.value = "";
  els.workspaceNameInput.value = "";
  els.workspaceMeta.textContent = "Draft workspace ready. Name it and save after loading evidence.";
  showToast("New workspace draft started.");
}

async function refreshServerWorkspaces() {
  if (!backendApi) return;
  try {
    const workspaces = await backendApi.listWorkspaces();
    saveJson(STORAGE_KEYS.workspaces, workspaces);
    renderWorkspaces();
  } catch (error) {
    if (state.backend.online) showToast(`Workspace sync unavailable: ${error.message}`, "warn");
  }
}

async function saveWorkspaceSnapshot() {
  const name = els.workspaceNameInput.value.trim();
  if (!name) return setInputMessage("Workspace name is required.");
  const workspaces = loadJson(STORAGE_KEYS.workspaces, []);
  const now = new Date().toISOString();
  const existingIndex = workspaces.findIndex((workspace) => workspace.id === state.activeWorkspaceId || workspace.name.toLowerCase() === name.toLowerCase());
  const existing = existingIndex >= 0 ? workspaces[existingIndex] : null;
  const workspace = {
    id: existing?.id || `workspace-${Date.now()}`,
    name,
    createdAt: existing?.createdAt || now,
    updatedAt: now,
    fileName: state.fileName || "",
    evidenceText: els.pasteInput.value.slice(0, 200000),
    records: state.records.length,
    detections: state.analysis?.detections?.length || 0,
    high: (state.analysis?.detections || []).filter((detection) => detection.severity === "high").length,
    entities: state.analysis?.entityRisk?.length || 0,
    bytes: state.analysis?.totals?.bytes || 0,
    sourceCount: loadJson(STORAGE_KEYS.sources, []).length,
    sources: loadJson(STORAGE_KEYS.sources, []),
    evidenceSources: state.evidenceSources,
    hunts: loadJson(STORAGE_KEYS.hunts, []),
    enrichment: state.enrichment,
    ruleProfile: loadJson(STORAGE_KEYS.ruleProfile, "balanced"),
    signatures: state.analysis ? buildBaselineSignature(state.analysis) : null
  };
  let saved = workspace;
  if (backendApi) {
    try {
      saved = await backendApi.saveWorkspace(workspace);
    } catch (error) {
      if (state.backend.online) {
        setInputMessage(`Workspace was not saved to the tenant store: ${error.message}`);
        return;
      }
    }
  }
  if (existingIndex >= 0) workspaces.splice(existingIndex, 1, workspace);
  else workspaces.unshift(saved);
  if (existingIndex >= 0) workspaces[existingIndex] = saved;
  saveJson(STORAGE_KEYS.workspaces, workspaces.slice(0, 20));
  state.activeWorkspaceId = saved.id;
  saveJson(STORAGE_KEYS.activeWorkspace, saved.id);
  renderWorkspaces();
  showToast(existing ? "Workspace updated." : "Workspace saved.");
}

function loadSelectedWorkspace() {
  const workspaces = loadJson(STORAGE_KEYS.workspaces, []);
  const workspace = workspaces.find((item) => item.id === els.workspaceSelect.value);
  if (!workspace) return;
  state.activeWorkspaceId = workspace.id;
  saveJson(STORAGE_KEYS.activeWorkspace, workspace.id);
  els.workspaceNameInput.value = workspace.name;
  els.workspaceMeta.textContent = `${formatNumber(workspace.records || 0)} records, ${formatNumber(workspace.detections || 0)} detections, updated ${formatDate(Date.parse(workspace.updatedAt || workspace.createdAt))}`;
  if (workspace.sources) saveJson(STORAGE_KEYS.sources, workspace.sources);
  if (workspace.hunts) saveJson(STORAGE_KEYS.hunts, workspace.hunts);
  if (workspace.enrichment) {
    state.enrichment = workspace.enrichment;
    saveJson(STORAGE_KEYS.enrichment, workspace.enrichment);
  }
  if (workspace.ruleProfile) {
    els.ruleProfileSelect.value = workspace.ruleProfile;
    saveJson(STORAGE_KEYS.ruleProfile, workspace.ruleProfile);
    updateRuleProfileDescription();
  }
  if (workspace.evidenceText) {
    els.pasteInput.value = workspace.evidenceText;
    runAnalysis(workspace.evidenceText, workspace.fileName || workspace.name);
  } else {
    renderCoverage();
    renderSavedHunts();
  }
  showToast(`Workspace "${workspace.name}" selected.`);
}

async function loadGuidedDemo() {
  els.workspaceNameInput.value = "Demo - Public admin access";
  els.pasteInput.value = SAMPLE_LOG;
  saveJson(STORAGE_KEYS.sources, [
    {
      id: "demo-prod-vpc",
      name: "Prod AWS VPC",
      type: "AWS VPC",
      account: "123456789012",
      region: "us-east-1",
      scope: ["eni-0a1b2c3d", "eni-0e4f5a6b", "eni-0c7d8e9f", "10.0.0.0/16"],
      createdAt: new Date().toISOString()
    },
    {
      id: "demo-flowlogs",
      name: "Prod VPC Flow Logs",
      type: "CloudWatch Log Group",
      account: "Cloud Platform",
      region: "us-east-1",
      scope: ["/aws/vpc/flowlogs/prod", "AWSLogs/123456789012/vpcflowlogs/"],
      createdAt: new Date().toISOString()
    }
  ]);
  runAnalysis(SAMPLE_LOG, "Guided demo VPC flow evidence");
  window.setTimeout(async () => {
    await saveWorkspaceSnapshot();
    if (state.analysis?.detections?.[0]) {
      const detection = state.analysis.detections[0];
      try {
        await saveCaseRecord({
          title: `Demo: ${detection.title}`,
          assignee: "SOC analyst",
          status: "Triaged",
          severity: detection.severity,
          notes: `${detection.copy}\n\nResponse guidance: ${detection.response?.[0] || "Review linked evidence."}`,
          linkedDetection: detection.id,
          auditAction: "Demo case created",
          auditDetail: detection.title
        });
        await refreshCases();
      } catch (error) {
        showToast(`Demo case was not saved: ${error.message}`, "warn");
      }
    }
    els.aiPromptPreset.value = "Which entities should I investigate first and why?";
    applyAiPromptPreset();
    activateTab("overview");
    showToast("Guided demo workspace loaded with evidence, sources, and a case.");
  }, 0);
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

async function readFiles(fileList) {
  if (state.busy) {
    setInputMessage("Wait for the current evidence analysis to finish before adding another batch.");
    return;
  }
  const files = Array.from(fileList || []);
  if (!files.length) return;
  if (files.length > MAX_BROWSER_BATCH_FILES) {
    setInputMessage(`Select no more than ${MAX_BROWSER_BATCH_FILES} files per browser analysis batch.`);
    return;
  }

  setBusy(true, `Reading ${files.length} evidence source${files.length === 1 ? "" : "s"}`);
  clearInputMessage();
  const inputs = [];
  const rawParts = [];
  const batchTenantId = state.backend.principal?.tenantId || "local-browser";
  let decodedBytes = 0;
  try {
    for (let index = 0; index < files.length; index += 1) {
      const file = files[index];
      setBusy(true, `Reading ${index + 1} of ${files.length}: ${file.name}`);
      try {
        const text = await readFileText(file);
        const textBytes = browserTextBytes(text);
        if (decodedBytes + textBytes > MAX_BROWSER_TEXT_BYTES) {
          throw new Error(`Combined decoded evidence exceeds the ${formatBytes(MAX_BROWSER_TEXT_BYTES)} browser batch limit`);
        }
        decodedBytes += textBytes;
        const sourceId = `evidence-source-${index + 1}`;
        const parsed = parseVpcFlowLog(text);
        const telemetry = await parseEvidenceTelemetry(text, {
          sourceId,
          sourceName: file.name,
          tenantId: batchTenantId
        }, parsed.records);
        inputs.push({ id: sourceId, name: file.name, size: file.size, textBytes, parsed, telemetry });
        rawParts.push(`# SignalPrism evidence source: ${safeEvidenceSourceName(file.name)}\n${text}`);
      } catch (error) {
        inputs.push({
          id: `evidence-source-${index + 1}`,
          name: file.name,
          size: file.size,
          error: error.message || "File could not be read"
        });
      }
    }

    const merged = mergeParsedEvidence(inputs);
    const batchName = evidenceBatchName(merged.sources);
    const rawEvidenceText = rawParts.join("\n\n");
    els.pasteInput.value = rawEvidenceText.slice(0, 70000);
    els.fileMeta.textContent = `${formatNumber(files.length)} file${files.length === 1 ? "" : "s"} - ${formatBytes(files.reduce((total, file) => total + file.size, 0))}`;
    await commitParsedEvidence(merged, batchName, rawEvidenceText);
  } catch (error) {
    setStatus("Evidence batch failed", "warn");
    setInputMessage(error.message || "The evidence batch could not be analyzed.");
  } finally {
    setBusy(false);
  }
}

async function readFileText(file) {
  if (file.size > MAX_BROWSER_FILE_BYTES) {
    throw new Error(`Browser uploads are limited to ${formatBytes(MAX_BROWSER_FILE_BYTES)}. Use a managed S3 or CloudWatch source for larger evidence.`);
  }
  if (file.name.toLowerCase().endsWith(".gz")) {
    if (typeof DecompressionStream === "undefined") {
      throw new Error("This browser cannot decompress .gz files");
    }
    const stream = file.stream().pipeThrough(new DecompressionStream("gzip"));
    return readBoundedTextStream(stream, MAX_BROWSER_TEXT_BYTES);
  }
  const text = await file.text();
  assertBrowserTextSize(text);
  return text;
}

async function runAnalysis(text, fileName) {
  if (!String(text || "").trim()) {
    setStatus("No log text to analyze", "warn");
    setInputMessage("Paste flow log text or upload a supported evidence file first.");
    return;
  }

  setBusy(true, "Analyzing evidence");
  clearInputMessage();
  try {
    assertBrowserTextSize(text);
    const sourceId = "evidence-source-1";
    const parsed = parseVpcFlowLog(text);
    const telemetry = await parseEvidenceTelemetry(text, {
      sourceId,
      sourceName: fileName,
      tenantId: state.backend.principal?.tenantId || "local-browser"
    }, parsed.records);
    const merged = mergeParsedEvidence([{ id: sourceId, name: fileName, textBytes: browserTextBytes(text), parsed, telemetry }]);
    await commitParsedEvidence(merged, fileName, text);
  } catch (error) {
    setStatus("Analysis failed", "warn");
    setInputMessage(error.message || "Analysis failed.");
  } finally {
    setBusy(false);
  }
}

async function commitParsedEvidence(merged, fileName, rawEvidenceText) {
  try {
    state.records = merged.records;
    state.filtered = merged.records;
    state.fields = merged.fields;
    state.errors = merged.errors;
    state.fileName = fileName;
    state.rawEvidenceText = rawEvidenceText;
    state.evidenceSources = merged.sources;
    state.stitching.events = merged.events;
    state.heatmap.selection = null;
    state.heatmap.model = null;
    state.heatmap.zoom = 1;
    state.heatmap.panRatio = 0;
    state.heatmap.panX = 0;
    state.heatmap.panY = 0;
    rebuildEventStitching(false);
    state.analysis = analyzeRecords(merged.records, merged.errors);
    enrichAnalysis(state.analysis);
    applyBaselineObservations(state.analysis);
    applyDetectionPolicy(state.analysis);
    persistHistory(fileName, state.analysis);
    const persistence = await persistEvidenceIndexedDb(fileName, merged.records, state.analysis);

    refreshProtocolFilter(merged.records);
    refreshEvidenceSourceFilter(merged.sources);
    renderEvidenceSources();
    applyFilters();
    renderDashboard();
    updateStatus();
    if (!merged.records.length && !merged.events.length) {
      setInputMessage("No supported events were parsed. Check the source format, field order, delimiter, or pasted text.");
    } else {
      const retained = persistence.backendRetained ? " and retained" : "";
      const failed = merged.sources.filter((source) => source.status === "failed").length;
      const partial = failed ? `; ${failed} source${failed === 1 ? "" : "s"} could not be parsed` : "";
      showToast(`${formatNumber(merged.records.length)} flows and ${formatNumber(merged.events.length)} normalized events analyzed${retained} from ${formatNumber(merged.sources.length)} source${merged.sources.length === 1 ? "" : "s"}${partial}.`, failed ? "warn" : "success");
    }
  } catch (error) {
    setStatus("Analysis failed", "warn");
    setInputMessage(error.message || "Analysis failed.");
  }
}

function mergeParsedEvidence(inputs) {
  const records = [];
  const events = [];
  const errors = [];
  const fields = new Set();
  const sources = [];

  (inputs || []).forEach((input, index) => {
    const id = input.id || `evidence-source-${index + 1}`;
    const name = input.name || `Evidence source ${index + 1}`;
    const parsed = input.parsed || null;
    const telemetry = input.telemetry || null;
    const sourceEvents = telemetry?.events || [];
    const structuredTelemetry = sourceEvents.length && !(telemetry?.formats || []).some((format) => STITCHING_FLOW_FORMATS.has(format));
    const sourceRecords = structuredTelemetry ? [] : parsed?.records || [];
    const flowErrors = structuredTelemetry ? [] : parsed?.errors || [];
    const telemetryErrors = telemetry?.errors || [];
    const sourceErrors = sourceRecords.length ? flowErrors : sourceEvents.length ? telemetryErrors : [...flowErrors, ...telemetryErrors];
    const hasEvidence = sourceRecords.length || sourceEvents.length;
    let status = input.error || !hasEvidence ? "failed" : sourceErrors.length ? "warning" : "ready";
    let errorMessage = input.error || "";
    if (!input.error && parsed && !hasEvidence) errorMessage = "No supported flow or telemetry events were parsed";

    sourceRecords.forEach((record) => records.push({
      ...record,
      evidenceSource: name,
      evidenceSourceId: id,
      sourceLineNumber: record.lineNumber
    }));
    sourceEvents.forEach((event) => events.push({ ...event, evidenceSource: name, evidenceSourceId: id }));
    sourceErrors.forEach((issue) => errors.push({
      ...issue,
      line: issue.line || (Number.isInteger(issue.index) ? issue.index + 1 : null),
      source: name,
      sourceId: id
    }));
    (parsed?.fields || []).forEach((field) => fields.add(field));
    if (errorMessage) errors.push({ line: null, message: errorMessage, source: name, sourceId: id });
    if (!parsed && !errorMessage) {
      status = "failed";
      errors.push({ line: null, message: "File could not be parsed", source: name, sourceId: id });
    }
    sources.push({
      id,
      name,
      size: Number(input.size || 0),
      textBytes: Number(input.textBytes || 0),
      records: sourceRecords.length,
      events: sourceEvents.length,
      errors: sourceErrors.length + (errorMessage ? 1 : 0),
      fields: parsed?.fields || [],
      formats: telemetry?.formats || [],
      status,
      message: errorMessage
    });
  });

  return { records, events, errors, fields: [...fields], sources };
}

function evidenceBatchName(sources) {
  const names = (sources || []).map((source) => source.name);
  if (!names.length) return "Evidence batch";
  if (names.length === 1) return names[0];
  return `${names.length} files: ${names.slice(0, 2).join(", ")}${names.length > 2 ? ` +${names.length - 2}` : ""}`;
}

function safeEvidenceSourceName(name) {
  return String(name || "evidence").replace(/[\r\n\u0000-\u001f\u007f]/g, " ").slice(0, 240);
}

function browserTextBytes(text) {
  return new TextEncoder().encode(String(text || "")).byteLength;
}

async function readBoundedTextStream(stream, maxBytes) {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new Error(`Decompressed evidence exceeds the ${formatBytes(maxBytes)} browser analysis limit.`);
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    return text;
  } finally {
    reader.releaseLock();
  }
}

function assertBrowserTextSize(text) {
  const bytes = new TextEncoder().encode(String(text || "")).byteLength;
  if (bytes > MAX_BROWSER_TEXT_BYTES) {
    throw new Error(`Evidence exceeds the ${formatBytes(MAX_BROWSER_TEXT_BYTES)} browser analysis limit. Use an asynchronous managed source import.`);
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

function collectMessages(value, depth = 0, budget = { remaining: MAX_STRUCTURED_MESSAGES }) {
  if (!value || depth > MAX_STRUCTURED_DEPTH || budget.remaining <= 0) return [];
  if (typeof value === "string") {
    budget.remaining -= 1;
    return [value];
  }
  if (Array.isArray(value)) {
    const messages = [];
    for (const item of value) {
      if (budget.remaining <= 0) break;
      messages.push(...collectMessages(item, depth + 1, budget));
    }
    return messages;
  }
  if (typeof value !== "object") return [];
  if (typeof value.message === "string") return collectMessages(value.message, depth + 1, budget);
  if (Array.isArray(value.logEvents)) return collectMessages(value.logEvents, depth + 1, budget);
  if (value.event) return collectMessages(value.event, depth + 1, budget);
  if (value.record) return collectMessages(value.record, depth + 1, budget);
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
  const evidenceSource = els.evidenceSourceFilter.value;

  state.filtered = state.records.filter((record) => {
    const matchesAction = action === "all" || record.action === action;
    const matchesProtocol = protocol === "all" || record.protocol === protocol;
    const matchesEvidenceSource = evidenceSource === "all" || record.evidenceSourceId === evidenceSource;
    const matchesHeatmap = !state.heatmap.selection || !networkHeatmapApi?.recordMatchesHeatmapSelection || networkHeatmapApi.recordMatchesHeatmapSelection(record, state.heatmap.selection);
    const matchesExecutiveFinding = !state.executive.evidenceRecords || state.executive.evidenceRecords.has(record);
    const haystack = [
      record.interfaceId,
      record.evidenceSource,
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
    return matchesAction && matchesProtocol && matchesEvidenceSource && matchesSearch && matchesHeatmap && matchesExecutiveFinding;
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

function refreshEvidenceSourceFilter(sources) {
  const available = (sources || []).filter((source) => source.records > 0);
  els.evidenceSourceFilter.innerHTML = `<option value="all">All evidence sources</option>${available
    .map((source) => `<option value="${escapeHtml(source.id)}">${escapeHtml(source.name)} (${formatNumber(source.records)})</option>`)
    .join("")}`;
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
    metricTemplate("Detections", formatNumber(analysis.detections.length), analysis.policySuppressed ? `${formatNumber(analysis.policySuppressed)} suppressed by policy` : "investigation queue"),
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
  renderFindings(findingsForHeatmapSelection(analysis.detections));
  renderObservations(analysis.observations || []);
  renderApplicationMix();
  renderTopFindings();
  renderCoverage();
  renderHistory();
  renderSavedHunts();
  renderOptimization();
  renderAnalystSummary();
  renderPolicyRecommendations();
  renderEventStitching();
  renderTopology();
  renderEnterprise();
  if (!state.selectedEntity && analysis.entityRisk[0]) {
    selectEntity(analysis.entityRisk[0].key, false);
  } else {
    renderEntityDetail();
  }
  renderImportQuality();
}

async function renderTopFindings() {
  if (!els.topFindingsTable || !executiveReportingApi) return;
  refreshTopFindingFilterOptions();
  if (!state.analysis) {
    els.topFindingsTable.innerHTML = `<tr><td colspan="10">${emptyState()}</td></tr>`;
    els.topFindingsStatus.textContent = "Analyze evidence to rank findings.";
    els.topFindingDetail.innerHTML = "";
    return;
  }
  const token = ++state.executive.renderToken;
  const cases = await listCaseRecords().catch(() => []);
  if (token !== state.executive.renderToken) return;
  const findings = executiveReportingApi.buildTopFindings({
    detections: state.analysis.detections || [],
    records: state.records,
    assets: loadJson(STORAGE_KEYS.assetContext, {}),
    threatIntel: loadJson(STORAGE_KEYS.threatIntel, {}),
    cases,
    filters: {
      period: els.topFindingsPeriod.value,
      source: els.topFindingsSource.value,
      severity: els.topFindingsSeverity.value,
      environment: els.topFindingsEnvironment.value
    },
    limit: 10
  });
  state.executive.topFindings = findings;
  if (!findings.some((finding) => finding.id === state.executive.selectedFindingId)) state.executive.selectedFindingId = findings[0]?.id || "";
  const active = findings.find((finding) => finding.id === state.executive.selectedFindingId) || findings[0] || null;
  els.topFindingsStatus.textContent = findings.length
    ? `${findings.length} consolidated finding${findings.length === 1 ? "" : "s"} ranked by severity, confidence, business context, exposure, breadth, velocity, intelligence, and case pressure.`
    : "No findings match the current period and context filters.";
  els.topFindingsTable.innerHTML = findings.length
    ? findings.map((finding) => topFindingRow(finding, finding.id === active?.id)).join("")
    : `<tr><td colspan="10">${emptyState()}</td></tr>`;
  renderTopFindingDetail(active);
}

function refreshTopFindingFilterOptions() {
  const sourceValue = els.topFindingsSource.value || "all";
  const sources = state.evidenceSources?.length
    ? state.evidenceSources
    : [...new Map(state.records.filter((record) => record.evidenceSourceId || record.evidenceSource).map((record) => [record.evidenceSourceId || record.evidenceSource, { id: record.evidenceSourceId || record.evidenceSource, name: record.evidenceSource || record.evidenceSourceId }])).values()];
  els.topFindingsSource.innerHTML = `<option value="all">All sources</option>${sources.map((source) => `<option value="${escapeHtml(source.id || source.name)}">${escapeHtml(source.name || source.id)}</option>`).join("")}`;
  if ([...els.topFindingsSource.options].some((option) => option.value === sourceValue)) els.topFindingsSource.value = sourceValue;

  const environmentValue = els.topFindingsEnvironment.value || "all";
  const assets = loadJson(STORAGE_KEYS.assetContext, {});
  const environments = [...new Set(Object.values(assets).map((asset) => asset?.environment).filter(Boolean))].sort();
  els.topFindingsEnvironment.innerHTML = `<option value="all">All environments</option>${environments.map((environment) => `<option value="${escapeHtml(environment)}">${escapeHtml(environment)}</option>`).join("")}`;
  if ([...els.topFindingsEnvironment.options].some((option) => option.value === environmentValue)) els.topFindingsEnvironment.value = environmentValue;
}

function topFindingRow(finding, selected) {
  const affected = finding.assets.length
    ? finding.assets.slice(0, 2).map((asset) => asset.label || asset.key).join(", ")
    : finding.entities.slice(0, 2).join(", ") || "Unknown";
  const trendLabel = finding.trend === "new" ? "New" : finding.trend === "up" ? `Up ${Math.abs(finding.trendDelta)}` : finding.trend === "down" ? `Down ${Math.abs(finding.trendDelta)}` : "Flat";
  const lastSeen = finding.lastSeenMs ? formatDate(finding.lastSeenMs) : "Unknown";
  const sourceCount = Math.max(1, finding.sourceNames.length);
  return `<tr class="${selected ? "selected" : ""}" data-top-finding-row="${escapeHtml(finding.id)}">
    <td><strong>${finding.rank}</strong></td>
    <td><strong>${escapeHtml(finding.title)}</strong><span>${escapeHtml([finding.tactic, finding.technique].filter(Boolean).join(" / "))}</span></td>
    <td><span class="urgency-score ${escapeHtml(finding.urgencyLabel.toLowerCase())}">${finding.urgency}</span></td>
    <td><strong class="trend-indicator ${escapeHtml(finding.trend)}">${escapeHtml(trendLabel)}</strong><span>${finding.currentCount} current / ${finding.previousCount} prior</span></td>
    <td><strong>${escapeHtml(affected)}</strong><span>${escapeHtml(finding.environment)}</span></td>
    <td><strong>${finding.blastRadius}</strong><span>entit${finding.blastRadius === 1 ? "y" : "ies"}</span></td>
    <td><strong>${Math.round(finding.confidence * 100)}%</strong><span>${sourceCount} source${sourceCount === 1 ? "" : "s"}</span></td>
    <td><strong>${escapeHtml(finding.owner)}</strong><span>${escapeHtml(finding.status)}</span></td>
    <td><strong>${escapeHtml(lastSeen)}</strong><span>${finding.records.length} evidence row${finding.records.length === 1 ? "" : "s"}</span></td>
    <td><button class="mini-button" type="button" data-top-finding="${escapeHtml(finding.id)}">Explain</button></td>
  </tr>`;
}

function renderTopFindingDetail(finding) {
  if (!finding) {
    els.topFindingDetail.innerHTML = "";
    return;
  }
  els.topFindingDetail.innerHTML = `<div class="finding-score-detail">
    <div class="finding-score-summary">
      <p class="panel-kicker">Urgency ${finding.urgency}/100 - ${escapeHtml(finding.urgencyLabel)}</p>
      <h3>${escapeHtml(finding.title)}</h3>
      <p>${escapeHtml(finding.copy || "Review the linked evidence and business context before disposition.")}</p>
      <div class="button-row">
        <button class="ghost-button compact" type="button" data-top-evidence="${escapeHtml(finding.id)}" ${finding.records.length ? "" : "disabled title=\"No linked evidence rows\""}>View evidence</button>
      </div>
    </div>
    <div class="finding-score-factors" aria-label="Urgency score factors">
      ${finding.factors.map((item) => `<div class="score-factor-row">
        <strong>${escapeHtml(item.label)}</strong><span>${item.score}/${item.maximum} - ${escapeHtml(item.evidence)}</span>
        <div class="score-factor-track" aria-hidden="true"><i style="width:${item.maximum ? Math.round(item.score / item.maximum * 100) : 0}%"></i></div>
      </div>`).join("")}
    </div>
  </div>`;
}

function handleTopFindingAction(event) {
  const explain = event.target.closest("[data-top-finding]");
  const evidence = event.target.closest("[data-top-evidence]");
  const id = evidence?.dataset.topEvidence || explain?.dataset.topFinding;
  if (!id) return;
  const finding = state.executive.topFindings.find((item) => item.id === id);
  if (!finding) return;
  state.executive.selectedFindingId = id;
  if (evidence) {
    if (!finding.records.length) return setInputMessage("This finding has no directly linked evidence rows.");
    state.executive.evidenceRecords = new Set(finding.records);
    applyFilters();
    renderFindings(findingsForHeatmapSelection(state.analysis?.detections || []));
    activateTab("records");
    showToast(`${formatNumber(finding.records.length)} linked evidence row${finding.records.length === 1 ? "" : "s"} selected.`);
    return;
  }
  els.topFindingsTable.querySelectorAll("tr").forEach((row) => row.classList.toggle("selected", row.dataset.topFindingRow === id));
  renderTopFindingDetail(finding);
}

function resetTopFindingsFilters() {
  els.topFindingsPeriod.value = "evidence";
  els.topFindingsSource.value = "all";
  els.topFindingsSeverity.value = "all";
  els.topFindingsEnvironment.value = "all";
  state.executive.evidenceRecords = null;
  state.executive.selectedFindingId = "";
  applyFilters();
  renderFindings(findingsForHeatmapSelection(state.analysis?.detections || []));
  renderTopFindings();
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
  if (els.topFindingsTable) els.topFindingsTable.innerHTML = `<tr><td colspan="10">${emptyState()}</td></tr>`;
  if (els.topFindingDetail) els.topFindingDetail.innerHTML = "";
  if (els.topFindingsStatus) els.topFindingsStatus.textContent = "Analyze evidence to rank findings.";
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
    els.stitchChainList,
    els.stitchDetail,
    els.stitchGapList,
    els.topologyCanvas,
    els.replayEventList,
    els.enterpriseCoverageList,
    els.detectionRuleResultList,
    els.investigationGraphList,
    els.incidentOpsList,
    els.qualityDashboardList,
    els.governanceReadinessList
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
  if (els.stitchStatus) els.stitchStatus.textContent = "No normalized evidence";
  if (els.stitchMetricGrid) {
    els.stitchMetricGrid.innerHTML = [
      metricTemplate("Incident chains", "0", "multi-source"),
      metricTemplate("Explainable links", "0", "confidence-scored"),
      metricTemplate("Normalized events", "0", "0 formats"),
      metricTemplate("Conflicts", "0", "unsafe joins blocked")
    ].join("");
  }
  if (els.replayEventCountLabel) els.replayEventCountLabel.textContent = "0 of 0 records";
  if (els.playReplayButton) els.playReplayButton.textContent = "Play";
  if (state.replayTimer) {
    window.clearInterval(state.replayTimer);
    state.replayTimer = null;
  }
  state.huntResults = [];
  renderHuntResults();
  renderSavedHunts();
  renderCoverage();
  renderHistory();
  renderOptimization();
  renderImportQuality();
  renderRecordsTable();
  renderEnterprise();
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
    const sourceCount = Math.max(1, state.evidenceSources.filter((source) => source.records > 0 || source.events > 0).length);
    els.parseIssueList.innerHTML = `<div class="issue-item"><strong>No parser issues</strong>${escapeHtml(formatNumber(state.records.length))} flows and ${escapeHtml(formatNumber(state.stitching.events.length))} normalized events parsed from ${escapeHtml(formatNumber(sourceCount))} source${sourceCount === 1 ? "" : "s"}.</div>`;
    return;
  }

  els.parseIssueList.innerHTML = issues
    .slice(0, 5)
    .map((issue) => {
      const location = issue.source ? `${issue.source}${issue.line ? `, line ${issue.line}` : ""}` : issue.line ? `Line ${issue.line}` : "Evidence source";
      return `<div class="issue-item"><strong>${escapeHtml(location)}</strong>${escapeHtml(issue.message)}</div>`;
    })
    .join("");
}

function renderEvidenceSources() {
  if (!els.evidenceSourceList) return;
  const sources = state.evidenceSources || [];
  if (!sources.length) {
    els.evidenceSourceList.innerHTML = "";
    return;
  }
  els.evidenceSourceList.innerHTML = sources
    .slice(0, 6)
    .map((source) => {
      const result = source.status === "failed"
        ? source.message || "Not parsed"
        : `${formatNumber(source.records)} flows, ${formatNumber(source.events || 0)} events${source.formats?.length ? `, ${source.formats.join(", ")}` : ""}${source.errors ? `, ${formatNumber(source.errors)} issues` : ""}`;
      return `<div class="evidence-source-item" data-status="${escapeHtml(source.status)}"><strong title="${escapeHtml(source.name)}">${escapeHtml(source.name)}</strong><span>${escapeHtml(result)}</span></div>`;
    })
    .join("") + (sources.length > 6 ? `<div class="evidence-source-item"><strong>${formatNumber(sources.length - 6)} more sources</strong><span>Loaded</span></div>` : "");
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
          <div class="explain-grid">
            <div><strong>Why it fired</strong><span>${escapeHtml(explainDetection(finding))}</span></div>
            <div><strong>Evidence basis</strong><span>${escapeHtml(detectionEvidenceText(finding))}</span></div>
            <div><strong>Confidence</strong><span>${escapeHtml(confidenceLabel(finding.confidence || 0))}</span></div>
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

function findingsForHeatmapSelection(findings) {
  return findings.filter((finding) => {
    const records = finding.records || [];
    const matchesHeatmap = !state.heatmap.selection || !networkHeatmapApi?.recordMatchesHeatmapSelection || records.some((record) => networkHeatmapApi.recordMatchesHeatmapSelection(record, state.heatmap.selection));
    const matchesExecutiveFinding = !state.executive.evidenceRecords || records.some((record) => state.executive.evidenceRecords.has(record));
    return matchesHeatmap && matchesExecutiveFinding;
  });
}

function explainDetection(finding) {
  const title = `${finding.title || ""} ${finding.technique || ""} ${(finding.tags || []).join(" ")}`.toLowerCase();
  if (title.includes("beacon")) return "Repeated accepted outbound connections show a regular timing pattern.";
  if (title.includes("sensitive") || title.includes("admin")) return "Traffic touched a sensitive service or administrative port.";
  if (title.includes("rejected") || title.includes("probing")) return "Multiple rejected flows suggest scanning, blocked access attempts, or misconfiguration.";
  if (title.includes("large") || title.includes("transfer")) return "The flow volume is materially higher than normal triage thresholds.";
  if (title.includes("internal") || title.includes("lateral")) return "Private-to-private access reached services commonly used in lateral movement.";
  if (title.includes("baseline")) return "The entity, port, application, or path was not present in the saved baseline.";
  if (title.includes("ai")) return "Enrichment matched known AI-service application or domain hints.";
  return finding.copy || "The detection rule matched the linked flow evidence.";
}

function confidenceLabel(confidence) {
  if (confidence >= 0.75) return "High confidence - strong evidence pattern";
  if (confidence >= 0.55) return "Medium confidence - validate context";
  return "Low confidence - treat as an observation";
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
    els.recordsTable.innerHTML = `<tr><td colspan="9">${emptyState()}</td></tr>`;
    renderSortState();
    return;
  }

  const sorted = sortedRecords(state.filtered);
  els.recordsTable.innerHTML = sorted
    .slice(0, 500)
    .map(
      (record) => `<tr>
        <td>${escapeHtml(formatDate(record.start))}</td>
        <td class="evidence-source-cell" title="${escapeHtml(record.evidenceSource || "Unknown source")}">${escapeHtml(record.evidenceSource || "Unknown source")}</td>
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
        return [record.evidenceSource, record.source, record.destination, record.interfaceId, record.action, record.protocol, record.logStatus, app].join(" ").toLowerCase().includes(lower);
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
        file: record.evidenceSource,
        evidence: record.evidenceSource,
        filename: record.evidenceSource,
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
  const managedAccounts = new Set(sources.map((source) => source.account).filter(Boolean));
  const managedRegions = new Set(sources.map((source) => source.region).filter(Boolean));
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
    coverageTile("Managed Sources", formatNumber(sources.length), `${formatNumber(managedAccounts.size)} accounts, ${formatNumber(managedRegions.size)} regions`)
  ].join("");
}

function coverageTile(label, value, detail) {
  return `<div class="coverage-tile"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><span>${escapeHtml(detail)}</span></div>`;
}

function uniqueRawValues(field) {
  return new Set(state.records.map((record) => record.raw?.[field]).filter((value) => value && value !== "-"));
}

async function refreshManagedSourcesFromBackend() {
  if (!backendApi) return;
  try {
    const sources = await backendApi.listSources();
    saveJson(STORAGE_KEYS.sources, sources);
    renderCoverage();
  } catch (error) {
    if (state.backend.online) showToast(`Managed source sync unavailable: ${error.message}`, "warn");
  }
}

async function saveSourceConfig() {
  const name = els.sourceNameInput.value.trim();
  const scope = els.sourceScopeInput.value.split(/\s+/).map((value) => value.trim()).filter(Boolean);
  if (!name || !scope.length) {
    setInputMessage("Add a source name and at least one expected ENI or CIDR.");
    return;
  }
  const invalid = scope.filter((value) => !isValidScopeValue(value));
  if (invalid.length) {
    setInputMessage(`Invalid source scope: ${invalid.slice(0, 3).join(", ")}. Use ENI IDs, IPv4 CIDRs, IPs, log groups, or S3-style prefixes.`);
    return;
  }
  const sources = loadJson(STORAGE_KEYS.sources, []);
  const existingIndex = sources.findIndex((source) => source.name.toLowerCase() === name.toLowerCase());
  const item = {
    id: existingIndex >= 0 ? sources[existingIndex].id : `source-${Date.now()}`,
    name,
    type: els.sourceTypeInput.value,
    account: els.sourceAccountInput.value.trim(),
    region: els.sourceRegionInput.value.trim(),
    scope,
    ownerUserId: sources[existingIndex]?.ownerUserId || "",
    ownerName: sources[existingIndex]?.ownerName || "",
    createdAt: sources[existingIndex]?.createdAt || new Date().toISOString()
  };
  let saved = item;
  if (backendApi) {
    try {
      saved = await backendApi.saveSource(item);
    } catch (error) {
      if (state.backend.online) {
        setInputMessage(`Source was not saved to the tenant store: ${error.message}`);
        return;
      }
    }
  }
  if (existingIndex >= 0) {
    sources.splice(existingIndex, 1, saved);
  } else {
    sources.unshift(saved);
  }
  saveJson(STORAGE_KEYS.sources, sources.slice(0, 20));
  els.sourceNameInput.value = "";
  els.sourceAccountInput.value = "";
  els.sourceRegionInput.value = "";
  els.sourceScopeInput.value = "";
  renderCoverage();
  showToast(existingIndex >= 0 ? "Source watchlist updated." : "Source watchlist saved.");
}

function isValidScopeValue(value) {
  return /^eni-[a-z0-9]+$/i.test(value) || /^(\d{1,3}\.){3}\d{1,3}(\/([0-9]|[12][0-9]|3[0-2]))?$/.test(value) || /^\/aws\/[\w/.-]+$/i.test(value) || /^s3:\/\/[\w.-]+\/?[\w./=-]*$/i.test(value) || /^[\w./=-]+\/?$/.test(value);
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
      <span>${escapeHtml([source.type, source.account, source.region].filter(Boolean).join(" - ") || "Managed source")}</span>
      <span>${escapeHtml(source.ownerName ? `Owner: ${source.ownerName}` : "Owner: unassigned")}</span>
      <span>${escapeHtml(source.scope.join(", "))}</span>
      <span class="inline-actions">
        <button class="mini-button" type="button" data-ingest-source="${escapeHtml(source.id)}">Ingest</button>
        <button class="mini-button" type="button" data-ingest-source-async="${escapeHtml(source.id)}">Async</button>
        <button class="mini-button" type="button" data-schedule-source="${escapeHtml(source.id)}">Schedule</button>
        <button class="mini-button danger" type="button" data-delete-source="${escapeHtml(source.id)}">Delete</button>
      </span>
    </div>`)
    .join("");
}

async function ingestManagedSource(id) {
  if (!backendApi) return setInputMessage("Backend module is not available.");
  try {
    setBusy(true, "Ingesting managed source");
    const result = await backendApi.ingestManagedSource(id);
    els.pasteInput.value = result.text || "";
    if (result.text) runAnalysis(result.text, result.sourceLabel || result.managedSourceName || "Managed source ingest");
    showToast(`Imported ${result.objectCount ?? result.eventCount ?? 0} items from ${result.managedSourceName || "managed source"}.`);
    await renderBackendJobs();
  } catch (error) {
    setInputMessage(error.message);
  } finally {
    setBusy(false);
  }
}

async function ingestManagedSourceAsync(id) {
  if (!backendApi) return setInputMessage("Backend module is not available.");
  try {
    const run = await backendApi.ingestManagedSourceAsync(id);
    showToast(`Async ingest started for ${run.jobName || "managed source"}.`);
    await refreshJobRuns();
    activateTab("pipeline");
  } catch (error) {
    setInputMessage(error.message);
  }
}

async function scheduleManagedSourceJob(id) {
  if (!backendApi) return setInputMessage("Backend module is not available.");
  const source = loadJson(STORAGE_KEYS.sources, []).find((item) => String(item.id) === String(id));
  try {
    await backendApi.scheduleManagedSource(id, {
      name: source ? `${source.name} ingest` : "Managed source ingest",
      intervalMinutes: Number(els.jobIntervalInput.value || 15)
    });
    showToast("Managed source ingest job scheduled.");
    await renderBackendJobs();
  } catch (error) {
    setInputMessage(error.message);
  }
}

function deleteSourceConfig(id) {
  const sources = loadJson(STORAGE_KEYS.sources, []);
  const source = sources.find((item) => String(item.id) === String(id));
  if (!source) return;
  confirmAction({
    title: "Delete source watchlist entry?",
    body: `This removes "${source.name}" from coverage scoring in this browser.`,
    confirmLabel: "Delete Source",
    onConfirm: async () => {
      try {
        if (backendApi) await backendApi.deleteSource(id);
        saveJson(STORAGE_KEYS.sources, sources.filter((item) => String(item.id) !== String(id)));
        renderCoverage();
        showToast("Source watchlist entry deleted.");
      } catch (error) {
        setInputMessage(error.message);
      }
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
    onConfirm: async () => {
      try {
        if (backendApi) await Promise.all(sources.map((source) => backendApi.deleteSource(source.id)));
        saveJson(STORAGE_KEYS.sources, []);
        renderCoverage();
        showToast("Source watchlist cleared.");
      } catch (error) {
        setInputMessage(error.message);
      }
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

function updateRuleProfileDescription() {
  const profile = els.ruleProfileSelect?.value || "balanced";
  const descriptions = {
    strict: "Strict shows every detection and observation for maximum sensitivity.",
    balanced: "Balanced keeps the default detection mix for day-to-day triage.",
    focused: "Focused suppresses lower-confidence medium and low items for executive triage."
  };
  if (els.ruleProfileDescription) els.ruleProfileDescription.textContent = descriptions[profile] || descriptions.balanced;
}

function applyRuleProfile() {
  const profile = els.ruleProfileSelect.value;
  saveJson(STORAGE_KEYS.ruleProfile, profile);
  updateRuleProfileDescription();
  if (state.records.length) {
    state.analysis = analyzeRecords(state.records, state.errors);
    enrichAnalysis(state.analysis);
    applyBaselineObservations(state.analysis);
    applyDetectionPolicy(state.analysis);
    applyFilters();
    renderDashboard();
  }
  showToast(`Detection profile set to ${profile}.`);
}

function applyDetectionPolicy(analysis) {
  const profile = loadJson(STORAGE_KEYS.ruleProfile, "balanced");
  tuneAnalysisForProfile(analysis, profile, state.records);
}

function tuneAnalysisForProfile(analysis, profile = "balanced", records = []) {
  analysis.ruleProfile = profile;
  analysis.policySuppressed = 0;
  if (profile !== "focused") {
    analysis.findings = [...analysis.detections, ...(analysis.observations || [])];
    return analysis;
  }
  const before = (analysis.detections || []).length + (analysis.observations || []).length;
  analysis.detections = (analysis.detections || []).filter((detection) => detection.severity === "high" || (detection.confidence || 0) >= 0.65);
  analysis.observations = (analysis.observations || []).filter((observation) => (observation.confidence || 0) >= 0.65 && !observation.tags?.includes("Baseline"));
  analysis.findings = [...analysis.detections, ...analysis.observations];
  analysis.policySuppressed = Math.max(0, before - analysis.findings.length);
  analysis.entityRisk = buildEntityRisk(records, analysis.detections);
  return analysis;
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
    state.backend.online = true;
    state.backend.health = health;
    state.backend.auth = auth;
    state.backend.ai = ai;
    state.backend.authMode = health.authMode || auth.authMode || "local-dev";
    if (idbApi?.setStoragePolicy) {
      await idbApi.setStoragePolicy({ enabled: health.browserEvidenceCache === "enabled", retentionDays: 7, maxRecords: 50_000 });
    }
    const store = health.storeMode === "dynamodb" ? "DynamoDB" : "local store";
    els.backendStatusLabel.textContent = health.awsConfigured ? `Backend ready - ${store}, AWS credentials detected` : `Backend ready - ${store}, AWS credentials missing`;
    renderAiStatus(ai, health.awsConfigured);
    await renderBackendAuth(auth);
    await renderBackendJobs();
    if (state.backend.principal) {
      await refreshJobRuns(true);
      await refreshAuditEventsFromBackend(true);
      startJobRunPolling();
    } else {
      stopJobRunPolling();
    }
  } catch {
    if (state.backend.principal) await clearActiveClientStorage();
    state.backend.online = false;
    state.backend.principal = null;
    await setActiveStorageScope(null, "offline-local");
    state.backend.health = null;
    state.backend.auth = null;
    state.backend.ai = null;
    if (idbApi?.setStoragePolicy) await idbApi.setStoragePolicy({ enabled: false, retentionDays: 7, maxRecords: 50_000 });
    stopJobRunPolling();
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
  const bedrockNarrativeOption = els.executiveNarrativeSelect?.querySelector('option[value="bedrock"]');
  if (bedrockNarrativeOption) bedrockNarrativeOption.disabled = disabled;
  if (disabled && els.executiveNarrativeSelect?.value === "bedrock") els.executiveNarrativeSelect.value = "evidence";
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
    state.backend.principal = principal;
    await setActiveStorageScope(principal);
    const roles = principal?.roles?.length ? principal.roles.join(", ") : "viewer";
    els.authStatusLabel.textContent = principal?.authType === "oidc" ? `Signed in as ${principal.name || principal.subject}` : principal?.authType?.startsWith("api-key") ? "API key session" : "Local admin session";
    els.authRoleLabel.textContent = `Tenant: ${principal?.tenantId || auth.defaultTenant || "default"}. Roles: ${roles}. Admin can delete jobs and export audit; analyst can ingest, export, run AI, and manage cases; viewer can inspect.`;
  } catch {
    state.backend.principal = null;
    await setActiveStorageScope(null);
    els.authStatusLabel.textContent = auth.enabled ? "SSO required" : "API key required";
    els.authRoleLabel.textContent = auth.enabled ? `Use ${auth.issuer} and mapped groups for access.` : "Start an HttpOnly backend session with the API key to use cloud ingest and schedules.";
  }
}

async function saveBackendApiKey() {
  if (!backendApi) return;
  try {
    const key = els.apiKeyInput.value.trim();
    await backendApi.saveApiKey(key);
    els.apiKeyInput.value = "";
    showToast(key ? "Secure backend session started." : "Backend session cleared.");
    await refreshBackendStatus();
  } catch (error) {
    setInputMessage(error.message);
  }
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
  await clearActiveClientStorage();
  await backendApi.clearCredentials();
  state.backend.principal = null;
  await setActiveStorageScope(null);
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
            <button class="mini-button" type="button" data-run-job-async="${escapeHtml(job.id)}">Async</button>
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

async function refreshJobRuns(silent = false) {
  if (!backendApi || !els.backendJobRunsList) return;
  try {
    const runs = await backendApi.listJobRuns();
    saveJson(STORAGE_KEYS.jobRuns, runs);
    renderJobRuns(runs);
    notifyCompletedJobRuns(runs, silent);
  } catch (error) {
    if (!silent && state.backend.online) els.backendJobRunsList.innerHTML = `<div class="empty-state"><strong>Job status unavailable</strong><span>${escapeHtml(error.message)}</span></div>`;
  }
}

function renderJobRuns(runs = []) {
  if (!els.backendJobRunsList) return;
  if (!runs.length) {
    els.backendJobRunsList.innerHTML = emptyState();
    return;
  }
  els.backendJobRunsList.innerHTML = runs
    .slice(0, 8)
    .map((run) => {
      const pct = Math.max(4, Math.min(100, Number(run.progress || 0)));
      return `<div class="rank-item">
        <span class="rank-label">${escapeHtml(run.jobName || "Async ingest")}</span>
        <span class="rank-value">${escapeHtml(run.status)} - ${escapeHtml(run.message || "")}</span>
        <div class="rank-bar"><span style="width:${pct}%"></span></div>
      </div>`;
    })
    .join("");
}

function notifyCompletedJobRuns(runs = [], silent = false) {
  const seen = loadJson(STORAGE_KEYS.seenJobRuns, {});
  let changed = false;
  runs.forEach((run) => {
    if (!["completed", "failed"].includes(run.status) || seen[run.id] === run.status) return;
    seen[run.id] = run.status;
    changed = true;
    if (!silent) {
      showToast(run.status === "completed" ? `${run.jobName || "Async ingest"} completed.` : `${run.jobName || "Async ingest"} failed: ${run.message || "Unknown error"}`, run.status === "completed" ? "success" : "warn");
    }
  });
  if (changed) saveJson(STORAGE_KEYS.seenJobRuns, seen);
}

function startJobRunPolling() {
  stopJobRunPolling();
  if (!backendApi) return;
  state.jobRunPoller = window.setInterval(() => refreshJobRuns(false), 10000);
}

function stopJobRunPolling() {
  if (!state.jobRunPoller) return;
  window.clearInterval(state.jobRunPoller);
  state.jobRunPoller = null;
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

async function runBackendJobAsync(id) {
  try {
    const run = await backendApi.runJobAsync(id);
    showToast(`Async ingest started for ${run.jobName || "job"}.`);
    await refreshJobRuns();
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
  els.aiPromptPreset.value = "";
  els.aiAnswerPanel.classList.remove("loading");
  els.aiAnswerPanel.innerHTML = `<div class="empty-state"><strong>No AI response yet</strong><span>Ask a question about the current investigation evidence.</span></div>`;
}

function applyAiPromptPreset() {
  if (els.aiPromptPreset.value) {
    els.aiQuestionInput.value = els.aiPromptPreset.value;
  }
}

function buildAiEvidenceContext() {
  return buildAiEvidenceContextModel({
    analysis: state.analysis || {},
    records: state.records,
    filtered: state.filtered,
    source: state.fileName || "Current browser evidence",
    workspaceName: loadJson(STORAGE_KEYS.workspaces, []).find((workspace) => workspace.id === state.activeWorkspaceId)?.name || "",
    sources: loadJson(STORAGE_KEYS.sources, []),
    ruleProfile: state.analysis?.ruleProfile || loadJson(STORAGE_KEYS.ruleProfile, "balanced")
  });
}

function buildAiEvidenceContextModel({ analysis = {}, records = [], filtered = [], source = "Current browser evidence", workspaceName = "", sources = [], ruleProfile = "balanced" }) {
  return {
    source,
    workspace: workspaceName,
    generatedAt: new Date().toISOString(),
    metrics: {
      records: records.length,
      filteredRecords: filtered.length,
      detections: analysis.detections?.length || 0,
      observations: analysis.observations?.length || 0,
      highSeverity: (analysis.detections || []).filter((item) => item.severity === "high").length,
      rejected: records.filter((record) => record.action === "REJECT").length,
      bytes: sumBy(records, "bytes")
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
    sampleRecords: filtered.slice(0, 25).map((record) => ({
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
    })),
    sources,
    ruleProfile: analysis.ruleProfile || ruleProfile
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
        if (index === 0 && values.some((value) => /ip|dst|domain|sni|app|latitude|longitude|country|city/i.test(value))) {
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
    ai: item.ai === true || item.ai === "true" || AI_DOMAIN_HINTS.some((hint) => domain.includes(hint)),
    latitude: coordinateValue(item.latitude ?? item.lat, -90, 90),
    longitude: coordinateValue(item.longitude ?? item.lon ?? item.lng, -180, 180),
    country: item.country || item.countryCode || "",
    region: item.region || item.state || "",
    city: item.city || "",
    geoSource: item.geoSource || item.locationSource || "analyst enrichment",
    geoPrecision: item.geoPrecision || item.locationPrecision || "approximate"
  };
}

function coordinateValue(value, minimum, maximum) {
  if (value === "" || value === null || value === undefined) return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= minimum && number <= maximum ? number : null;
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
  let backendRetained = false;
  if (backendApi) {
    try {
      let evidenceUpload = null;
      if (state.backend.online && state.backend.health?.directEvidenceUploads && state.rawEvidenceText) {
        const safeName = String(fileName || "browser-evidence.log").replace(/[\\/\u0000-\u001f\u007f]/g, "-").slice(0, 240) || "browser-evidence.log";
        const file = new File([state.rawEvidenceText], safeName, { type: "text/plain" });
        evidenceUpload = await backendApi.uploadEvidenceFile(file);
      }
      const rawEvidenceText = evidenceUpload ? "" : state.rawEvidenceText;
      const estimatedBytes = new TextEncoder().encode(rawEvidenceText).byteLength;
      if (!evidenceUpload && estimatedBytes > 512 * 1024) {
        throw new Error("Direct evidence object storage is required for browser evidence larger than 512 KB");
      }
      await backendApi.saveEvidenceRun({
        fileName,
        recordCount: records.length,
        records: records.slice(0, evidenceUpload ? 50 : 500),
        rawEvidenceText,
        evidenceUploadId: evidenceUpload?.id || "",
        analysis
      });
      backendRetained = true;
    } catch (error) {
      if (state.backend.health?.evidenceRetentionRequired) throw new Error(`Required evidence retention failed: ${error.message}`);
      if (state.backend.online) showToast(`Tenant evidence store skipped: ${error.message}`, "warn");
    }
  }
  if (!idbApi?.saveEvidenceRun) return { backendRetained, browserCached: false };
  let browserCached = false;
  try {
    browserCached = Boolean(await idbApi.saveEvidenceRun({ fileName, records, analysis }));
  } catch (error) {
    showToast(`IndexedDB persistence failed: ${error.message}`, "warn");
  }
  return { backendRetained, browserCached };
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
  const title = els.caseTitleInput.value.trim();
  if (!title) return setInputMessage("Case title is required.");
  try {
    const record = await saveCaseRecord({
      id: els.caseIdInput.value || undefined,
      revision: els.caseIdInput.value ? editingCaseRevision : undefined,
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
    editingCaseRevision = Number(record.revision || 1);
    await refreshCases(record.id);
    await operationsController?.refreshCaseTasks();
    showToast("Case saved.");
  } catch (error) {
    setInputMessage(error.message);
  }
}

async function refreshCases(selectedId = "") {
  const cases = await listCaseRecords();
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
  const cases = await listCaseRecords();
  const item = cases.find((caseItem) => caseItem.id === id);
  if (!item) return;
  els.caseIdInput.value = item.id;
  editingCaseRevision = Number(item.revision || 1);
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
      await deleteCaseRecord(id);
      await refreshCases();
      showToast("Case deleted.");
    }
  });
}

async function renderCaseAudit(caseId) {
  if (!caseId) return;
  els.caseAuditTitle.textContent = `Case audit log`;
  const audit = await listCaseAuditRecords(caseId);
  if (!audit.length) {
    els.caseAuditList.innerHTML = emptyState();
    return;
  }
  els.caseAuditList.innerHTML = audit
    .map((entry) => `<div class="issue-item"><strong>${escapeHtml(entry.action)}</strong>${escapeHtml(formatDate(Date.parse(entry.createdAt)))} - ${escapeHtml(entry.detail || "")}</div>`)
    .join("");
}

async function saveCaseRecord(caseRecord) {
  if (backendApi) {
    try {
      return await backendApi.saveCase(caseRecord);
    } catch (error) {
      if (state.backend.online) {
        setInputMessage(`Case was not saved to the tenant store: ${error.message}`);
        throw error;
      }
    }
  }
  if (!idbApi?.saveCase) throw new Error("Case storage is not available in this browser.");
  return idbApi.saveCase(caseRecord);
}

async function listCaseRecords() {
  if (backendApi) {
    try {
      return await backendApi.listCases();
    } catch (error) {
      if (state.backend.online) {
        setInputMessage(`Case list unavailable: ${error.message}`);
        return [];
      }
    }
  }
  return idbApi?.listCases ? idbApi.listCases() : [];
}

async function deleteCaseRecord(id) {
  if (backendApi) return backendApi.deleteCase(id);
  if (!idbApi?.deleteCase) throw new Error("Case storage is not available in this browser.");
  return idbApi.deleteCase(id);
}

async function listCaseAuditRecords(caseId) {
  if (backendApi) {
    try {
      return await backendApi.listCaseAudit(caseId);
    } catch (error) {
      if (state.backend.online) return [];
    }
  }
  return idbApi?.listAudit ? idbApi.listAudit(caseId) : [];
}

async function refreshTenantUsersFromBackend() {
  if (!backendApi) return;
  try {
    const users = await backendApi.listTenantUsers();
    saveJson(STORAGE_KEYS.tenantUsers, users);
    renderTenantAdmin();
  } catch (error) {
    if (state.backend.online && hasRole("admin")) showToast(`Tenant admin sync unavailable: ${error.message}`, "warn");
  }
}

function renderTenantAdmin() {
  if (!els.adminTenantLabel) return;
  const users = loadJson(STORAGE_KEYS.tenantUsers, []);
  const sources = loadJson(STORAGE_KEYS.sources, []);
  const principal = state.backend.principal;
  const canAdmin = hasRole("admin");
  els.adminTenantLabel.textContent = principal ? `Tenant ${principal.tenantId || "default"} - ${principal.roles?.join(", ") || "viewer"}` : "Backend session required";
  els.adminUserCountLabel.textContent = String(users.length);
  renderAdminSourceOptions(users, sources);
  renderAdminOpsGrid(users, sources);
  renderAccessReview(users, sources);
  renderAuditReview();
  renderExportApprovals();
  [els.adminUserNameInput, els.adminUserEmailInput, els.adminUserRoleInput, els.adminUserStatusInput, els.adminUserSourceInput, els.sourceOwnerSourceInput, els.sourceOwnerUserInput].forEach((control) => {
    if (control) control.disabled = !canAdmin;
  });
  els.saveTenantUserButton.disabled = !canAdmin;
  els.assignSourceOwnerButton.disabled = !canAdmin;
  if (!state.backend.online || !principal) {
    els.adminUserList.innerHTML = `<div class="empty-state"><strong>Backend session required</strong><span>Start the backend and sign in with an admin role to manage tenant access.</span></div>`;
    els.sourceOwnershipList.innerHTML = emptyState();
    return;
  }
  if (!canAdmin) {
    els.adminUserList.innerHTML = `<div class="empty-state"><strong>Admin role required</strong><span>Your current role can view tenant data in other tabs, but cannot manage users or source ownership.</span></div>`;
    els.sourceOwnershipList.innerHTML = emptyState();
    return;
  }
  els.adminUserList.innerHTML = users.length
    ? users
        .map((user) => `<article class="entity-card">
          <div class="entity-name">${escapeHtml(user.name || user.email)}</div>
          <div class="risk-score ${user.role === "admin" ? "high" : user.role === "analyst" ? "medium" : ""}">${escapeHtml(user.role[0].toUpperCase())}</div>
          <div class="entity-meta">
            <span class="tag">${escapeHtml(user.email)}</span>
            <span class="tag">${escapeHtml(user.status || "active")}</span>
            <button class="mini-button" type="button" data-edit-tenant-user="${escapeHtml(user.id)}">Edit</button>
            <button class="mini-button danger" type="button" data-delete-tenant-user="${escapeHtml(user.id)}">Delete</button>
          </div>
        </article>`)
        .join("")
    : `<div class="empty-state"><strong>No tenant users</strong><span>Add analysts, viewers, or admins to document ownership.</span></div>`;
  els.sourceOwnershipList.innerHTML = sources.length
    ? sources
        .map((source) => `<div class="issue-item">
          <strong>${escapeHtml(source.name)}</strong>
          <span>${escapeHtml(source.ownerName || "Unassigned")}</span>
          <span>${escapeHtml([source.type, source.region].filter(Boolean).join(" - "))}</span>
        </div>`)
        .join("")
    : emptyState();
}

function activeTenantUsers(users = []) {
  return users.filter((user) => !["disabled", "suspended", "revoked"].includes(String(user.status || "active").toLowerCase()));
}

function roleCount(users = [], role) {
  return users.filter((user) => String(user.role || "").toLowerCase() === role && !["disabled", "suspended", "revoked"].includes(String(user.status || "active").toLowerCase())).length;
}

function buildAccessReview(users = [], sources = []) {
  const activeUsers = activeTenantUsers(users);
  const admins = roleCount(users, "admin");
  const unassignedSources = sources.filter((source) => !source.ownerUserId && !source.ownerName);
  const disabledUsers = users.filter((user) => ["disabled", "suspended", "revoked"].includes(String(user.status || "").toLowerCase()));
  const invitedUsers = users.filter((user) => String(user.status || "").toLowerCase() === "invited");
  const analystsWithoutSources = activeUsers.filter((user) => user.role === "analyst" && sources.length && !(user.sourceIds || []).length);
  const ownerProblems = sources.filter((source) => {
    if (!source.ownerUserId) return false;
    const owner = users.find((user) => user.id === source.ownerUserId);
    return !owner || !activeTenantUsers([owner]).length;
  });
  const staleUsers = users.filter((user) => {
    const timestamp = Date.parse(user.updatedAt || user.createdAt || "");
    return Number.isFinite(timestamp) && Date.now() - timestamp > 90 * 24 * 60 * 60 * 1000;
  });
  const issues = [
    {
      title: "Admin coverage",
      detail: admins ? `${formatNumber(admins)} active admin${admins === 1 ? "" : "s"} available for privileged actions` : "No active admin users are recorded in the tenant roster",
      tone: admins ? "ok" : "warn"
    },
    {
      title: "Source ownership",
      detail: unassignedSources.length ? `${formatNumber(unassignedSources.length)} managed source${unassignedSources.length === 1 ? "" : "s"} need an accountable owner` : "Every managed source has an owner",
      tone: unassignedSources.length ? "warn" : "ok"
    },
    {
      title: "Analyst scoping",
      detail: analystsWithoutSources.length ? `${formatNumber(analystsWithoutSources.length)} analyst${analystsWithoutSources.length === 1 ? "" : "s"} have no source scope assigned` : "Analyst source scopes are documented",
      tone: analystsWithoutSources.length ? "warn" : "ok"
    },
    {
      title: "Owner validity",
      detail: ownerProblems.length ? `${formatNumber(ownerProblems.length)} source owner assignment${ownerProblems.length === 1 ? "" : "s"} point to missing or disabled users` : "Source owners map to active tenant users",
      tone: ownerProblems.length ? "warn" : "ok"
    },
    {
      title: "Dormant access",
      detail: staleUsers.length ? `${formatNumber(staleUsers.length)} roster entr${staleUsers.length === 1 ? "y" : "ies"} have not changed in 90 days` : "No stale roster entries detected",
      tone: staleUsers.length ? "warn" : "ok"
    },
    {
      title: "Lifecycle cleanup",
      detail: disabledUsers.length || invitedUsers.length ? `${formatNumber(disabledUsers.length)} disabled and ${formatNumber(invitedUsers.length)} invited users need periodic review` : "No disabled or pending users need cleanup",
      tone: disabledUsers.length || invitedUsers.length ? "warn" : "ok"
    }
  ];
  return {
    activeUsers,
    admins,
    unassignedSources,
    disabledUsers,
    invitedUsers,
    analystsWithoutSources,
    ownerProblems,
    staleUsers,
    issues
  };
}

function renderAdminOpsGrid(users = [], sources = []) {
  if (!els.adminOpsGrid) return;
  const review = buildAccessReview(users, sources);
  const ownerCoverage = sources.length ? Math.round(((sources.length - review.unassignedSources.length) / sources.length) * 100) : 0;
  els.adminOpsGrid.innerHTML = [
    metricTemplate("Active users", formatNumber(review.activeUsers.length), `${formatNumber(roleCount(users, "analyst"))} analysts`),
    metricTemplate("Admins", formatNumber(review.admins), review.admins ? "privileged users" : "coverage gap"),
    metricTemplate("Owner coverage", `${ownerCoverage}%`, `${formatNumber(sources.length - review.unassignedSources.length)} of ${formatNumber(sources.length)} sources`),
    metricTemplate("Review items", formatNumber(review.issues.filter((issue) => issue.tone === "warn").length), "access findings")
  ].join("");
}

function renderAccessReview(users = loadJson(STORAGE_KEYS.tenantUsers, []), sources = loadJson(STORAGE_KEYS.sources, [])) {
  if (!els.accessReviewList) return;
  if (!state.backend.online || !state.backend.principal) {
    els.accessReviewList.innerHTML = `<div class="empty-state"><strong>Backend session required</strong><span>Sign in as a tenant admin to review RBAC and source accountability.</span></div>`;
    return;
  }
  if (!hasRole("admin")) {
    els.accessReviewList.innerHTML = `<div class="empty-state"><strong>Admin role required</strong><span>Access reviews include tenant users, source owners, and exportable audit context.</span></div>`;
    return;
  }
  const review = buildAccessReview(users, sources);
  els.accessReviewList.innerHTML = review.issues.map((issue) => enterpriseIssue(issue.title, issue.detail, issue.tone)).join("");
}

function exportAccessReview() {
  if (!hasRole("admin")) return setInputMessage("Admin role is required to export access reviews.");
  const users = loadJson(STORAGE_KEYS.tenantUsers, []);
  const sources = loadJson(STORAGE_KEYS.sources, []);
  const review = buildAccessReview(users, sources);
  const payload = {
    product: "SignalPrism NDR",
    type: "tenant-access-review",
    exportedAt: new Date().toISOString(),
    tenantId: state.backend.principal?.tenantId || "default",
    principal: state.backend.principal ? { subject: state.backend.principal.subject, email: state.backend.principal.email, roles: state.backend.principal.roles } : null,
    summary: {
      activeUsers: review.activeUsers.length,
      admins: review.admins,
      unassignedSources: review.unassignedSources.length,
      analystsWithoutSources: review.analystsWithoutSources.length,
      ownerProblems: review.ownerProblems.length,
      staleUsers: review.staleUsers.length
    },
    findings: review.issues,
    users: users.map(({ id, name, email, role, status, sourceIds }) => ({ id, name, email, role, status, sourceIds })),
    sources: sources.map(({ id, name, type, account, region, ownerUserId, ownerName }) => ({ id, name, type, account, region, ownerUserId, ownerName }))
  };
  downloadText(`signalprism-access-review-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(payload, null, 2), "application/json");
  showToast("Access review exported.");
}

async function refreshAuditEventsFromBackend(silent = false) {
  if (!backendApi?.listAuditEvents) {
    renderAuditReview();
    return;
  }
  if (!state.backend.online || !state.backend.principal || !hasRole("admin")) {
    renderAuditReview();
    return;
  }
  try {
    const result = await backendApi.listAuditEvents({ limit: 200 });
    saveJson(STORAGE_KEYS.auditEvents, result.events || []);
    renderAuditReview();
    renderProductionHardening();
    if (!silent) showToast(`${formatNumber(result.count || 0)} audit events refreshed.`);
  } catch (error) {
    if (!silent && state.backend.online) setInputMessage(`Audit events unavailable: ${error.message}`);
    renderAuditReview();
  }
}

function filteredAuditEvents() {
  const action = String(els.auditActionFilterInput?.value || "").trim().toLowerCase();
  const actor = String(els.auditActorFilterInput?.value || "").trim().toLowerCase();
  return loadJson(STORAGE_KEYS.auditEvents, [])
    .filter((entry) => !action || String(entry.action || "").toLowerCase().includes(action))
    .filter((entry) => !actor || auditActor(entry).toLowerCase().includes(actor));
}

function auditActor(entry) {
  return String(entry.actor || entry.email || entry.subject || entry.principal?.email || entry.principal?.subject || "system");
}

function auditDetail(entry) {
  if (entry.detail) return String(entry.detail);
  const details = entry.details || {};
  const fields = [details.title, details.name, details.email, details.jobName, details.fileName, details.sourceLabel, details.source, details.destination, details.caseId, details.jobId, details.sourceId, details.workspace, details.format, details.error].filter(Boolean);
  if (fields.length) return fields.join(" - ");
  return entry.tenantId ? `Tenant ${entry.tenantId}` : "No additional details recorded";
}

function renderAuditReview() {
  if (!els.auditReviewList) return;
  if (!state.backend.online || !state.backend.principal) {
    els.auditReviewList.innerHTML = `<div class="empty-state"><strong>Backend session required</strong><span>Tenant audit review is available after signing in with an admin role.</span></div>`;
    return;
  }
  if (!hasRole("admin")) {
    els.auditReviewList.innerHTML = `<div class="empty-state"><strong>Admin role required</strong><span>Audit records include tenant activity, exports, auth, and ingest actions.</span></div>`;
    return;
  }
  const events = filteredAuditEvents();
  if (!events.length) {
    els.auditReviewList.innerHTML = `<div class="empty-state"><strong>No matching audit events</strong><span>Refresh the tenant log or adjust the action and actor filters.</span></div>`;
    return;
  }
  els.auditReviewList.innerHTML = events
    .slice(0, 50)
    .map((entry) => {
      const created = Date.parse(entry.createdAt || "");
      const retention = entry.retentionUntil ? `Retain until ${entry.retentionUntil.slice(0, 10)}` : "Retention not set";
      return `<div class="issue-item">
        <strong>${escapeHtml(entry.action || "audit.event")}</strong>
        <span>${escapeHtml(auditActor(entry))} - ${escapeHtml(Number.isFinite(created) ? formatDate(created) : "-")} - ${escapeHtml(retention)}</span>
        <span>${escapeHtml(auditDetail(entry))}</span>
      </div>`;
    })
    .join("");
}

async function renderExportApprovals() {
  if (!els.exportApprovalList) return;
  if (!state.backend.online || !state.backend.principal || (!hasRole("admin") && !hasRole("analyst"))) {
    els.exportApprovalList.innerHTML = `<div class="empty-state"><strong>Authenticated analyst access required</strong><span>Export requests are tenant-scoped and available after sign-in.</span></div>`;
    return;
  }
  try {
    const approvals = await backendApi.listExportApprovals();
    if (!approvals.length) {
      els.exportApprovalList.innerHTML = `<div class="empty-state"><strong>No export requests</strong><span>Controlled investigation exports will appear here.</span></div>`;
      return;
    }
    els.exportApprovalList.innerHTML = approvals.slice(0, 25).map((approval) => {
      const canApprove = hasRole("admin") && approval.status === "pending";
      const canDownload = approval.status === "approved";
      const action = canApprove
        ? `<button class="mini-button" type="button" data-approve-export="${escapeHtml(approval.id)}">Approve</button>`
        : canDownload
          ? `<button class="mini-button" type="button" data-download-export="${escapeHtml(approval.id)}" data-export-kind="${escapeHtml(approval.kind)}">Download</button>`
          : "";
      return `<div class="issue-item">
        <strong>${escapeHtml(approval.label || (approval.kind === "security-lake" ? "Security Lake export" : "Investigation package"))}</strong>
        <span>${escapeHtml(approval.requestedBy || "unknown")} - ${escapeHtml(approval.status)} - ${escapeHtml(String(approval.format || "json").toUpperCase())} - ${escapeHtml(approval.requestedAt ? new Date(approval.requestedAt).toLocaleString() : "")}</span>
        <span class="mono">SHA-256 ${escapeHtml(String(approval.payloadHash || "").slice(0, 20))}</span>
        ${action}
      </div>`;
    }).join("");
  } catch (error) {
    els.exportApprovalList.innerHTML = `<div class="empty-state"><strong>Approval queue unavailable</strong><span>${escapeHtml(error.message)}</span></div>`;
  }
}

async function approveExportRequest(id) {
  try {
    await backendApi.approveExport(id);
    await renderExportApprovals();
    showToast("Export request approved for one-time use.");
  } catch (error) {
    setInputMessage(error.message);
  }
}

async function downloadApprovedExport(id, kind) {
  try {
    if (kind === "security-lake") {
      const lines = [
        ...buildOcsfNetworkActivity(state.filtered.length ? state.filtered : state.records),
        ...buildOcsfFindings(state.analysis?.detections || [])
      ].map((item) => JSON.stringify(item));
      const payload = lines.join("\n") + "\n";
      if (!lines.length) throw new Error("There is no current OCSF evidence to export.");
      const contentSha256 = await sha256Text(payload);
      const manifest = await backendApi.exportSecurityLakeManifest({ approvalId: id, contentSha256 });
      if (!manifest.contentSha256 || manifest.contentSha256 !== contentSha256) {
        throw new Error("Current OCSF evidence does not match the approved export hash.");
      }
      downloadText("signalprism-security-lake-ocsf.ndjson", payload, "application/x-ndjson");
    } else {
      const result = await backendApi.exportInvestigationPackage({ approvalId: id });
      if (result.reportType === "executive-brief" && result.report) downloadExecutiveBriefPayload(result.report, result.format || "json");
      else downloadText(`signalprism-investigation-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(result, null, 2), "application/json");
    }
    await renderExportApprovals();
    showToast("Approved export downloaded and consumed.");
  } catch (error) {
    setInputMessage(error.message);
  }
}

async function exportAuditReviewNdjson() {
  if (!hasRole("admin")) return setInputMessage("Admin role is required to export tenant audit events.");
  if (backendApi?.exportAuditNdjson && state.backend.online) {
    try {
      const text = await backendApi.exportAuditNdjson();
      downloadText(`signalprism-audit-${new Date().toISOString().slice(0, 10)}.ndjson`, text, "application/x-ndjson");
      await refreshAuditEventsFromBackend(true);
      showToast("Tenant audit exported.");
      return;
    } catch (error) {
      setInputMessage(`Audit export failed: ${error.message}`);
    }
  }
  const events = filteredAuditEvents();
  if (!events.length) return setInputMessage("No cached audit events are available to export.");
  downloadText(`signalprism-audit-cached-${new Date().toISOString().slice(0, 10)}.ndjson`, events.map((entry) => JSON.stringify(entry)).join("\n") + "\n", "application/x-ndjson");
  showToast("Cached audit events exported.");
}

function renderAdminSourceOptions(users, sources) {
  if (!els.adminUserSourceInput || !els.sourceOwnerSourceInput || !els.sourceOwnerUserInput) return;
  els.adminUserSourceInput.innerHTML = sources.map((source) => `<option value="${escapeHtml(source.id)}">${escapeHtml(source.name)}</option>`).join("");
  els.sourceOwnerSourceInput.innerHTML = `<option value="">Select source</option>${sources.map((source) => `<option value="${escapeHtml(source.id)}">${escapeHtml(source.name)}</option>`).join("")}`;
  els.sourceOwnerUserInput.innerHTML = `<option value="">Unassigned</option>${users.map((user) => `<option value="${escapeHtml(user.id)}">${escapeHtml(user.name || user.email)} (${escapeHtml(user.role)})</option>`).join("")}`;
}

async function saveTenantUser() {
  if (!backendApi) return setInputMessage("Backend module is not available.");
  const sourceIds = [...els.adminUserSourceInput.selectedOptions].map((option) => option.value).filter(Boolean);
  try {
    const user = await backendApi.saveTenantUser({
      id: els.adminUserIdInput.value || undefined,
      name: els.adminUserNameInput.value.trim(),
      email: els.adminUserEmailInput.value.trim(),
      role: els.adminUserRoleInput.value,
      status: els.adminUserStatusInput.value,
      sourceIds
    });
    const users = loadJson(STORAGE_KEYS.tenantUsers, []);
    const index = users.findIndex((item) => item.id === user.id);
    if (index >= 0) users.splice(index, 1, user);
    else users.unshift(user);
    saveJson(STORAGE_KEYS.tenantUsers, users);
    clearTenantUserForm();
    renderTenantAdmin();
    await refreshAuditEventsFromBackend(true);
    showToast("Tenant user saved.");
  } catch (error) {
    setInputMessage(error.message);
  }
}

function editTenantUser(id) {
  const user = loadJson(STORAGE_KEYS.tenantUsers, []).find((item) => item.id === id);
  if (!user) return;
  els.adminUserIdInput.value = user.id;
  els.adminUserNameInput.value = user.name || "";
  els.adminUserEmailInput.value = user.email || "";
  els.adminUserRoleInput.value = user.role || "viewer";
  els.adminUserStatusInput.value = user.status || "active";
  [...els.adminUserSourceInput.options].forEach((option) => {
    option.selected = (user.sourceIds || []).includes(option.value);
  });
}

function deleteTenantUser(id) {
  confirmAction({
    title: "Delete tenant user?",
    body: "This removes the user from the SignalPrism tenant roster. It does not change your identity provider.",
    confirmLabel: "Delete User",
    onConfirm: async () => {
      try {
        await backendApi.deleteTenantUser(id);
        saveJson(STORAGE_KEYS.tenantUsers, loadJson(STORAGE_KEYS.tenantUsers, []).filter((user) => user.id !== id));
        renderTenantAdmin();
        await refreshAuditEventsFromBackend(true);
        showToast("Tenant user deleted.");
      } catch (error) {
        setInputMessage(error.message);
      }
    }
  });
}

async function assignSourceOwner() {
  if (!backendApi) return setInputMessage("Backend module is not available.");
  const sourceId = els.sourceOwnerSourceInput.value;
  if (!sourceId) return setInputMessage("Select a managed source before assigning ownership.");
  try {
    const source = await backendApi.assignSourceOwner(sourceId, els.sourceOwnerUserInput.value);
    const sources = loadJson(STORAGE_KEYS.sources, []);
    const index = sources.findIndex((item) => item.id === source.id);
    if (index >= 0) sources.splice(index, 1, source);
    saveJson(STORAGE_KEYS.sources, sources);
    renderCoverage();
    renderTenantAdmin();
    await refreshAuditEventsFromBackend(true);
    showToast("Source owner updated.");
  } catch (error) {
    setInputMessage(error.message);
  }
}

function clearTenantUserForm() {
  els.adminUserIdInput.value = "";
  els.adminUserNameInput.value = "";
  els.adminUserEmailInput.value = "";
  els.adminUserRoleInput.value = "analyst";
  els.adminUserStatusInput.value = "active";
  [...els.adminUserSourceInput.options].forEach((option) => {
    option.selected = false;
  });
}

function hasRole(role) {
  return Boolean(state.backend.principal?.roles?.includes(role));
}

async function refreshEnterpriseFromBackend() {
  if (!backendApi) {
    ensureDefaultDetectionRules();
    renderEnterprise();
    return;
  }
  try {
    const [settings, rules, artifacts, telemetryEvents, correlations, responseActions, contentBundles, readiness] = await Promise.all([
      backendApi.enterpriseSettings(),
      backendApi.listDetectionRules(),
      backendApi.listEnterpriseArtifacts ? backendApi.listEnterpriseArtifacts() : Promise.resolve([]),
      backendApi.listTelemetryEvents ? backendApi.listTelemetryEvents() : Promise.resolve([]),
      backendApi.listCorrelations ? backendApi.listCorrelations() : Promise.resolve([]),
      backendApi.listResponseActions ? backendApi.listResponseActions() : Promise.resolve([]),
      backendApi.listDetectionContentBundles ? backendApi.listDetectionContentBundles() : Promise.resolve([]),
      backendApi.enterpriseReadiness ? backendApi.enterpriseReadiness() : Promise.resolve(null)
    ]);
    saveJson(STORAGE_KEYS.enterpriseSettings, settings);
    saveJson(STORAGE_KEYS.detectionRules, rules.length ? rules : enterpriseDefaultRules());
    applyEnterpriseArtifactsFromBackend(artifacts);
    state.enterprise = { ...state.enterprise, telemetryEvents, correlations, responseActions, contentBundles, readiness };
  } catch (error) {
    ensureDefaultDetectionRules();
    if (state.backend.online) showToast(`Enterprise sync unavailable: ${error.message}`, "warn");
  }
  renderEnterprise();
}

async function refreshEnterpriseSecurityOperations(silent = false) {
  if (!backendApi || !state.backend.online) {
    if (!silent) showToast("Connect to the backend to refresh enterprise controls.", "warn");
    renderEnterpriseSecurityOperations([]);
    return;
  }
  if (els.refreshHardeningButton) els.refreshHardeningButton.disabled = true;
  try {
    const [telemetryEvents, correlations, responseActions, contentBundles, readiness] = await Promise.all([
      backendApi.listTelemetryEvents(),
      backendApi.listCorrelations(),
      backendApi.listResponseActions(),
      backendApi.listDetectionContentBundles(),
      backendApi.enterpriseReadiness()
    ]);
    state.enterprise = { ...state.enterprise, telemetryEvents, correlations, responseActions, contentBundles, readiness };
    const cases = await listCaseRecords().catch(() => []);
    renderEnterpriseSecurityOperations(cases);
    renderProductionHardening();
    if (!silent) showToast("Enterprise deployment posture refreshed.");
  } catch (error) {
    if (!silent) showToast(`Enterprise refresh failed: ${error.message}`, "error");
  } finally {
    if (els.refreshHardeningButton) els.refreshHardeningButton.disabled = false;
  }
}

function applyEnterpriseArtifactsFromBackend(artifacts = []) {
  const grouped = {
    THREAT_INTEL: STORAGE_KEYS.threatIntel,
    COPILOT_NOTE: STORAGE_KEYS.copilotNotes,
    PLAYBOOK_RUN: STORAGE_KEYS.playbookRuns,
    EVIDENCE_VAULT_BUNDLE: STORAGE_KEYS.evidenceVault,
    ENTERPRISE_REPORT: STORAGE_KEYS.enterpriseReports,
    EXECUTIVE_BRIEF: STORAGE_KEYS.executiveBriefs,
    REPORT_SCHEDULE: STORAGE_KEYS.reportSchedules,
    REPORT_DELIVERY: STORAGE_KEYS.reportDeliveries
  };
  Object.entries(grouped).forEach(([type, key]) => {
    const values = artifacts.filter((artifact) => artifact.type === type).map((artifact) => ({
      ...(artifact.payload || artifact),
      _artifactRevision: artifact.revision,
      _artifactCreatedAt: artifact.createdAt
    }));
    if (values.length) saveJson(key, type === "THREAT_INTEL" ? mergeThreatIntelValues(values) : values.slice(0, 25));
  });
}

function ensureDefaultDetectionRules() {
  const rules = loadJson(STORAGE_KEYS.detectionRules, []);
  if (!rules.length) saveJson(STORAGE_KEYS.detectionRules, enterpriseDefaultRules());
  if (!loadJson(STORAGE_KEYS.enterpriseSettings, null)) saveJson(STORAGE_KEYS.enterpriseSettings, defaultEnterpriseSettingsClient());
}

function enterpriseDefaultRules() {
  const now = new Date().toISOString();
  return [
    {
      id: "builtin-public-admin-rejects",
      name: "Public admin probing",
      description: "Repeated rejected traffic to SSH/RDP/SMB/database ports.",
      query: "action:REJECT port:22",
      severity: "high",
      tactic: "Reconnaissance",
      technique: "Active Scanning",
      attackId: "T1595",
      status: "production",
      enabled: true,
      owner: "SignalPrism",
      builtIn: true,
      createdAt: now,
      updatedAt: now
    },
    {
      id: "builtin-lateral-sensitive-access",
      name: "Accepted sensitive lateral access",
      description: "Accepted internal access to administrative or database services.",
      query: "action:ACCEPT port:5432",
      severity: "medium",
      tactic: "Lateral Movement",
      technique: "Remote Services",
      attackId: "T1021",
      status: "production",
      enabled: true,
      owner: "SignalPrism",
      builtIn: true,
      createdAt: now,
      updatedAt: now
    },
    {
      id: "builtin-high-egress",
      name: "High-volume external egress",
      description: "Large accepted public transfer that may require ownership review.",
      query: "action:ACCEPT bytes>1000000",
      severity: "medium",
      tactic: "Exfiltration",
      technique: "Exfiltration Over Web Service",
      attackId: "T1567",
      status: "test",
      enabled: true,
      owner: "SignalPrism",
      builtIn: true,
      createdAt: now,
      updatedAt: now
    }
  ];
}

function defaultEnterpriseSettingsClient() {
  return {
    id: "default",
    securityLake: { enabled: false, bucket: "", prefix: "custom/SignalPrismNDR", region: "us-east-1", format: "ocsf-ndjson" },
    siem: { target: "Security Lake", endpoint: "", exportMode: "manual" },
    governance: { evidenceRetentionDays: 90, legalHold: false, exportApprovalRequired: true, auditRetentionDays: 2555, scimEnabled: false },
    dataPlatform: { analyticsStore: "Security Lake + Athena", searchStore: "", archiveStore: "S3 Object Lock evidence packages", queryEngine: "Athena" }
  };
}

function enterpriseSettingsValue() {
  return { ...defaultEnterpriseSettingsClient(), ...(loadJson(STORAGE_KEYS.enterpriseSettings, null) || {}) };
}

async function renderEnterprise() {
  if (!els.enterpriseMetricGrid) return;
  ensureDefaultDetectionRules();
  const settings = enterpriseSettingsValue();
  syncEnterpriseInputs(settings);
  const cases = await listCaseRecords().catch(() => []);
  const readiness = buildEnterpriseReadiness(cases);
  const deploymentReadiness = state.enterprise.readiness;
  const displayedScore = deploymentReadiness?.score ?? readiness.score;
  els.enterpriseReadinessLabel.textContent = `${displayedScore}% enterprise ready`;
  els.enterpriseMetricGrid.innerHTML = [
    metricTemplate("Readiness", `${displayedScore}%`, deploymentReadiness ? `${deploymentReadiness.passed} of ${deploymentReadiness.total} deployment controls` : readiness.blockers.length ? `${readiness.blockers.length} gaps` : "operational"),
    metricTemplate("Source ownership", `${readiness.ownerCoverage}%`, `${formatNumber(readiness.sourcesOwned)} of ${formatNumber(readiness.sourcesTotal)} sources`),
    metricTemplate("Rule coverage", formatNumber(readiness.rulesProduction), `${formatNumber(readiness.rulesTotal)} analytics`),
    metricTemplate("Open incidents", formatNumber(readiness.openCases), `${formatNumber(readiness.highCases)} high severity`),
    metricTemplate("OCSF pipeline", settings.securityLake?.bucket ? "Ready" : "Draft", settings.siem?.target || "Security Lake"),
    metricTemplate("Threat intel", formatNumber(readiness.threatIndicators), "active indicators"),
    metricTemplate("Vault bundles", formatNumber(readiness.vaultBundles), "retained exports")
  ].join("");
  renderDetectionOperations(cases);
  renderProductionHardening();
  renderEnterpriseSecurityOperations(cases);
  renderCitedCopilot();
  renderSourceHealth();
  renderEnterpriseCoverage();
  renderThreatIntel();
  renderEntityRiskScoring();
  renderDetectionRules();
  renderDetectionAsCode();
  renderSecurityLakeManifest();
  renderAssetContext();
  renderInvestigationGraph();
  renderReplayTimeline();
  renderPolicyFindings();
  renderIncidentOps(cases);
  renderPlaybooks(cases);
  renderQualityDashboard(cases);
  renderGovernanceReadiness(readiness, settings);
  renderEvidenceVault();
  renderEnterpriseReport();
  renderEnterpriseAdminReadiness();
}

function renderEnterpriseSecurityOperations(cases = []) {
  renderSignalFusion();
  renderResponseActions(cases);
  renderDetectionContentBundles();
}

function renderSignalFusion() {
  if (!els.telemetryMetricGrid || !els.correlationList) return;
  const events = state.enterprise.telemetryEvents || [];
  const findings = state.enterprise.correlations || [];
  const formats = new Set(events.map((event) => event.format).filter(Boolean));
  const high = findings.filter((finding) => ["critical", "high"].includes(finding.severity)).length;
  const identities = new Set(events.map((event) => event.identity).filter(Boolean));
  els.telemetryMetricGrid.innerHTML = [
    metricTemplate("Events", formatNumber(events.length), `${formatNumber(formats.size)} formats`),
    metricTemplate("Correlations", formatNumber(findings.length), `${formatNumber(high)} high priority`),
    metricTemplate("Identities", formatNumber(identities.size), "cloud principals and sensors")
  ].join("");
  els.correlationList.innerHTML = findings.length
    ? findings.slice(0, 50).map((finding) => `<div class="issue-item ${["critical", "high"].includes(finding.severity) ? "warning" : ""}">
        <strong>${escapeHtml(finding.title)} <span class="tag ${tagClass(finding.severity)}">${escapeHtml(finding.severity)}</span></strong>
        <span>${escapeHtml(finding.summary)} ${escapeHtml(finding.technique || "")} | ${formatNumber(finding.evidenceIds?.length || 0)} evidence events | score ${formatNumber(finding.score)}</span>
      </div>`).join("")
    : `<div class="empty-state"><strong>No cross-source findings</strong><span>Ingest CloudTrail, DNS, GuardDuty, Zeek, or Suricata JSON, then run correlation.</span></div>`;
}

function renderResponseActions(cases = []) {
  if (!els.responseActionList) return;
  const actions = state.enterprise.responseActions || [];
  const correlations = state.enterprise.correlations || [];
  updateSelectOptions(els.responseCaseInput, [{ value: "", label: "No linked case" }, ...cases.map((item) => ({ value: item.id, label: `${item.title} (${item.status})` }))]);
  updateSelectOptions(els.responseCorrelationInput, [{ value: "", label: "No linked correlation" }, ...correlations.map((item) => ({ value: item.id, label: `${item.title} - ${item.entity}` }))]);
  const pending = actions.filter((action) => action.status === "pending").length;
  const executed = actions.filter((action) => action.status === "executed").length;
  els.responseActionStatusLabel.textContent = `${formatNumber(pending)} pending | ${formatNumber(executed)} executed`;
  els.responseActionList.innerHTML = actions.length
    ? actions.slice(0, 100).map((action) => {
        const canApprove = action.status === "pending" && hasRole("admin");
        return `<div class="issue-item ${action.status === "execution-failed" ? "warning" : ""}">
          <strong>${escapeHtml(responseActionLabel(action.type))} <span class="tag ${action.status === "executed" ? "green" : action.status === "execution-failed" ? "red" : "amber"}">${escapeHtml(action.status)}</span></strong>
          <span>${escapeHtml(action.target)} | requested by ${escapeHtml(action.requestedBy || "unknown")} | ${escapeHtml(action.reason || "")}</span>
          ${canApprove ? `<div class="inline-actions"><button class="mini-button" type="button" data-approve-response-action="${escapeHtml(action.id)}">Approve</button></div>` : ""}
        </div>`;
      }).join("")
    : `<div class="empty-state"><strong>No response requests</strong><span>Create a governed action from a validated finding or case.</span></div>`;
}

function renderDetectionContentBundles() {
  if (!els.detectionContentList) return;
  const bundles = state.enterprise.contentBundles || [];
  const verification = state.enterprise.contentVerification;
  els.importDetectionContentButton.disabled = !hasRole("admin");
  els.importDetectionContentButton.title = hasRole("admin") ? "Verify and import this bundle into test status" : "Admin role required";
  const verificationHtml = verification
    ? `<div class="issue-item"><strong>Verified ${escapeHtml(verification.name || verification.id)}</strong><span>${escapeHtml(verification.version)} | ${formatNumber(verification.ruleCount)} rules | Ed25519 | ${escapeHtml(String(verification.digest || "").slice(0, 16))}...</span></div>`
    : "";
  els.detectionContentList.innerHTML = `${verificationHtml}${bundles.length
    ? bundles.slice(0, 50).map((bundle) => `<div class="issue-item"><strong>${escapeHtml(bundle.name || bundle.id)} <span class="tag green">verified</span></strong><span>Version ${escapeHtml(bundle.version)} | ${formatNumber(bundle.ruleCount)} rules | imported by ${escapeHtml(bundle.importedBy || "unknown")}</span></div>`).join("")
    : `<div class="empty-state"><strong>No signed content imported</strong><span>Verify a trusted Ed25519 bundle before importing rules into test status.</span></div>`}`;
}

function updateSelectOptions(select, options) {
  if (!select) return;
  const selected = select.value;
  select.innerHTML = options.map((option) => `<option value="${escapeHtml(option.value)}">${escapeHtml(option.label)}</option>`).join("");
  if (options.some((option) => String(option.value) === selected)) select.value = selected;
}

function responseActionLabel(type) {
  return {
    "isolate-entity": "Isolate entity",
    "block-ip": "Block IP",
    "disable-access-key": "Disable access key",
    "restrict-security-group": "Restrict security group",
    "quarantine-workload": "Quarantine workload",
    "revoke-session": "Revoke sessions",
    "capture-packets": "Request packet capture",
    "create-ticket": "Create ticket",
    "notify-soc": "Notify SOC",
    "rollback-action": "Rollback action"
  }[type] || type || "Response action";
}

function loadEnterpriseTelemetrySample() {
  const base = Date.now() - 10 * 60 * 1000;
  const iso = (offset) => new Date(base + offset * 1000).toISOString();
  const events = [];
  for (let index = 0; index < 6; index += 1) {
    events.push({ eventVersion: "1.09", eventTime: iso(index * 30), eventSource: "sts.amazonaws.com", eventName: "AssumeRole", awsRegion: "us-east-1", sourceIPAddress: "203.0.113.77", errorCode: "AccessDenied", recipientAccountId: "123456789012", userIdentity: { arn: `arn:aws:iam::123456789012:user/probe-${index}` } });
  }
  events.push({ eventVersion: "1.09", eventTime: iso(240), eventSource: "iam.amazonaws.com", eventName: "AttachRolePolicy", awsRegion: "us-east-1", sourceIPAddress: "10.0.1.12", recipientAccountId: "123456789012", userIdentity: { arn: "arn:aws:iam::123456789012:user/compromised-admin" }, requestParameters: { roleName: "ProductionApp", policyArn: "arn:aws:iam::aws:policy/AdministratorAccess" } });
  events.push({ timestamp: iso(300), event_type: "alert", src_ip: "10.0.1.12", src_port: 49152, dest_ip: "198.51.100.44", dest_port: 443, proto: "TCP", alert: { action: "allowed", severity: 1, category: "Potentially Bad Traffic", signature: "Possible command and control callback" } });
  events.push({ id: "gd-sample-1", type: "Backdoor:EC2/C&CActivity.B", title: "EC2 instance communicating with a command and control server", severity: 8.2, createdAt: iso(305), updatedAt: iso(305), accountId: "123456789012", region: "us-east-1", resource: { resourceType: "Instance", instanceDetails: { instanceId: "i-0123456789abcdef0", networkInterfaces: [{ privateIpAddress: "10.0.1.12" }] } }, service: { action: { actionType: "NETWORK_CONNECTION", networkConnectionAction: { protocol: "TCP", localIpDetails: { ipAddressV4: "10.0.1.12" }, localPortDetails: { port: 49152 }, remoteIpDetails: { ipAddressV4: "198.51.100.44" }, remotePortDetails: { port: 443 } } } } });
  for (let index = 0; index < 9; index += 1) events.push({ query_timestamp: iso(330 + index * 10), srcaddr: "10.0.1.12", query_name: `${"a".repeat(62)}${index}.example-cdn.net.`, query_type: "A", transport: "UDP", vpc_id: "vpc-0abc123", region: "us-east-1" });
  els.telemetryFormatInput.value = "auto";
  els.telemetryPayloadInput.value = JSON.stringify(events, null, 2);
  showToast("Loaded a mixed CloudTrail, GuardDuty, Suricata, and Route 53 sample.");
}

async function ingestEnterpriseTelemetry() {
  const payload = els.telemetryPayloadInput.value.trim();
  if (!payload) return showToast("Paste telemetry JSON or load the sample first.", "warn");
  if (!backendApi?.ingestTelemetry) return showToast("The enterprise telemetry API is unavailable.", "error");
  els.ingestTelemetryButton.disabled = true;
  try {
    const result = await backendApi.ingestTelemetry(els.telemetryFormatInput.value, payload);
    showToast(`${formatNumber(result.accepted)} telemetry events ingested${result.rejected ? `; ${formatNumber(result.rejected)} rejected` : ""}.`);
    await refreshEnterpriseSecurityOperations(true);
  } catch (error) {
    showToast(`Telemetry ingest failed: ${error.message}`, "error");
  } finally {
    els.ingestTelemetryButton.disabled = false;
  }
}

async function correlateEnterpriseTelemetry() {
  if (!backendApi?.runTelemetryCorrelation) return showToast("The telemetry correlation API is unavailable.", "error");
  els.correlateTelemetryButton.disabled = true;
  try {
    const result = await backendApi.runTelemetryCorrelation(60);
    showToast(`${formatNumber(result.findingCount)} cross-source findings produced from ${formatNumber(result.eventCount)} events.`);
    await refreshEnterpriseSecurityOperations(true);
  } catch (error) {
    showToast(`Correlation failed: ${error.message}`, "error");
  } finally {
    els.correlateTelemetryButton.disabled = false;
  }
}

async function requestEnterpriseResponseAction() {
  if (!backendApi?.requestResponseAction) return showToast("The governed response API is unavailable.", "error");
  els.requestResponseActionButton.disabled = true;
  try {
    const action = await backendApi.requestResponseAction({
      type: els.responseActionTypeInput.value,
      executionMode: els.responseExecutionModeInput.value,
      target: els.responseActionTargetInput.value.trim(),
      reason: els.responseActionReasonInput.value.trim(),
      caseId: els.responseCaseInput.value,
      correlationId: els.responseCorrelationInput.value
    });
    els.responseActionTargetInput.value = "";
    els.responseActionReasonInput.value = "";
    showToast(`${responseActionLabel(action.type)} requested; a separate admin must approve it.`);
    await refreshEnterpriseSecurityOperations(true);
  } catch (error) {
    showToast(`Response request failed: ${error.message}`, "error");
  } finally {
    els.requestResponseActionButton.disabled = false;
  }
}

function approveEnterpriseResponseAction(id) {
  confirmAction({
    title: "Approve governed response?",
    body: "Approval records your identity and may emit a containment event to the configured automation bus. Downstream responders must honor the action ID for idempotency.",
    confirmLabel: "Approve Action",
    onConfirm: async () => {
      try {
        const action = await backendApi.approveResponseAction(id);
        showToast(action.status === "executed" ? "Response action emitted to automation." : "Response action approved; execution remains disabled.");
        await refreshEnterpriseSecurityOperations(true);
      } catch (error) {
        showToast(`Response approval failed: ${error.message}`, "error");
      }
    }
  });
}

async function verifyEnterpriseDetectionContent() {
  const bundle = parseDetectionContentInput();
  if (!bundle) return;
  els.verifyDetectionContentButton.disabled = true;
  try {
    state.enterprise.contentVerification = await backendApi.verifyDetectionContent(bundle);
    renderDetectionContentBundles();
    showToast(`Verified ${state.enterprise.contentVerification.ruleCount} signed detection rules.`);
  } catch (error) {
    state.enterprise.contentVerification = null;
    renderDetectionContentBundles();
    showToast(`Content verification failed: ${error.message}`, "error");
  } finally {
    els.verifyDetectionContentButton.disabled = false;
  }
}

function importEnterpriseDetectionContent() {
  const bundle = parseDetectionContentInput();
  if (!bundle) return;
  confirmAction({
    title: "Import signed detection content?",
    body: "Every rule will enter test status. Production promotion still requires passing evidence and an independent admin approval.",
    confirmLabel: "Import to Test",
    onConfirm: async () => {
      els.importDetectionContentButton.disabled = true;
      try {
        const result = await backendApi.importDetectionContent(bundle);
        saveJson(STORAGE_KEYS.detectionRules, result.rules || []);
        state.enterprise.contentVerification = result.bundle;
        showToast(`${formatNumber(result.rules?.length || 0)} signed rules imported into test status.`);
        await refreshEnterpriseFromBackend();
      } catch (error) {
        showToast(`Content import failed: ${error.message}`, "error");
      } finally {
        els.importDetectionContentButton.disabled = !hasRole("admin");
      }
    }
  });
}

function parseDetectionContentInput() {
  const text = els.detectionContentInput.value.trim();
  if (!text) {
    showToast("Paste a signed detection content bundle first.", "warn");
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    showToast("Detection content must be valid JSON.", "error");
    return null;
  }
}

function syncEnterpriseInputs(settings) {
  if (document.activeElement && ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName) && document.activeElement.closest("#enterprisePanel")) return;
  els.securityLakeBucketInput.value = settings.securityLake?.bucket || "";
  els.enterpriseSecurityLakePrefixInput.value = settings.securityLake?.prefix || "custom/SignalPrismNDR";
  els.siemTargetInput.value = settings.siem?.target || "Security Lake";
  els.siemEndpointInput.value = settings.siem?.endpoint || "";
  els.retentionDaysInput.value = settings.governance?.evidenceRetentionDays || 90;
  els.legalHoldInput.checked = Boolean(settings.governance?.legalHold);
  els.exportApprovalInput.checked = settings.governance?.exportApprovalRequired !== false;
  els.analyticsStoreInput.value = settings.dataPlatform?.analyticsStore || "Security Lake + Athena";
  els.queryEngineInput.value = settings.dataPlatform?.queryEngine || "";
}

function buildEnterpriseReadiness(cases = []) {
  const sources = loadJson(STORAGE_KEYS.sources, []);
  const rules = loadJson(STORAGE_KEYS.detectionRules, []);
  const assets = Object.values(loadJson(STORAGE_KEYS.assetContext, {}));
  const threatIntel = Object.values(loadJson(STORAGE_KEYS.threatIntel, {}));
  const vaultBundles = loadJson(STORAGE_KEYS.evidenceVault, []);
  const settings = enterpriseSettingsValue();
  const sourcesOwned = sources.filter((source) => source.ownerName || source.ownerUserId).length;
  const rulesProduction = rules.filter((rule) => rule.enabled !== false && rule.status === "production").length;
  const openCases = cases.filter((item) => item.status !== "Closed").length;
  const highCases = cases.filter((item) => item.status !== "Closed" && item.severity === "high").length;
  const blockers = [];
  if (!sources.length) blockers.push("No managed sources");
  if (sources.length && sourcesOwned < sources.length) blockers.push("Source owners missing");
  if (!rulesProduction) blockers.push("No production rules");
  if (!settings.securityLake?.bucket) blockers.push("Security Lake bucket not configured");
  if (!assets.length) blockers.push("No asset context");
  if (!threatIntel.length) blockers.push("Threat intelligence not connected");
  if (!settings.governance?.exportApprovalRequired) blockers.push("Export approval disabled");
  const score = Math.max(0, Math.min(100, 100 - blockers.length * 14 - (state.errors.length ? 8 : 0)));
  return {
    score,
    blockers,
    ownerCoverage: sources.length ? Math.round((sourcesOwned / sources.length) * 100) : 0,
    sourcesOwned,
    sourcesTotal: sources.length,
    rulesProduction,
    rulesTotal: rules.length,
    openCases,
    highCases,
    threatIndicators: threatIntel.length,
    vaultBundles: vaultBundles.length
  };
}

function buildDetectionOperations(cases = []) {
  const rules = detectionRulesValue();
  const scoredRules = rules.map((rule) => ({ rule, quality: scoreDetectionRuleQuality(rule) }));
  const avgQuality = scoredRules.length ? Math.round(scoredRules.reduce((sum, item) => sum + item.quality.score, 0) / scoredRules.length) : 0;
  const productionRules = rules.filter((rule) => rule.enabled !== false && rule.status === "production");
  const mappedRules = rules.filter((rule) => rule.attackId);
  const testedRules = rules.filter((rule) => Number(rule.testCount || 0) > 0);
  const staleRules = rules.filter((rule) => {
    const lastTested = Date.parse(rule.lastTestedAt || "");
    return !Number.isFinite(lastTested) || Date.now() - lastTested > 30 * 24 * 60 * 60 * 1000;
  });
  const noisyRules = rules.filter((rule) => Number(rule.testCount || 0) > 100);
  const detections = state.analysis?.detections || [];
  const highDetections = detections.filter((detection) => detection.severity === "high").length;
  const linkedDetectionIds = new Set(cases.map((item) => item.linkedDetection).filter(Boolean));
  const untriagedDetections = detections.filter((detection) => !linkedDetectionIds.has(detection.id));
  const openCases = cases.filter((item) => item.status !== "Closed");
  const failedRuns = loadJson(STORAGE_KEYS.jobRuns, []).filter((run) => String(run.status || "").toLowerCase() === "failed");
  const score = Math.max(
    0,
    Math.min(
      100,
      100 -
        (productionRules.length ? 0 : 18) -
        (rules.length && mappedRules.length < rules.length ? 10 : 0) -
        (rules.length && testedRules.length < rules.length ? 12 : 0) -
        Math.min(staleRules.length * 4, 16) -
        Math.min(noisyRules.length * 6, 18) -
        Math.min(untriagedDetections.length * 3, 18) -
        Math.min(failedRuns.length * 5, 20)
    )
  );
  const issues = [
    enterpriseIssue("Production analytics", productionRules.length ? `${formatNumber(productionRules.length)} production rules are enabled` : "No production detection rules are enabled", productionRules.length ? "ok" : "warn"),
    enterpriseIssue("ATT&CK mapping", rules.length && mappedRules.length === rules.length ? "Every detection rule has a technique mapping" : `${formatNumber(mappedRules.length)} of ${formatNumber(rules.length)} rules are mapped`, rules.length && mappedRules.length === rules.length ? "ok" : "warn"),
    enterpriseIssue("Rule testing", rules.length && testedRules.length === rules.length ? "All rules have passing current-evidence tests" : `${formatNumber(testedRules.length)} of ${formatNumber(rules.length)} rules have test evidence`, rules.length && testedRules.length === rules.length ? "ok" : "warn"),
    enterpriseIssue("Test freshness", staleRules.length ? `${formatNumber(staleRules.length)} rules need a fresh test run` : "Rule tests are fresh or built-in defaults are current", staleRules.length ? "warn" : "ok"),
    enterpriseIssue("Triage load", untriagedDetections.length ? `${formatNumber(untriagedDetections.length)} current detections are not linked to cases` : "Current detections are linked or no active detections exist", untriagedDetections.length ? "warn" : "ok"),
    enterpriseIssue("Import reliability", failedRuns.length ? `${formatNumber(failedRuns.length)} recent async import runs failed` : "No failed async import runs in local history", failedRuns.length ? "warn" : "ok")
  ];
  return {
    score,
    avgQuality,
    rulesTotal: rules.length,
    productionRules: productionRules.length,
    mappedRules: mappedRules.length,
    testedRules: testedRules.length,
    highDetections,
    untriagedDetections: untriagedDetections.length,
    openCases: openCases.length,
    failedRuns: failedRuns.length,
    noisyRules: noisyRules.length,
    issues
  };
}

function renderDetectionOperations(cases = []) {
  if (!els.detectionOpsGrid || !els.detectionOpsList) return;
  const ops = buildDetectionOperations(cases);
  els.detectionOpsLabel.textContent = `${ops.score}% operating health`;
  els.detectionOpsGrid.innerHTML = [
    metricTemplate("Health", `${ops.score}%`, ops.score >= 80 ? "steady state" : "needs review"),
    metricTemplate("Rule quality", `${ops.avgQuality}%`, `${formatNumber(ops.rulesTotal)} analytics`),
    metricTemplate("Production", formatNumber(ops.productionRules), `${formatNumber(ops.mappedRules)} mapped`),
    metricTemplate("Triage", formatNumber(ops.untriagedDetections), `${formatNumber(ops.openCases)} open cases`),
    metricTemplate("Import failures", formatNumber(ops.failedRuns), "async runs")
  ].join("");
  els.detectionOpsList.innerHTML = ops.issues.join("");
}

function buildProductionHardeningChecks() {
  const health = state.backend.health || {};
  const settings = enterpriseSettingsValue();
  const sources = loadJson(STORAGE_KEYS.sources, []);
  const users = loadJson(STORAGE_KEYS.tenantUsers, []);
  const auditEvents = loadJson(STORAGE_KEYS.auditEvents, []);
  const ownedSources = sources.filter((source) => source.ownerName || source.ownerUserId).length;
  const sourceCoverage = sources.length ? Math.round((ownedSources / sources.length) * 100) : 0;
  const authMode = health.authMode || state.backend.authMode || "none";
  const directIngestReported = Object.prototype.hasOwnProperty.call(health, "directIngestEnabled");
  return [
    {
      title: "Identity boundary",
      detail: authMode === "oidc" ? "OIDC/SSO is configured for tenant sessions" : authMode === "api-key" ? "API-key sessions are enabled; prefer OIDC/SSO before production" : "Local-dev admin mode is active",
      tone: authMode === "oidc" ? "ok" : "warn"
    },
    {
      title: "Session protection",
      detail: health.sessionAuth ? `HttpOnly session auth and CSRF are enabled${health.sessionCookieSecure ? " with Secure cookies" : " without Secure cookie flag"}` : "Session auth state is not reported",
      tone: health.sessionAuth && (health.sessionCookieSecure || (typeof location !== "undefined" && location.hostname === "localhost")) ? "ok" : "warn"
    },
    {
      title: "Direct ingest boundary",
      detail: directIngestReported ? (health.directIngestEnabled ? "Direct S3/CloudWatch ingest endpoints are enabled" : "Direct S3/CloudWatch ingest is disabled in favor of managed sources") : "Backend did not report direct ingest posture",
      tone: directIngestReported && !health.directIngestEnabled ? "ok" : "warn"
    },
    {
      title: "Tenant data store",
      detail: health.storeMode === "dynamodb" ? "DynamoDB tenant store is active" : "Local JSON store is active; use DynamoDB or Postgres for production",
      tone: health.storeMode === "dynamodb" ? "ok" : "warn"
    },
    {
      title: "Raw evidence storage",
      detail: health.evidenceObjectStorage === "s3" ? "Raw evidence packages are stored in S3 object storage" : "Raw evidence packages are retained locally",
      tone: health.evidenceObjectStorage === "s3" ? "ok" : "warn"
    },
    {
      title: "Audit review",
      detail: auditEvents.length ? `${formatNumber(auditEvents.length)} tenant audit events cached for review` : "No cached audit events yet; refresh as admin",
      tone: auditEvents.length ? "ok" : "warn"
    },
    {
      title: "Source accountability",
      detail: sources.length ? `${sourceCoverage}% of managed sources have owners` : "No managed sources are configured",
      tone: sources.length && sourceCoverage === 100 ? "ok" : "warn"
    },
    {
      title: "Privileged access",
      detail: users.length ? `${formatNumber(roleCount(users, "admin"))} admins and ${formatNumber(roleCount(users, "analyst"))} analysts in tenant roster` : "Tenant roster is empty or unavailable",
      tone: roleCount(users, "admin") ? "ok" : "warn"
    },
    {
      title: "Governance retention",
      detail: `${formatNumber(settings.governance?.evidenceRetentionDays || 90)} day evidence retention, ${formatNumber(settings.governance?.auditRetentionDays || 2555)} day audit retention`,
      tone: (settings.governance?.evidenceRetentionDays || 0) >= 90 && (settings.governance?.auditRetentionDays || 0) >= 365 ? "ok" : "warn"
    },
    {
      title: "AI guardrails",
      detail: health.bedrockEnabled ? "Bedrock assistant is feature-flagged and role-gated" : "Bedrock assistant is disabled by feature flag",
      tone: health.bedrockEnabled ? "ok" : "warn"
    }
  ];
}

function renderProductionHardening() {
  if (!els.productionHardeningList) return;
  if (Array.isArray(state.enterprise.readiness?.checks)) {
    els.productionHardeningList.innerHTML = state.enterprise.readiness.checks
      .map((check) => enterpriseIssue(check.name, check.status === "pass" ? "Control is configured." : check.remediation, check.status === "pass" ? "ok" : "warn"))
      .join("");
    return;
  }
  const checks = buildProductionHardeningChecks();
  els.productionHardeningList.innerHTML = checks.map((check) => enterpriseIssue(check.title, check.detail, check.tone)).join("");
}

function renderEnterpriseCoverage() {
  const sources = loadJson(STORAGE_KEYS.sources, []);
  const interfaces = new Set(state.records.map((record) => record.interfaceId).filter((value) => value && value !== "-"));
  const accounts = [...uniqueRawValues("account-id")];
  const missingOwners = sources.filter((source) => !source.ownerName && !source.ownerUserId);
  const lines = [
    enterpriseIssue("Observed accounts", accounts.length ? accounts.join(", ") : "No account IDs in current evidence", accounts.length ? "ok" : "warn"),
    enterpriseIssue("Observed interfaces", interfaces.size ? [...interfaces].slice(0, 8).join(", ") : "No ENIs observed", interfaces.size ? "ok" : "warn"),
    enterpriseIssue("Owner gaps", missingOwners.length ? missingOwners.map((source) => source.name).slice(0, 6).join(", ") : "All managed sources have owners", missingOwners.length ? "warn" : "ok"),
    enterpriseIssue("Log health", state.errors.length ? `${state.errors.length} parser issues need review` : "No parser issues in current evidence", state.errors.length ? "warn" : "ok")
  ];
  els.enterpriseCoverageList.innerHTML = lines.join("");
}

function enterpriseIssue(title, detail, tone = "ok") {
  return `<div class="issue-item ${tone === "warn" ? "warning" : ""}"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(detail)}</span></div>`;
}

async function persistEnterpriseArtifact(type, title, payload, status = "active", artifactId = "") {
  const cleanPayload = payload && typeof payload === "object" ? { ...payload } : payload;
  const revision = Number(cleanPayload?._artifactRevision || 0);
  if (cleanPayload && typeof cleanPayload === "object") {
    delete cleanPayload._artifactRevision;
    delete cleanPayload._artifactCreatedAt;
  }
  const artifact = {
    id: artifactId || `${String(type).toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${Date.now()}`,
    type,
    title,
    status,
    payload: cleanPayload,
    ...(revision ? { revision } : {}),
    createdAt: payload?._artifactCreatedAt || new Date().toISOString()
  };
  try {
    if (backendApi?.saveEnterpriseArtifact) return await backendApi.saveEnterpriseArtifact(artifact);
  } catch (error) {
    if (state.backend.online) showToast(`Artifact kept locally: ${error.message}`, "warn");
  }
  return artifact;
}

function renderCitedCopilot() {
  const notes = loadJson(STORAGE_KEYS.copilotNotes, []);
  if (!notes.length) {
    els.copilotCitationList.innerHTML = `<div class="empty-state"><strong>No cited answer yet</strong><span>Ask a question to generate a deterministic investigation answer with evidence references.</span></div>`;
    return;
  }
  const note = notes[0];
  els.copilotCitationList.innerHTML = `<div class="issue-item">
    <strong>${escapeHtml(note.question || "Investigation answer")}</strong>
    <span>${escapeHtml(note.answer || "")}</span>
  </div>${(note.citations || [])
    .map((citation) => `<div class="issue-item"><strong>${escapeHtml(citation.ref)}</strong><span>${escapeHtml(citation.detail)}</span></div>`)
    .join("")}`;
}

async function generateCitedCopilotAnswer() {
  if (!state.records.length && !state.analysis?.detections?.length) return setInputMessage("Analyze evidence before generating a cited answer.");
  const question = els.copilotQuestionInput.value.trim() || "Which entities should I investigate first and why?";
  const cases = await listCaseRecords().catch(() => []);
  const note = buildCitedInvestigationAnswer({
    question,
    analysis: state.analysis,
    records: state.filtered.length ? state.filtered : state.records,
    cases,
    assets: loadJson(STORAGE_KEYS.assetContext, {}),
    threatIntel: loadJson(STORAGE_KEYS.threatIntel, {})
  });
  await persistEnterpriseArtifact("COPILOT_NOTE", question, note);
  const notes = [note, ...loadJson(STORAGE_KEYS.copilotNotes, [])].slice(0, 12);
  saveJson(STORAGE_KEYS.copilotNotes, notes);
  renderCitedCopilot();
  showToast("Evidence-cited copilot answer generated.");
}

function buildCitedInvestigationAnswer({ question = "", analysis = null, records = [], cases = [], assets = {}, threatIntel = {} } = {}) {
  const detections = analysis?.detections || [];
  const topDetection = detections.find((item) => item.severity === "high") || detections[0] || null;
  const topEntity = topDetection?.entity || analysis?.entityRisk?.[0]?.entity || records.find((record) => isPrivateIp(record.source))?.source || records[0]?.source || "unknown";
  const entityRecords = records.filter((record) => record.source === topEntity || record.destination === topEntity).slice(0, 5);
  const intelMatches = records
    .flatMap((record) => [record.source, record.destination])
    .filter((value, index, values) => value && value !== "-" && values.indexOf(value) === index && threatIntel[value])
    .slice(0, 5);
  const asset = assets[topEntity] || Object.values(assets).find((item) => item.ip === topEntity || item.eni === topEntity || item.instance === topEntity) || null;
  const citations = [];
  if (topDetection) citations.push({ ref: `Detection ${topDetection.id || "top"}`, detail: `${topDetection.title} on ${topDetection.entity || "network entity"} with ${Math.round((topDetection.confidence || 0) * 100)}% confidence.` });
  entityRecords.forEach((record, index) => {
    citations.push({ ref: `Flow ${index + 1}`, detail: `${formatEndpoint(record.source, record.srcPort)} -> ${formatEndpoint(record.destination, record.dstPort)} ${record.action} ${classifyApplication(record)} ${formatBytes(record.bytes)} at ${formatDate(record.start)}.` });
  });
  intelMatches.forEach((indicator) => citations.push({ ref: `Threat intel ${indicator}`, detail: `${threatIntel[indicator].label || "Known indicator"} from ${threatIntel[indicator].source || "threat feed"} with ${threatIntel[indicator].severity || "medium"} severity.` }));
  if (asset) citations.push({ ref: `Asset ${asset.asset || asset.key}`, detail: `${asset.owner || "Unknown owner"} owns ${asset.environment || "unknown environment"} asset with ${asset.criticality || "medium"} criticality.` });
  if (cases.length) citations.push({ ref: "Case context", detail: `${cases.filter((item) => item.status !== "Closed").length} open cases and ${cases.filter((item) => item.severity === "high").length} high-severity cases in this tenant.` });
  const answerParts = [
    topDetection ? `${topEntity} should be investigated first because ${topDetection.title.toLowerCase()} is present.` : `${topEntity} is the best starting point because it appears in the current evidence set.`,
    asset ? `Business context raises priority: ${asset.asset || asset.key} is ${asset.criticality || "medium"} criticality and owned by ${asset.owner || "an unknown owner"}.` : "Add asset ownership to improve prioritization.",
    intelMatches.length ? `Threat intelligence matched ${intelMatches.length} observed indicator${intelMatches.length === 1 ? "" : "s"}.` : "No threat-intelligence match is loaded for the observed indicators.",
    "Validate the cited flows, confirm expected service ownership, then create or update a case with containment steps."
  ];
  return {
    id: `copilot-note-${Date.now()}`,
    question,
    answer: answerParts.join(" "),
    citations: citations.slice(0, 10),
    createdAt: new Date().toISOString()
  };
}

function renderSourceHealth() {
  const health = buildSourceHealth(loadJson(STORAGE_KEYS.sources, []), loadJson(STORAGE_KEYS.jobRuns, []), state.records, state.errors);
  els.sourceHealthList.innerHTML = health.length
    ? health.map((item) => enterpriseIssue(item.title, item.detail, item.tone)).join("")
    : `<div class="empty-state"><strong>No managed sources</strong><span>Add S3 or CloudWatch sources to monitor freshness and ownership.</span></div>`;
}

function buildSourceHealth(sources = [], jobRuns = [], records = [], errors = []) {
  if (!sources.length) return [];
  const latestRunBySource = new Map();
  jobRuns.forEach((run) => {
    const key = run.sourceId || run.jobId || "";
    if (!key) return;
    const previous = latestRunBySource.get(key);
    if (!previous || String(run.updatedAt || run.createdAt || "").localeCompare(String(previous.updatedAt || previous.createdAt || "")) > 0) latestRunBySource.set(key, run);
  });
  const observedEnis = new Set(records.map((record) => record.interfaceId).filter(Boolean));
  return sources.slice(0, 6).map((source) => {
    const run = latestRunBySource.get(source.id) || null;
    const observedScope = (source.scope || []).some((item) => observedEnis.has(item));
    const stale = run?.updatedAt ? Date.now() - Date.parse(run.updatedAt) > 24 * 60 * 60 * 1000 : true;
    const missingOwner = !source.ownerName && !source.ownerUserId;
    const tone = run?.status === "failed" || missingOwner || (stale && !observedScope) || errors.length ? "warn" : "ok";
    const detail = [
      run ? `${run.status} ${run.message || ""}` : "No async import recorded",
      source.ownerName || source.ownerUserId ? `owner ${source.ownerName || source.ownerUserId}` : "owner missing",
      observedScope ? "scope observed in evidence" : "scope not observed"
    ].join(" - ");
    return { title: source.name, detail, tone };
  });
}

async function discoverSourcesFromEvidence() {
  if (!state.records.length) return setInputMessage("Analyze evidence before running source discovery.");
  const discovered = await buildDiscoveredSourcesFromEvidence();
  if (!discovered.length) return setInputMessage("No account, region, or ENI source candidates were found.");
  const current = loadJson(STORAGE_KEYS.sources, []);
  const merged = [...current];
  for (const source of discovered) {
    const index = merged.findIndex((item) => item.id === source.id || item.name === source.name);
    let saved = source;
    if (backendApi) {
      try {
        saved = await backendApi.saveSource(source);
      } catch (error) {
        if (state.backend.online) showToast(`Discovered source kept locally: ${error.message}`, "warn");
      }
    }
    if (index >= 0) merged.splice(index, 1, { ...merged[index], ...saved, scope: [...new Set([...(merged[index].scope || []), ...(saved.scope || [])])] });
    else merged.unshift(saved);
  }
  saveJson(STORAGE_KEYS.sources, merged.slice(0, 50));
  renderCoverage();
  renderTenantAdmin();
  renderEnterprise();
  showToast(`${discovered.length} enterprise source candidate${discovered.length === 1 ? "" : "s"} discovered.`);
}

async function buildDiscoveredSourcesFromEvidence() {
  const groups = new Map();
  state.records.forEach((record) => {
    const account = record.accountId || record.raw?.["account-id"] || "unknown-account";
    const region = record.raw?.region || record.raw?.["az-id"] || "unknown-region";
    const key = `${account}:${region}`;
    if (!groups.has(key)) groups.set(key, { account, region, enis: new Set(), cidrs: new Set() });
    const group = groups.get(key);
    if (record.interfaceId && record.interfaceId !== "-") group.enis.add(record.interfaceId);
    [record.source, record.destination].filter(isPrivateIp).forEach((ip) => group.cidrs.add(`${ip.split(".").slice(0, 2).join(".")}.0.0/16`));
  });
  return (await Promise.all([...groups.values()]
    .map(async (group) => ({
      id: `discovered-${(await sha256Text(`${group.account}:${group.region}`)).slice(0, 32)}`,
      name: `Discovered ${group.account} ${group.region}`,
      type: "AWS Account",
      account: group.account,
      region: group.region === "unknown-region" ? "" : group.region,
      scope: [...group.enis, ...group.cidrs].slice(0, 40),
      ownerUserId: "",
      ownerName: "",
      createdAt: new Date().toISOString()
    }))))
    .filter((source) => source.scope.length);
}

function mergeThreatIntelValues(values = []) {
  const merged = {};
  values.forEach((value) => {
    const indicators = Array.isArray(value?.indicators) ? value.indicators : Array.isArray(value) ? value : Object.values(value || {});
    indicators.forEach((indicator) => {
      const normalized = normalizeThreatIntel(indicator);
      if (normalized.indicator) merged[normalized.indicator] = normalized;
    });
  });
  return merged;
}

function applyThreatIntelInput() {
  const parsed = parseThreatIntel(els.threatIntelInput.value);
  if (!Object.keys(parsed).length) return setInputMessage("No threat intelligence indicators were recognized. Use JSONL or CSV with indicator/ip/domain fields.");
  const current = loadJson(STORAGE_KEYS.threatIntel, {});
  const merged = { ...current, ...parsed };
  saveJson(STORAGE_KEYS.threatIntel, merged);
  persistEnterpriseArtifact("THREAT_INTEL", "Threat intelligence import", { indicators: Object.values(parsed) });
  renderEnterprise();
  showToast(`${formatNumber(Object.keys(parsed).length)} threat indicator${Object.keys(parsed).length === 1 ? "" : "s"} applied.`);
}

function parseThreatIntel(text) {
  const rows = {};
  let header = null;
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
        if (index === 0 && values.some((value) => /indicator|ip|domain|severity|confidence/i.test(value))) {
          header = values.map((value) => value.trim());
          return;
        }
        if (header) {
          item = {};
          header.forEach((field, fieldIndex) => {
            item[field] = values[fieldIndex];
          });
        }
      }
      const normalized = normalizeThreatIntel(item || {});
      if (normalized.indicator) rows[normalized.indicator] = normalized;
    });
  return rows;
}

function normalizeThreatIntel(item = {}) {
  const indicator = String(item.indicator || item.ip || item.domain || item.value || "").trim();
  if (!indicator) return { indicator: "" };
  const severity = ["critical", "high", "medium", "low"].includes(String(item.severity || "").toLowerCase()) ? String(item.severity).toLowerCase() : "medium";
  return {
    indicator,
    type: item.type || (indicator.includes(".") && !/^\d+\.\d+\.\d+\.\d+$/.test(indicator) ? "domain" : "ip"),
    severity,
    label: String(item.label || item.threat || item.description || "Threat indicator").trim(),
    source: String(item.source || item.feed || "manual import").trim(),
    confidence: Math.max(0, Math.min(100, Number(item.confidence || item.score || (severity === "high" || severity === "critical" ? 85 : 55)))),
    firstSeen: item.firstSeen || item.first_seen || "",
    lastSeen: item.lastSeen || item.last_seen || "",
    importedAt: new Date().toISOString()
  };
}

function renderThreatIntel() {
  const intel = Object.values(loadJson(STORAGE_KEYS.threatIntel, {}));
  const observed = new Set(state.records.flatMap((record) => [record.source, record.destination]));
  if (!intel.length) {
    els.threatIntelList.innerHTML = `<div class="empty-state"><strong>No threat intelligence loaded</strong><span>Paste an indicator feed to enrich external IPs and risk scoring.</span></div>`;
    return;
  }
  const matches = intel.filter((indicator) => observed.has(indicator.indicator));
  els.threatIntelList.innerHTML = [
    enterpriseIssue("Loaded indicators", `${formatNumber(intel.length)} active indicators from ${formatNumber(new Set(intel.map((item) => item.source)).size)} sources`, "ok"),
    enterpriseIssue("Observed matches", matches.length ? `${formatNumber(matches.length)} indicators appear in current evidence` : "No loaded indicators match current evidence", matches.length ? "warn" : "ok"),
    ...matches.slice(0, 5).map((indicator) => enterpriseIssue(indicator.indicator, `${indicator.label} - ${indicator.severity} - ${indicator.confidence}% confidence`, "warn"))
  ].join("");
}

function buildEntityRiskScores(records = [], analysis = null, assets = {}, threatIntel = {}) {
  const scores = new Map();
  const bump = (entity, points, reason) => {
    if (!entity || entity === "-") return;
    if (!scores.has(entity)) scores.set(entity, { entity, score: 0, reasons: new Set(), asset: assets[entity] || null, intel: threatIntel[entity] || null });
    const current = scores.get(entity);
    current.score += points;
    current.reasons.add(reason);
  };
  records.forEach((record) => {
    const sensitive = SENSITIVE_PORTS.has(record.dstPort);
    if (record.action === "REJECT" && isPublicIp(record.source) && sensitive) bump(record.destination, 14, `public ${SENSITIVE_PORTS.get(record.dstPort)} probing`);
    if (record.action === "ACCEPT" && isPrivateIp(record.source) && isPrivateIp(record.destination) && sensitive) bump(record.destination, 22, "accepted sensitive lateral access");
    if (record.action === "ACCEPT" && isPrivateIp(record.source) && isPublicIp(record.destination) && record.bytes > 1_000_000) bump(record.source, 18, "large external egress");
    if (threatIntel[record.source]) bump(record.destination, threatIntel[record.source].severity === "high" ? 28 : 18, `matched intel ${record.source}`);
    if (threatIntel[record.destination]) bump(record.source, threatIntel[record.destination].severity === "high" ? 28 : 18, `matched intel ${record.destination}`);
  });
  (analysis?.detections || []).forEach((detection) => bump(detection.entity, detection.severity === "high" ? 30 : detection.severity === "medium" ? 18 : 8, detection.title));
  Object.values(assets || {}).forEach((asset) => {
    const key = asset.ip || asset.eni || asset.instance || asset.key;
    if (asset.criticality === "high") bump(key, 12, "high-criticality asset");
  });
  return [...scores.values()]
    .map((item) => ({ ...item, score: Math.max(0, Math.min(100, item.score)), reasons: [...item.reasons].slice(0, 4) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 10);
}

function renderEntityRiskScoring() {
  const scores = buildEntityRiskScores(state.records, state.analysis, loadJson(STORAGE_KEYS.assetContext, {}), loadJson(STORAGE_KEYS.threatIntel, {}));
  els.entityRiskScoringList.innerHTML = scores.length
    ? scores.slice(0, 6).map((item) => `<article class="entity-card">
      <div class="entity-name">${escapeHtml(item.entity)}</div>
      <div class="risk-score ${riskClass(item.score)}">${formatNumber(item.score)}</div>
      <div class="entity-meta">
        ${item.reasons.map((reason) => `<span class="tag">${escapeHtml(reason)}</span>`).join("")}
      </div>
    </article>`).join("")
    : `<div class="empty-state"><strong>No scored entities</strong><span>Analyze evidence and add asset or threat context to calculate risk.</span></div>`;
}

function detectionRulesValue() {
  ensureDefaultDetectionRules();
  return loadJson(STORAGE_KEYS.detectionRules, []);
}

function renderDetectionRules() {
  const rules = detectionRulesValue();
  els.detectionRuleCountLabel.textContent = String(rules.length);
  els.detectionRuleList.innerHTML = rules.length
    ? rules
        .map((rule) => {
          const productionAction = rule.status === "production" ? "Retire" : "Approve";
          const productionDisabled = rule.builtIn || !state.backend.online || !hasRole("admin") || !["test", "production"].includes(rule.status);
          const productionReason = rule.builtIn
            ? "Built-in rules must be cloned before lifecycle changes"
            : !state.backend.online
              ? "An authenticated backend is required"
              : !hasRole("admin")
                ? "Tenant admin approval is required"
                : rule.status === "draft"
                  ? "Run and save a passing test first"
                  : `${productionAction} this server-governed rule`;
          return `<article class="entity-card">
          <div class="entity-name">${escapeHtml(rule.name)}</div>
          <div class="risk-score ${riskClass(rule.severity === "high" ? 85 : rule.severity === "medium" ? 45 : 15)}">${escapeHtml(rule.severity[0].toUpperCase())}</div>
          <div class="entity-meta">
            <span class="tag">${escapeHtml(rule.status || "draft")}</span>
            <span class="tag">${escapeHtml(rule.attackId || rule.tactic || "ATT&CK")}</span>
            <button class="mini-button" type="button" data-test-rule="${escapeHtml(rule.id)}">Test</button>
            <button class="mini-button" type="button" data-edit-rule="${escapeHtml(rule.id)}">Edit</button>
            <button class="mini-button" type="button" data-promote-rule="${escapeHtml(rule.id)}" title="${escapeHtml(productionReason)}" ${productionDisabled ? "disabled" : ""}>${productionAction}</button>
            <button class="mini-button" type="button" data-clone-rule="${escapeHtml(rule.id)}">Clone</button>
            ${rule.builtIn ? "" : `<button class="mini-button danger" type="button" data-delete-rule="${escapeHtml(rule.id)}">Delete</button>`}
          </div>
        </article>`;
        })
        .join("")
    : emptyState();
}

function readDetectionRuleForm() {
  return {
    id: els.detectionRuleIdInput.value || undefined,
    name: els.detectionRuleNameInput.value.trim(),
    query: els.detectionRuleQueryInput.value.trim(),
    description: els.detectionRuleDescriptionInput.value.trim(),
    severity: els.detectionRuleSeverityInput.value,
    tactic: els.detectionRuleTacticInput.value.trim(),
    technique: els.detectionRuleTechniqueInput.value.trim(),
    attackId: els.detectionRuleAttackInput.value.trim(),
    status: "draft",
    enabled: true
  };
}

function testDetectionRuleForm() {
  const rule = readDetectionRuleForm();
  if (!rule.query) return setInputMessage("Enter a rule query before testing.");
  const result = testDetectionRule(rule);
  els.detectionRuleResultList.innerHTML = renderRuleTestResult(rule, result);
}

async function testDetectionRuleById(id) {
  const rule = detectionRulesValue().find((item) => item.id === id);
  if (!rule) return;
  const result = testDetectionRule(rule);
  els.detectionRuleResultList.innerHTML = renderRuleTestResult(rule, result);
  let updated = { ...rule, testCount: result.count, lastTestedAt: new Date().toISOString(), status: rule.status === "production" ? "production" : "test" };
  if (state.backend.online && !rule.builtIn) {
    try {
      updated = await backendApi.saveDetectionRule(updated);
    } catch (error) {
      setInputMessage(`Rule test was not saved to the tenant catalog: ${error.message}`);
      return;
    }
  }
  saveDetectionRuleLocal(updated);
  renderDetectionRules();
  showToast(`Rule test saved with ${formatNumber(result.count)} match${result.count === 1 ? "" : "es"}.`);
}

function testDetectionRule(rule) {
  const matches = state.records.filter((record) => matchesHunt(record, rule.query));
  return { count: matches.length, sample: matches.slice(0, 5) };
}

function renderRuleTestResult(rule, result) {
  return `<div class="issue-item"><strong>${escapeHtml(rule.name || "Draft rule")}</strong><span>${formatNumber(result.count)} matching records for ${escapeHtml(rule.query || "no query")}</span></div>${
    result.sample.length
      ? result.sample.map((record) => `<div class="issue-item"><strong>${escapeHtml(formatEndpoint(record.source, record.srcPort))} -> ${escapeHtml(formatEndpoint(record.destination, record.dstPort))}</strong><span>${escapeHtml(record.action)} ${escapeHtml(classifyApplication(record))} ${escapeHtml(formatBytes(record.bytes))}</span></div>`).join("")
      : `<div class="issue-item warning"><strong>No current matches</strong><span>Keep as draft, broaden the query, or test with another evidence set.</span></div>`
  }`;
}

async function saveDetectionRuleForm() {
  const rule = readDetectionRuleForm();
  if (!rule.name || !rule.query) return setInputMessage("Rule name and query are required.");
  const tested = testDetectionRule(rule);
  const savedRule = { ...rule, testCount: tested.count, lastTestedAt: new Date().toISOString(), status: tested.count ? "test" : "draft" };
  try {
    let persisted = savedRule;
    if (backendApi) persisted = await backendApi.saveDetectionRule(savedRule);
    saveDetectionRuleLocal(persisted);
    clearDetectionRuleForm();
    renderEnterprise();
    showToast("Detection rule saved.");
  } catch (error) {
    if (!state.backend.online) {
      saveDetectionRuleLocal(savedRule);
      renderEnterprise();
      showToast("Detection rule saved locally.");
    } else {
      setInputMessage(error.message);
    }
  }
}

function saveDetectionRuleLocal(rule) {
  const rules = detectionRulesValue();
  const index = rules.findIndex((item) => item.id === rule.id);
  if (index >= 0) rules.splice(index, 1, rule);
  else rules.unshift(rule);
  saveJson(STORAGE_KEYS.detectionRules, rules.slice(0, 100));
}

function editDetectionRule(id) {
  const rule = detectionRulesValue().find((item) => item.id === id);
  if (!rule) return;
  els.detectionRuleIdInput.value = rule.builtIn ? "" : rule.id;
  els.detectionRuleNameInput.value = rule.name || "";
  els.detectionRuleQueryInput.value = rule.query || "";
  els.detectionRuleDescriptionInput.value = rule.description || "";
  els.detectionRuleSeverityInput.value = rule.severity || "medium";
  els.detectionRuleTacticInput.value = rule.tactic || "";
  els.detectionRuleTechniqueInput.value = rule.technique || "";
  els.detectionRuleAttackInput.value = rule.attackId || "";
  els.detectionRuleResultList.innerHTML = `<div class="issue-item"><strong>${escapeHtml(rule.name)}</strong><span>${escapeHtml(rule.description || "Ready to edit or test.")}</span></div>`;
}

function clearDetectionRuleForm() {
  els.detectionRuleIdInput.value = "";
  els.detectionRuleNameInput.value = "";
  els.detectionRuleQueryInput.value = "";
  els.detectionRuleDescriptionInput.value = "";
  els.detectionRuleSeverityInput.value = "medium";
  els.detectionRuleTacticInput.value = "";
  els.detectionRuleTechniqueInput.value = "";
  els.detectionRuleAttackInput.value = "";
}

function deleteDetectionRuleById(id) {
  const rule = detectionRulesValue().find((item) => item.id === id);
  if (!rule || rule.builtIn) return;
  confirmAction({
    title: "Delete detection rule?",
    body: `This removes "${rule.name}" from the tenant rule catalog.`,
    confirmLabel: "Delete Rule",
    onConfirm: async () => {
      try {
        if (backendApi) await backendApi.deleteDetectionRule(id);
      } catch (error) {
        if (state.backend.online) return setInputMessage(error.message);
      }
      saveJson(STORAGE_KEYS.detectionRules, detectionRulesValue().filter((item) => item.id !== id));
      renderEnterprise();
      showToast("Detection rule deleted.");
    }
  });
}

async function promoteDetectionRule(id) {
  const rule = detectionRulesValue().find((item) => item.id === id);
  if (!rule) return;
  if (rule.builtIn) return setInputMessage("Clone a built-in rule before changing its lifecycle.");
  if (!state.backend.online || !backendApi) return setInputMessage("Production rule lifecycle changes require an authenticated backend.");
  if (!hasRole("admin")) return setInputMessage("Tenant admin approval is required for production rule lifecycle changes.");
  if (!["test", "production"].includes(rule.status)) return setInputMessage("Run and save a rule test before requesting production approval.");
  const nextStatus = rule.status === "production" ? "retired" : "production";
  try {
    const updated = await backendApi.promoteDetectionRule(rule.id, nextStatus);
    saveDetectionRuleLocal(updated);
    renderEnterprise();
    showToast(`Rule moved to ${nextStatus}.`);
  } catch (error) {
    setInputMessage(error.message);
  }
}

function cloneDetectionRule(id) {
  const rule = detectionRulesValue().find((item) => item.id === id);
  if (!rule) return;
  const clone = {
    ...rule,
    id: `rule-${Date.now()}`,
    name: `${rule.name} copy`,
    status: "draft",
    builtIn: false,
    version: 1,
    approvedBy: "",
    approvedAt: "",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  saveDetectionRuleLocal(clone);
  editDetectionRule(clone.id);
  renderDetectionRules();
  showToast("Detection rule cloned as draft.");
}

function scoreDetectionRuleQuality(rule = {}) {
  let score = 20;
  const gaps = [];
  if (rule.query) score += 15;
  else gaps.push("missing query");
  if (rule.description && rule.description.length > 30) score += 12;
  else gaps.push("thin description");
  if (rule.attackId) score += 14;
  else gaps.push("no ATT&CK technique");
  if (rule.owner && rule.owner !== "unknown") score += 10;
  else gaps.push("no owner");
  if (Number(rule.testCount || 0) > 0) score += 14;
  else gaps.push("no passing fixture");
  if (rule.status === "production") score += 15;
  else if (rule.status === "test") score += 8;
  return { score: Math.max(0, Math.min(100, score)), gaps };
}

function renderDetectionAsCode() {
  const rules = detectionRulesValue();
  if (!rules.length) {
    els.detectionAsCodeList.innerHTML = emptyState();
    return;
  }
  const scored = rules.map((rule) => ({ rule, quality: scoreDetectionRuleQuality(rule) }));
  const avg = Math.round(scored.reduce((sum, item) => sum + item.quality.score, 0) / scored.length);
  const production = rules.filter((rule) => rule.status === "production").length;
  const unmapped = rules.filter((rule) => !rule.attackId).length;
  els.detectionAsCodeList.innerHTML = [
    enterpriseIssue("Average quality", `${avg}% across ${formatNumber(rules.length)} rules`, avg >= 75 ? "ok" : "warn"),
    enterpriseIssue("Production coverage", `${formatNumber(production)} production rules`, production ? "ok" : "warn"),
    enterpriseIssue("Mapping gaps", unmapped ? `${formatNumber(unmapped)} rules need ATT&CK mapping` : "All rules mapped", unmapped ? "warn" : "ok"),
    ...scored.slice(0, 4).map((item) => enterpriseIssue(item.rule.name, `${item.quality.score}% quality - v${item.rule.version || 1} - ${item.rule.status || "draft"}`, item.quality.score >= 70 ? "ok" : "warn"))
  ].join("");
}

function buildDetectionAsCodeBundle(rules = []) {
  return {
    product: "SignalPrism NDR",
    schema: "signalprism.detections.v1",
    exportedAt: new Date().toISOString(),
    rules: rules.map((rule) => ({
      id: rule.id,
      name: rule.name,
      version: rule.version || 1,
      status: rule.status || "draft",
      enabled: rule.enabled !== false,
      severity: rule.severity,
      query: rule.query,
      description: rule.description,
      attack: { tactic: rule.tactic, technique: rule.technique, id: rule.attackId },
      owner: rule.owner || "",
      approval: { approvedBy: rule.approvedBy || "", approvedAt: rule.approvedAt || "" },
      quality: scoreDetectionRuleQuality(rule)
    }))
  };
}

function exportDetectionAsCodeBundle() {
  const bundle = buildDetectionAsCodeBundle(detectionRulesValue());
  downloadText("signalprism-detections-as-code.json", JSON.stringify(bundle, null, 2), "application/json");
  persistEnterpriseArtifact("DETECTION_AS_CODE_EXPORT", "Detection-as-code export", { ruleCount: bundle.rules.length, exportedAt: bundle.exportedAt });
  showToast("Detection-as-code bundle exported.");
}

async function saveEnterpriseIntegration() {
  const settings = readEnterpriseSettingsForm();
  await persistEnterpriseSettings(settings, "Integration settings saved.");
}

async function saveGovernanceControls() {
  const settings = readEnterpriseSettingsForm();
  await persistEnterpriseSettings(settings, "Governance controls saved.");
}

function readEnterpriseSettingsForm() {
  const current = enterpriseSettingsValue();
  return {
    ...current,
    securityLake: {
      ...(current.securityLake || {}),
      bucket: els.securityLakeBucketInput.value.trim(),
      prefix: els.enterpriseSecurityLakePrefixInput.value.trim() || "custom/SignalPrismNDR",
      region: "us-east-1",
      format: "ocsf-ndjson"
    },
    siem: {
      ...(current.siem || {}),
      target: els.siemTargetInput.value,
      endpoint: els.siemEndpointInput.value.trim(),
      exportMode: "manual"
    },
    governance: {
      ...(current.governance || {}),
      evidenceRetentionDays: Number(els.retentionDaysInput.value || 90),
      legalHold: els.legalHoldInput.checked,
      exportApprovalRequired: els.exportApprovalInput.checked
    },
    dataPlatform: {
      ...(current.dataPlatform || {}),
      analyticsStore: els.analyticsStoreInput.value,
      queryEngine: els.queryEngineInput.value.trim() || els.analyticsStoreInput.value
    }
  };
}

async function persistEnterpriseSettings(settings, successMessage) {
  let saved = settings;
  try {
    if (backendApi) saved = await backendApi.saveEnterpriseSettings(settings);
  } catch (error) {
    if (state.backend.online) return setInputMessage(error.message);
  }
  saveJson(STORAGE_KEYS.enterpriseSettings, saved);
  renderEnterprise();
  showToast(successMessage);
}

async function exportSecurityLakeOcsf() {
  if (!state.records.length && !state.analysis?.detections?.length) return setInputMessage("Analyze evidence before exporting OCSF data.");
  const settings = readEnterpriseSettingsForm();
  saveJson(STORAGE_KEYS.enterpriseSettings, settings);
  const networkEvents = buildOcsfNetworkActivity(state.filtered.length ? state.filtered : state.records);
  const findings = buildOcsfFindings(state.analysis?.detections || []);
  const lines = [...networkEvents, ...findings].map((item) => JSON.stringify(item));
  const contentSha256 = await sha256Text(lines.join("\n") + "\n");
  const destination = settings.securityLake.bucket ? `s3://${settings.securityLake.bucket}/${settings.securityLake.prefix}` : "manual-download";
  let manifest = {
    id: `security-lake-export-${Date.now()}`,
    recordCount: networkEvents.length,
    findingCount: findings.length,
    destination,
    format: "ocsf-ndjson",
    exportedAt: new Date().toISOString()
  };
  try {
    if (backendApi) {
      manifest = await backendApi.exportSecurityLakeManifest({
        recordCount: networkEvents.length,
        findingCount: findings.length,
        destination,
        format: "ocsf-ndjson",
        accountId: [...uniqueRawValues("account-id")][0] || "",
        region: settings.securityLake.region || "us-east-1",
        contentSha256
      });
      if (manifest.pending) {
        await renderExportApprovals();
        showToast("Security Lake export submitted for approval.");
        return;
      }
    }
  } catch (error) {
    if (state.backend.online || settings.governance?.exportApprovalRequired !== false) return setInputMessage(`Security Lake export blocked: ${error.message}`);
  }
  if (settings.governance?.exportApprovalRequired !== false && !state.backend.online) return setInputMessage("Controlled exports require an authenticated backend approval.");
  if (manifest.contentSha256 && manifest.contentSha256 !== contentSha256) return setInputMessage("Approved export content no longer matches the reviewed payload.");
  saveJson(STORAGE_KEYS.securityLakeManifest, manifest);
  downloadText("signalprism-security-lake-ocsf.ndjson", lines.join("\n") + "\n", "application/x-ndjson");
  renderEnterprise();
  showToast("Security Lake OCSF export created.");
}

function buildOcsfNetworkActivity(records = []) {
  return records.slice(0, 1000).map((record) => ({
    category_name: "Network Activity",
    class_name: "Network Activity",
    activity_name: record.action === "REJECT" ? "Connection Denied" : "Connection Accepted",
    time: Number.isFinite(record.start) ? record.start * 1000 : Date.now(),
    src_endpoint: { ip: record.source, port: record.srcPort, interface_uid: record.interfaceId },
    dst_endpoint: { ip: record.destination, port: record.dstPort },
    connection_info: { protocol_name: record.protocol, direction: isPrivateIp(record.source) && !isPrivateIp(record.destination) ? "Outbound" : "Unknown" },
    traffic: { bytes: record.bytes, packets: record.packets },
    status: record.action,
    metadata: { product: { name: "SignalPrism NDR" }, version: "0.2.0" }
  }));
}

function buildOcsfFindings(detections = []) {
  return detections.slice(0, 500).map((detection) => ({
    category_name: "Findings",
    class_name: "Security Finding",
    activity_name: detection.title,
    severity: detection.severity,
    confidence: Math.round((detection.confidence || 0) * 100),
    finding_info: { uid: detection.id, title: detection.title, desc: detection.copy },
    resources: [{ name: detection.entity || "unknown", type: "network_entity" }],
    unmapped: { tactic: detection.tactic, technique: detection.technique, tags: detection.tags },
    metadata: { product: { name: "SignalPrism NDR" }, version: "0.2.0" }
  }));
}

function renderSecurityLakeManifest() {
  const settings = enterpriseSettingsValue();
  const manifest = loadJson(STORAGE_KEYS.securityLakeManifest, null);
  els.securityLakeManifestList.innerHTML = [
    enterpriseIssue("Destination", settings.securityLake?.bucket ? `s3://${settings.securityLake.bucket}/${settings.securityLake.prefix}` : "Manual OCSF download until bucket is configured", settings.securityLake?.bucket ? "ok" : "warn"),
    enterpriseIssue("SIEM target", `${settings.siem?.target || "Security Lake"}${settings.siem?.endpoint ? ` - ${settings.siem.endpoint}` : ""}`, "ok"),
    manifest ? enterpriseIssue("Last export", `${formatNumber(manifest.recordCount)} network events, ${formatNumber(manifest.findingCount)} findings at ${formatDate(Date.parse(manifest.exportedAt) / 1000)}`, "ok") : enterpriseIssue("Last export", "No OCSF export created in this browser.", "warn")
  ].join("");
}

function applyAssetContextInput() {
  const parsed = parseAssetContext(els.assetContextInput.value);
  if (!Object.keys(parsed).length) return setInputMessage("No asset rows were recognized. Use JSONL or CSV with ip/eni/instance and owner fields.");
  const current = loadJson(STORAGE_KEYS.assetContext, {});
  saveJson(STORAGE_KEYS.assetContext, { ...current, ...parsed });
  renderEnterprise();
  showToast(`${formatNumber(Object.keys(parsed).length)} asset context record${Object.keys(parsed).length === 1 ? "" : "s"} applied.`);
}

function parseAssetContext(text) {
  const rows = {};
  let header = null;
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
        if (index === 0 && values.some((value) => /ip|eni|instance|asset|owner/i.test(value))) {
          header = values.map((value) => value.trim());
          return;
        }
        if (header) {
          item = {};
          header.forEach((field, fieldIndex) => {
            item[field] = values[fieldIndex];
          });
        }
      }
      const key = item?.ip || item?.eni || item?.interfaceId || item?.instance || item?.instanceId || item?.asset;
      if (key) rows[key] = normalizeAssetContext(item);
    });
  return rows;
}

function normalizeAssetContext(item = {}) {
  return {
    key: item.ip || item.eni || item.interfaceId || item.instance || item.instanceId || item.asset || "",
    ip: item.ip || "",
    eni: item.eni || item.interfaceId || "",
    instance: item.instance || item.instanceId || "",
    asset: item.asset || item.name || "",
    owner: item.owner || item.team || "",
    criticality: item.criticality || item.tier || "medium",
    environment: item.environment || item.env || "",
    account: item.account || item.accountId || "",
    role: item.role || ""
  };
}

function renderAssetContext() {
  const assets = Object.values(loadJson(STORAGE_KEYS.assetContext, {}));
  if (!assets.length) {
    els.assetContextList.innerHTML = `<div class="empty-state"><strong>No asset context</strong><span>Add EC2 tags, CMDB rows, or ownership data to enrich entity triage.</span></div>`;
    return;
  }
  els.assetContextList.innerHTML = assets.slice(0, 8).map((asset) => `<article class="entity-card">
    <div class="entity-name">${escapeHtml(asset.asset || asset.key)}</div>
    <div class="risk-score ${asset.criticality === "high" ? "high" : asset.criticality === "medium" ? "medium" : ""}">${escapeHtml(String(asset.criticality || "m")[0].toUpperCase())}</div>
    <div class="entity-meta">
      <span class="tag">${escapeHtml(asset.owner || "No owner")}</span>
      <span class="tag">${escapeHtml(asset.environment || "environment unknown")}</span>
      <span class="tag mono">${escapeHtml(asset.ip || asset.eni || asset.instance || asset.key)}</span>
    </div>
  </article>`).join("");
}

function renderInvestigationGraph() {
  const topology = topologyApi?.buildTopology ? topologyApi.buildTopology(state.records) : { nodes: [], edges: [] };
  const assets = loadJson(STORAGE_KEYS.assetContext, {});
  const enrichedNodes = topology.nodes.filter((node) => assets[node.key]).length;
  els.investigationGraphList.innerHTML = [
    enterpriseIssue("Graph nodes", `${formatNumber(topology.nodes.length)} entities, ${formatNumber(enrichedNodes)} enriched`, topology.nodes.length ? "ok" : "warn"),
    enterpriseIssue("Graph edges", `${formatNumber(topology.edges.length)} observed communication paths`, topology.edges.length ? "ok" : "warn"),
    enterpriseIssue("Replay", state.records.length ? "Topology replay is available in the Topology tab." : "Load evidence to enable graph replay.", state.records.length ? "ok" : "warn")
  ].join("");
}

function exportInvestigationGraph() {
  if (!state.records.length) return setInputMessage("Analyze evidence before exporting the investigation graph.");
  const topology = topologyApi?.buildTopology ? topologyApi.buildTopology(state.records) : { nodes: [], edges: [] };
  const payload = {
    product: "SignalPrism NDR",
    exportedAt: new Date().toISOString(),
    source: state.fileName || "current evidence",
    nodes: topology.nodes,
    edges: topology.edges,
    assets: loadJson(STORAGE_KEYS.assetContext, {}),
    detections: state.analysis?.detections || []
  };
  downloadText("signalprism-investigation-graph.json", JSON.stringify(payload, null, 2), "application/json");
  showToast("Investigation graph exported.");
}

function buildReplayTimeline(records = [], detections = []) {
  const events = records
    .filter((record) => Number.isFinite(record.start))
    .sort((a, b) => a.start - b.start)
    .slice(0, 500)
    .map((record, index) => ({
      id: `flow-${index + 1}`,
      time: record.start,
      type: "flow",
      severity: record.action === "REJECT" && isPublicIp(record.source) && SENSITIVE_PORTS.has(record.dstPort) ? "medium" : "low",
      title: `${record.action} ${classifyApplication(record)}`,
      detail: `${formatEndpoint(record.source, record.srcPort)} -> ${formatEndpoint(record.destination, record.dstPort)} ${formatBytes(record.bytes)}`,
      entity: record.destination || record.source
    }));
  detections.forEach((detection, index) => {
    events.push({
      id: `detection-${detection.id || index}`,
      time: records[index]?.start || Date.now(),
      type: "detection",
      severity: detection.severity || "medium",
      title: detection.title,
      detail: detection.copy || detection.entity || "",
      entity: detection.entity || ""
    });
  });
  return events.sort((a, b) => a.time - b.time);
}

function renderReplayTimeline() {
  const timeline = buildReplayTimeline(state.records, state.analysis?.detections || []);
  if (!timeline.length) {
    els.replayTimelineList.innerHTML = `<div class="empty-state"><strong>No replay timeline</strong><span>Load evidence to reconstruct flows, detections, and investigation milestones.</span></div>`;
    return;
  }
  const high = timeline.filter((event) => event.severity === "high").length;
  const detectionEvents = timeline.filter((event) => event.type === "detection").length;
  els.replayTimelineList.innerHTML = [
    enterpriseIssue("Timeline events", `${formatNumber(timeline.length)} replay events across ${formatRange(timeline[0].time, timeline.at(-1).time)}`, "ok"),
    enterpriseIssue("Detection overlays", `${formatNumber(detectionEvents)} detection milestones`, detectionEvents ? "ok" : "warn"),
    enterpriseIssue("Critical moments", high ? `${formatNumber(high)} high-severity moments` : "No high-severity moments in timeline", high ? "warn" : "ok"),
    ...timeline.slice(-3).reverse().map((event) => enterpriseIssue(event.title, `${formatDate(event.time)} - ${event.detail}`, event.severity === "high" ? "warn" : "ok"))
  ].join("");
}

function exportReplayTimeline() {
  if (!state.records.length) return setInputMessage("Analyze evidence before exporting a replay timeline.");
  const timeline = buildReplayTimeline(state.records, state.analysis?.detections || []);
  const payload = {
    product: "SignalPrism NDR",
    exportedAt: new Date().toISOString(),
    source: state.fileName || "current evidence",
    timeline
  };
  downloadText("signalprism-investigation-replay.json", JSON.stringify(payload, null, 2), "application/json");
  persistEnterpriseArtifact("REPLAY_TIMELINE_EXPORT", "Investigation replay export", { eventCount: timeline.length, exportedAt: payload.exportedAt });
  showToast("Investigation replay timeline exported.");
}

function analyzePolicyInput() {
  const pasted = parsePolicyRows(els.policyInput.value);
  const findings = buildPolicyFindings(pasted);
  saveJson(STORAGE_KEYS.policyFindings, findings);
  renderPolicyFindings();
  showToast(`${formatNumber(findings.length)} policy exposure finding${findings.length === 1 ? "" : "s"} generated.`);
}

function parsePolicyRows(text) {
  const rows = [];
  String(text || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .forEach((line) => {
      if (line.startsWith("{")) {
        try {
          rows.push(JSON.parse(line));
        } catch {
          // Ignore malformed rows and continue with deterministic evidence-based checks.
        }
      } else {
        const port = Number((line.match(/\bport[:= ]+(\d+)/i) || [])[1]);
        rows.push({ raw: line, source: (line.match(/(0\.0\.0\.0\/0|::\/0|\d+\.\d+\.\d+\.\d+\/\d+)/) || [])[1] || "", port, action: /allow|accept/i.test(line) ? "allow" : "" });
      }
    });
  return rows;
}

function buildPolicyFindings(policyRows = []) {
  const findings = [];
  policyRows.forEach((row, index) => {
    const port = Number(row.port || row.fromPort || row.dstPort || row.destinationPort || 0);
    const source = String(row.source || row.cidr || row.cidrIp || row.ipRange || "");
    if (/0\.0\.0\.0\/0|::\/0/.test(source) && SENSITIVE_PORTS.has(port)) {
      findings.push({ id: `policy-${index}`, severity: "high", title: "Public sensitive service exposure", detail: `${source} can reach ${SENSITIVE_PORTS.get(port)} (${port}) on ${row.resource || row.groupId || "a policy resource"}.` });
    }
  });
  const publicAccepted = state.records.filter((record) => record.action === "ACCEPT" && isPublicIp(record.source) && SENSITIVE_PORTS.has(record.dstPort));
  if (publicAccepted.length) findings.push({ id: "evidence-public-accepted", severity: "high", title: "Observed accepted public sensitive access", detail: `${formatNumber(publicAccepted.length)} accepted public flows reached sensitive services.` });
  const highEgress = state.records.filter((record) => record.action === "ACCEPT" && isPrivateIp(record.source) && isPublicIp(record.destination) && record.bytes > 1_000_000);
  if (highEgress.length) findings.push({ id: "evidence-high-egress", severity: "medium", title: "High-volume public egress", detail: `${formatNumber(highEgress.length)} flows exceeded 1 MB to public destinations.` });
  if (!findings.length) findings.push({ id: "policy-clean", severity: "low", title: "No critical policy exposure found", detail: "No public sensitive allow rule or matching accepted sensitive flow was identified in the current inputs." });
  return findings;
}

function renderPolicyFindings() {
  const findings = loadJson(STORAGE_KEYS.policyFindings, []);
  els.policyFindingList.innerHTML = findings.length
    ? findings.map((finding) => `<div class="issue-item ${finding.severity === "high" ? "warning" : ""}"><strong>${escapeHtml(finding.title)}</strong><span>${escapeHtml(finding.detail)}</span></div>`).join("")
    : `<div class="empty-state"><strong>No policy analysis yet</strong><span>Paste security group or NACL rules, then analyze exposure against current evidence.</span></div>`;
}

function renderIncidentOps(cases = []) {
  if (!cases.length) {
    els.incidentOpsList.innerHTML = `<div class="empty-state"><strong>No cases yet</strong><span>Create a case from a detection to start incident operations.</span></div>`;
    return;
  }
  els.incidentOpsList.innerHTML = cases.slice(0, 6).map((item) => {
    const open = item.status !== "Closed";
    const slaHours = item.severity === "high" ? 4 : item.severity === "medium" ? 24 : 72;
    return `<div class="issue-item ${open && item.severity === "high" ? "warning" : ""}">
      <strong>${escapeHtml(item.title)}</strong>
      <span>${escapeHtml(item.status)} - ${escapeHtml(item.assignee || "Unassigned")} - ${slaHours}h response SLA</span>
    </div>`;
  }).join("");
}

function renderPlaybooks(cases = []) {
  els.playbookCaseSelect.innerHTML = cases.length
    ? cases.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.title)} (${escapeHtml(item.status)})</option>`).join("")
    : `<option value="">No cases available</option>`;
  const runs = loadJson(STORAGE_KEYS.playbookRuns, []);
  els.playbookRunList.innerHTML = runs.length
    ? runs.slice(0, 5).map((run) => {
        const completed = (run.steps || []).filter((step) => step.status === "complete").length;
        return enterpriseIssue(run.title, `${completed}/${(run.steps || []).length} steps complete - ${run.status}`, run.status === "blocked" ? "warn" : "ok");
      }).join("")
    : `<div class="empty-state"><strong>No playbook runs</strong><span>Select a case and create a guided response run.</span></div>`;
}

async function createPlaybookRun() {
  const cases = await listCaseRecords().catch(() => []);
  const caseRecord = cases.find((item) => item.id === els.playbookCaseSelect.value) || cases[0] || null;
  if (!caseRecord) return setInputMessage("Create or sync a case before starting a response playbook.");
  const template = els.playbookTemplateSelect.value;
  const run = {
    id: `playbook-${Date.now()}`,
    template,
    caseId: caseRecord.id,
    title: `${playbookTemplateLabel(template)} - ${caseRecord.title}`,
    status: "active",
    steps: buildPlaybookSteps(template, caseRecord),
    createdAt: new Date().toISOString()
  };
  await persistEnterpriseArtifact("PLAYBOOK_RUN", run.title, run);
  saveJson(STORAGE_KEYS.playbookRuns, [run, ...loadJson(STORAGE_KEYS.playbookRuns, [])].slice(0, 20));
  renderPlaybooks(cases);
  showToast("Response playbook run created.");
}

function playbookTemplateLabel(template) {
  return {
    "contain-public-admin": "Public admin containment",
    "investigate-lateral-movement": "Lateral movement investigation",
    "validate-egress": "Egress validation",
    "executive-brief": "Executive briefing"
  }[template] || "Response playbook";
}

function buildPlaybookSteps(template, caseRecord = {}) {
  const common = [
    { title: "Confirm evidence scope", owner: caseRecord.assignee || "Analyst", status: "open" },
    { title: "Attach cited evidence package", owner: "Analyst", status: "open" },
    { title: "Record containment decision", owner: "Incident commander", status: "open" }
  ];
  const templates = {
    "contain-public-admin": [
      { title: "Validate public source and target owner", owner: caseRecord.assignee || "Analyst", status: "open" },
      { title: "Request security group or NACL restriction", owner: "Cloud security", status: "open" },
      { title: "Re-run evidence query after change", owner: "Detection engineer", status: "open" }
    ],
    "investigate-lateral-movement": [
      { title: "Map source, target, and service ownership", owner: "SOC analyst", status: "open" },
      { title: "Check recent identity and workload changes", owner: "Cloud platform", status: "open" },
      { title: "Hunt for repeated accepted sensitive paths", owner: "Detection engineer", status: "open" }
    ],
    "validate-egress": [
      { title: "Confirm destination reputation and ASN", owner: "Threat intel", status: "open" },
      { title: "Validate expected transfer volume with owner", owner: "Application owner", status: "open" },
      { title: "Add temporary egress monitor", owner: "SOC analyst", status: "open" }
    ],
    "executive-brief": [
      { title: "Summarize impact and business owner", owner: "Incident commander", status: "open" },
      { title: "Capture current risk and containment status", owner: "SOC lead", status: "open" },
      { title: "Prepare customer/compliance talking points", owner: "Security leadership", status: "open" }
    ]
  };
  return [...(templates[template] || []), ...common].map((step, index) => ({ id: `step-${index + 1}`, ...step }));
}

function renderQualityDashboard(cases = []) {
  const rules = detectionRulesValue();
  const closed = cases.filter((item) => item.status === "Closed").length;
  const open = cases.length - closed;
  const noisyRules = rules.filter((rule) => Number(rule.testCount || 0) > 100).length;
  const production = rules.filter((rule) => rule.status === "production").length;
  els.qualityDashboardList.innerHTML = [
    enterpriseIssue("Case closure", cases.length ? `${formatNumber(closed)} closed, ${formatNumber(open)} open` : "No cases measured yet", cases.length ? "ok" : "warn"),
    enterpriseIssue("Rule maturity", `${formatNumber(production)} production of ${formatNumber(rules.length)} total rules`, production ? "ok" : "warn"),
    enterpriseIssue("Noisy analytics", noisyRules ? `${formatNumber(noisyRules)} rules matched more than 100 current records` : "No noisy rules in current test set", noisyRules ? "warn" : "ok"),
    enterpriseIssue("ATT&CK mapping", `${formatNumber(rules.filter((rule) => rule.attackId).length)} rules mapped to technique IDs`, rules.some((rule) => rule.attackId) ? "ok" : "warn")
  ].join("");
}

function renderGovernanceReadiness(readiness, settings) {
  els.governanceReadinessList.innerHTML = [
    enterpriseIssue("Evidence retention", `${formatNumber(settings.governance?.evidenceRetentionDays || 90)} days${settings.governance?.legalHold ? " with legal hold" : ""}`, "ok"),
    enterpriseIssue("Export approval", settings.governance?.exportApprovalRequired ? "Required for controlled evidence sharing" : "Disabled", settings.governance?.exportApprovalRequired ? "ok" : "warn"),
    enterpriseIssue("Analytics platform", `${settings.dataPlatform?.analyticsStore || "Not selected"} via ${settings.dataPlatform?.queryEngine || "query engine not set"}`, settings.dataPlatform?.analyticsStore ? "ok" : "warn"),
    ...(readiness.blockers.length ? readiness.blockers.map((blocker) => enterpriseIssue("Readiness gap", blocker, "warn")) : [enterpriseIssue("Readiness gaps", "No major enterprise readiness blockers detected.", "ok")])
  ].join("");
}

async function createEvidenceVaultBundle() {
  if (!state.records.length && !state.analysis?.detections?.length) return setInputMessage("Analyze evidence before creating a vault bundle.");
  const cases = await listCaseRecords().catch(() => []);
  const settings = enterpriseSettingsValue();
  const manifest = await buildEvidenceVaultManifest({
    records: state.records,
    analysis: state.analysis,
    cases,
    settings,
    source: state.fileName || "current evidence"
  });
  await persistEnterpriseArtifact("EVIDENCE_VAULT_BUNDLE", manifest.title, manifest);
  saveJson(STORAGE_KEYS.evidenceVault, [manifest, ...loadJson(STORAGE_KEYS.evidenceVault, [])].slice(0, 25));
  renderEvidenceVault();
  showToast("Evidence vault bundle created.");
}

async function buildEvidenceVaultManifest({ records = [], analysis = null, cases = [], settings = enterpriseSettingsValue(), source = "" } = {}) {
  const createdAt = new Date().toISOString();
  const retentionDays = Number(settings.governance?.evidenceRetentionDays || 90);
  const retentionUntil = new Date(Date.now() + retentionDays * 24 * 60 * 60 * 1000).toISOString();
  const evidenceHash = await sha256Text(JSON.stringify({ records, detections: analysis?.detections || [] }));
  return {
    id: `vault-${Date.now()}`,
    title: `Vault bundle ${new Date().toISOString().slice(0, 10)}`,
    source,
    createdAt,
    retentionUntil,
    retentionDays,
    legalHold: Boolean(settings.governance?.legalHold),
    chainOfCustody: [
      { action: "bundle.created", actor: state.backend.principal?.email || "local analyst", at: createdAt },
      { action: "hash.calculated", actor: "SignalPrism NDR", at: createdAt, hash: evidenceHash }
    ],
    counts: {
      records: records.length,
      detections: analysis?.detections?.length || 0,
      highDetections: (analysis?.detections || []).filter((item) => item.severity === "high").length,
      cases: cases.length
    },
    evidenceHash,
    evidenceHashAlgorithm: "SHA-256",
    storage: settings.dataPlatform?.archiveStore || "local evidence vault"
  };
}

function renderEvidenceVault() {
  const bundles = loadJson(STORAGE_KEYS.evidenceVault, []);
  if (!bundles.length) {
    els.evidenceVaultList.innerHTML = `<div class="empty-state"><strong>No evidence vault bundles</strong><span>Create a retained bundle after analyzing evidence or building a case.</span></div>`;
    return;
  }
  els.evidenceVaultList.innerHTML = bundles.slice(0, 5).map((bundle) => enterpriseIssue(bundle.title, `${formatNumber(bundle.counts?.records || 0)} records - retain until ${bundle.retentionUntil?.slice(0, 10) || "not set"} - ${bundle.legalHold ? "legal hold" : "standard hold"}`, bundle.legalHold ? "warn" : "ok")).join("");
}

async function renderExecutiveReporting() {
  if (!els.executiveBriefOutput || !executiveReportingApi) return;
  const canWrite = hasRole("admin") || hasRole("analyst");
  const canSchedule = hasRole("admin");
  [els.generateExecutiveBriefButton, els.exportExecutivePdfButton, els.exportExecutiveCsvButton, els.exportExecutiveJsonButton].forEach((button) => {
    button.disabled = !canWrite;
    button.title = canWrite ? "" : "Admin or analyst role required";
  });
  [els.reportScheduleNameInput, els.reportScheduleFrequencySelect, els.reportSchedulePeriodSelect, els.reportScheduleFormatSelect, els.reportScheduleClassificationSelect, els.reportScheduleRecipientsInput, els.saveReportScheduleButton].forEach((control) => {
    control.disabled = !canSchedule;
  });
  els.reportScheduleAccessLabel.textContent = canSchedule ? "Admin managed - tenant inbox" : "Admin role required";
  if (!els.executiveOrganizationInput.value) els.executiveOrganizationInput.value = state.backend.principal?.tenantId || "";
  if (!state.executive.currentReport) state.executive.currentReport = loadJson(STORAGE_KEYS.executiveBriefs, [])[0] || null;
  renderExecutiveBriefOutput(state.executive.currentReport);
  renderReportSchedules();
  if (canSchedule) runDueReportSchedules();
}

async function generateExecutiveBrief(options = {}) {
  const settings = typeof options === "object" && options && !(options instanceof Event) ? options : {};
  if (!executiveReportingApi) return setInputMessage("Executive reporting module is unavailable.");
  if (!state.analysis && !state.records.length) return setInputMessage("Analyze evidence before generating an executive brief.");
  if (!hasRole("admin") && !hasRole("analyst")) return setInputMessage("Admin or analyst role is required to generate executive reports.");
  const period = settings.period || els.executivePeriodSelect.value;
  const classification = settings.classification || els.executiveClassificationSelect.value;
  const narrativeMode = settings.narrativeMode || els.executiveNarrativeSelect.value;
  const organization = String(settings.organization || els.executiveOrganizationInput.value || state.backend.principal?.tenantId || "Current tenant").trim().slice(0, 100);
  const reports = loadJson(STORAGE_KEYS.executiveBriefs, []);
  const previousReport = reports.find((report) => report.period?.key === period) || null;
  const cases = await listCaseRecords().catch(() => []);
  const report = executiveReportingApi.buildExecutiveBrief({
    detections: state.analysis?.detections || [],
    records: state.records,
    assets: loadJson(STORAGE_KEYS.assetContext, {}),
    threatIntel: loadJson(STORAGE_KEYS.threatIntel, {}),
    cases,
    sourceHealth: buildSourceHealth(loadJson(STORAGE_KEYS.sources, []), loadJson(STORAGE_KEYS.jobRuns, []), state.records, state.errors),
    activeCampaigns: state.enterprise.campaigns ?? null,
    responseActions: state.enterprise.responseActions || [],
    period,
    previousReport,
    tenant: { tenantId: state.backend.principal?.tenantId || "default", name: organization },
    branding: { organization, logoText: "SignalPrism NDR" },
    classification,
    generatedBy: state.backend.principal?.email || state.backend.principal?.name || state.backend.principal?.subject || "local analyst"
  });
  report.narrativeMode = "evidence";
  if (narrativeMode === "bedrock") {
    if (state.backend.ai?.enabled && backendApi && state.backend.online) {
      els.executiveBriefStatus.textContent = "Generating a bounded Bedrock narrative from cited report facts...";
      try {
        const ai = await backendApi.askAi({
          mode: "summary",
          question: "Write a concise executive NDR summary using only the supplied report facts. Preserve the [F#] and [M#] citations, distinguish unknown context, and do not introduce new claims.",
          context: {
            reportId: report.id,
            posture: report.posture,
            metrics: report.metrics,
            findings: report.findings.slice(0, 5),
            caveats: report.caveats,
            deterministicNarrative: report.narrative
          }
        });
        const answer = String(ai.answer || "").trim();
        if (answer) {
          report.aiNarrative = /\[(?:F|M)\d+\]/.test(answer) ? answer : `${answer} Evidence anchors: [F1] [M1] [M5].`;
          report.narrativeMode = "bedrock-assisted";
        }
      } catch (error) {
        if (!settings.silent) showToast(`Bedrock narrative unavailable; evidence-cited summary retained: ${error.message}`, "warn");
      }
    } else if (!settings.silent) {
      showToast("Bedrock is unavailable; the evidence-cited narrative was generated instead.", "warn");
    }
  }
  report.integrity.sha256 = await sha256Text(JSON.stringify({ ...report, integrity: undefined }));
  await persistEnterpriseArtifact("EXECUTIVE_BRIEF", report.title, report, "active", report.id);
  saveJson(STORAGE_KEYS.executiveBriefs, [report, ...reports.filter((item) => item.id !== report.id)].slice(0, 25));
  state.executive.currentReport = report;
  renderExecutiveBriefOutput(report);
  if (!settings.silent) showToast("Executive security brief generated with evidence citations.");
  return report;
}

function renderExecutiveBriefOutput(report) {
  if (!report) {
    els.executiveBriefOutput.innerHTML = "";
    els.executiveBriefStatus.textContent = "Generate a brief from the current evidence and tenant operations data.";
    return;
  }
  const delta = report.posture?.delta;
  const deltaLabel = delta === null || delta === undefined ? "No prior score" : `${delta > 0 ? "+" : ""}${delta} vs prior`;
  els.executiveBriefStatus.textContent = `${report.classification} - ${report.period?.label || "Current evidence"} - generated ${new Date(report.generatedAt).toLocaleString()} - SHA-256 ${String(report.integrity?.sha256 || report.integrity?.contentFingerprint || "pending").slice(0, 16)}`;
  els.executiveBriefOutput.innerHTML = `<div class="executive-report-heading">
      <div><p class="panel-kicker">${escapeHtml(report.organization)} - ${escapeHtml(report.classification)}</p><h3>${escapeHtml(report.title)}</h3><p>${escapeHtml(report.period?.label || "Current evidence")} - ${formatNumber(report.evidence?.recordCount || 0)} records - ${formatNumber(report.evidence?.caseCount || 0)} cases</p></div>
      <div class="executive-posture"><strong>${escapeHtml(String(report.posture?.score ?? 0))}</strong><span>${escapeHtml(report.posture?.label || "Unknown")} risk - ${escapeHtml(deltaLabel)}</span></div>
    </div>
    <div class="executive-narrative"><strong>${report.narrativeMode === "bedrock-assisted" ? "Bedrock-assisted narrative" : "Evidence-cited narrative"}</strong><p>${escapeHtml(report.aiNarrative || report.narrative || "")}</p></div>
    <div class="executive-table-wrap">
      <table class="executive-table report-metrics-table"><thead><tr><th scope="col">Metric</th><th scope="col">Current</th><th scope="col">Previous</th><th scope="col">Change</th><th scope="col">Interpretation</th></tr></thead>
      <tbody>${(report.metrics || []).map((metricItem, index) => `<tr><td><strong>[M${index + 1}] ${escapeHtml(metricItem.label)}</strong></td><td><strong>${escapeHtml(executiveMetricValue(metricItem.current, metricItem.unit))}</strong></td><td>${escapeHtml(executiveMetricValue(metricItem.previous, metricItem.unit))}</td><td>${escapeHtml(metricItem.delta === null ? "Unknown" : `${metricItem.delta > 0 ? "+" : ""}${metricItem.delta}${metricItem.unit || ""}`)}</td><td>${escapeHtml(metricItem.interpretation)}</td></tr>`).join("")}</tbody></table>
    </div>
    <div class="executive-table-wrap">
      <table class="executive-table report-findings-table"><thead><tr><th scope="col">Rank</th><th scope="col">Finding</th><th scope="col">Urgency</th><th scope="col">Trend</th><th scope="col">Owner</th><th scope="col">Status</th></tr></thead>
      <tbody>${(report.findings || []).map((finding) => `<tr><td><strong>[F${finding.rank}]</strong></td><td><strong>${escapeHtml(finding.title)}</strong><span>${escapeHtml(finding.entities?.slice(0, 2).join(", ") || "Unknown entity")}</span></td><td><span class="urgency-score ${escapeHtml(String(finding.urgencyLabel || "low").toLowerCase())}">${finding.urgency}</span></td><td>${escapeHtml(finding.trend)}</td><td>${escapeHtml(finding.owner)}</td><td>${escapeHtml(finding.status)}</td></tr>`).join("") || `<tr><td colspan="6">No ranked findings</td></tr>`}</tbody></table>
    </div>
    <div class="executive-decisions"><strong>Decisions and actions</strong><ul>${(report.decisions || []).map((decision) => `<li>${escapeHtml(`${decision.findingRef}: ${decision.text}`)}</li>`).join("") || "<li>No immediate decision recorded.</li>"}</ul></div>
    ${report.caveats?.length ? `<div class="executive-caveats"><strong>Coverage and caveats</strong><ul>${report.caveats.map((caveat) => `<li>${escapeHtml(caveat)}</li>`).join("")}</ul></div>` : ""}`;
}

function executiveMetricValue(value, unit = "") {
  return value === null || value === undefined ? "Unknown" : `${formatNumber(value)}${unit || ""}`;
}

async function exportExecutiveBrief(format) {
  if (!hasRole("admin") && !hasRole("analyst")) return setInputMessage("Admin or analyst role is required to export executive reports.");
  let report = state.executive.currentReport;
  if (!report) report = await generateExecutiveBrief({ silent: true });
  if (!report) return;
  const exportPayload = { product: "SignalPrism NDR", reportType: "executive-brief", format, report };
  try {
    if (backendApi && state.backend.online) {
      const governed = await backendApi.exportInvestigationPackage(exportPayload);
      if (governed?.pending) {
        await renderExportApprovals();
        showToast("Executive report export submitted for approval.", "warn");
        return;
      }
      report = governed.report || report;
    } else if (enterpriseSettingsValue().governance?.exportApprovalRequired) {
      throw new Error("The governed backend is required while export approval is enabled.");
    }
    downloadExecutiveBriefPayload(report, format);
    showToast(`Executive ${format.toUpperCase()} exported.`);
  } catch (error) {
    setInputMessage(error.message);
  }
}

function downloadExecutiveBriefPayload(report, format) {
  const date = String(report.generatedAt || new Date().toISOString()).slice(0, 10);
  if (format === "csv") {
    downloadText(`signalprism-executive-brief-${date}.csv`, executiveReportingApi.executiveReportCsv(report), "text/csv;charset=utf-8");
    return;
  }
  if (format === "pdf") {
    downloadBlob(`signalprism-executive-brief-${date}.pdf`, new Blob([buildExecutivePdf(report)], { type: "application/pdf" }));
    return;
  }
  downloadText(`signalprism-executive-brief-${date}.json`, JSON.stringify(report, null, 2), "application/json");
}

function buildExecutivePdf(report) {
  const lines = [
    report.logoText || "SignalPrism NDR",
    report.title || "Executive Security Brief",
    `${report.organization || "Current tenant"} | ${report.classification || "Confidential"}`,
    `${report.period?.label || "Current evidence"} | Generated ${report.generatedAt || ""}`,
    "",
    `Risk posture: ${report.posture?.label || "Unknown"} (${report.posture?.score ?? 0}/100)`,
    "",
    ...(wrapPdfText(report.aiNarrative || report.narrative || "No narrative available.", 92)),
    "",
    "EXECUTIVE METRICS",
    ...(report.metrics || []).flatMap((item, index) => wrapPdfText(`[M${index + 1}] ${item.label}: ${executiveMetricValue(item.current, item.unit)} | Prior ${executiveMetricValue(item.previous, item.unit)} | ${item.interpretation}`, 92)),
    "",
    "TOP FINDINGS",
    ...(report.findings || []).flatMap((item) => wrapPdfText(`[F${item.rank}] ${item.title} | Urgency ${item.urgency}/100 | ${item.owner} | ${item.status} | Last ${item.lastSeen}`, 92)),
    "",
    "DECISIONS AND ACTIONS",
    ...(report.decisions || []).flatMap((item) => wrapPdfText(`${item.findingRef}: ${item.text}`, 92)),
    "",
    "COVERAGE AND CAVEATS",
    ...(report.caveats?.length ? report.caveats.flatMap((item) => wrapPdfText(item, 92)) : ["No material reporting caveat recorded."]),
    "",
    `Integrity: ${report.integrity?.sha256 || report.integrity?.contentFingerprint || "Not available"}`
  ];
  return createTextPdf(lines);
}

function createTextPdf(inputLines) {
  const lines = inputLines.map((line) => String(line || "").normalize("NFKD").replace(/[^\x20-\x7E]/g, "?")).slice(0, 600);
  const pages = [];
  for (let index = 0; index < lines.length; index += 48) pages.push(lines.slice(index, index + 48));
  if (!pages.length) pages.push(["SignalPrism NDR Executive Brief"]);
  const objects = new Map();
  const pageIds = pages.map((_, index) => 4 + index * 2);
  objects.set(1, "<< /Type /Catalog /Pages 2 0 R >>");
  objects.set(2, `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${pages.length} >>`);
  objects.set(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  pages.forEach((pageLines, index) => {
    const pageId = pageIds[index];
    const streamId = pageId + 1;
    const content = `BT\n/F1 10 Tf\n48 760 Td\n14 TL\n${pageLines.map((line) => `(${escapePdfText(line)}) Tj\nT*`).join("\n")}\nET`;
    objects.set(pageId, `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ${streamId} 0 R >>`);
    objects.set(streamId, `<< /Length ${new TextEncoder().encode(content).length} >>\nstream\n${content}\nendstream`);
  });
  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  const objectCount = 3 + pages.length * 2;
  for (let id = 1; id <= objectCount; id += 1) {
    offsets[id] = new TextEncoder().encode(pdf).length;
    pdf += `${id} 0 obj\n${objects.get(id)}\nendobj\n`;
  }
  const xrefOffset = new TextEncoder().encode(pdf).length;
  pdf += `xref\n0 ${objectCount + 1}\n0000000000 65535 f \n${offsets.slice(1).map((offset) => `${String(offset).padStart(10, "0")} 00000 n `).join("\n")}\n`;
  pdf += `trailer\n<< /Size ${objectCount + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  return new TextEncoder().encode(pdf);
}

function wrapPdfText(text, width) {
  const words = String(text || "").split(/\s+/).filter(Boolean);
  const lines = [];
  let line = "";
  words.forEach((word) => {
    if (!line) line = word;
    else if (`${line} ${word}`.length <= width) line += ` ${word}`;
    else {
      lines.push(line);
      line = word;
    }
  });
  if (line) lines.push(line);
  return lines.length ? lines : [""];
}

function escapePdfText(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

async function saveReportSchedule(event) {
  event?.preventDefault?.();
  if (!hasRole("admin")) return setReportScheduleMessage("Admin role is required to manage report schedules.", "error");
  try {
    const schedule = executiveReportingApi.validateReportSchedule({
      name: els.reportScheduleNameInput.value,
      frequency: els.reportScheduleFrequencySelect.value,
      period: els.reportSchedulePeriodSelect.value,
      format: els.reportScheduleFormatSelect.value,
      classification: els.reportScheduleClassificationSelect.value,
      recipients: els.reportScheduleRecipientsInput.value
    }, loadJson(STORAGE_KEYS.tenantUsers, []));
    const savedArtifact = await persistEnterpriseArtifact("REPORT_SCHEDULE", schedule.name, schedule, schedule.status, schedule.id);
    const savedSchedule = { ...schedule, _artifactRevision: savedArtifact.revision, _artifactCreatedAt: savedArtifact.createdAt };
    const schedules = [savedSchedule, ...loadJson(STORAGE_KEYS.reportSchedules, []).filter((item) => item.id !== schedule.id)].slice(0, 50);
    saveJson(STORAGE_KEYS.reportSchedules, schedules);
    els.reportScheduleForm.reset();
    els.reportScheduleClassificationSelect.value = "Confidential";
    setReportScheduleMessage("Schedule saved for governed tenant-inbox delivery.", "success");
    renderReportSchedules();
    showToast("Executive report schedule saved.");
  } catch (error) {
    setReportScheduleMessage(error.message, "error");
  }
}

function setReportScheduleMessage(message, tone = "") {
  els.reportScheduleMessage.textContent = message;
  els.reportScheduleMessage.className = `form-message ${tone}`.trim();
}

function renderReportSchedules() {
  const schedules = loadJson(STORAGE_KEYS.reportSchedules, []);
  const deliveries = loadJson(STORAGE_KEYS.reportDeliveries, []);
  if (!schedules.length && !deliveries.length) {
    els.reportScheduleList.innerHTML = `<div class="empty-state"><strong>No report schedules</strong><span>Tenant administrators can create weekly or monthly executive brief deliveries.</span></div>`;
    return;
  }
  const canAdmin = hasRole("admin");
  els.reportScheduleList.innerHTML = [
    ...schedules.map((schedule) => `<div class="schedule-row"><div><strong>${escapeHtml(schedule.name)}</strong><span>${escapeHtml(`${schedule.frequency} - ${schedule.period} - ${schedule.format.toUpperCase()} - ${schedule.status}`)}</span><span>Next ${escapeHtml(schedule.nextRunAt ? new Date(schedule.nextRunAt).toLocaleString() : "not scheduled")} - ${escapeHtml(schedule.recipients.join(", "))}</span></div><div class="schedule-row-actions"><button class="mini-button" type="button" data-run-report-schedule="${escapeHtml(schedule.id)}" ${canAdmin && schedule.status === "active" ? "" : "disabled"}>Run</button><button class="mini-button" type="button" data-pause-report-schedule="${escapeHtml(schedule.id)}" ${canAdmin ? "" : "disabled"}>${schedule.status === "paused" ? "Resume" : "Pause"}</button><button class="mini-button danger" type="button" data-delete-report-schedule="${escapeHtml(schedule.id)}" ${canAdmin ? "" : "disabled"}>Delete</button></div></div>`),
    ...deliveries.slice(0, 10).map((delivery) => `<div class="schedule-row"><div><strong>${escapeHtml(delivery.scheduleName)} delivery</strong><span>${escapeHtml(`${delivery.format.toUpperCase()} - ${delivery.classification} - delivered ${new Date(delivery.deliveredAt).toLocaleString()}`)}</span><span>${escapeHtml(delivery.recipients.join(", "))}</span></div><div class="schedule-row-actions"><button class="mini-button" type="button" data-download-report-delivery="${escapeHtml(delivery.id)}">Download</button></div></div>`)
  ].join("");
  els.reportScheduleList.querySelectorAll("[data-download-report-delivery]").forEach((button) => button.addEventListener("click", () => downloadReportDelivery(button.dataset.downloadReportDelivery)));
}

async function runReportSchedule(id, automatic = false) {
  if (!hasRole("admin")) return;
  const schedules = loadJson(STORAGE_KEYS.reportSchedules, []);
  const schedule = schedules.find((item) => item.id === id);
  if (!schedule || schedule.status !== "active") return;
  try {
    const report = await generateExecutiveBrief({ period: schedule.period, classification: schedule.classification, narrativeMode: "evidence", silent: true });
    if (!report) return;
    const delivery = {
      id: `report-delivery-${Date.now()}`,
      scheduleId: schedule.id,
      scheduleName: schedule.name,
      report,
      format: schedule.format,
      classification: schedule.classification,
      recipients: schedule.recipients,
      destination: "tenant-inbox",
      status: "delivered",
      deliveredAt: new Date().toISOString()
    };
    const updated = executiveReportingApi.advanceReportSchedule(schedule, new Date());
    saveJson(STORAGE_KEYS.reportDeliveries, [delivery, ...loadJson(STORAGE_KEYS.reportDeliveries, [])].slice(0, 50));
    const [savedScheduleArtifact] = await Promise.all([
      persistEnterpriseArtifact("REPORT_SCHEDULE", updated.name, updated, updated.status, updated.id),
      persistEnterpriseArtifact("REPORT_DELIVERY", `${schedule.name} delivery`, delivery, "delivered", delivery.id)
    ]);
    const savedSchedule = { ...updated, _artifactRevision: savedScheduleArtifact.revision, _artifactCreatedAt: savedScheduleArtifact.createdAt };
    saveJson(STORAGE_KEYS.reportSchedules, schedules.map((item) => item.id === id ? savedSchedule : item));
    renderReportSchedules();
    if (!automatic) showToast("Executive report delivered to the tenant inbox.");
  } catch (error) {
    if (!automatic) setReportScheduleMessage(error.message, "error");
  }
}

async function runDueReportSchedules() {
  if (state.executive.runningDueSchedules) return;
  const due = loadJson(STORAGE_KEYS.reportSchedules, []).filter((schedule) => schedule.status === "active" && Date.parse(schedule.nextRunAt || 0) <= Date.now());
  if (!due.length) return;
  state.executive.runningDueSchedules = true;
  try {
    for (const schedule of due.slice(0, 5)) await runReportSchedule(schedule.id, true);
  } finally {
    state.executive.runningDueSchedules = false;
  }
}

async function toggleReportSchedule(id) {
  if (!hasRole("admin")) return;
  const schedules = loadJson(STORAGE_KEYS.reportSchedules, []);
  const schedule = schedules.find((item) => item.id === id);
  if (!schedule) return;
  const updated = { ...schedule, status: schedule.status === "paused" ? "active" : "paused", updatedAt: new Date().toISOString() };
  const savedArtifact = await persistEnterpriseArtifact("REPORT_SCHEDULE", updated.name, updated, updated.status, updated.id);
  const savedSchedule = { ...updated, _artifactRevision: savedArtifact.revision, _artifactCreatedAt: savedArtifact.createdAt };
  saveJson(STORAGE_KEYS.reportSchedules, schedules.map((item) => item.id === id ? savedSchedule : item));
  renderReportSchedules();
}

function deleteReportSchedule(id) {
  if (!hasRole("admin")) return;
  const schedule = loadJson(STORAGE_KEYS.reportSchedules, []).find((item) => item.id === id);
  if (!schedule) return;
  confirmAction({
    title: "Delete executive report schedule?",
    body: `This stops ${schedule.name}. Existing tenant-inbox deliveries remain available for their retention period.`,
    confirmLabel: "Delete Schedule",
    onConfirm: async () => {
      if (backendApi?.deleteEnterpriseArtifact && state.backend.online) await backendApi.deleteEnterpriseArtifact(id);
      saveJson(STORAGE_KEYS.reportSchedules, loadJson(STORAGE_KEYS.reportSchedules, []).filter((item) => item.id !== id));
      renderReportSchedules();
      showToast("Report schedule deleted.");
    }
  });
}

function downloadReportDelivery(id) {
  const delivery = loadJson(STORAGE_KEYS.reportDeliveries, []).find((item) => item.id === id);
  if (!delivery) return setInputMessage("Report delivery was not found.");
  downloadExecutiveBriefPayload(delivery.report, delivery.format);
}

async function generateEnterpriseReport() {
  const cases = await listCaseRecords().catch(() => []);
  const report = buildEnterpriseReport({
    mode: els.reportModeSelect.value,
    analysis: state.analysis,
    records: state.records,
    cases,
    settings: enterpriseSettingsValue(),
    riskScores: buildEntityRiskScores(state.records, state.analysis, loadJson(STORAGE_KEYS.assetContext, {}), loadJson(STORAGE_KEYS.threatIntel, {})),
    sourceHealth: buildSourceHealth(loadJson(STORAGE_KEYS.sources, []), loadJson(STORAGE_KEYS.jobRuns, []), state.records, state.errors)
  });
  await persistEnterpriseArtifact("ENTERPRISE_REPORT", report.title, report);
  saveJson(STORAGE_KEYS.enterpriseReports, [report, ...loadJson(STORAGE_KEYS.enterpriseReports, [])].slice(0, 12));
  renderEnterpriseReport();
  showToast("Enterprise report generated.");
}

function buildEnterpriseReport({ mode = "analyst", analysis = null, records = [], cases = [], settings = enterpriseSettingsValue(), riskScores = [], sourceHealth = [] } = {}) {
  const detections = analysis?.detections || [];
  const high = detections.filter((item) => item.severity === "high").length;
  const openCases = cases.filter((item) => item.status !== "Closed").length;
  const sections = {
    analyst: [
      `${formatNumber(detections.length)} detections across ${formatNumber(records.length)} records.`,
      `Top entity: ${riskScores[0]?.entity || analysis?.entityRisk?.[0]?.entity || "not available"}.`,
      `${sourceHealth.filter((item) => item.tone === "warn").length} source-health issues need review.`
    ],
    executive: [
      `${high ? "Elevated" : "Moderate"} network risk based on ${formatNumber(high)} high-severity detections.`,
      `${formatNumber(openCases)} open incident case${openCases === 1 ? "" : "s"} require ownership.`,
      `Security Lake pipeline is ${settings.securityLake?.bucket ? "configured" : "not yet configured"}.`
    ],
    compliance: [
      `Evidence retention is ${formatNumber(settings.governance?.evidenceRetentionDays || 90)} days.`,
      `Export approval is ${settings.governance?.exportApprovalRequired ? "enabled" : "disabled"}.`,
      `${loadJson(STORAGE_KEYS.evidenceVault, []).length} evidence vault bundle${loadJson(STORAGE_KEYS.evidenceVault, []).length === 1 ? "" : "s"} are tracked locally.`
    ],
    manager: [
      `${formatNumber(cases.length)} total cases, ${formatNumber(openCases)} open.`,
      `${formatNumber(detectionRulesValue().filter((rule) => rule.status === "production").length)} production detections.`,
      `${formatNumber(loadJson(STORAGE_KEYS.playbookRuns, []).length)} active or historical response playbooks.`
    ]
  };
  return {
    id: `report-${Date.now()}`,
    title: `${mode[0].toUpperCase()}${mode.slice(1)} enterprise report`,
    mode,
    createdAt: new Date().toISOString(),
    summary: sections[mode] || sections.analyst,
    metrics: {
      records: records.length,
      detections: detections.length,
      highDetections: high,
      openCases,
      readiness: buildEnterpriseReadiness(cases).score
    }
  };
}

function renderEnterpriseReport() {
  const reports = loadJson(STORAGE_KEYS.enterpriseReports, []);
  if (!reports.length) {
    els.enterpriseReportPanel.innerHTML = `<div class="empty-state"><strong>No report generated</strong><span>Select a mode and generate a stakeholder-ready summary.</span></div>`;
    return;
  }
  const report = reports[0];
  els.enterpriseReportPanel.innerHTML = `<h3>${escapeHtml(report.title)}</h3>
    <p>${escapeHtml(report.createdAt ? new Date(report.createdAt).toLocaleString() : "")}</p>
    <ul>${(report.summary || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function renderEnterpriseAdminReadiness() {
  const users = loadJson(STORAGE_KEYS.tenantUsers, []);
  const settings = enterpriseSettingsValue();
  const adminCount = users.filter((user) => user.role === "admin" && user.status !== "disabled").length;
  els.enterpriseAdminList.innerHTML = [
    enterpriseIssue("RBAC users", users.length ? `${formatNumber(users.length)} tenant users, ${formatNumber(adminCount)} admins` : "No tenant users configured locally", users.length ? "ok" : "warn"),
    enterpriseIssue("SSO status", state.backend.authMode === "oidc" ? "OIDC configured on backend" : "Local/API-key mode active", state.backend.authMode === "oidc" ? "ok" : "warn"),
    enterpriseIssue("SCIM provisioning", settings.governance?.scimEnabled ? "Enabled in governance settings" : "Not enabled yet", settings.governance?.scimEnabled ? "ok" : "warn"),
    enterpriseIssue("AI permissions", hasRole("admin") || hasRole("analyst") ? "Current role can run AI actions" : "Viewer role cannot run AI actions", hasRole("viewer") && !hasRole("analyst") && !hasRole("admin") ? "warn" : "ok")
  ].join("");
}

function rebuildEventStitching(showFeedback = false) {
  if (!eventStitchingApi?.buildStitchedIncidents) {
    loadEventStitchingApi().then(() => rebuildEventStitching(showFeedback)).catch((error) => setInputMessage(`Event stitching could not start: ${error.message}`));
    return;
  }
  const events = state.heatmap.selection && networkHeatmapApi?.recordMatchesHeatmapSelection
    ? state.stitching.events.filter(eventMatchesHeatmapSelection)
    : state.stitching.events;
  const result = eventStitchingApi.buildStitchedIncidents(events, {
    windowMinutes: Number(els.stitchWindowSelect?.value || 240),
    minimumLinkConfidence: Number(els.stitchConfidenceSelect?.value || 0.62)
  });
  state.stitching.result = result;
  if (!result.chains.some((chain) => chain.id === state.stitching.selectedChainId)) {
    state.stitching.selectedChainId = result.chains[0]?.id || "";
  }
  renderEventStitching();
  if (showFeedback) {
    showToast(result.chainCount
      ? `${formatNumber(result.chainCount)} incident chain${result.chainCount === 1 ? "" : "s"} rebuilt from ${formatNumber(result.eventCount)} events.`
      : `No defensible multi-source chain met the selected confidence policy.`, result.chainCount ? "success" : "warn");
  }
}

function eventMatchesHeatmapSelection(event) {
  const timestamp = Date.parse(event.timestamp || event.createdAt || "");
  return networkHeatmapApi.recordMatchesHeatmapSelection({
    source: event.sourceIp || event.source || "-",
    destination: event.destinationIp || event.destination || "-",
    srcPort: event.sourcePort || event.srcPort || null,
    dstPort: event.destinationPort || event.dstPort || null,
    start: Number.isFinite(timestamp) ? timestamp : event.start,
    accountId: event.accountId || "-",
    protocol: event.protocol || event.format || "-",
    evidenceSource: event.evidenceSource || "Unknown source"
  }, state.heatmap.selection);
}

function renderEventStitching() {
  if (!els.stitchMetricGrid) return;
  const result = state.stitching.result;
  if (!result) {
    els.stitchStatus.textContent = state.stitching.events.length ? "Building incident chains" : "No normalized evidence";
    els.stitchMetricGrid.innerHTML = [
      metricTemplate("Incident chains", "0", "multi-source"),
      metricTemplate("Explainable links", "0", "confidence-scored"),
      metricTemplate("Normalized events", formatNumber(state.stitching.events.length), "waiting for correlation"),
      metricTemplate("Conflicts", "0", "unsafe joins blocked")
    ].join("");
    els.stitchChainList.innerHTML = eventStitchingEmptyState("No incident chains", "Upload at least two related evidence sources to build an ordered investigation chain.");
    els.stitchDetail.innerHTML = eventStitchingEmptyState("Select a chain", "Chain evidence, source provenance, and link reasoning will appear here.");
    els.stitchGapList.innerHTML = eventStitchingEmptyState("No coverage assessment", "Telemetry gaps are calculated after evidence normalization.");
    els.exportStitchingButton.disabled = true;
    return;
  }

  els.stitchStatus.textContent = `${formatNumber(result.chainCount)} chains, ${formatNumber(result.linkCount)} links, ${formatNumber(result.sourceCount)} sources`;
  els.stitchMetricGrid.innerHTML = [
    metricTemplate("Incident chains", formatNumber(result.chainCount), `${formatNumber(result.linkedEventCount)} linked events`),
    metricTemplate("Explainable links", formatNumber(result.linkCount), `${Math.round((result.chains[0]?.confidence || 0) * 100)}% top confidence`),
    metricTemplate("Normalized events", formatNumber(result.eventCount), `${formatNumber(result.formatCount)} detected formats`),
    metricTemplate("Conflicts", formatNumber(result.conflicts.length), `${formatNumber(result.suppressedEntityCount)} shared entities suppressed`)
  ].join("");
  els.exportStitchingButton.disabled = !result.chainCount;

  els.stitchChainList.innerHTML = result.chains.length
    ? result.chains.map((chain) => `<button class="stitch-chain-row${chain.id === state.stitching.selectedChainId ? " active" : ""}" type="button" data-stitch-chain="${escapeHtml(chain.id)}" aria-pressed="${chain.id === state.stitching.selectedChainId}">
        <span class="stitch-chain-heading"><strong>${escapeHtml(chain.title)}</strong><span class="tag ${tagClass(chain.severity)}">${escapeHtml(chain.severity.toUpperCase())}</span></span>
        <span>${escapeHtml(chain.stages.join(" -> "))}</span>
        <span>${escapeHtml(String(Math.round(chain.confidence * 100)))}% confidence, ${escapeHtml(formatNumber(chain.events.length))} events, ${escapeHtml(formatNumber(chain.evidenceSources.length))} sources</span>
      </button>`).join("")
    : eventStitchingEmptyState("No defensible chain found", `${formatNumber(result.eventCount)} events were normalized, but no risk-bearing sequence crossed two independent evidence sources at the selected confidence threshold.`);

  const selected = result.chains.find((chain) => chain.id === state.stitching.selectedChainId) || result.chains[0];
  renderStitchedChainDetail(selected);
  renderStitchingGaps(result, selected);
}

function renderStitchedChainDetail(chain) {
  if (!chain) {
    els.stitchDetail.innerHTML = eventStitchingEmptyState("No chain selected", "Adjust the time window or confidence policy when related events are expected but remain unlinked.");
    return;
  }
  const incomingLinks = new Map(chain.links.map((link) => [link.toEventId, link]));
  els.stitchDetail.innerHTML = `<div class="stitch-detail-header">
      <div><p class="panel-kicker">Selected incident</p><h3>${escapeHtml(chain.title)}</h3></div>
      <div class="stitch-score ${escapeHtml(chain.severity)}"><span>Urgency</span><strong>${escapeHtml(String(chain.score))}</strong></div>
    </div>
    <p class="stitch-narrative">${escapeHtml(chain.narrative)}</p>
    <div class="entity-meta">
      ${chain.evidenceSources.map((source) => `<span class="tag">${escapeHtml(source)}</span>`).join("")}
      <span class="tag">${escapeHtml(String(Math.round(chain.confidence * 100)))}% confidence</span>
      <span class="tag">${escapeHtml(formatDate(Date.parse(chain.firstSeen)))} to ${escapeHtml(formatDate(Date.parse(chain.lastSeen)))}</span>
    </div>
    <ol class="stitch-timeline">
      ${chain.events.map((event) => {
        const link = incomingLinks.get(event.id);
        const endpointText = [event.sourceIp, event.destinationIp].filter(Boolean).join(" -> ");
        return `<li>
          ${link ? `<div class="stitch-link-reason"><strong>${escapeHtml(link.relationship.replace(/-/g, " "))} (${escapeHtml(String(Math.round(link.confidence * 100)))}%)</strong><span>${escapeHtml(link.reasons.join(". "))}</span></div>` : ""}
          <div class="stitch-event-heading"><span class="stitch-stage">${escapeHtml(stitchEventStage(chain, event))}</span><time datetime="${escapeHtml(event.timestamp)}">${escapeHtml(formatDate(Date.parse(event.timestamp)))}</time></div>
          <strong>${escapeHtml(event.summary || `${event.format} event`)}</strong>
          <span>${escapeHtml(event.evidenceSource)} - ${escapeHtml(event.format)}${endpointText ? ` - ${escapeHtml(endpointText)}` : ""}</span>
          <div class="entity-meta">${[event.identity, event.resource, event.interfaceId, event.communityId].filter(Boolean).slice(0, 4).map((entity) => `<span class="tag mono">${escapeHtml(entity)}</span>`).join("")}</div>
        </li>`;
      }).join("")}
    </ol>`;
}

function stitchEventStage(chain, event) {
  if (event.stage) return event.stage;
  if (event.category === "authentication") return "Credential Access";
  if (event.action && ["AttachGroupPolicy", "AttachRolePolicy", "AttachUserPolicy", "CreateAccessKey", "PassRole", "PutRolePolicy", "PutUserPolicy"].includes(event.action)) return "Privilege Escalation";
  if (Number(event.bytes) >= 10 * 1024 * 1024 || event.category === "dns" && String(event.query || "").length >= 60) return "Exfiltration";
  if (["threat-finding", "ids-alert", "dns"].includes(event.category)) return "Command and Control";
  return chain.stages[0] || "Observed Activity";
}

function renderStitchingGaps(result, chain) {
  const items = [
    ...(result.gaps || []).map((gap) => ({ title: gap.type.replace(/-/g, " "), detail: gap.detail, tone: gap.severity })),
    ...(result.conflicts || []).map((conflict) => ({ title: `Blocked: ${conflict.type.replace(/-/g, " ")}`, detail: conflict.detail, tone: "medium" })),
    ...((chain?.gaps || []).map((detail) => ({ title: "Chain coverage gap", detail, tone: "low" })))
  ];
  els.stitchGapList.innerHTML = items.length
    ? items.slice(0, 20).map((item) => `<div class="issue-item"><strong>${escapeHtml(item.title)}</strong><span>${escapeHtml(item.detail)}</span></div>`).join("")
    : `<div class="issue-item"><strong>No material stitching gaps</strong><span>The selected chain includes identity, DNS, and independent detection evidence with no blocked ambiguous joins.</span></div>`;
}

function eventStitchingEmptyState(title, copy) {
  return `<div class="empty-state"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(copy)}</span></div>`;
}

async function exportStitchedIncidents() {
  const result = state.stitching.result;
  if (!result?.chainCount) return setInputMessage("Build at least one stitched incident chain before exporting.");
  if (state.backend.online && !hasRole("admin") && !hasRole("analyst")) return setInputMessage("An analyst or admin role is required to export stitched evidence.");
  if (enterpriseSettingsValue().governance?.exportApprovalRequired !== false) {
    await exportInvestigationPackage();
    return;
  }
  const exportResult = {
    ...result,
    chains: result.chains.map((chain) => ({
      ...chain,
      events: chain.events.map(({ raw, ...event }) => event)
    }))
  };
  downloadText(`signalprism-stitched-incidents-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(exportResult, null, 2), "application/json");
  showToast("Stitched incidents exported without raw payload bodies.");
}

function renderTopology() {
  if (!topologyApi?.buildTopology || !networkHeatmapApi) return;
  syncHeatmapControls();
  if (!state.records.length) {
    els.topologyCanvas.innerHTML = emptyState();
    if (els.replayEventList) els.replayEventList.innerHTML = emptyState();
    state.heatmap.model = null;
    els.exportHeatmapButton.disabled = true;
    return;
  }
  const replay = buildTopologyReplaySnapshot(state.records, Number(els.replayRangeInput.value || 100));
  const selectedRecords = replay.includedRecords.filter((record) => !state.heatmap.selection || networkHeatmapApi.recordMatchesHeatmapSelection(record, state.heatmap.selection));
  const evidenceSets = heatmapEvidenceSets();
  const options = {
    groupBy: state.heatmap.groupBy,
    metric: state.heatmap.metric,
    scale: state.heatmap.scale,
    evidenceFilter: state.heatmap.evidenceFilter,
    zoom: state.heatmap.zoom,
    panRatio: state.heatmap.panRatio,
    detectionKeys: evidenceSets.detectionKeys,
    stitchedKeys: evidenceSets.stitchedKeys,
    enrichment: state.enrichment,
    allowDemoCoordinates: true
  };

  els.topologyCanvas.className = `topology-canvas topology-mode-${state.heatmap.mode} heatmap-zoom-${heatmapZoomClass()}`;
  if (state.heatmap.mode === "activity") {
    state.heatmap.model = networkHeatmapApi.buildActivityHeatmap(replay.includedRecords, options);
    els.topologyCanvas.innerHTML = networkHeatmapApi.renderActivityHeatmap(state.heatmap.model, state.heatmap.selection);
    els.topologyViewHeading.textContent = "Time activity heatmap";
    els.heatmapStatusLabel.textContent = activityHeatmapStatus(state.heatmap.model);
  } else if (state.heatmap.mode === "matrix") {
    state.heatmap.model = networkHeatmapApi.buildCommunicationMatrix(replay.includedRecords, options);
    els.topologyCanvas.innerHTML = networkHeatmapApi.renderCommunicationMatrix(state.heatmap.model, state.heatmap.selection);
    els.topologyViewHeading.textContent = "Communication matrix";
    els.heatmapStatusLabel.textContent = matrixHeatmapStatus(state.heatmap.model);
  } else if (state.heatmap.mode === "geographic") {
    state.heatmap.model = networkHeatmapApi.buildGeographicHeatmap(replay.includedRecords, options);
    els.topologyCanvas.innerHTML = networkHeatmapApi.renderGeographicHeatmap(state.heatmap.model, {
      zoom: state.heatmap.zoom,
      panX: state.heatmap.panX,
      panY: state.heatmap.panY,
      selection: state.heatmap.selection
    });
    els.topologyViewHeading.textContent = "Geographic network activity";
    els.heatmapStatusLabel.textContent = geographicHeatmapStatus(state.heatmap.model);
  } else {
    const topology = topologyApi.buildTopology(selectedRecords);
    state.heatmap.model = { kind: "graph", ...topology, inputRecordCount: selectedRecords.length };
    els.topologyCanvas.innerHTML = topologyApi.renderTopologySvg(topology);
    els.topologyViewHeading.textContent = "Entity-to-entity paths";
    els.heatmapStatusLabel.textContent = `${formatNumber(topology.nodes.length)} entities, ${formatNumber(topology.edges.length)} observed paths`;
  }
  els.exportHeatmapButton.disabled = state.heatmap.mode === "graph" || !state.heatmap.model;
  els.replayTimeLabel.textContent = replay.percent >= 100 ? "All evidence" : `Replay through ${formatDate(replay.cutoff)}`;
  if (els.replayEventCountLabel) {
    const selectedCopy = state.heatmap.selection ? `, ${formatNumber(selectedRecords.length)} selected` : "";
    els.replayEventCountLabel.textContent = `${formatNumber(replay.includedRecords.length)} of ${formatNumber(state.records.length)} records${selectedCopy}`;
  }
  if (els.replayEventList) {
    const recentRecords = selectedRecords
      .filter((record) => Number.isFinite(record.start))
      .sort((a, b) => b.start - a.start)
      .slice(0, 8);
    els.replayEventList.innerHTML = recentRecords.length
      ? recentRecords
          .map(
            (record) => `<div class="issue-item">
              <strong>${escapeHtml(formatDate(record.start))} ${escapeHtml(record.action)}</strong>
              <span class="mono">${escapeHtml(formatEndpoint(record.source, record.srcPort))} -> ${escapeHtml(formatEndpoint(record.destination, record.dstPort))}</span>
              <span>${escapeHtml(record.protocol)} ${escapeHtml(formatBytes(record.bytes))} ${escapeHtml(record.interfaceId || "")}</span>
            </div>`
          )
          .join("")
      : emptyState();
  }
  bindHeatmapCellInteractions();
  renderHeatmapSelectionContext();
}

function bindHeatmapCellInteractions() {
  els.topologyCanvas.querySelectorAll("[data-heat-kind]").forEach((target) => {
    target.addEventListener("click", selectHeatmapCell);
    target.addEventListener("dblclick", openHeatmapEvidence);
  });
}

function setTopologyMode(mode) {
  if (!networkHeatmapApi?.HEATMAP_MODES?.includes(mode)) return;
  state.heatmap.mode = mode;
  if (mode === "matrix" && !["entity", "subnet", "account", "source"].includes(state.heatmap.groupBy)) {
    state.heatmap.groupBy = "entity";
  }
  state.heatmap.zoom = 1;
  state.heatmap.panRatio = 0;
  state.heatmap.panX = 0;
  state.heatmap.panY = 0;
  renderTopology();
}

function syncHeatmapControls() {
  const isGraph = state.heatmap.mode === "graph";
  els.heatmapToolbar.hidden = isGraph;
  els.heatmapContextBar.hidden = isGraph;
  els.topologyModeControl.querySelectorAll("[data-topology-mode]").forEach((button) => {
    const active = button.dataset.topologyMode === state.heatmap.mode;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  const groupOptions = [...els.heatmapGroupSelect.options];
  groupOptions.forEach((option) => {
    option.disabled = state.heatmap.mode === "matrix" && ["port", "protocol"].includes(option.value);
  });
  els.heatmapGroupSelect.value = state.heatmap.groupBy;
  els.heatmapGroupSelect.disabled = state.heatmap.mode === "geographic";
  els.heatmapMetricSelect.value = state.heatmap.metric;
  els.heatmapScaleSelect.value = state.heatmap.scale;
  els.heatmapEvidenceFilter.value = state.heatmap.evidenceFilter;
  els.heatmapPanUpButton.disabled = !["matrix", "geographic"].includes(state.heatmap.mode);
  els.heatmapPanDownButton.disabled = !["matrix", "geographic"].includes(state.heatmap.mode);
}

function updateHeatmapOptions() {
  state.heatmap.groupBy = els.heatmapGroupSelect.value;
  state.heatmap.metric = els.heatmapMetricSelect.value;
  state.heatmap.scale = els.heatmapScaleSelect.value;
  state.heatmap.evidenceFilter = els.heatmapEvidenceFilter.value;
  state.heatmap.zoom = 1;
  state.heatmap.panRatio = 0;
  state.heatmap.panX = 0;
  state.heatmap.panY = 0;
  if (state.heatmap.selection && state.heatmap.selection.groupBy && state.heatmap.selection.groupBy !== state.heatmap.groupBy) clearHeatmapSelection(false);
  renderTopology();
}

function heatmapEvidenceSets() {
  const detectionKeys = new Set();
  const stitchedKeys = new Set();
  (state.analysis?.detections || []).forEach((detection) => {
    (detection.records || []).forEach((record) => detectionKeys.add(networkHeatmapApi.recordEvidenceKey(record)));
  });
  (state.stitching.result?.chains || []).forEach((chain) => {
    (chain.events || []).forEach((event) => stitchedKeys.add(networkHeatmapApi.eventEvidenceKey(event)));
  });
  return { detectionKeys, stitchedKeys };
}

function activityHeatmapStatus(model) {
  const omitted = model.omittedRowCount ? `, ${formatNumber(model.omittedRowCount)} lower-volume groups omitted` : "";
  return `${formatNumber(model.visibleRecordCount)} visible flows, ${formatNumber(model.rows.length)} groups${omitted}`;
}

function matrixHeatmapStatus(model) {
  const omitted = model.omittedGroupCount ? `, ${formatNumber(model.omittedGroupCount)} groups omitted` : "";
  return `${formatNumber(model.visibleRecordCount)} visible flows, ${formatNumber(model.groups.length)} endpoint groups${omitted}`;
}

function geographicHeatmapStatus(model) {
  const approximate = model.approximateEndpointCount ? `, ${formatNumber(model.approximateEndpointCount)} approximate locations` : "";
  return `${formatNumber(model.mappedEndpointCount || model.points.length)} mapped endpoints in ${formatNumber(model.points.length)} locations, ${formatNumber(model.unresolvedEndpointCount)} unresolved observations${approximate}`;
}

function heatmapZoomClass() {
  if (state.heatmap.zoom >= 3) return 4;
  if (state.heatmap.zoom >= 2) return 3;
  if (state.heatmap.zoom >= 1.4) return 2;
  return 1;
}

function zoomHeatmap(direction) {
  if (state.heatmap.mode === "graph") return;
  const maximum = state.heatmap.mode === "activity" ? 8 : 4;
  const factor = direction > 0 ? 1.5 : 1 / 1.5;
  state.heatmap.zoom = Math.max(1, Math.min(maximum, Number((state.heatmap.zoom * factor).toFixed(2))));
  renderTopology();
}

function panHeatmap(horizontal, vertical) {
  if (state.heatmap.mode === "activity") {
    state.heatmap.panRatio = Math.max(0, Math.min(1, state.heatmap.panRatio + horizontal * 0.14));
    renderTopology();
    return;
  }
  if (state.heatmap.mode === "matrix") {
    els.topologyCanvas.scrollBy({ left: horizontal * 180, top: vertical * 180, behavior: "smooth" });
    return;
  }
  if (state.heatmap.mode === "geographic") {
    state.heatmap.panX = Math.max(-1, Math.min(1, state.heatmap.panX + horizontal * 0.16));
    state.heatmap.panY = Math.max(-1, Math.min(1, state.heatmap.panY + vertical * 0.16));
    renderTopology();
  }
}

function resetHeatmapView() {
  state.heatmap.zoom = 1;
  state.heatmap.panRatio = 0;
  state.heatmap.panX = 0;
  state.heatmap.panY = 0;
  els.topologyCanvas.scrollTo({ left: 0, top: 0 });
  renderTopology();
}

function selectHeatmapCell(event) {
  if (Date.now() < (state.heatmap.suppressClickUntil || 0)) return;
  const target = event.currentTarget?.matches?.("[data-heat-kind]") ? event.currentTarget : event.target.closest("[data-heat-kind]");
  if (!target) return;
  event.stopPropagation();
  commitHeatmapSelection(selectionFromHeatTarget(target, event.shiftKey));
}

function selectionFromHeatTarget(target, extend = false) {
  if (target.dataset.heatKind === "activity") {
    const start = Number(target.dataset.heatStart);
    const end = Number(target.dataset.heatEnd);
    if (extend && state.heatmap.selection?.type === "activity" && state.heatmap.selection.rowKey === target.dataset.heatRow) {
      return { ...state.heatmap.selection, start: Math.min(state.heatmap.selection.start, start), end: Math.max(state.heatmap.selection.end, end) };
    }
    return { type: "activity", rowKey: target.dataset.heatRow, groupBy: state.heatmap.groupBy, start, end };
  }
  if (target.dataset.heatKind === "matrix") {
    return { type: "matrix", sourceKey: target.dataset.heatSource, destinationKey: target.dataset.heatDestination, groupBy: ["entity", "subnet", "account", "source"].includes(state.heatmap.groupBy) ? state.heatmap.groupBy : "entity" };
  }
  if (target.dataset.heatKind === "geographic") {
    const ips = String(target.dataset.heatIps || target.dataset.heatIp || "").split(",").filter(Boolean);
    return { type: "geographic", ip: ips[0] || target.dataset.heatIp, ips };
  }
  return null;
}

function commitHeatmapSelection(selection) {
  if (!selection) return;
  state.heatmap.selection = selection;
  applyFilters();
  renderFindings(findingsForHeatmapSelection(state.analysis?.detections || []));
  rebuildEventStitching(false);
  renderTopology();
  showToast(`${formatNumber(state.filtered.length)} evidence record${state.filtered.length === 1 ? "" : "s"} selected.`);
}

function clearHeatmapSelection(render = true) {
  state.heatmap.selection = null;
  state.heatmap.drag = null;
  applyFilters();
  renderFindings(state.analysis?.detections || []);
  rebuildEventStitching(false);
  if (render) renderTopology();
}

function renderHeatmapSelectionContext() {
  const selection = state.heatmap.selection;
  els.clearHeatmapSelectionButton.disabled = !selection;
  if (!selection) {
    els.heatmapSelectionLabel.textContent = state.heatmap.mode === "activity" ? "Click a cell or Shift+drag across a row to select evidence" : "Select a cell or endpoint to filter linked evidence";
    return;
  }
  if (selection.type === "activity") {
    els.heatmapSelectionLabel.textContent = `${selection.rowKey}, ${formatDate(selection.start)} through ${formatDate(selection.end)} - ${formatNumber(state.filtered.length)} records`;
  } else if (selection.type === "matrix") {
    els.heatmapSelectionLabel.textContent = `${selection.sourceKey} to ${selection.destinationKey} - ${formatNumber(state.filtered.length)} records`;
  } else {
    const endpoints = selection.ips?.length > 1 ? `${formatNumber(selection.ips.length)} endpoints` : selection.ip;
    els.heatmapSelectionLabel.textContent = `${endpoints} - ${formatNumber(state.filtered.length)} records`;
  }
}

function openHeatmapEvidence(event) {
  const target = event.currentTarget?.matches?.("[data-heat-kind]") ? event.currentTarget : event.target.closest("[data-heat-kind]");
  if (!target) return;
  event.stopPropagation();
  commitHeatmapSelection(selectionFromHeatTarget(target, event.shiftKey));
  activateTab("records");
}

function handleHeatmapWheel(event) {
  if (state.heatmap.mode === "graph") return;
  if (!event.ctrlKey && Math.abs(event.deltaY) < Math.abs(event.deltaX)) return;
  event.preventDefault();
  zoomHeatmap(event.deltaY < 0 ? 1 : -1);
}

function startHeatmapDrag(event) {
  if (state.heatmap.mode === "graph" || event.button !== 0) return;
  const cell = event.target.closest('[data-heat-kind="activity"]');
  if (cell) {
    if (!event.shiftKey) return;
    state.heatmap.drag = {
      type: "brush",
      pointerId: event.pointerId,
      rowKey: cell.dataset.heatRow,
      start: Number(cell.dataset.heatStart),
      end: Number(cell.dataset.heatEnd),
      currentStart: Number(cell.dataset.heatStart),
      currentEnd: Number(cell.dataset.heatEnd),
      startX: event.clientX,
      startY: event.clientY,
      moved: false
    };
    return;
  }
  if (event.target.closest("[data-heat-kind]")) return;
  state.heatmap.drag = {
    type: "pan",
    pointerId: event.pointerId,
    startX: event.clientX,
    startY: event.clientY,
    scrollLeft: els.topologyCanvas.scrollLeft,
    scrollTop: els.topologyCanvas.scrollTop,
    panX: state.heatmap.panX,
    panY: state.heatmap.panY
  };
  els.topologyCanvas.setPointerCapture?.(event.pointerId);
  els.topologyCanvas.classList.add("is-panning");
}

function moveHeatmapDrag(event) {
  const drag = state.heatmap.drag;
  if (!drag || drag.pointerId !== event.pointerId) return;
  if (drag.type === "brush") {
    const target = document.elementFromPoint(event.clientX, event.clientY)?.closest?.('[data-heat-kind="activity"]');
    if (target?.dataset.heatRow !== drag.rowKey) return;
    drag.moved = drag.moved || target.dataset.heatStart !== String(drag.start) || Math.abs(event.clientX - drag.startX) > 4 || Math.abs(event.clientY - drag.startY) > 4;
    drag.currentStart = Number(target.dataset.heatStart);
    drag.currentEnd = Number(target.dataset.heatEnd);
    if (drag.moved) updateBrushPreview();
    return;
  }
  const deltaX = event.clientX - drag.startX;
  const deltaY = event.clientY - drag.startY;
  if (state.heatmap.mode === "matrix") {
    els.topologyCanvas.scrollLeft = drag.scrollLeft - deltaX;
    els.topologyCanvas.scrollTop = drag.scrollTop - deltaY;
  }
}

function endHeatmapDrag(event) {
  const drag = state.heatmap.drag;
  if (!drag || drag.pointerId !== event.pointerId) return;
  state.heatmap.drag = null;
  els.topologyCanvas.classList.remove("is-panning");
  if (drag.type === "brush") {
    if (!drag.moved) return;
    state.heatmap.suppressClickUntil = Date.now() + 250;
    commitHeatmapSelection({
      type: "activity",
      rowKey: drag.rowKey,
      groupBy: state.heatmap.groupBy,
      start: Math.min(drag.start, drag.currentStart),
      end: Math.max(drag.end, drag.currentEnd)
    });
    return;
  }
  if (state.heatmap.mode === "geographic") {
    state.heatmap.panX = Math.max(-1, Math.min(1, drag.panX - (event.clientX - drag.startX) / 450));
    state.heatmap.panY = Math.max(-1, Math.min(1, drag.panY - (event.clientY - drag.startY) / 260));
    renderTopology();
  }
}

function updateBrushPreview() {
  const drag = state.heatmap.drag;
  if (!drag || drag.type !== "brush") return;
  const start = Math.min(drag.start, drag.currentStart);
  const end = Math.max(drag.end, drag.currentEnd);
  els.topologyCanvas.querySelectorAll('[data-heat-kind="activity"]').forEach((cell) => {
    const inRange = cell.dataset.heatRow === drag.rowKey && Number(cell.dataset.heatStart) <= end && Number(cell.dataset.heatEnd) >= start;
    cell.classList.toggle("brush-preview", inRange);
  });
}

function handleHeatmapKeydown(event) {
  const target = event.target.closest?.("[data-heat-kind]");
  if (target && ["Enter", " "].includes(event.key)) {
    event.preventDefault();
    commitHeatmapSelection(selectionFromHeatTarget(target, event.shiftKey));
    return;
  }
  if (event.key === "Escape" && state.heatmap.selection) clearHeatmapSelection();
}

async function exportHeatmapView() {
  if (!state.heatmap.model || state.heatmap.mode === "graph") return setInputMessage("Open a heatmap view before exporting it.");
  if (state.backend.online && !hasRole("admin") && !hasRole("analyst")) return setInputMessage("An analyst or admin role is required to export heatmap evidence.");
  if (enterpriseSettingsValue().governance?.exportApprovalRequired !== false) {
    await exportInvestigationPackage();
    return;
  }
  const payload = buildHeatmapExportModel();
  downloadText(`signalprism-${state.heatmap.mode}-heatmap-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(payload, null, 2), "application/json");
  showToast("Heatmap view and selected evidence exported.");
}

function buildHeatmapExportModel() {
  const model = state.heatmap.model ? JSON.parse(JSON.stringify(state.heatmap.model)) : null;
  if (model?.cells) model.cells = model.cells.map(({ recordIndexes, ...cell }) => cell);
  if (model?.points) model.points = model.points.map(({ recordIndexes, ...point }) => point);
  if (model?.edges) model.edges = model.edges.map(({ recordIndexes, ...edge }) => edge);
  return {
    product: "SignalPrism NDR",
    exportedAt: new Date().toISOString(),
    mode: state.heatmap.mode,
    options: {
      groupBy: state.heatmap.groupBy,
      metric: state.heatmap.metric,
      scale: state.heatmap.scale,
      evidenceFilter: state.heatmap.evidenceFilter,
      replayPercent: Number(els.replayRangeInput.value || 100)
    },
    selection: state.heatmap.selection,
    summary: model,
    evidence: state.filtered.slice(0, 1000).map((record) => ({
      evidenceSource: record.evidenceSource,
      source: record.source,
      destination: record.destination,
      srcPort: record.srcPort,
      dstPort: record.dstPort,
      protocol: record.protocol,
      action: record.action,
      bytes: record.bytes,
      start: record.start
    }))
  };
}

function buildTopologyReplaySnapshot(records, percent = 100) {
  const normalizedPercent = Math.max(0, Math.min(100, Number(percent) || 0));
  const timed = records.filter((record) => Number.isFinite(record.start)).sort((a, b) => a.start - b.start);
  if (!timed.length) {
    return { percent: normalizedPercent, cutoff: Infinity, includedRecords: records, recentRecords: records.slice(-8).reverse() };
  }
  const index = Math.min(timed.length - 1, Math.max(0, Math.floor((timed.length - 1) * (normalizedPercent / 100))));
  const cutoff = normalizedPercent >= 100 ? Infinity : timed[index].start;
  const includedRecords = records.filter((record) => !Number.isFinite(record.start) || record.start <= cutoff);
  return {
    percent: normalizedPercent,
    cutoff,
    includedRecords,
    recentRecords: includedRecords
      .filter((record) => Number.isFinite(record.start))
      .sort((a, b) => b.start - a.start)
      .slice(0, 8)
  };
}

function toggleTopologyReplay() {
  if (state.replayTimer) {
    window.clearInterval(state.replayTimer);
    state.replayTimer = null;
    els.playReplayButton.textContent = "Play";
    return;
  }
  els.playReplayButton.textContent = "Pause";
  state.replayTimer = window.setInterval(() => {
    const next = Number(els.replayRangeInput.value || 0) + 5;
    els.replayRangeInput.value = next >= 100 ? 100 : next;
    renderTopology();
    if (next >= 100) toggleTopologyReplay();
  }, 700);
}

function stepTopologyReplay(delta) {
  const next = Math.max(0, Math.min(100, Number(els.replayRangeInput.value || 100) + delta));
  els.replayRangeInput.value = String(next);
  renderTopology();
}

function updateStatus() {
  const total = state.records.length;
  const eventCount = state.stitching.events.length;
  if (!total && !eventCount) {
    setStatus(state.errors.length ? "No records parsed" : "No log loaded", "warn");
    return;
  }
  const skipped = state.errors.length ? `, ${state.errors.length} skipped` : "";
  const sourceCount = state.evidenceSources.filter((source) => source.records > 0 || source.events > 0).length;
  const sources = sourceCount ? ` from ${formatNumber(sourceCount)} source${sourceCount === 1 ? "" : "s"}` : "";
  setStatus(`${formatNumber(total)} flows, ${formatNumber(eventCount)} normalized events${sources}${skipped}`, "ready");
}

function setStatus(text, className) {
  els.statusPill.className = `status-pill ${className}`;
  els.statusText.textContent = text;
}

async function exportInvestigationPackage() {
  if (!state.analysis) {
    setInputMessage("Analyze evidence before exporting an investigation package.");
    return;
  }
  const cases = await listCaseRecords();
  const workspaces = loadJson(STORAGE_KEYS.workspaces, []);
  const workspace = workspaces.find((item) => item.id === state.activeWorkspaceId) || null;
  let packageBody = buildInvestigationPackageModel({
    analysis: state.analysis,
    records: state.records,
    filtered: state.filtered,
    workspace,
    source: state.fileName,
    evidenceSources: state.evidenceSources,
    sources: loadJson(STORAGE_KEYS.sources, []),
    hunts: loadJson(STORAGE_KEYS.hunts, []),
    cases,
    stitchedIncidents: state.stitching.result,
    heatmapView: state.heatmap.mode === "graph" ? null : buildHeatmapExportModel(),
    analystSummary: els.analystSummary.textContent.trim(),
    aiAnswer: els.aiAnswerPanel.textContent.trim()
  });
  if (backendApi) {
    try {
      packageBody = await backendApi.exportInvestigationPackage(packageBody);
      if (packageBody.pending) {
        await renderExportApprovals();
        showToast("Investigation export submitted for approval.");
        return;
      }
    } catch (error) {
      if (state.backend.online) {
        setInputMessage(`Export blocked by backend policy: ${error.message}`);
        return;
      }
    }
  }
  if (enterpriseSettingsValue().governance?.exportApprovalRequired !== false && !state.backend.online) {
    setInputMessage("Controlled exports require an authenticated backend approval.");
    return;
  }
  const slug = (workspace?.name || state.fileName || "signalprism-investigation").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60);
  downloadText(`${slug || "signalprism-investigation"}-package.json`, JSON.stringify(packageBody, null, 2), "application/json");
  showToast("Investigation package exported.");
}

function buildInvestigationPackageModel({ analysis, records = [], filtered = [], workspace = null, source = "", evidenceSources = [], sources = [], hunts = [], cases = [], stitchedIncidents = null, heatmapView = null, analystSummary = "", aiAnswer = "" }) {
  return {
    product: "SignalPrism NDR",
    exportedAt: new Date().toISOString(),
    workspace: workspace ? packageWorkspace(workspace) : null,
    source,
    evidenceSources,
    summary: {
      records: records.length,
      filteredRecords: filtered.length,
      detections: analysis?.detections?.length || 0,
      observations: analysis?.observations?.length || 0,
      highSeverity: (analysis?.detections || []).filter((detection) => detection.severity === "high").length,
      entities: analysis?.entityRisk?.length || 0,
      bytes: analysis?.totals?.bytes || 0,
      timeRange: analysis?.timeRange || null,
      ruleProfile: analysis?.ruleProfile || "balanced",
      stitchedChains: stitchedIncidents?.chainCount || 0,
      stitchedLinks: stitchedIncidents?.linkCount || 0
    },
    detections: (analysis?.detections || []).map(packageDetection),
    observations: (analysis?.observations || []).map(packageDetection),
    priorityEntities: (analysis?.entityRisk || []).slice(0, 25),
    paths: {
      internal: (analysis?.internalPaths || []).slice(0, 25),
      external: (analysis?.externalPaths || []).slice(0, 25)
    },
    sources,
    hunts,
    cases,
    stitchedIncidents: stitchedIncidents ? packageStitchedIncidents(stitchedIncidents) : null,
    heatmapView,
    analystSummary,
    aiAnswer,
    records: filtered.slice(0, 500).map((record) => ({
      evidenceSource: record.evidenceSource,
      source: record.source,
      destination: record.destination,
      srcPort: record.srcPort,
      dstPort: record.dstPort,
      protocol: record.protocol,
      action: record.action,
      packets: record.packets,
      bytes: record.bytes,
      start: record.start,
      end: record.end,
      interfaceId: record.interfaceId,
      logStatus: record.logStatus
    }))
  };
}

function packageStitchedIncidents(result) {
  return {
    generatedAt: result.generatedAt,
    options: result.options,
    eventCount: result.eventCount,
    sourceCount: result.sourceCount,
    formatCount: result.formatCount,
    sources: result.sources,
    formats: result.formats,
    linkCount: result.linkCount,
    chainCount: result.chainCount,
    linkedEventCount: result.linkedEventCount,
    unlinkedEventCount: result.unlinkedEventCount,
    conflicts: (result.conflicts || []).slice(0, 100),
    gaps: (result.gaps || []).slice(0, 100),
    chains: (result.chains || []).slice(0, 50).map((chain) => ({
      ...chain,
      events: (chain.events || []).slice(0, 200).map(({ raw, ...event }) => event),
      links: (chain.links || []).slice(0, 500)
    }))
  };
}

function packageDetection(detection) {
  return {
    id: detection.id,
    severity: detection.severity,
    confidence: detection.confidence,
    title: detection.title,
    summary: detection.copy,
    tactic: detection.tactic,
    technique: detection.technique,
    entity: detection.entity,
    response: detection.response,
    tags: detection.tags,
    evidence: (detection.records || []).slice(0, 20).map((record) => ({
      evidenceSource: record.evidenceSource,
      source: record.source,
      destination: record.destination,
      srcPort: record.srcPort,
      dstPort: record.dstPort,
      protocol: record.protocol,
      action: record.action,
      bytes: record.bytes,
      start: record.start,
      interfaceId: record.interfaceId
    }))
  };
}

function packageWorkspace(workspace) {
  const { evidenceText, ...metadata } = workspace;
  return metadata;
}

function exportFilteredCsv() {
  if (!state.filtered.length) {
    setInputMessage("There are no filtered records to export.");
    return;
  }
  const headers = ["evidenceSource", "time", "action", "source", "srcport", "destination", "dstport", "protocol", "packets", "bytes", "logStatus", "interfaceId"];
  const lines = [
    headers.join(","),
    ...state.filtered.map((record) =>
      [
        record.evidenceSource || "",
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

async function exportRedactedRecords() {
  if (!state.records.length) {
    setInputMessage("Analyze evidence before exporting redacted records.");
    return;
  }
  const rows = [];
  for (const record of state.records) {
    rows.push({
      time: formatDate(record.start),
      action: record.action,
      source: await redactValue(record.source, "ip"),
      srcport: record.srcPort || "",
      destination: await redactValue(record.destination, "ip"),
      dstport: record.dstPort || "",
      protocol: record.protocol,
      packets: record.packets,
      bytes: record.bytes,
      interfaceId: await redactValue(record.interfaceId, "account"),
      accountId: await redactValue(record.accountId, "account"),
      app: classifyApplication(record)
    });
  }
  downloadText("ndr-redacted-records.json", JSON.stringify(rows, null, 2), "application/json");
  showToast("Redacted evidence exported with session-scoped HMAC pseudonyms.");
}

async function redactValue(value, kind) {
  if (!value || value === "-") return value;
  if (kind === "ip" && els.maskIps.checked) {
    return isPrivateIp(value) || isPublicIp(value) ? `ip-${(await pseudonymizeValue(value)).slice(0, 12)}` : value;
  }
  if (kind === "account" && els.maskAccounts.checked) {
    const matches = [...new Set(String(value).match(/[a-z0-9-]{6,}/gi) || [])];
    let redacted = String(value);
    for (const match of matches) redacted = redacted.replaceAll(match, `id-${(await pseudonymizeValue(match)).slice(0, 12)}`);
    return redacted;
  }
  if (kind === "domain" && els.maskDomains.checked) {
    return `domain-${(await pseudonymizeValue(value)).slice(0, 12)}`;
  }
  return value;
}

async function sha256Text(text) {
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto is required for evidence integrity operations.");
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(text)));
  return bytesToHex(new Uint8Array(digest));
}

async function pseudonymizeValue(value) {
  const key = await pseudonymizationKey();
  const signature = await globalThis.crypto.subtle.sign("HMAC", key, new TextEncoder().encode(String(value)));
  return bytesToHex(new Uint8Array(signature));
}

async function pseudonymizationKey() {
  if (!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) throw new Error("Web Crypto is required for redacted exports.");
  if (pseudonymKeyCache?.scope === activeStorageScope) return pseudonymKeyCache.key;
  const storageKey = `signalprism.pseudonym-key.${activeStorageScope}`;
  let encoded = "";
  try {
    encoded = sessionStorage.getItem(storageKey) || "";
  } catch {
    // Sandboxed browsers may deny session storage; the key remains memory-only.
  }
  let raw;
  if (encoded) {
    raw = Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0));
  } else {
    raw = globalThis.crypto.getRandomValues(new Uint8Array(32));
    try {
      sessionStorage.setItem(storageKey, btoa(String.fromCharCode(...raw)));
    } catch {
      // Memory-only pseudonyms are still safe but will change after a reload.
    }
  }
  const key = await globalThis.crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  pseudonymKeyCache = { scope: activeStorageScope, key };
  return key;
}

function bytesToHex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
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
  downloadBlob(fileName, blob);
}

function downloadBlob(fileName, blob) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function escapeCef(value) {
  return String(value ?? "").replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/=/g, "\\=");
}

function csvValue(value) {
  const text = String(value ?? "").replace(/\r\n?/g, "\n");
  const neutralized = /^[\t ]*[=+\-@]/.test(text) ? `'${text}` : text;
  return /[",\n]/.test(neutralized) ? `"${neutralized.replace(/"/g, "\"\"")}"` : neutralized;
}

function emptyState() {
  return els.emptyStateTemplate.innerHTML;
}

function tagClass(severity) {
  return severity === "critical" || severity === "high" ? "red" : severity === "medium" ? "amber" : "green";
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
    tuneAnalysisForProfile,
    buildAiEvidenceContextModel,
    buildInvestigationPackageModel,
    buildTopologyReplaySnapshot,
    buildOcsfNetworkActivity,
    buildOcsfFindings,
    buildPolicyFindings,
    buildCitedInvestigationAnswer,
    buildDetectionAsCodeBundle,
    buildEntityRiskScores,
    buildEvidenceVaultManifest,
    buildEnterpriseReport,
    buildPlaybookSteps,
    buildReplayTimeline,
    buildSourceHealth,
    mergeParsedEvidence,
    csvValue,
    parseThreatIntel,
    scoreDetectionRuleQuality,
    SAMPLE_LOG
  };
}
