const PERIOD_MS = {
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
  "90d": 90 * 24 * 60 * 60 * 1000
};

const SENSITIVE_PORTS = new Set([21, 22, 23, 25, 110, 135, 139, 143, 389, 445, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017]);

export function buildTopFindings({
  detections = [],
  records = [],
  assets = {},
  threatIntel = {},
  cases = [],
  filters = {},
  limit = 10,
  now = Date.now()
} = {}) {
  const period = reportingPeriod(records, filters.period || "evidence", now);
  const assetIndex = buildAssetIndex(assets);
  const intelIndex = buildIntelIndex(threatIntel);
  const groups = new Map();

  detections.forEach((detection, detectionIndex) => {
    if (!matchesSeverity(detection, filters.severity)) return;
    const detectionRecords = detection.records?.length ? detection.records : recordsForEntity(records, detection.entity);
    const currentRecords = detectionRecords.filter((record) => recordInWindow(record, period.start, period.end) && recordMatchesFilters(record, filters, assetIndex));
    const previousRecords = period.previousStart === null
      ? []
      : detectionRecords.filter((record) => recordInPreviousWindow(record, period.previousStart, period.start) && recordMatchesFilters(record, filters, assetIndex));
    if (!currentRecords.length && detectionRecords.length) return;
    if (!currentRecords.length && !detectionRecords.length && !allowsUntimedFinding(filters)) return;

    const key = normalizedFindingKey(detection);
    const group = groups.get(key) || {
      key,
      title: detection.title || "Untitled finding",
      tactic: detection.tactic || "Unmapped",
      technique: detection.technique || "Unmapped",
      severity: detection.severity || "low",
      confidence: 0,
      copy: detection.copy || "",
      response: [],
      tags: new Set(),
      detectionIds: new Set(),
      records: [],
      previousRecords: [],
      recordKeys: new Set(),
      previousRecordKeys: new Set(),
      entities: new Set(),
      sourceNames: new Set()
    };
    group.severity = higherSeverity(group.severity, detection.severity);
    group.confidence = Math.max(group.confidence, normalizeConfidence(detection.confidence));
    if (detection.id) group.detectionIds.add(detection.id);
    else group.detectionIds.add(`finding-${detectionIndex + 1}`);
    if (detection.entity) group.entities.add(detection.entity);
    (detection.response || []).forEach((step) => group.response.push(step));
    (detection.tags || []).forEach((tag) => group.tags.add(tag));
    currentRecords.forEach((record) => {
      const key = recordKey(record);
      if (!group.recordKeys.has(key)) {
        group.records.push(record);
        group.recordKeys.add(key);
      }
      if (record.source && record.source !== "-") group.entities.add(record.source);
      if (record.destination && record.destination !== "-") group.entities.add(record.destination);
      if (record.evidenceSource) group.sourceNames.add(record.evidenceSource);
    });
    previousRecords.forEach((record) => {
      const key = recordKey(record);
      if (!group.previousRecordKeys.has(key)) {
        group.previousRecords.push(record);
        group.previousRecordKeys.add(key);
      }
    });
    groups.set(key, group);
  });

  return [...groups.values()]
    .map((group) => scoreFinding(group, { assetIndex, intelIndex, cases, period }))
    .sort((a, b) => b.urgency - a.urgency || severityRank(b.severity) - severityRank(a.severity) || b.lastSeenMs - a.lastSeenMs)
    .slice(0, Math.max(1, Math.min(50, Number(limit) || 10)))
    .map((finding, index) => ({ ...finding, rank: index + 1 }));
}

export function buildExecutiveBrief({
  detections = [],
  records = [],
  assets = {},
  threatIntel = {},
  cases = [],
  sourceHealth = [],
  activeCampaigns = null,
  responseActions = [],
  period = "30d",
  previousReport = null,
  tenant = {},
  branding = {},
  classification = "Confidential",
  generatedBy = "SignalPrism",
  generatedAt = new Date().toISOString()
} = {}) {
  const topFindings = buildTopFindings({ detections, records, assets, threatIntel, cases, filters: { period }, limit: 10, now: Date.parse(generatedAt) || Date.now() });
  const window = reportingPeriod(records, period, Date.parse(generatedAt) || Date.now());
  const previousMetrics = new Map((previousReport?.metrics || []).map((metric) => [metric.id, metric.current]));
  const openCases = cases.filter((item) => !isClosedCase(item));
  const highRiskFindings = topFindings.filter((finding) => finding.urgency >= 70).length;
  const criticalAssets = new Set(topFindings.flatMap((finding) => finding.assets.filter((asset) => ["critical", "high"].includes(String(asset.criticality || "").toLowerCase())).map((asset) => asset.key)));
  const healthySources = sourceHealth.filter((item) => item.tone === "ok" || item.status === "healthy").length;
  const coverage = sourceHealth.length ? Math.round(healthySources / sourceHealth.length * 100) : null;
  const currentValues = {
    highRiskFindings,
    criticalAssets: criticalAssets.size,
    openCases: openCases.length,
    overdueCases: openCases.filter((item) => caseSlaState(item, generatedAt).overdue).length,
    telemetryCoverage: coverage,
    activeCampaigns: Array.isArray(activeCampaigns) ? activeCampaigns.filter((item) => !["closed", "resolved"].includes(String(item.status || "active").toLowerCase())).length : null,
    pendingResponse: responseActions.filter((item) => ["requested", "pending", "approved"].includes(String(item.status || "").toLowerCase())).length
  };
  const inferredPrevious = {
    highRiskFindings: topFindings.filter((finding) => finding.previousCount > 0 && finding.urgency >= 70).length,
    criticalAssets: null,
    openCases: null,
    overdueCases: null,
    telemetryCoverage: null,
    activeCampaigns: null,
    pendingResponse: null
  };
  const metrics = [
    metric("highRiskFindings", "High-urgency findings", currentValues, inferredPrevious, previousMetrics, "Measures evidence clusters scoring 70 or higher."),
    metric("criticalAssets", "Critical assets affected", currentValues, inferredPrevious, previousMetrics, "Counts known high or critical business assets; unknown context is excluded."),
    metric("openCases", "Open cases", currentValues, inferredPrevious, previousMetrics, "Tracks active investigation workload."),
    metric("overdueCases", "Overdue case SLAs", currentValues, inferredPrevious, previousMetrics, "Highlights open cases beyond severity-based response targets."),
    metric("telemetryCoverage", "Healthy source coverage", currentValues, inferredPrevious, previousMetrics, "Shows the percentage of configured sources reporting healthy." , "%"),
    metric("activeCampaigns", "Active campaigns", currentValues, inferredPrevious, previousMetrics, "Counts unresolved multi-event campaigns."),
    metric("pendingResponse", "Pending response actions", currentValues, inferredPrevious, previousMetrics, "Counts response actions awaiting execution or verification.")
  ];
  const riskScore = topFindings[0]?.urgency || 0;
  const posture = riskPosture(riskScore);
  const knownAssetFindings = topFindings.filter((finding) => finding.assets.length).length;
  const caveats = [];
  if (!records.length) caveats.push("No network records were available for this report.");
  if (topFindings.length && knownAssetFindings < topFindings.length) caveats.push(`${topFindings.length - knownAssetFindings} ranked finding${topFindings.length - knownAssetFindings === 1 ? " lacks" : "s lack"} matched asset ownership or criticality.`);
  if (!sourceHealth.length) caveats.push("Managed-source health was not available, so telemetry coverage is Unknown.");
  if (!previousReport && period === "evidence") caveats.push("The evidence window has no independent prior-period baseline.");
  const narrative = buildNarrative({ posture, riskScore, topFindings, metrics, openCases, caveats });
  const report = {
    id: `executive-brief-${Date.parse(generatedAt) || Date.now()}`,
    schemaVersion: 1,
    title: `${branding.reportTitle || "Network Detection and Response Executive Brief"}`,
    organization: branding.organization || tenant.name || tenant.tenantId || "Current tenant",
    logoText: branding.logoText || "SignalPrism NDR",
    classification: normalizeClassification(classification),
    tenantId: tenant.tenantId || "default",
    generatedAt,
    generatedBy,
    period: { key: period, label: periodLabel(period), start: isoOrNull(window.start), end: isoOrNull(window.end) },
    posture: { label: posture, score: riskScore, delta: previousReport ? riskScore - Number(previousReport.posture?.score || 0) : null },
    narrative,
    metrics,
    findings: topFindings.map(publicFinding),
    decisions: topFindings.slice(0, 3).map((finding, index) => ({ ref: `D${index + 1}`, findingRef: `F${finding.rank}`, text: finding.response[0] || `Validate ownership and disposition for ${finding.title}.` })),
    caveats,
    evidence: {
      recordCount: records.length,
      detectionCount: detections.length,
      caseCount: cases.length,
      sourceCount: sourceHealth.length,
      assetContextCoverage: topFindings.length ? Math.round(knownAssetFindings / topFindings.length * 100) : null
    }
  };
  report.integrity = { canonicalVersion: 1, contentFingerprint: stableHash(JSON.stringify(report)) };
  return report;
}

export function executiveReportCsv(report = {}) {
  const rows = [
    ["SignalPrism Executive Brief"],
    ["Organization", report.organization || ""],
    ["Classification", report.classification || ""],
    ["Period", report.period?.label || ""],
    ["Generated", report.generatedAt || ""],
    [],
    ["Executive metrics"],
    ["Metric", "Current", "Previous", "Change", "Interpretation"]
  ];
  (report.metrics || []).forEach((metricItem) => rows.push([
    metricItem.label,
    displayMetricValue(metricItem.current, metricItem.unit),
    displayMetricValue(metricItem.previous, metricItem.unit),
    metricItem.delta === null ? "Unknown" : `${metricItem.delta > 0 ? "+" : ""}${metricItem.delta}${metricItem.unit || ""}`,
    metricItem.interpretation
  ]));
  rows.push([], ["Top findings"], ["Rank", "Finding", "Urgency", "Severity", "Trend", "Assets", "Blast radius", "Confidence", "Owner", "Status", "Last seen"]);
  (report.findings || []).forEach((finding) => rows.push([
    finding.rank, finding.title, finding.urgency, finding.severity, finding.trend, finding.assets.map((asset) => asset.label || asset.key).join("; "),
    finding.blastRadius, `${Math.round(finding.confidence * 100)}%`, finding.owner, finding.status, finding.lastSeen
  ]));
  rows.push([], ["Caveats"]);
  (report.caveats || []).forEach((caveat) => rows.push([caveat]));
  return rows.map((row) => row.map(csvCell).join(",")).join("\n") + "\n";
}

export function validateReportSchedule(input = {}, tenantUsers = []) {
  const name = String(input.name || "").trim();
  if (name.length < 3 || name.length > 80) throw new Error("Schedule name must be between 3 and 80 characters.");
  const frequency = ["weekly", "monthly"].includes(input.frequency) ? input.frequency : "weekly";
  const format = ["pdf", "csv", "json"].includes(input.format) ? input.format : "pdf";
  const recipients = [...new Set(String(input.recipients || "").split(/[;,]/).map((value) => value.trim().toLowerCase()).filter(Boolean))];
  if (!recipients.length) throw new Error("Add at least one tenant recipient.");
  if (recipients.some((email) => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) throw new Error("Every recipient must be a valid email address.");
  const activeEmails = new Set(tenantUsers.filter((user) => String(user.status || "active").toLowerCase() === "active").map((user) => String(user.email || "").toLowerCase()));
  if (activeEmails.size) {
    const external = recipients.filter((email) => !activeEmails.has(email));
    if (external.length) throw new Error(`Recipients must be active tenant users: ${external.join(", ")}`);
  }
  const now = input.now ? new Date(input.now) : new Date();
  const schedule = {
    id: input.id || `report-schedule-${now.getTime()}`,
    name,
    frequency,
    format,
    recipients,
    period: ["7d", "30d", "90d"].includes(input.period) ? input.period : frequency === "monthly" ? "30d" : "7d",
    classification: normalizeClassification(input.classification),
    destination: "tenant-inbox",
    status: input.status === "paused" ? "paused" : "active",
    createdAt: input.createdAt || now.toISOString(),
    updatedAt: now.toISOString(),
    lastRunAt: input.lastRunAt || null,
    nextRunAt: input.nextRunAt || nextScheduleRun(now, frequency).toISOString()
  };
  return schedule;
}

export function advanceReportSchedule(schedule, from = new Date()) {
  const value = new Date(from);
  return { ...schedule, lastRunAt: value.toISOString(), nextRunAt: nextScheduleRun(value, schedule.frequency).toISOString(), updatedAt: value.toISOString() };
}

function scoreFinding(group, { assetIndex, intelIndex, cases, period }) {
  const entities = [...group.entities];
  const matchedAssets = uniqueBy(entities.flatMap((entity) => assetIndex.get(String(entity).toLowerCase()) || []), (asset) => asset.key);
  const matchedIntel = entities.filter((entity) => intelIndex.has(String(entity).toLowerCase()));
  const linkedCases = cases.filter((caseRecord) => caseMatchesFinding(caseRecord, group));
  const openCases = linkedCases.filter((caseRecord) => !isClosedCase(caseRecord));
  const criticality = highestCriticality(matchedAssets);
  const exposure = group.records.some((record) => isPublicPrivateSensitive(record)) || /public|external/i.test(`${group.title} ${group.tags.size ? [...group.tags].join(" ") : ""}`);
  const confidence = Math.max(0, Math.min(1, group.confidence));
  const velocity = velocityScore(group.records, period);
  const breadth = Math.min(10, Math.max(0, (new Set(entities).size - 1) * 2));
  const caseFactor = Math.min(5, openCases.reduce((total, item) => total + (caseSlaState(item).overdue ? 3 : 0) + (!item.assignee ? 2 : 0), 0));
  const factors = [
    factor("Severity", severityPoints(group.severity), 25, group.severity),
    factor("Confidence", Math.round(confidence * 15), 15, `${Math.round(confidence * 100)}%`),
    factor("Asset criticality", criticalityScore(criticality), 15, criticality || "Unknown"),
    factor("Exposure", exposure ? 10 : 0, 10, exposure ? "Public or sensitive path" : "Not observed"),
    factor("Breadth", breadth, 10, `${entities.length} entities`),
    factor("Velocity", velocity, 10, `${group.records.length} current events`),
    factor("Threat intelligence", matchedIntel.length ? 10 : 0, 10, matchedIntel.length ? `${matchedIntel.length} matches` : "No match"),
    factor("Case and SLA", caseFactor, 5, openCases.length ? `${openCases.length} open case${openCases.length === 1 ? "" : "s"}` : "No linked case")
  ];
  const urgency = Math.max(0, Math.min(100, factors.reduce((sum, item) => sum + item.score, 0)));
  const currentCount = group.records.length || 1;
  const previousCount = group.previousRecords.length;
  const trend = previousCount === 0 ? "new" : currentCount > previousCount * 1.15 ? "up" : currentCount < previousCount * 0.85 ? "down" : "flat";
  const lastSeenMs = Math.max(0, ...group.records.map(recordTimestamp).filter(Number.isFinite));
  const owner = openCases.find((item) => item.assignee)?.assignee || matchedAssets.find((asset) => asset.owner)?.owner || "Unassigned";
  return {
    id: stableHash(group.key),
    title: group.title,
    tactic: group.tactic,
    technique: group.technique,
    severity: group.severity,
    urgency,
    urgencyLabel: riskPosture(urgency),
    confidence,
    copy: group.copy,
    response: [...new Set(group.response)].slice(0, 5),
    tags: [...group.tags],
    detectionIds: [...group.detectionIds],
    records: group.records,
    evidenceKeys: group.records.map(recordKey),
    entities,
    assets: matchedAssets,
    threatIntelMatches: matchedIntel,
    sourceNames: [...group.sourceNames],
    environment: uniqueValues(matchedAssets.map((asset) => asset.environment)).join(", ") || "Unknown",
    owner,
    status: openCases[0]?.status || (linkedCases.length ? "Closed" : "Unassigned"),
    caseIds: linkedCases.map((item) => item.id),
    blastRadius: Math.max(1, new Set(entities).size),
    currentCount,
    previousCount,
    trend,
    trendDelta: currentCount - previousCount,
    lastSeenMs,
    lastSeen: lastSeenMs ? new Date(lastSeenMs).toISOString() : "Unknown",
    factors
  };
}

function publicFinding(finding) {
  const { records, evidenceKeys, lastSeenMs, ...rest } = finding;
  return rest;
}

function metric(id, label, currentValues, inferredPrevious, previousMetrics, interpretation, unit = "") {
  const current = currentValues[id];
  const previous = previousMetrics.has(id) ? previousMetrics.get(id) : inferredPrevious[id];
  const delta = Number.isFinite(current) && Number.isFinite(previous) ? current - previous : null;
  return { id, label, current, previous: Number.isFinite(previous) ? previous : null, delta, unit, interpretation };
}

function buildNarrative({ posture, riskScore, topFindings, metrics, openCases, caveats }) {
  if (!topFindings.length) return `Risk posture is ${posture} (${riskScore}/100). No ranked findings were produced from the current evidence [M1]. ${caveats[0] || "Continue monitoring telemetry coverage."}`;
  const top = topFindings[0];
  const highMetric = metrics.find((item) => item.id === "highRiskFindings");
  const coverageMetric = metrics.find((item) => item.id === "telemetryCoverage");
  const coverageText = coverageMetric?.current === null ? "Telemetry coverage is Unknown" : `Healthy telemetry coverage is ${coverageMetric.current}%`;
  return `Risk posture is ${posture} (${riskScore}/100), led by ${top.title} on ${top.entities[0] || "an observed entity"} [F1]. ${highMetric.current} high-urgency finding${highMetric.current === 1 ? " is" : "s are"} active [M1], with ${openCases.length} open case${openCases.length === 1 ? "" : "s"} [M3]. ${coverageText} [M5]. ${caveats[0] || "No material reporting caveat was identified."}`;
}

function reportingPeriod(records, key, now) {
  const times = records.map(recordTimestamp).filter((value) => Number.isFinite(value) && value > 0);
  const latest = times.length ? Math.max(...times) : now;
  const earliest = times.length ? Math.min(...times) : latest;
  if (!PERIOD_MS[key]) return { key: "evidence", start: earliest, end: latest, previousStart: null };
  const duration = PERIOD_MS[key];
  return { key, start: latest - duration, end: latest, previousStart: latest - duration * 2 };
}

function recordMatchesFilters(record, filters, assetIndex) {
  if (filters.source && filters.source !== "all" && ![record.evidenceSourceId, record.evidenceSource].includes(filters.source)) return false;
  if (filters.environment && filters.environment !== "all") {
    const contexts = [record.source, record.destination, record.interfaceId].flatMap((value) => assetIndex.get(String(value || "").toLowerCase()) || []);
    if (!contexts.some((asset) => String(asset.environment || "").toLowerCase() === String(filters.environment).toLowerCase())) return false;
  }
  return true;
}

function allowsUntimedFinding(filters) {
  return (!filters.source || filters.source === "all") && (!filters.environment || filters.environment === "all");
}

function recordInWindow(record, start, end) {
  const timestamp = recordTimestamp(record);
  return Number.isFinite(timestamp) && timestamp >= start && timestamp <= end;
}

function recordInPreviousWindow(record, start, end) {
  const timestamp = recordTimestamp(record);
  return Number.isFinite(timestamp) && timestamp >= start && timestamp < end;
}

function recordTimestamp(record) {
  const value = record?.start ?? record?.timestamp ?? record?.eventTime ?? record?.createdAt ?? record?.end;
  if (typeof value === "number") return value < 10_000_000_000 ? value * 1000 : value;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function recordKey(record) {
  return [record?.evidenceSourceId, record?.start, record?.source, record?.destination, record?.srcPort, record?.dstPort, record?.protocol].join("|");
}

function recordsForEntity(records, entity) {
  if (!entity || ["environment", "collector", "input source"].includes(String(entity).toLowerCase())) return records;
  return records.filter((record) => [record.source, record.destination, record.interfaceId].includes(entity));
}

function buildAssetIndex(assets) {
  const index = new Map();
  const values = Array.isArray(assets) ? assets : Object.entries(assets || {}).map(([key, value]) => ({ key, ...(value || {}) }));
  values.forEach((asset, indexValue) => {
    const normalized = { key: asset.key || asset.asset || asset.ip || asset.eni || `asset-${indexValue + 1}`, label: asset.asset || asset.name || asset.instance || asset.ip || asset.eni || asset.key || "Asset", ...asset };
    [normalized.key, normalized.ip, normalized.eni, normalized.instance, normalized.asset, normalized.account].filter(Boolean).forEach((key) => {
      const normalizedKey = String(key).toLowerCase();
      index.set(normalizedKey, [...(index.get(normalizedKey) || []), normalized]);
    });
  });
  return index;
}

function buildIntelIndex(threatIntel) {
  const index = new Map();
  const values = Array.isArray(threatIntel) ? threatIntel : Object.entries(threatIntel || {}).map(([value, context]) => ({ value, ...(context || {}) }));
  values.forEach((item) => {
    const value = String(item.value || item.indicator || item.ip || item.domain || "").toLowerCase();
    if (value) index.set(value, item);
  });
  return index;
}

function caseMatchesFinding(caseRecord, group) {
  const detectionIds = group.detectionIds;
  const linked = [caseRecord.detectionId, caseRecord.linkedDetectionId, caseRecord.linkedDetection, ...(caseRecord.detectionIds || [])].filter(Boolean);
  return linked.some((id) => detectionIds.has(id));
}

function caseSlaState(caseRecord, nowValue = new Date().toISOString()) {
  const severity = String(caseRecord.severity || "medium").toLowerCase();
  const hours = { critical: 1, high: 4, medium: 24, low: 72 }[severity] || 24;
  const opened = Date.parse(caseRecord.createdAt || caseRecord.updatedAt || nowValue);
  return { overdue: !isClosedCase(caseRecord) && Number.isFinite(opened) && Date.parse(nowValue) - opened > hours * 60 * 60 * 1000, hours };
}

function isClosedCase(caseRecord) {
  return ["closed", "resolved"].includes(String(caseRecord.status || "").toLowerCase());
}

function isPublicPrivateSensitive(record) {
  return record?.action === "ACCEPT" && SENSITIVE_PORTS.has(Number(record.dstPort)) && isPublicIp(record.source) && isPrivateIp(record.destination);
}

function isPrivateIp(value) {
  const parts = String(value || "").split(".").map(Number);
  return parts.length === 4 && (parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168));
}

function isPublicIp(value) {
  const parts = String(value || "").split(".").map(Number);
  return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) && !isPrivateIp(value) && parts[0] !== 127 && parts[0] !== 0 && !(parts[0] === 169 && parts[1] === 254);
}

function velocityScore(records, period) {
  if (!records.length) return 0;
  const durationHours = Math.max(1, (period.end - period.start) / (60 * 60 * 1000));
  const perHour = records.length / durationHours;
  return Math.min(10, Math.round(Math.log2(1 + perHour * 4) * 2.5));
}

function highestCriticality(assets) {
  return assets.map((asset) => String(asset.criticality || "").toLowerCase()).sort((a, b) => criticalityScore(b) - criticalityScore(a))[0] || "";
}

function criticalityScore(value) {
  return { critical: 15, high: 13, medium: 8, low: 3 }[String(value || "").toLowerCase()] || 0;
}

function severityPoints(value) {
  return { critical: 25, high: 22, medium: 14, low: 7 }[String(value || "").toLowerCase()] || 0;
}

function severityRank(value) {
  return { critical: 4, high: 3, medium: 2, low: 1 }[String(value || "").toLowerCase()] || 0;
}

function higherSeverity(a, b) {
  return severityRank(b) > severityRank(a) ? b : a;
}

function matchesSeverity(detection, filter) {
  return !filter || filter === "all" || String(detection.severity || "low").toLowerCase() === String(filter).toLowerCase();
}

function normalizedFindingKey(detection) {
  return [detection.title, detection.tactic, detection.technique].map((value) => String(value || "").trim().toLowerCase()).join("|");
}

function normalizeConfidence(value) {
  const number = Number(value || 0);
  return Math.max(0, Math.min(1, number > 1 ? number / 100 : number));
}

function factor(label, score, maximum, evidence) {
  return { label, score, maximum, evidence };
}

function riskPosture(score) {
  if (score >= 85) return "Critical";
  if (score >= 70) return "High";
  if (score >= 45) return "Guarded";
  return "Low";
}

function normalizeClassification(value) {
  const normalized = String(value || "Confidential").trim();
  return ["Public", "Internal", "Confidential", "Restricted"].includes(normalized) ? normalized : "Confidential";
}

function periodLabel(value) {
  return { evidence: "Current evidence", "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", "90d": "Last 90 days" }[value] || "Current evidence";
}

function nextScheduleRun(from, frequency) {
  const next = new Date(from);
  next.setUTCHours(12, 0, 0, 0);
  if (frequency === "monthly") {
    next.setUTCMonth(next.getUTCMonth() + 1, 1);
  } else {
    const days = (8 - next.getUTCDay()) % 7 || 7;
    next.setUTCDate(next.getUTCDate() + days);
  }
  return next;
}

function displayMetricValue(value, unit = "") {
  return value === null || value === undefined ? "Unknown" : `${value}${unit}`;
}

function csvCell(value) {
  const text = String(value ?? "");
  const safe = /^[\t ]*[=+\-@]/.test(text) ? `'${text}` : text;
  return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

function isoOrNull(value) {
  return Number.isFinite(value) && value > 0 ? new Date(value).toISOString() : null;
}

function uniqueBy(values, keyFn) {
  const seen = new Set();
  return values.filter((value) => {
    const key = keyFn(value);
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function uniqueValues(values) {
  return [...new Set(values.filter(Boolean))];
}

function stableHash(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `exec-${(hash >>> 0).toString(16).padStart(8, "0")}`;
}
