import { createHash } from "node:crypto";

export const OCSF_PROFILES = Object.freeze({
  "native-current": {
    id: "native-current",
    label: "Native OCSF 1.8",
    version: "1.8.0",
    destination: "native",
    compression: "zstd",
    constraints: []
  },
  "security-lake-1.3": {
    id: "security-lake-1.3",
    label: "Amazon Security Lake OCSF 1.3",
    version: "1.3.0",
    destination: "amazon-security-lake",
    compression: "zstd",
    constraints: ["one-event-class-per-source", "assigned-source-prefix", "time-ordered-records", "five-minute-or-size-aware-delivery"]
  },
  "legacy-1.4": {
    id: "legacy-1.4",
    label: "Legacy SignalPrism OCSF 1.4",
    version: "1.4.0",
    destination: "legacy",
    compression: "snappy",
    constraints: ["migration-only"]
  }
});

export function resolveOcsfProfile(value = "native-current") {
  const key = String(value || "native-current").toLowerCase();
  const profile = OCSF_PROFILES[key];
  if (!profile) throw new Error(`Unsupported OCSF profile: ${key}`);
  return profile;
}

export function buildAdvancedOperations({ events = [], findings = [], campaigns = [], sources = [], cases = [], tasks = [], sensors = [], previousModels = [] } = {}, options = {}) {
  const now = Date.parse(options.now || new Date().toISOString());
  const entityGraph = buildEntityGraph(events, findings, { now });
  const behavior = buildSeasonalBehaviorModels(events, previousModels, { now });
  const encryptedTraffic = analyzeEncryptedTraffic(events);
  const protocolAnalytics = analyzeProtocolTraffic(events);
  const sourceHealth = buildSourceHealth(sources, sensors, { now });
  const urgentFindings = scoreAttackUrgency(findings, campaigns, entityGraph, { now });
  const exposurePaths = buildExposurePaths(entityGraph, findings, options.exposureContext || {});
  const dataEconomics = estimateTelemetryEconomics(events, options.pipelinePolicy || {});
  const slaBreaches = tasks.filter((task) => !["done", "closed"].includes(String(task.status || "").toLowerCase()) && Date.parse(task.dueAt || 0) < now);
  return {
    generatedAt: new Date(now).toISOString(),
    metrics: {
      urgentSignals: urgentFindings.filter((item) => item.urgency >= 70).length,
      activeCampaigns: campaigns.filter((item) => !["closed", "resolved"].includes(String(item.status || "").toLowerCase())).length,
      unhealthySources: sourceHealth.filter((item) => item.state !== "healthy").length,
      openCases: cases.filter((item) => !["closed", "resolved"].includes(String(item.status || "").toLowerCase())).length,
      slaBreaches: slaBreaches.length,
      entityCount: entityGraph.nodes.length,
      estimatedDailyCostUsd: dataEconomics.estimatedDailyCostUsd
    },
    urgentFindings,
    sourceHealth,
    entityGraph,
    behavior,
    encryptedTraffic,
    protocolAnalytics,
    exposurePaths,
    dataEconomics,
    slaBreaches: slaBreaches.slice(0, 20)
  };
}

export function buildSourceHealth(sources = [], sensors = [], { now = Date.now() } = {}) {
  const all = [
    ...sources.map((source) => ({ ...source, kind: "source" })),
    ...sensors.map((sensor) => ({ ...sensor, kind: "sensor" }))
  ];
  return all.map((item) => {
    const heartbeatAt = item.lastHeartbeatAt || item.lastSuccessAt || item.lastRunAt || item.updatedAt || item.createdAt;
    const ageMinutes = heartbeatAt ? Math.max(0, (now - Date.parse(heartbeatAt)) / 60000) : Infinity;
    const expectedMinutes = Math.max(1, Number(item.expectedIntervalMinutes || item.intervalMinutes || 15));
    const lagSeconds = Math.max(0, Number(item.lagSeconds || item.deliveryLagSeconds || 0));
    const errorRate = clamp(Number(item.errorRate || item.failedPercent || 0), 0, 100);
    const coverage = clamp(Number(item.coveragePercent ?? 100), 0, 100);
    let state = "healthy";
    const reasons = [];
    if (item.enabled === false || item.status === "disabled") {
      state = "disabled";
      reasons.push("Collection is disabled");
    } else {
      if (!Number.isFinite(ageMinutes) || ageMinutes > expectedMinutes * 4) reasons.push("Heartbeat is stale");
      if (lagSeconds > expectedMinutes * 120) reasons.push("Delivery lag exceeds two collection intervals");
      if (errorRate >= 10) reasons.push("Error rate is elevated");
      if (coverage < 90) reasons.push("Expected telemetry coverage is incomplete");
      if (reasons.length) state = reasons.some((reason) => reason.includes("stale") || reason.includes("disabled")) ? "critical" : "degraded";
    }
    return {
      id: String(item.id || item.name || `health-${all.indexOf(item)}`),
      name: String(item.name || item.id || "Unnamed telemetry source"),
      kind: item.kind,
      state,
      reasons,
      ageMinutes: Number.isFinite(ageMinutes) ? Math.round(ageMinutes) : null,
      lagSeconds: Math.round(lagSeconds),
      errorRate: round(errorRate, 1),
      coveragePercent: round(coverage, 1),
      region: item.region || "global",
      owner: item.ownerName || item.owner || "Unassigned",
      lastHeartbeatAt: heartbeatAt || null
    };
  }).sort((a, b) => healthRank(a.state) - healthRank(b.state) || b.lagSeconds - a.lagSeconds);
}

export function buildEntityGraph(events = [], findings = [], { now = Date.now(), maxNodes = 2000, maxEdges = 5000 } = {}) {
  const nodes = new Map();
  const edges = new Map();
  const addNode = (value, type, event) => {
    if (!value || nodes.size >= maxNodes) return null;
    const id = `${type}:${String(value).toLowerCase()}`;
    const current = nodes.get(id) || { id, value: String(value), type, firstSeen: event.timestamp, lastSeen: event.timestamp, observations: 0, risk: 0, attributes: {} };
    current.observations += 1;
    current.firstSeen = earlier(current.firstSeen, event.timestamp);
    current.lastSeen = later(current.lastSeen, event.timestamp);
    current.risk = Math.max(current.risk, severityScore(event.severity));
    current.attributes = { ...current.attributes, region: event.region || current.attributes.region, accountId: event.accountId || current.attributes.accountId, workload: event.workload || current.attributes.workload };
    nodes.set(id, current);
    return id;
  };
  for (const event of events) {
    const source = addNode(event.sourceIp, "ip", event);
    const destination = addNode(event.destinationIp, "ip", event);
    const identity = addNode(event.identity || event.userName, "identity", event);
    const workload = addNode(event.workload || event.resource, "workload", event);
    const application = addNode(event.application || event.sni || event.query, "application", event);
    [[source, destination, "communicated"], [identity, source || workload, "used"], [workload, destination, "connected"], [source, application, "accessed"]].forEach(([from, to, relation]) => {
      if (!from || !to || from === to || edges.size >= maxEdges) return;
      const id = `${from}|${relation}|${to}`;
      const current = edges.get(id) || { id, from, to, relation, firstSeen: event.timestamp, lastSeen: event.timestamp, observations: 0, bytes: 0, ports: [], protocols: [], communityIds: [] };
      current.observations += 1;
      current.bytes += Math.max(0, Number(event.bytes || 0));
      current.firstSeen = earlier(current.firstSeen, event.timestamp);
      current.lastSeen = later(current.lastSeen, event.timestamp);
      current.ports = uniqueLimited(current.ports, event.destinationPort, 12);
      current.protocols = uniqueLimited(current.protocols, event.protocol, 8);
      const communityId = event.communityId || communityIdV1(event);
      current.communityIds = uniqueLimited(current.communityIds, communityId, 8);
      edges.set(id, current);
    });
  }
  for (const finding of findings) {
    for (const value of finding.entities || [finding.entity].filter(Boolean)) {
      const node = [...nodes.values()].find((item) => item.value === String(value));
      if (node) node.risk = Math.max(node.risk, Number(finding.score || severityScore(finding.severity)));
    }
  }
  return {
    generatedAt: new Date(now).toISOString(),
    nodes: [...nodes.values()].sort((a, b) => b.risk - a.risk || b.observations - a.observations),
    edges: [...edges.values()].sort((a, b) => Date.parse(a.lastSeen || 0) - Date.parse(b.lastSeen || 0)),
    timeline: [...new Set(events.map((event) => event.timestamp).filter(Boolean))].sort().slice(-500)
  };
}

export function buildSeasonalBehaviorModels(events = [], previousModels = [], { now = Date.now() } = {}) {
  const groups = new Map();
  for (const event of events) {
    const entity = String(event.identity || event.workload || event.sourceIp || "unknown");
    const timestamp = Date.parse(event.timestamp || 0);
    if (!Number.isFinite(timestamp)) continue;
    const date = new Date(timestamp);
    const season = `${date.getUTCDay()}-${date.getUTCHours()}`;
    const peerGroup = String(event.peerGroup || event.namespace || event.accountId || event.region || "global");
    const key = `${entity}|${peerGroup}|${season}`;
    const bucket = groups.get(key) || { entity, peerGroup, season, values: [], destinations: new Set(), ports: new Set(), samples: 0 };
    bucket.values.push(Math.max(0, Number(event.bytes || 0)));
    if (event.destinationIp) bucket.destinations.add(String(event.destinationIp));
    if (event.destinationPort) bucket.ports.add(Number(event.destinationPort));
    bucket.samples += 1;
    groups.set(key, bucket);
  }
  const previous = new Map(previousModels.map((model) => [model.id, model]));
  const models = [...groups.values()].map((bucket) => {
    const values = bucket.values.sort((a, b) => a - b);
    const medianBytes = median(values);
    const madBytes = median(values.map((value) => Math.abs(value - medianBytes)).sort((a, b) => a - b));
    const id = `seasonal-${hash(`${bucket.entity}|${bucket.peerGroup}|${bucket.season}`).slice(0, 16)}`;
    const old = previous.get(id);
    const driftPercent = old?.medianBytes ? Math.abs(medianBytes - old.medianBytes) / Math.max(1, old.medianBytes) * 100 : 0;
    return {
      id,
      entity: bucket.entity,
      peerGroup: bucket.peerGroup,
      season: bucket.season,
      sampleCount: bucket.samples,
      medianBytes: Math.round(medianBytes),
      madBytes: Math.round(madBytes),
      distinctDestinations: bucket.destinations.size,
      distinctPorts: bucket.ports.size,
      driftPercent: round(driftPercent, 1),
      state: bucket.samples < 5 ? "learning" : driftPercent >= 50 ? "drifted" : "stable",
      governed: true,
      trainedAt: new Date(now).toISOString()
    };
  });
  return {
    models: models.sort((a, b) => b.driftPercent - a.driftPercent || b.sampleCount - a.sampleCount),
    drifted: models.filter((model) => model.state === "drifted").length,
    learning: models.filter((model) => model.state === "learning").length,
    minimumSamples: 5,
    governance: { poisoningGuard: "exclude-confirmed-incidents", approvalRequired: true, rollbackSnapshots: 3 }
  };
}

export function analyzeEncryptedTraffic(events = []) {
  const encrypted = events.filter((event) => event.tlsVersion || event.sni || event.ja3 || event.ja4 || String(event.protocol || "").toLowerCase().includes("quic") || Number(event.destinationPort) === 443);
  const findings = [];
  for (const event of encrypted) {
    const reasons = [];
    if (["tls1.0", "tls1.1", "ssl3"].includes(String(event.tlsVersion || "").toLowerCase())) reasons.push("obsolete TLS version");
    if (!event.sni && Number(event.destinationPort) === 443) reasons.push("missing server name metadata");
    if (event.ja4Risk === "malicious" || event.fingerprintReputation === "malicious") reasons.push("known malicious fingerprint reputation");
    if (String(event.protocol || "").toLowerCase().includes("quic") && !event.quicVersion) reasons.push("QUIC version unavailable");
    const periodicity = Number(event.periodicity || 0);
    if (periodicity >= 0.9) reasons.push("highly periodic encrypted sessions");
    if (reasons.length) findings.push({
      id: `encrypted-${event.id || hash(JSON.stringify(event)).slice(0, 12)}`,
      eventId: event.id,
      sourceIp: event.sourceIp,
      destinationIp: event.destinationIp,
      sni: event.sni || "",
      tlsVersion: event.tlsVersion || "unknown",
      fingerprint: event.ja4 || event.ja3 || "unavailable",
      fingerprintSource: event.ja4 ? "source-supplied-ja4" : event.ja3 ? "source-supplied-ja3" : "none",
      reasons,
      severity: reasons.some((reason) => reason.includes("malicious")) ? "high" : "medium"
    });
  }
  return {
    observed: encrypted.length,
    tls: encrypted.filter((event) => event.tlsVersion || event.sni || event.ja3 || event.ja4).length,
    quic: encrypted.filter((event) => String(event.protocol || "").toLowerCase().includes("quic")).length,
    fingerprintCoveragePercent: encrypted.length ? round(encrypted.filter((event) => event.ja4 || event.ja3).length / encrypted.length * 100, 1) : 0,
    findings: findings.slice(0, 500),
    licensePolicy: "Only source-supplied or license-cleared fingerprints are evaluated."
  };
}

export function analyzeProtocolTraffic(events = []) {
  const supported = new Set(["dns", "http", "https", "tls", "ssh", "rdp", "smb", "kerberos", "ldap", "quic"]);
  const counts = new Map();
  const findings = [];
  for (const event of events) {
    const protocol = String(event.application || event.service || event.protocol || "unknown").toLowerCase();
    counts.set(protocol, (counts.get(protocol) || 0) + 1);
    const reason = protocol === "dns" && String(event.query || "").length > 120 ? "Long DNS label may indicate tunneling" :
      protocol === "ssh" && String(event.outcome || "").toLowerCase().includes("fail") ? "Failed SSH authentication" :
      ["smb", "rdp", "ldap"].includes(protocol) && isPublicIp(event.sourceIp) ? `Internet-originated ${protocol.toUpperCase()} session` : "";
    if (reason) findings.push({ id: `protocol-${event.id || hash(JSON.stringify(event)).slice(0, 12)}`, eventId: event.id, protocol, reason, communityId: event.communityId || communityIdV1(event), severity: protocol === "dns" ? "medium" : "high" });
  }
  return {
    observedProtocols: [...counts.entries()].map(([protocol, count]) => ({ protocol, count, parsed: supported.has(protocol) })).sort((a, b) => b.count - a.count),
    communityIdCoveragePercent: events.length ? round(events.filter((event) => event.communityId || communityIdV1(event)).length / events.length * 100, 1) : 0,
    findings: findings.slice(0, 500),
    integrations: ["Zeek", "Corelight", "Suricata", "Community ID v1"]
  };
}

export function scoreAttackUrgency(findings = [], campaigns = [], graph = { nodes: [] }, { now = Date.now() } = {}) {
  const campaignBySignal = new Map();
  campaigns.forEach((campaign) => (campaign.signalIds || []).forEach((id) => campaignBySignal.set(id, campaign)));
  return findings.map((finding) => {
    const campaign = campaignBySignal.get(finding.id);
    const entities = finding.entities || [finding.entity].filter(Boolean);
    const radius = normalizeBlastRadius(campaign?.blastRadius, entities.length);
    const breadth = clamp((entities.length + radius.entityCount + radius.accountCount * 2 + radius.regionCount * 3) * 8, 0, 100);
    const ageMinutes = Math.max(0, (now - Date.parse(finding.lastSeen || finding.createdAt || now)) / 60000);
    const velocity = clamp(Number(finding.eventCount || finding.matchCount || 1) * 5 + Math.max(0, 30 - ageMinutes), 0, 100);
    const privilege = clamp(finding.privileged === true || /admin|root|role|iam/i.test(JSON.stringify(entities)) ? 90 : Number(finding.privilegeScore || 20), 0, 100);
    const impact = clamp(Number(finding.impactScore || severityScore(finding.severity)), 0, 100);
    const rawConfidence = Number(finding.confidence ?? finding.score ?? 50);
    const confidence = clamp(rawConfidence >= 0 && rawConfidence <= 1 ? rawConfidence * 100 : rawConfidence, 0, 100);
    const blastRadius = clamp(radius.entityCount * 5 + radius.accountCount * 15 + radius.regionCount * 10, 0, 100);
    const exposure = Math.max(0, ...graph.nodes.filter((node) => entities.includes(node.value)).map((node) => node.risk));
    const urgency = Math.round(breadth * 0.14 + velocity * 0.18 + privilege * 0.18 + impact * 0.18 + confidence * 0.18 + blastRadius * 0.10 + exposure * 0.04);
    return {
      ...finding,
      urgency,
      urgencyBand: urgency >= 85 ? "critical" : urgency >= 70 ? "high" : urgency >= 45 ? "medium" : "low",
      scoring: { breadth: round(breadth), velocity: round(velocity), privilege: round(privilege), impact: round(impact), confidence: round(confidence), blastRadius: round(blastRadius), exposure: round(exposure) },
      campaignId: campaign?.id || "",
      recommendation: urgency >= 85 ? "Escalate and prepare containment" : urgency >= 70 ? "Assign for immediate investigation" : "Review in priority order"
    };
  }).sort((a, b) => b.urgency - a.urgency || Date.parse(b.lastSeen || 0) - Date.parse(a.lastSeen || 0));
}

export function buildExposurePaths(graph = { nodes: [], edges: [] }, findings = [], context = {}) {
  const vulnerable = new Set((context.vulnerabilities || []).filter((item) => Number(item.cvss || 0) >= 7).map((item) => String(item.entity)));
  const privileged = new Set((context.privilegedEntities || []).map(String));
  const risky = new Set(findings.flatMap((finding) => finding.entities || [finding.entity].filter(Boolean)).map(String));
  return graph.edges.flatMap((edge) => {
    const from = graph.nodes.find((node) => node.id === edge.from);
    const to = graph.nodes.find((node) => node.id === edge.to);
    if (!from || !to) return [];
    const internetOrigin = isPublicIp(from.value);
    const risk = (internetOrigin ? 30 : 0) + (vulnerable.has(to.value) ? 35 : 0) + (privileged.has(to.value) ? 25 : 0) + (risky.has(from.value) || risky.has(to.value) ? 20 : 0);
    if (risk < 30) return [];
    return [{ id: `exposure-${hash(edge.id).slice(0, 14)}`, from: from.value, to: to.value, relation: edge.relation, risk: clamp(risk, 0, 100), internetOrigin, vulnerableDestination: vulnerable.has(to.value), privilegedDestination: privileged.has(to.value), observedAt: edge.lastSeen, evidence: edge.communityIds }];
  }).sort((a, b) => b.risk - a.risk).slice(0, 100);
}

export function estimateTelemetryEconomics(events = [], policy = {}) {
  const bytes = events.reduce((sum, event) => sum + Math.max(0, Number(event.bytes || Buffer.byteLength(JSON.stringify(event)))), 0);
  const duplicates = Math.max(0, events.length - new Set(events.map((event) => event.id || hash(JSON.stringify(event)))).size);
  const duplicatePercent = events.length ? duplicates / events.length * 100 : 0;
  const maskedFields = Array.isArray(policy.maskFields) ? policy.maskFields : ["raw", "userAgent"];
  const hotDays = clamp(Number(policy.hotRetentionDays || 7), 1, 90);
  const coldDays = clamp(Number(policy.coldRetentionDays || 365), hotDays, 3650);
  const projectedDailyGb = bytes / 1024 ** 3 * Math.max(1, Number(policy.dailyMultiplier || 24));
  const estimatedDailyCostUsd = projectedDailyGb * (Number(policy.ingestUsdPerGb || 0.18) + Number(policy.hotStorageUsdPerGbMonth || 0.10) * hotDays / 30 + Number(policy.coldStorageUsdPerGbMonth || 0.004) * coldDays / 30);
  return {
    observedEvents: events.length,
    observedBytes: bytes,
    duplicateEvents: duplicates,
    duplicatePercent: round(duplicatePercent, 1),
    projectedDailyGb: round(projectedDailyGb, 3),
    estimatedDailyCostUsd: round(estimatedDailyCostUsd, 2),
    hotRetentionDays: hotDays,
    coldRetentionDays: coldDays,
    maskedFields,
    routing: policy.routing || { detections: "hot", normalized: "warm", raw: "cold" },
    recommendations: [
      ...(duplicatePercent >= 5 ? ["Enable content-hash deduplication before hot-tier indexing."] : []),
      ...(hotDays > 14 ? ["Review hot retention; current policy materially increases hunt-tier cost."] : []),
      "Mask configured sensitive fields before external delivery."
    ]
  };
}

export function buildRetrospectiveMatches(events = [], indicators = []) {
  const now = Date.now();
  const normalized = indicators.slice(0, 5000).map((indicator) => ({ ...indicator, value: String(indicator.value || indicator.indicator || "").toLowerCase() })).filter((indicator) => indicator.value && !["revoked", "inactive"].includes(String(indicator.status || "").toLowerCase()) && (!indicator.expiresAt || Date.parse(indicator.expiresAt) > now));
  const index = new Map();
  normalized.forEach((indicator) => {
    if (!index.has(indicator.value)) index.set(indicator.value, []);
    index.get(indicator.value).push(indicator);
  });
  const matches = [];
  for (const event of events) {
    const searchable = new Set([event.sourceIp, event.destinationIp, event.sni, event.query, event.ja3, event.ja4, event.identity].filter(Boolean).map((value) => String(value).toLowerCase()));
    for (const value of searchable) {
      for (const indicator of index.get(value) || []) matches.push({ id: `sighting-${hash(`${event.id}|${indicator.id}|${indicator.value}`).slice(0, 18)}`, eventId: event.id, indicatorId: indicator.id, feedId: indicator.feedId || "", value: indicator.value, confidence: Number(indicator.confidence || 50), sourceReliability: Number(indicator.sourceReliability || 50), firstSeen: event.timestamp, lastSeen: event.timestamp, sourceIp: event.sourceIp, destinationIp: event.destinationIp });
    }
  }
  return matches.slice(0, 5000);
}

export function evaluateInvestigationAgent(run = {}, policy = {}) {
  const citations = Array.isArray(run.citations) ? run.citations : [];
  const toolCalls = Array.isArray(run.toolCalls) ? run.toolCalls : [];
  const unsupported = (run.claims || []).filter((claim) => !claim.citationIds?.length).length;
  const approvalViolations = toolCalls.filter((call) => call.mutating && !call.approvalId).length;
  const score = clamp(100 - unsupported * 15 - approvalViolations * 30 - (citations.length ? 0 : 25), 0, 100);
  return {
    score,
    passed: score >= Number(policy.minimumScore || 80) && approvalViolations === 0,
    citationCount: citations.length,
    unsupportedClaims: unsupported,
    approvalViolations,
    tests: [
      { name: "Evidence citations", passed: citations.length > 0 },
      { name: "No unsupported material claims", passed: unsupported === 0 },
      { name: "Mutating tools are approval-gated", passed: approvalViolations === 0 },
      { name: "Tenant scope is explicit", passed: Boolean(run.tenantId) }
    ],
    evaluatedAt: new Date().toISOString()
  };
}

export function communityIdV1(event = {}, seed = 0) {
  const source = ipBytes(event.sourceIp);
  const destination = ipBytes(event.destinationIp);
  const sourcePort = Number(event.sourcePort || 0);
  const destinationPort = Number(event.destinationPort || 0);
  const protocol = protocolNumber(event.protocol);
  if (!source || !destination || source.length !== destination.length || !protocol || !validPort(sourcePort) || !validPort(destinationPort)) return "";
  let src = source;
  let dst = destination;
  let sport = sourcePort;
  let dport = destinationPort;
  const addressOrder = Buffer.compare(src, dst);
  if (addressOrder > 0 || (addressOrder === 0 && sport > dport)) {
    [src, dst] = [dst, src];
    [sport, dport] = [dport, sport];
  }
  const buffer = Buffer.alloc(2 + src.length + dst.length + 6);
  buffer.writeUInt16BE(clamp(Number(seed), 0, 65535), 0);
  src.copy(buffer, 2);
  const destinationOffset = 2 + src.length;
  dst.copy(buffer, destinationOffset);
  const protocolOffset = destinationOffset + dst.length;
  buffer.writeUInt8(protocol, protocolOffset);
  buffer.writeUInt8(0, protocolOffset + 1);
  buffer.writeUInt16BE(sport, protocolOffset + 2);
  buffer.writeUInt16BE(dport, protocolOffset + 4);
  return `1:${createHash("sha1").update(buffer).digest("base64")}`;
}

export function normalizeSensor(body = {}, principal = {}, existing = null) {
  const now = new Date().toISOString();
  const name = String(body.name || existing?.name || "").trim().slice(0, 120);
  if (!name) throw new Error("Sensor name is required");
  return {
    id: String(existing?.id || body.id || `sensor-${hash(`${principal.tenantId}|${name}`).slice(0, 16)}`),
    tenantId: principal.tenantId,
    name,
    type: allow(body.type || existing?.type, ["cloud-tap", "packet", "zeek", "corelight", "virtual", "api"], "virtual"),
    status: allow(body.status, ["healthy", "degraded", "critical", "disabled"], existing?.status || "healthy"),
    region: String(body.region || existing?.region || "global").slice(0, 64),
    owner: String(body.owner || existing?.owner || "Unassigned").slice(0, 120),
    serviceAccountId: String(body.serviceAccountId || existing?.serviceAccountId || "").replace(/[^a-zA-Z0-9._-]/g, "").slice(0, 160),
    expectedIntervalMinutes: clamp(Number(body.expectedIntervalMinutes || existing?.expectedIntervalMinutes || 5), 1, 1440),
    lastHeartbeatAt: body.lastHeartbeatAt || existing?.lastHeartbeatAt || now,
    lagSeconds: clamp(Number(body.lagSeconds || 0), 0, 86400),
    errorRate: clamp(Number(body.errorRate || 0), 0, 100),
    coveragePercent: clamp(Number(body.coveragePercent ?? 100), 0, 100),
    createdAt: existing?.createdAt || now,
    updatedAt: now
  };
}

export function normalizePacketManifest(body = {}, principal = {}) {
  const now = new Date().toISOString();
  const objectUri = String(body.objectUri || "").trim();
  if (!/^(s3|local-evidence):\/\//.test(objectUri)) throw new Error("Packet object URI must use s3:// or local-evidence://");
  const sha256 = String(body.sha256 || "").toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(sha256)) throw new Error("Packet manifest requires a SHA-256 digest");
  return {
    id: String(body.id || `pcap-${hash(`${objectUri}|${sha256}`).slice(0, 20)}`),
    tenantId: principal.tenantId,
    objectUri,
    versionId: String(body.versionId || "").trim().slice(0, 1024),
    sha256,
    bytes: clamp(Number(body.bytes || 0), 0, Number.MAX_SAFE_INTEGER),
    packetCount: clamp(Number(body.packetCount || 0), 0, Number.MAX_SAFE_INTEGER),
    capturedAt: body.capturedAt || now,
    sensorId: String(body.sensorId || "").slice(0, 160),
    evidenceUploadId: String(body.evidenceUploadId || "").slice(0, 160),
    caseId: String(body.caseId || "").slice(0, 160),
    communityIds: (body.communityIds || []).map(String).slice(0, 1000),
    classification: allow(body.classification, ["internal", "confidential", "restricted"], "restricted"),
    immutable: true,
    createdBy: principal.email || principal.subject || "unknown",
    createdAt: now,
    updatedAt: now
  };
}

export function normalizeResponsePolicy(body = {}, principal = {}, existing = null) {
  const now = new Date().toISOString();
  return {
    id: "default",
    tenantId: principal.tenantId,
    mode: allow(body.mode, ["observe", "approve", "enforce"], existing?.mode || "approve"),
    killSwitch: body.killSwitch === true,
    allowedAdapters: (body.allowedAdapters || existing?.allowedAdapters || ["aws-network-firewall", "aws-ec2", "aws-iam", "kubernetes", "sensor-capture", "case-management", "rollback"]).map(String).slice(0, 50),
    maxTargets: clamp(Number(body.maxTargets || existing?.maxTargets || 1), 1, 100),
    requireSeparateApprover: body.requireSeparateApprover !== false,
    requireCase: body.requireCase !== false,
    verificationMinutes: clamp(Number(body.verificationMinutes || existing?.verificationMinutes || 15), 1, 1440),
    rollbackRequired: body.rollbackRequired !== false,
    updatedBy: principal.email || principal.subject || "unknown",
    createdAt: existing?.createdAt || now,
    updatedAt: now
  };
}

export function normalizeCaseTask(body = {}, principal = {}, existing = null) {
  const now = new Date().toISOString();
  const title = String(body.title || existing?.title || "").trim().slice(0, 200);
  if (!title) throw new Error("Task title is required");
  const caseId = String(body.caseId || existing?.caseId || "").trim();
  if (!caseId) throw new Error("Task caseId is required");
  const dueAt = body.dueAt || existing?.dueAt || new Date(Date.now() + 4 * 3600_000).toISOString();
  if (!Number.isFinite(Date.parse(dueAt))) throw new Error("Case task due date is invalid");
  return {
    id: String(existing?.id || body.id || `task-${hash(`${caseId}|${title}|${now}`).slice(0, 18)}`),
    tenantId: principal.tenantId,
    caseId,
    title,
    status: allow(body.status, ["todo", "in-progress", "blocked", "done"], existing?.status || "todo"),
    assignee: String(body.assignee || existing?.assignee || "Unassigned").slice(0, 160),
    watchers: (body.watchers || existing?.watchers || []).map(String).slice(0, 100),
    dueAt: new Date(dueAt).toISOString(),
    escalationPolicy: String(body.escalationPolicy || existing?.escalationPolicy || "P1 15m / P2 1h / P3 4h").slice(0, 180),
    createdAt: existing?.createdAt || now,
    updatedAt: now
  };
}

function ipv4Bytes(value) {
  const parts = String(value || "").split(".").map(Number);
  return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) ? Buffer.from(parts) : null;
}

function ipv6Bytes(value) {
  let text = String(value || "").toLowerCase();
  if (!text.includes(":")) return null;
  const ipv4Tail = text.match(/(\d+\.\d+\.\d+\.\d+)$/)?.[1];
  if (ipv4Tail) {
    const bytes = ipv4Bytes(ipv4Tail);
    if (!bytes) return null;
    text = `${text.slice(0, -ipv4Tail.length)}${bytes.readUInt16BE(0).toString(16)}:${bytes.readUInt16BE(2).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const groups = [...left, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[a-f0-9]{1,4}$/.test(group))) return null;
  const buffer = Buffer.alloc(16);
  groups.forEach((group, index) => buffer.writeUInt16BE(Number.parseInt(group, 16), index * 2));
  return buffer;
}

function ipBytes(value) {
  return ipv4Bytes(value) || ipv6Bytes(value);
}

function normalizeBlastRadius(value, fallbackEntities = 0) {
  if (value && typeof value === "object") {
    return {
      entityCount: clamp(value.entityCount, 0, 10000),
      accountCount: clamp(value.accountCount, 0, 1000),
      regionCount: clamp(value.regionCount, 0, 100)
    };
  }
  return { entityCount: clamp(value || fallbackEntities, 0, 10000), accountCount: 0, regionCount: 0 };
}

function protocolNumber(value) {
  const normalized = String(value || "").toLowerCase();
  if (["tcp", "6"].includes(normalized)) return 6;
  if (["udp", "17", "quic"].includes(normalized)) return 17;
  if (["icmp", "1"].includes(normalized)) return 1;
  return 0;
}

function validPort(value) { return Number.isInteger(value) && value >= 0 && value <= 65535; }
function severityScore(value) { return { critical: 95, high: 80, medium: 55, low: 25, informational: 10 }[String(value || "").toLowerCase()] || clamp(Number(value || 0), 0, 100); }
function healthRank(value) { return { critical: 0, degraded: 1, disabled: 2, healthy: 3 }[value] ?? 4; }
function isPublicIp(value) {
  const text = String(value || "").toLowerCase();
  const parts = text.split(".").map(Number);
  if (parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)) return !([10].includes(parts[0]) || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168) || parts[0] === 127 || parts[0] === 0 || parts[0] >= 224);
  const ipv6 = ipv6Bytes(text);
  if (!ipv6) return false;
  return !(ipv6.equals(Buffer.alloc(16)) || ipv6.equals(Buffer.from("00000000000000000000000000000001", "hex")) || (ipv6[0] & 0xfe) === 0xfc || (ipv6[0] === 0xfe && (ipv6[1] & 0xc0) === 0x80) || ipv6[0] === 0xff);
}
function earlier(a, b) { return !a ? b : !b ? a : Date.parse(a) <= Date.parse(b) ? a : b; }
function later(a, b) { return !a ? b : !b ? a : Date.parse(a) >= Date.parse(b) ? a : b; }
function uniqueLimited(values, value, limit) { if (value === undefined || value === null || value === "") return values; return values.includes(value) ? values : [...values, value].slice(0, limit); }
function median(values) { if (!values.length) return 0; const middle = Math.floor(values.length / 2); return values.length % 2 ? values[middle] : (values[middle - 1] + values[middle]) / 2; }
function clamp(value, min, max) { return Math.min(max, Math.max(min, Number.isFinite(Number(value)) ? Number(value) : min)); }
function round(value, digits = 0) { const power = 10 ** digits; return Math.round(Number(value || 0) * power) / power; }
function hash(value) { return createHash("sha256").update(String(value)).digest("hex"); }
function allow(value, values, fallback) { const normalized = String(value || "").toLowerCase(); return values.includes(normalized) ? normalized : fallback; }
