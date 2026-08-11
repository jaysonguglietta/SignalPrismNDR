const MAX_SOURCE_EVENTS = 100_000;
const MAX_STITCH_EVENTS = 50_000;
const MAX_LINKS = 20_000;
const MAX_CHAIN_EVENTS = 500;
const MAX_RAW_CHARS = 2048;
const ADMIN_PORTS = new Set([21, 22, 23, 135, 139, 389, 445, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017]);
const COMMON_PROTOCOLS = new Set(["TCP", "UDP", "ICMP", "ICMPV6", ""]);
const PRIVILEGE_ACTIONS = new Set([
  "AttachGroupPolicy", "AttachRolePolicy", "AttachUserPolicy", "CreateAccessKey", "CreateLoginProfile",
  "CreatePolicyVersion", "PassRole", "PutGroupPolicy", "PutRolePolicy", "PutUserPolicy", "UpdateAssumeRolePolicy"
]);
const AUTH_ACTIONS = new Set(["ConsoleLogin", "AssumeRole", "GetSessionToken", "GetFederationToken"]);
const SEVERITY_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };

export function parseStitchingTelemetry(input, options = {}) {
  const sourceId = clean(options.sourceId, 160) || "evidence-source";
  const sourceName = clean(options.sourceName, 240) || sourceId;
  const tenantId = clean(options.tenantId, 160);
  const flowRecords = Array.isArray(options.flowRecords) ? options.flowRecords : [];
  if (flowRecords.length) {
    const events = [];
    const errors = [];
    flowRecords.slice(0, MAX_SOURCE_EVENTS).forEach((record, index) => {
      try {
        events.push(normalizeFlowRecord(record, { sourceId, sourceName, tenantId, index }));
      } catch (error) {
        errors.push({ index, message: error.message });
      }
    });
    return summarizeParse(events, errors, flowRecords.length);
  }

  const expanded = expandSourcePayload(input);
  const events = [];
  const errors = [...expanded.errors];
  expanded.records.slice(0, MAX_SOURCE_EVENTS).forEach((record, index) => {
    try {
      events.push(normalizeSourceEvent(record, { sourceId, sourceName, tenantId, index }));
    } catch (error) {
      errors.push({ index: record.__sourceIndex ?? index, message: error.message });
    }
  });
  if (expanded.records.length > MAX_SOURCE_EVENTS) {
    errors.push({ index: MAX_SOURCE_EVENTS, message: `Source exceeds the ${MAX_SOURCE_EVENTS} event browser normalization limit` });
  }
  return summarizeParse(events, errors, expanded.total);
}

export function buildStitchedIncidents(inputEvents = [], options = {}) {
  const windowMinutes = clampNumber(options.windowMinutes, 5, 1440, 240);
  const minimumLinkConfidence = clampNumber(options.minimumLinkConfidence, 0.5, 0.95, 0.62);
  const windowMs = windowMinutes * 60_000;
  const invalidEvents = [];
  const ordered = [];
  const sourceClockState = new Map();
  const clockUnstableSources = new Set();
  (Array.isArray(inputEvents) ? inputEvents : []).slice(0, MAX_STITCH_EVENTS).forEach((event) => {
    const timestampMs = Date.parse(event?.timestamp || "");
    if (!event || !Number.isFinite(timestampMs)) {
      invalidEvents.push(event?.id || "unknown-event");
      return;
    }
    const sourceKey = event.evidenceSourceId || event.evidenceSource || "unknown-source";
    const sourceIndex = Number(event.sourceIndex);
    const previousSourceEvent = sourceClockState.get(sourceKey);
    if (previousSourceEvent && Number.isFinite(sourceIndex) && sourceIndex > previousSourceEvent.sourceIndex && timestampMs < previousSourceEvent.timestampMs - 5 * 60_000) {
      clockUnstableSources.add(sourceKey);
    }
    if (!previousSourceEvent || !Number.isFinite(sourceIndex) || sourceIndex >= previousSourceEvent.sourceIndex) {
      sourceClockState.set(sourceKey, { sourceIndex, timestampMs });
    }
    ordered.push({ ...event, timestampMs, riskWeight: eventRiskWeight(event) });
  });
  ordered.sort((left, right) => left.timestampMs - right.timestampMs || String(left.id).localeCompare(String(right.id)));

  const keyFrequency = new Map();
  const eventEntities = ordered.map((event) => entitiesForEvent(event));
  eventEntities.forEach((entities) => new Set(entities.map((entity) => entity.key)).forEach((key) => keyFrequency.set(key, (keyFrequency.get(key) || 0) + 1)));
  const commonThreshold = Math.max(50, Math.ceil(ordered.length * 0.02));
  const suppressedKeys = new Set([...keyFrequency.entries()]
    .filter(([key, count]) => count > commonThreshold && (key.startsWith("ip:") || key.startsWith("domain:")))
    .map(([key]) => key));

  const activeByKey = new Map();
  const links = [];
  const conflicts = [];
  for (let currentIndex = 0; currentIndex < ordered.length && links.length < MAX_LINKS; currentIndex += 1) {
    const current = ordered[currentIndex];
    const currentEntities = eventEntities[currentIndex].filter((entity) => !suppressedKeys.has(entity.key));
    const candidates = new Map();
    currentEntities.forEach((entity) => {
      const previousIndexes = activeByKey.get(entity.key) || [];
      previousIndexes.slice(-40).forEach((previousIndex) => {
        const previous = ordered[previousIndex];
        if (current.timestampMs - previous.timestampMs > windowMs) return;
        if (!candidates.has(previousIndex)) candidates.set(previousIndex, []);
        const previousEntity = eventEntities[previousIndex].find((item) => item.key === entity.key);
        if (previousEntity) candidates.get(previousIndex).push({ previous: previousEntity, current: entity });
      });
    });

    candidates.forEach((matches, previousIndex) => {
      if (links.length >= MAX_LINKS) return;
      const previous = ordered[previousIndex];
      if (previous.tenantId !== current.tenantId && (previous.tenantId || current.tenantId)) {
        if (conflicts.length < 100) conflicts.push({
          type: "cross-tenant-blocked",
          events: [previous.id, current.id],
          detail: "Matching entities were not linked because tenant identity was different or missing on one side."
        });
        return;
      }
      const strongMatch = matches.some((match) => !["ip", "domain"].includes(match.current.type));
      const weakLinkClockRisk = !strongMatch && (clockUnstableSources.has(previous.evidenceSourceId || previous.evidenceSource) || clockUnstableSources.has(current.evidenceSourceId || current.evidenceSource));
      if (weakLinkClockRisk) {
        if (conflicts.length < 100) conflicts.push({
          type: "clock-skew-weak-link",
          events: [previous.id, current.id],
          detail: "IP or domain-only evidence was not linked because one source contains a material timestamp regression."
        });
        return;
      }
      if (!strongMatch && current.timestampMs - previous.timestampMs > 4 * 60 * 60_000) {
        if (conflicts.length < 100) conflicts.push({
          type: "broad-window-weak-link",
          events: [previous.id, current.id],
          detail: "IP or domain-only evidence more than four hours apart was not linked without a stronger identity, workload, interface, or session key."
        });
        return;
      }
      const crossAccountWeakEntity = previous.accountId && current.accountId && previous.accountId !== current.accountId && !strongMatch;
      if (crossAccountWeakEntity) {
        const privateAddressMatch = matches.some((match) => match.current.type === "ip" && isPrivateIp(match.current.value));
        if (conflicts.length < 100) conflicts.push({
          type: privateAddressMatch ? "ambiguous-private-ip" : "ambiguous-shared-network-entity",
          events: [previous.id, current.id],
          detail: `${privateAddressMatch ? "Private IP" : "IP or domain"} evidence spans accounts ${previous.accountId} and ${current.accountId} without a stronger identity, workload, interface, or session key.`
        });
        return;
      }
      const link = scoreEventLink(previous, current, matches, windowMs);
      if (link.confidence >= minimumLinkConfidence && (previous.riskWeight >= 1 || current.riskWeight >= 1 || strongMatch)) links.push(link);
    });

    currentEntities.forEach((entity) => {
      const existing = activeByKey.get(entity.key) || [];
      const recent = existing.filter((index) => current.timestampMs - ordered[index].timestampMs <= windowMs).slice(-39);
      recent.push(currentIndex);
      activeByKey.set(entity.key, recent);
    });
  }

  const eventById = new Map(ordered.map((event) => [event.id, event]));
  const indexById = new Map(ordered.map((event, index) => [event.id, index]));
  const parent = ordered.map((_, index) => index);
  const find = (index) => parent[index] === index ? index : (parent[index] = find(parent[index]));
  const union = (left, right) => {
    const rootLeft = find(left);
    const rootRight = find(right);
    if (rootLeft !== rootRight) parent[rootRight] = rootLeft;
  };
  links.forEach((link) => {
    const fromIndex = indexById.get(link.fromEventId);
    const toIndex = indexById.get(link.toEventId);
    if (Number.isInteger(fromIndex) && Number.isInteger(toIndex)) union(fromIndex, toIndex);
  });

  const components = new Map();
  ordered.forEach((event, index) => {
    const root = find(index);
    if (!components.has(root)) components.set(root, []);
    components.get(root).push(event);
  });
  const chains = [];
  components.forEach((componentEvents) => {
    if (componentEvents.length < 2 || !componentEvents.some((event) => event.riskWeight >= 1)) return;
    const eventIds = new Set(componentEvents.map((event) => event.id));
    const componentLinks = links.filter((link) => eventIds.has(link.fromEventId) && eventIds.has(link.toEventId));
    const evidenceSources = unique(componentEvents.map((event) => event.evidenceSource).filter(Boolean));
    if (evidenceSources.length < 2) return;
    chains.push(buildChain(componentEvents, componentLinks, eventEntities, indexById, windowMs));
  });
  chains.sort((left, right) => right.score - left.score || right.confidence - left.confidence || Date.parse(right.lastSeen) - Date.parse(left.lastSeen));

  const linkedEventIds = new Set(chains.flatMap((chain) => chain.eventIds));
  const formats = unique(ordered.map((event) => event.format).filter(Boolean));
  const sources = unique(ordered.map((event) => event.evidenceSource).filter(Boolean));
  const gaps = [];
  if (sources.length < 2) gaps.push({ type: "source-diversity", severity: "medium", detail: "At least two independently collected evidence sources are required for multi-source stitching." });
  if (!formats.some((format) => ["cloudtrail", "azure-activity", "entra-audit", "gcp-audit", "kubernetes-audit"].includes(format))) gaps.push({ type: "identity", severity: "low", detail: "No identity or control-plane telemetry is available to attribute network activity to a principal." });
  if (!ordered.some((event) => event.category === "dns")) gaps.push({ type: "dns", severity: "low", detail: "No DNS telemetry is available to connect destination IPs with queried domains." });
  if (!ordered.some((event) => event.category === "ids-alert" || event.category === "threat-finding")) gaps.push({ type: "independent-detection", severity: "low", detail: "No independent IDS or threat-finding source is available to corroborate flow behavior." });
  if (invalidEvents.length) gaps.push({ type: "invalid-time", severity: "medium", detail: `${invalidEvents.length} event${invalidEvents.length === 1 ? "" : "s"} could not be stitched because event time was invalid.` });
  if (suppressedKeys.size) gaps.push({ type: "common-entity-suppression", severity: "informational", detail: `${suppressedKeys.size} high-frequency IP or domain key${suppressedKeys.size === 1 ? " was" : "s were"} suppressed to prevent shared services from creating false incident chains.` });
  if (clockUnstableSources.size) gaps.push({ type: "clock-ordering", severity: "medium", detail: `${clockUnstableSources.size} source${clockUnstableSources.size === 1 ? " contains" : "s contain"} timestamp regressions greater than five minutes; weak network-entity links from those sources were blocked.` });
  if (links.length >= MAX_LINKS) gaps.push({ type: "link-limit", severity: "medium", detail: `Stitching reached the ${MAX_LINKS} link browser limit; use managed asynchronous analysis or a stricter confidence policy.` });
  if (inputEvents.length > MAX_STITCH_EVENTS) gaps.push({ type: "event-limit", severity: "medium", detail: `Stitching analyzed the first ${MAX_STITCH_EVENTS} time-valid events; use managed asynchronous analysis for larger batches.` });

  return {
    generatedAt: new Date().toISOString(),
    options: { windowMinutes, minimumLinkConfidence },
    eventCount: ordered.length,
    sourceCount: sources.length,
    formatCount: formats.length,
    sources,
    formats,
    linkCount: links.length,
    chainCount: chains.length,
    linkedEventCount: linkedEventIds.size,
    unlinkedEventCount: Math.max(0, ordered.length - linkedEventIds.size),
    chains: chains.slice(0, 250),
    links,
    conflicts,
    gaps,
    suppressedEntityCount: suppressedKeys.size,
    clockUnstableSourceCount: clockUnstableSources.size,
    invalidEventCount: invalidEvents.length
  };
}

function summarizeParse(events, errors, total) {
  return {
    events,
    errors,
    total,
    accepted: events.length,
    formats: unique(events.map((event) => event.format).filter(Boolean))
  };
}

function expandSourcePayload(input) {
  const text = String(input || "").trim();
  if (!text) return { records: [], errors: [], total: 0 };
  try {
    const parsed = JSON.parse(text);
    const records = expandContainer(parsed, 0, { remaining: MAX_SOURCE_EVENTS + 1 });
    return { records, errors: [], total: records.length };
  } catch {
    const records = [];
    const errors = [];
    const lines = text.split(/\r?\n/).filter((line) => line.trim() && !line.trim().startsWith("#"));
    lines.forEach((line, index) => {
      if (/^version(?:\s|$)/i.test(line.trim())) return;
      try {
        const parsed = JSON.parse(line);
        expandContainer(parsed, 0, { remaining: MAX_SOURCE_EVENTS + 1 }).forEach((record) => records.push({ ...record, __sourceIndex: index }));
      } catch {
        errors.push({ index, message: `Unsupported JSON event on line ${index + 1}` });
      }
    });
    return { records, errors, total: lines.length };
  }
}

function expandContainer(value, depth, budget) {
  if (value == null || depth > 12 || budget.remaining <= 0) return [];
  if (Array.isArray(value)) return value.flatMap((item) => expandContainer(item, depth + 1, budget));
  if (typeof value !== "object") return [];
  for (const key of ["Records", "records", "events", "logEvents", "entries", "logs"]) {
    if (Array.isArray(value[key])) return value[key].flatMap((item) => expandContainer(item, depth + 1, budget));
  }
  if (typeof value.message === "string") {
    try {
      return expandContainer(JSON.parse(value.message), depth + 1, budget);
    } catch {
      return [];
    }
  }
  budget.remaining -= 1;
  return [value];
}

function normalizeFlowRecord(record, context) {
  const timestamp = isoTimestamp(record.start);
  if (!timestamp) throw new Error("Flow record has an invalid timestamp");
  return baseEvent({
    id: `${context.sourceId}:flow:${context.index}:${record.lineNumber || context.index}`,
    format: flowFormat(record), provider: providerForFlow(record), category: "network", timestamp,
    accountId: record.accountId, sourceIp: record.source, sourcePort: record.srcPort,
    destinationIp: record.destination, destinationPort: record.dstPort, protocol: record.protocol,
    action: record.action || "observed", outcome: record.action === "REJECT" ? "failure" : "success",
    severity: record.action === "REJECT" && ADMIN_PORTS.has(record.dstPort) ? "medium" : "informational",
    bytes: record.bytes, packets: record.packets, interfaceId: record.interfaceId,
    direction: record.flowDirection, trafficPath: record.trafficPath,
    summary: `${record.action || "Observed"} ${endpoint(record.source, record.srcPort)} to ${endpoint(record.destination, record.dstPort)}`,
    raw: safeRaw(record.raw)
  }, context);
}

function normalizeSourceEvent(record, context) {
  if (!record || typeof record !== "object" || Array.isArray(record)) throw new Error("Telemetry event must be a JSON object");
  const format = detectFormat(record);
  const normalized = format === "cloudtrail" ? normalizeCloudTrail(record)
    : format === "guardduty" ? normalizeGuardDuty(record)
      : format === "route53-dns" ? normalizeRoute53(record)
        : format === "zeek" ? normalizeZeek(record)
          : format === "suricata" ? normalizeSuricata(record)
            : format === "ocsf" ? normalizeOcsf(record)
              : normalizeGeneric(record);
  const timestamp = isoTimestamp(normalized.timestamp);
  if (!timestamp) throw new Error(`${format} event has an invalid timestamp`);
  return baseEvent({
    id: `${context.sourceId}:${clean(record.id || record.eventID || record.eventId, 180) || `${format}:${context.index}:${timestamp}`}`,
    format,
    provider: normalized.provider || providerForFormat(format),
    category: normalized.category || "network",
    timestamp,
    accountId: normalized.accountId,
    region: normalized.region,
    sourceIp: normalized.sourceIp,
    sourcePort: normalized.sourcePort,
    destinationIp: normalized.destinationIp,
    destinationPort: normalized.destinationPort,
    protocol: normalized.protocol,
    identity: normalized.identity,
    action: normalized.action || "observed",
    outcome: normalized.outcome || "observed",
    resource: normalized.resource,
    workload: normalized.workload,
    query: normalized.query,
    destinationDomain: normalized.destinationDomain,
    sni: normalized.sni,
    severity: normalized.severity || "informational",
    findingType: normalized.findingType,
    signature: normalized.signature,
    bytes: normalized.bytes,
    packets: normalized.packets,
    application: normalized.application,
    interfaceId: normalized.interfaceId,
    communityId: normalized.communityId,
    sessionId: normalized.sessionId,
    summary: normalized.summary || eventSummary(format, normalized),
    raw: safeRaw(record)
  }, context);
}

function baseEvent(event, context) {
  return {
    ...event,
    tenantId: context.tenantId || "",
    evidenceSourceId: context.sourceId,
    evidenceSource: context.sourceName,
    sourceIndex: context.index,
    accountId: clean(event.accountId, 160),
    region: clean(event.region, 80),
    sourceIp: clean(event.sourceIp, 128),
    destinationIp: clean(event.destinationIp, 128),
    sourcePort: finiteNumber(event.sourcePort),
    destinationPort: finiteNumber(event.destinationPort),
    protocol: clean(event.protocol, 40).toUpperCase(),
    identity: clean(event.identity, 512),
    resource: clean(event.resource, 512),
    workload: clean(event.workload, 256),
    query: clean(event.query, 1024),
    destinationDomain: clean(event.destinationDomain, 512),
    sni: clean(event.sni, 512),
    action: clean(event.action, 256),
    outcome: clean(event.outcome, 80).toLowerCase(),
    severity: normalizeSeverity(event.severity),
    findingType: clean(event.findingType, 512),
    signature: clean(event.signature, 512),
    application: clean(event.application, 160),
    interfaceId: clean(event.interfaceId, 256),
    communityId: clean(event.communityId, 256),
    sessionId: clean(event.sessionId, 256),
    summary: clean(event.summary, 1024),
    bytes: finiteNumber(event.bytes) || 0,
    packets: finiteNumber(event.packets) || 0
  };
}

function detectFormat(record) {
  if (record.class_uid || record.class_name && record.metadata) return "ocsf";
  if (record.eventSource && record.eventName && (record.userIdentity || record.eventVersion)) return "cloudtrail";
  if (record.type && record.service && record.resource && Object.hasOwn(record, "severity")) return "guardduty";
  if (record.event_type || record.alert?.signature || record.flow_id) return "suricata";
  if (record["id.orig_h"] || record.uid || record._path || record.zeek) return "zeek";
  if (record.query_name || record.queryName || record.query_type || record.queryType || record.srcaddr && record.query) return "route53-dns";
  return "generic";
}

function normalizeCloudTrail(record) {
  const identity = record.userIdentity || {};
  const request = record.requestParameters || {};
  return {
    provider: "aws", category: AUTH_ACTIONS.has(record.eventName) ? "authentication" : "identity",
    timestamp: record.eventTime, accountId: record.recipientAccountId || identity.accountId, region: record.awsRegion,
    sourceIp: record.sourceIPAddress, destinationIp: request.destinationIp || request.ipAddress,
    destinationPort: request.port, protocol: record.eventType,
    identity: identity.arn || identity.principalId || identity.userName || identity.sessionContext?.sessionIssuer?.arn,
    action: record.eventName, outcome: record.errorCode || record.errorMessage ? "failure" : "success",
    resource: request.roleArn || request.userName || request.groupName || record.resources?.[0]?.ARN,
    severity: PRIVILEGE_ACTIONS.has(record.eventName) ? "high" : AUTH_ACTIONS.has(record.eventName) && (record.errorCode || record.errorMessage) ? "medium" : "informational",
    findingType: record.eventSource,
    summary: `${record.eventName || "CloudTrail action"} by ${identity.arn || identity.principalId || "unknown principal"}`
  };
}

function normalizeGuardDuty(record) {
  const action = record.service?.action || {};
  const network = action.networkConnectionAction || action.portProbeAction || {};
  const local = network.localIpDetails || network.portProbeDetails?.[0]?.localIpDetails || {};
  const remote = network.remoteIpDetails || network.portProbeDetails?.[0]?.remoteIpDetails || {};
  const instance = record.resource?.instanceDetails || {};
  return {
    provider: "aws", category: "threat-finding", timestamp: record.updatedAt || record.createdAt || record.service?.eventLastSeen,
    accountId: record.accountId, region: record.region, sourceIp: remote.ipAddressV4 || remote.ipAddressV6,
    destinationIp: local.ipAddressV4 || local.ipAddressV6 || instance.networkInterfaces?.[0]?.privateIpAddress,
    sourcePort: network.remotePortDetails?.port, destinationPort: network.localPortDetails?.port, protocol: network.protocol,
    identity: instance.instanceId || record.resource?.accessKeyDetails?.userName,
    action: action.actionType || "GuardDuty finding", outcome: record.service?.archived ? "archived" : "active",
    resource: instance.instanceId || record.resource?.resourceType, severity: guardDutySeverity(record.severity),
    findingType: record.type, signature: record.title || record.description,
    summary: record.title || record.description || record.type || "GuardDuty finding"
  };
}

function normalizeRoute53(record) {
  const answers = Array.isArray(record.answers) ? record.answers : [];
  return {
    provider: "aws", category: "dns", timestamp: record.query_timestamp || record.timestamp || record.time,
    accountId: record.account_id || record.accountId, region: record.region,
    sourceIp: record.srcaddr || record.srcAddr || record.sourceIp, sourcePort: record.srcport || record.srcPort,
    destinationIp: record.resolverIp || answers[0]?.Rdata || answers[0]?.data, destinationPort: 53,
    protocol: record.transport || "udp", identity: record.vpc_id || record.vpcId,
    action: record.query_type || record.queryType || "DNS query", outcome: record.rcode || record.responseCode || "observed",
    resource: record.hosted_zone_id || record.vpc_id, query: record.query_name || record.queryName,
    destinationDomain: record.query_name || record.queryName, severity: String(record.query_name || record.queryName || "").length >= 60 ? "medium" : "informational",
    summary: `DNS ${record.query_type || record.queryType || "query"} for ${record.query_name || record.queryName || "unknown name"}`
  };
}

function normalizeZeek(record) {
  const path = record._path || record.zeek || (record.query ? "dns" : "conn");
  return {
    provider: "zeek", category: path === "dns" ? "dns" : "network", timestamp: record.ts,
    sourceIp: record["id.orig_h"] || record.orig_h || record.sourceIp, sourcePort: record["id.orig_p"] || record.orig_p,
    destinationIp: record["id.resp_h"] || record.resp_h || record.destinationIp, destinationPort: record["id.resp_p"] || record.resp_p,
    protocol: record.proto || record.transport_proto, identity: record.uid, sessionId: record.uid,
    action: path, outcome: record.conn_state || record.rcode_name || "observed", application: record.service,
    query: record.query, destinationDomain: record.query || record.server_name, sni: record.server_name || record.sni,
    severity: record.notice ? "medium" : "informational", signature: record.note || record.msg,
    bytes: Number(record.orig_bytes || 0) + Number(record.resp_bytes || 0), communityId: record.community_id,
    summary: `${path} ${record["id.orig_h"] || record.orig_h || "unknown"} to ${record["id.resp_h"] || record.resp_h || record.query || "unknown"}`
  };
}

function normalizeSuricata(record) {
  return {
    provider: "suricata", category: record.event_type === "dns" ? "dns" : record.alert ? "ids-alert" : "network",
    timestamp: record.timestamp, sourceIp: record.src_ip, sourcePort: record.src_port,
    destinationIp: record.dest_ip, destinationPort: record.dest_port, protocol: record.proto,
    sessionId: record.flow_id, action: record.event_type || "network",
    outcome: record.alert?.action || record.flow?.state || "observed",
    query: record.dns?.rrname || record.dns?.query?.[0]?.rrname, destinationDomain: record.tls?.sni,
    severity: suricataSeverity(record.alert?.severity), findingType: record.alert?.category,
    signature: record.alert?.signature, bytes: Number(record.flow?.bytes_toserver || 0) + Number(record.flow?.bytes_toclient || 0),
    application: record.app_proto, communityId: record.community_id,
    summary: record.alert?.signature || `${record.event_type || "network"} ${record.src_ip || "unknown"} to ${record.dest_ip || "unknown"}`
  };
}

function normalizeOcsf(record) {
  const source = record.src_endpoint || record.src || {};
  const destination = record.dst_endpoint || record.dst || {};
  return {
    provider: record.metadata?.product?.vendor_name || "ocsf", category: Number(record.class_uid) === 2001 ? "threat-finding" : "network",
    timestamp: record.time || record.start_time || record.metadata?.logged_time, accountId: record.cloud?.account?.uid,
    region: record.cloud?.region, sourceIp: source.ip, sourcePort: source.port, destinationIp: destination.ip,
    destinationPort: destination.port, protocol: record.connection_info?.protocol_name,
    identity: record.actor?.user?.uid || record.user?.uid, action: record.activity_name || record.activity_id,
    outcome: record.status || record.status_id, resource: record.resources?.[0]?.uid || record.resources?.[0]?.name,
    severity: record.severity || record.severity_id, findingType: record.finding_info?.title,
    signature: record.finding_info?.desc, communityId: record.connection_info?.community_id,
    bytes: record.traffic?.bytes, packets: record.traffic?.packets,
    summary: record.finding_info?.title || record.activity_name || record.class_name || "OCSF event"
  };
}

function normalizeGeneric(record) {
  return {
    provider: record.provider || record.cloud?.provider || "generic", category: record.category || record.eventCategory || "network",
    timestamp: record.timestamp || record.time || record.eventTime || record.date,
    accountId: record.accountId || record.account_id || record.cloud?.account?.uid, region: record.region || record.cloud?.region,
    sourceIp: record.sourceIp || record.src_ip || record.srcaddr || record.source?.ip,
    sourcePort: record.sourcePort || record.src_port || record.srcport || record.source?.port,
    destinationIp: record.destinationIp || record.dest_ip || record.dstaddr || record.destination?.ip,
    destinationPort: record.destinationPort || record.dest_port || record.dstport || record.destination?.port,
    protocol: record.protocol || record.proto, identity: record.identity || record.user || record.principal,
    action: record.action || record.eventName || record.type || "observed", outcome: record.outcome || record.status || "observed",
    resource: record.resource || record.resourceId, workload: record.workload || record.instanceId || record.pod,
    query: record.query || record.domain, destinationDomain: record.destinationDomain || record.domain || record.sni,
    severity: record.severity, findingType: record.findingType || record.title, signature: record.signature || record.description,
    bytes: record.bytes, packets: record.packets, application: record.application || record.app,
    interfaceId: record.interfaceId || record.eni, communityId: record.communityId || record.community_id,
    sessionId: record.sessionId || record.session_id, summary: record.summary || record.message || record.title || "Generic telemetry event"
  };
}

function entitiesForEvent(event) {
  const entities = [];
  addEntity(entities, "identity", event.identity, "actor", 0.95);
  addEntity(entities, "resource", event.resource, "resource", 0.93);
  addEntity(entities, "workload", event.workload, "workload", 0.93);
  addEntity(entities, "interface", event.interfaceId, "interface", 0.94);
  addEntity(entities, "community", event.communityId, "session", 0.99);
  addEntity(entities, "session", event.sessionId, "session", 0.97);
  addEntity(entities, "ip", event.sourceIp, "source", isPrivateIp(event.sourceIp) ? 0.86 : 0.68);
  addEntity(entities, "ip", event.destinationIp, "destination", isPrivateIp(event.destinationIp) ? 0.84 : 0.62);
  addEntity(entities, "domain", normalizeDomain(event.query || event.destinationDomain || event.sni), "destination", 0.72);
  return dedupeBy(entities, (entity) => `${entity.key}|${entity.role}`);
}

function addEntity(entities, type, value, role, strength) {
  const normalized = clean(value, 512).toLowerCase();
  if (!normalized || normalized === "-" || ["0.0.0.0", "255.255.255.255"].includes(normalized)) return;
  entities.push({ key: `${type}:${normalized}`, type, value: clean(value, 512), role, strength });
}

function scoreEventLink(previous, current, matches, windowMs) {
  const scored = matches.map((match) => {
    let strength = Math.max(match.previous.strength, match.current.strength);
    let relationship = `shared-${match.current.type}`;
    if (match.previous.role === "destination" && match.current.role === "source") {
      strength += 0.08;
      relationship = "path-continuation";
    } else if (match.previous.role === "destination" && match.current.role === "destination") {
      strength -= 0.12;
      relationship = "shared-destination";
    } else if (match.previous.role === "source" && match.current.role === "source") {
      strength += 0.03;
      relationship = "same-actor";
    }
    return { ...match, strength: clamp(strength, 0, 0.99), relationship };
  }).sort((left, right) => right.strength - left.strength);
  const strongest = scored[0];
  const deltaMs = Math.max(0, current.timestampMs - previous.timestampMs);
  const timeScore = 1 - Math.min(1, deltaMs / windowMs) * 0.5;
  const crossSource = previous.evidenceSourceId !== current.evidenceSourceId;
  const crossFormat = previous.format !== current.format;
  const complementary = complementaryCategories(previous.category, current.category);
  const confidence = clamp(strongest.strength * 0.62 + timeScore * 0.18 + (crossSource ? 0.08 : 0) + (crossFormat ? 0.04 : 0) + (complementary ? 0.08 : 0), 0, 0.99);
  const reasons = [entityReason(strongest), `Events occurred ${duration(deltaMs)} apart`];
  if (crossSource) reasons.push(`Independent evidence from ${previous.evidenceSource} and ${current.evidenceSource}`);
  if (crossFormat) reasons.push(`${formatLabel(previous.format)} corroborated by ${formatLabel(current.format)}`);
  if (complementary) reasons.push(`${categoryLabel(previous.category)} activity is followed by ${categoryLabel(current.category)} evidence`);
  return {
    id: `link-${shortHash(`${previous.id}|${current.id}|${strongest.current.key}`)}`,
    fromEventId: previous.id,
    toEventId: current.id,
    relationship: strongest.relationship,
    confidence: round(confidence),
    timeDeltaMs: deltaMs,
    sharedEntities: unique(scored.map((item) => item.current.value)).slice(0, 8),
    reasons: unique(reasons).slice(0, 6)
  };
}

function buildChain(events, links, eventEntities, indexById, windowMs) {
  const ordered = events.slice().sort((left, right) => left.timestampMs - right.timestampMs);
  const sources = unique(ordered.map((event) => event.evidenceSource).filter(Boolean));
  const formats = unique(ordered.map((event) => event.format).filter(Boolean));
  const stages = unique(ordered.map(eventStage)).sort((left, right) => stageOrder(left) - stageOrder(right));
  const confidence = round(clamp(mean(links.map((link) => link.confidence)) + Math.min(0.08, (sources.length - 1) * 0.02), 0, 0.99));
  const score = Math.min(100, Math.round(confidence * 55 + Math.min(24, ordered.reduce((total, event) => total + event.riskWeight, 0) * 3) + Math.min(12, sources.length * 3) + Math.min(9, stages.length * 2)));
  const entityCounts = new Map();
  ordered.forEach((event) => (eventEntities[indexById.get(event.id)] || []).filter((entity) => !["domain", "session", "community"].includes(entity.type)).forEach((entity) => entityCounts.set(entity.value, (entityCounts.get(entity.value) || 0) + 1)));
  const primaryEntities = [...entityCounts.entries()].sort((left, right) => right[1] - left[1]).map(([entity]) => entity).slice(0, 8);
  const gaps = chainGaps(ordered, links, formats, windowMs);
  const id = `chain-${shortHash(`${ordered.map((event) => event.id).join("|")}|${links.map((link) => link.id).join("|")}`)}`;
  const lead = stages.includes("Exfiltration") ? "Multi-source exfiltration" : stages.includes("Lateral Movement") ? "Lateral movement" : stages.includes("Privilege Escalation") ? "Privilege escalation" : "Correlated activity";
  return {
    id,
    title: `${lead} chain involving ${primaryEntities[0] || "shared entities"}`,
    severity: score >= 90 ? "critical" : score >= 75 ? "high" : score >= 50 ? "medium" : "low",
    score,
    confidence,
    firstSeen: ordered[0].timestamp,
    lastSeen: ordered.at(-1).timestamp,
    durationMs: ordered.at(-1).timestampMs - ordered[0].timestampMs,
    stages,
    primaryEntities,
    evidenceSources: sources,
    sourceFormats: formats,
    eventIds: ordered.slice(0, MAX_CHAIN_EVENTS).map((event) => event.id),
    events: ordered.slice(0, MAX_CHAIN_EVENTS).map((event) => ({ ...stripRuntimeFields(event), stage: eventStage(event) })),
    links: links.slice(0, 1000),
    gaps,
    narrative: `${ordered.length} events from ${sources.length} independently named source${sources.length === 1 ? "" : "s"} connect across ${stages.join(" -> ") || "observed activity"}. ${links.length} explainable link${links.length === 1 ? "" : "s"} produced ${Math.round(confidence * 100)}% chain confidence.`
  };
}

function chainGaps(events, links, formats, windowMs) {
  const gaps = [];
  if (!formats.some((format) => ["cloudtrail", "azure-activity", "entra-audit", "gcp-audit", "kubernetes-audit"].includes(format))) gaps.push("Identity attribution is missing from this chain.");
  if (!events.some((event) => event.category === "dns")) gaps.push("DNS evidence is unavailable for destination attribution.");
  if (!events.some((event) => event.category === "ids-alert" || event.category === "threat-finding")) gaps.push("No independent threat finding corroborates this chain.");
  if (links.some((link) => link.confidence < 0.7)) gaps.push("One or more links are low confidence and require analyst validation.");
  for (let index = 1; index < events.length; index += 1) {
    if (events[index].timestampMs - events[index - 1].timestampMs > windowMs / 2) {
      gaps.push("The chain contains a material time gap that may hide missing telemetry.");
      break;
    }
  }
  return unique(gaps);
}

function eventRiskWeight(event) {
  let score = SEVERITY_WEIGHT[normalizeSeverity(event.severity)] || 0;
  if (["threat-finding", "ids-alert"].includes(event.category)) score += 3;
  if (event.category === "authentication" && event.outcome === "failure") score += 2;
  if (PRIVILEGE_ACTIONS.has(event.action)) score += 3;
  if (event.category === "network" && event.outcome === "failure") score += 1;
  if (ADMIN_PORTS.has(Number(event.destinationPort))) score += 1;
  if (Number(event.bytes) >= 10 * 1024 * 1024) score += 3;
  if (event.category === "dns" && String(event.query || "").length >= 60) score += 2;
  if (event.protocol && !COMMON_PROTOCOLS.has(String(event.protocol).toUpperCase())) score += 2;
  return Math.min(8, score);
}

function eventStage(event) {
  if (Number(event.bytes) >= 10 * 1024 * 1024 || event.category === "dns" && String(event.query || "").length >= 60) return "Exfiltration";
  if (PRIVILEGE_ACTIONS.has(event.action)) return "Privilege Escalation";
  if (event.category === "authentication" || event.outcome === "failure" && AUTH_ACTIONS.has(event.action)) return "Credential Access";
  if (event.category === "network" && ADMIN_PORTS.has(Number(event.destinationPort)) && isPrivateIp(event.sourceIp) && isPrivateIp(event.destinationIp)) return "Lateral Movement";
  if (event.category === "threat-finding" || event.category === "ids-alert" || event.category === "dns") return "Command and Control";
  if (event.category === "network" && event.outcome === "failure") return "Discovery";
  return "Observed Activity";
}

function stageOrder(stage) {
  return ["Credential Access", "Privilege Escalation", "Discovery", "Lateral Movement", "Command and Control", "Exfiltration", "Observed Activity"].indexOf(stage);
}

function complementaryCategories(left, right) {
  if (left === right) return false;
  const pair = new Set([left, right]);
  return pair.has("identity") && pair.has("network") || pair.has("threat-finding") && pair.has("network") || pair.has("ids-alert") && pair.has("network") || pair.has("dns") && pair.has("network");
}

function entityReason(match) {
  if (match.relationship === "path-continuation") return `Observed path continuation through ${match.current.value}`;
  if (match.current.type === "identity") return `Same authenticated identity ${match.current.value}`;
  if (match.current.type === "resource" || match.current.type === "workload") return `Same workload or resource ${match.current.value}`;
  if (match.current.type === "interface") return `Same network interface ${match.current.value}`;
  if (match.current.type === "community" || match.current.type === "session") return `Same session identifier ${match.current.value}`;
  if (match.current.type === "domain") return `Same normalized domain ${match.current.value}`;
  return `${match.relationship === "same-actor" ? "Same actor endpoint" : "Shared network endpoint"} ${match.current.value}`;
}

function stripRuntimeFields(event) {
  const { timestampMs, riskWeight, ...serializable } = event;
  return serializable;
}

function flowFormat(record) {
  if (record.raw?.version === "azure-nsg") return "azure-nsg";
  if (record.raw?.version === "gcp-vpc") return "gcp-vpc-flow";
  return "aws-vpc-flow";
}

function providerForFlow(record) {
  return record.raw?.version === "azure-nsg" ? "azure" : record.raw?.version === "gcp-vpc" ? "gcp" : "aws";
}

function providerForFormat(format) {
  if (["cloudtrail", "guardduty", "route53-dns", "aws-vpc-flow"].includes(format)) return "aws";
  if (format === "zeek" || format === "suricata") return format;
  return "generic";
}

function eventSummary(format, event) {
  return `${formatLabel(format)} ${event.action || "event"}${event.sourceIp || event.destinationIp ? ` involving ${event.sourceIp || "unknown"} and ${event.destinationIp || "unknown"}` : ""}`;
}

function formatLabel(format) {
  return ({ cloudtrail: "CloudTrail", guardduty: "GuardDuty", "route53-dns": "Route 53 DNS", zeek: "Zeek", suricata: "Suricata", "aws-vpc-flow": "VPC Flow Logs", ocsf: "OCSF" })[format] || clean(format, 80) || "Telemetry";
}

function categoryLabel(category) {
  return clean(category, 80).replace(/-/g, " ") || "related";
}

function guardDutySeverity(value) {
  const score = Number(value || 0);
  return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";
}

function suricataSeverity(value) {
  const severity = Number(value || 0);
  return severity === 1 ? "high" : severity === 2 ? "medium" : severity >= 3 ? "low" : "informational";
}

function normalizeSeverity(value) {
  const text = String(value || "informational").toLowerCase();
  if (["critical", "high", "medium", "low", "informational"].includes(text)) return text;
  const number = Number(value);
  if (number >= 9) return "critical";
  if (number >= 7) return "high";
  if (number >= 4) return "medium";
  if (number >= 1) return "low";
  return "informational";
}

function isoTimestamp(value) {
  if (Number.isFinite(value)) {
    const milliseconds = value > 10_000_000_000 ? value : value * 1000;
    return new Date(milliseconds).toISOString();
  }
  const parsed = Date.parse(String(value || ""));
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : "";
}

function isPrivateIp(value) {
  const parts = String(value || "").split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  return parts[0] === 10 || parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31 || parts[0] === 192 && parts[1] === 168;
}

function normalizeDomain(value) {
  return String(value || "").trim().toLowerCase().replace(/\.$/, "").slice(0, 512);
}

function endpoint(ip, port) {
  return `${ip || "unknown"}${port ? `:${port}` : ""}`;
}

function safeRaw(value) {
  try {
    return JSON.stringify(value).slice(0, MAX_RAW_CHARS);
  } catch {
    return "{}";
  }
}

function finiteNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : null;
}

function clean(value, limit = 1024) {
  if (value == null) return "";
  return String(value).replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, limit);
}

function clampNumber(value, minimum, maximum, fallback) {
  const number = Number(value);
  return Number.isFinite(number) ? clamp(number, minimum, maximum) : fallback;
}

function clamp(value, minimum, maximum) {
  return Math.max(minimum, Math.min(maximum, value));
}

function round(value) {
  return Math.round(value * 1000) / 1000;
}

function mean(values) {
  return values.length ? values.reduce((total, value) => total + value, 0) / values.length : 0;
}

function unique(values) {
  return [...new Set(values)];
}

function dedupeBy(values, keyFn) {
  const seen = new Set();
  return values.filter((value) => {
    const key = keyFn(value);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function duration(milliseconds) {
  if (milliseconds < 60_000) return `${Math.max(0, Math.round(milliseconds / 1000))} seconds`;
  if (milliseconds < 3_600_000) return `${Math.round(milliseconds / 60_000)} minutes`;
  return `${Math.round(milliseconds / 3_600_000)} hours`;
}

function shortHash(value) {
  let hash = 0x811c9dc5;
  const text = String(value || "");
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}
