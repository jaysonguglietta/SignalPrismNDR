import { createHash } from "node:crypto";

const MAX_EVENTS_PER_BATCH = 100_000;
const MAX_RAW_CHARS = 4096;
const MAX_STRING_CHARS = 1024;

const PRIVILEGED_ACTIONS = new Set([
  "AttachGroupPolicy",
  "AttachRolePolicy",
  "AttachUserPolicy",
  "CreateAccessKey",
  "CreateLoginProfile",
  "CreatePolicyVersion",
  "PassRole",
  "PutGroupPolicy",
  "PutRolePolicy",
  "PutUserPolicy",
  "UpdateAssumeRolePolicy"
]);

const AUTH_FAILURE_ACTIONS = new Set([
  "ConsoleLogin",
  "AssumeRole",
  "GetSessionToken",
  "GetFederationToken"
]);

export function parseTelemetryPayload(input, requestedFormat = "auto") {
  const expanded = expandPayload(input);
  const records = expanded.records;
  if (expanded.total > MAX_EVENTS_PER_BATCH) {
    throw new Error(`Telemetry batch exceeds ${MAX_EVENTS_PER_BATCH} events`);
  }
  const events = [];
  const errors = [...expanded.errors];
  records.forEach((record, index) => {
    try {
      events.push(normalizeTelemetryEvent(record, requestedFormat, index));
    } catch (error) {
      errors.push({ index, error: error.message });
    }
  });
  return { events, errors, total: expanded.total, accepted: events.length };
}

export function normalizeTelemetryEvent(record, requestedFormat = "auto", index = 0) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw new Error("Telemetry event must be a JSON object");
  }
  const format = requestedFormat === "auto" ? detectFormat(record) : normalizeFormat(requestedFormat);
  const event = format === "cloudtrail"
    ? normalizeCloudTrail(record)
    : format === "route53-dns"
      ? normalizeRoute53(record)
      : format === "guardduty"
        ? normalizeGuardDuty(record)
        : format === "zeek"
          ? normalizeZeek(record)
          : format === "suricata"
            ? normalizeSuricata(record)
            : format === "azure-nsg"
              ? normalizeAzureNsg(record)
              : format === "azure-activity"
                ? normalizeAzureActivity(record)
                : format === "entra-audit"
                  ? normalizeEntraAudit(record)
                  : format === "gcp-vpc-flow"
                    ? normalizeGcpVpcFlow(record)
                    : format === "gcp-audit"
                      ? normalizeGcpAudit(record)
                      : format === "kubernetes-audit"
                        ? normalizeKubernetesAudit(record)
                        : format === "cilium-hubble"
                          ? normalizeCiliumHubble(record)
                          : format === "gigamon"
                            ? normalizeGigamon(record)
                            : format === "extrahop"
                              ? normalizeExtraHop(record)
                              : format === "aws-vpc-flow"
                                ? normalizeAwsVpcFlow(record)
                                : normalizeGeneric(record);
  const timestamp = normalizeTimestamp(event.timestamp || record.timestamp || record.time || record.ts);
  const raw = safeJson(record, MAX_RAW_CHARS);
  const seed = `${format}|${timestamp}|${event.sourceIp}|${event.destinationIp}|${event.action}|${event.identity}|${canonicalJson(record)}`;
  return {
    id: cleanString(record.id || record.eventID || record.eventId || `telemetry-${stableHash(seed)}`, 180),
    format,
    provider: cleanString(event.provider || providerFor(format), 80),
    category: cleanString(event.category || "network", 80),
    timestamp,
    accountId: cleanString(event.accountId, 128),
    region: cleanString(event.region, 80),
    sourceIp: cleanString(event.sourceIp, 128),
    sourcePort: cleanNumber(event.sourcePort),
    destinationIp: cleanString(event.destinationIp, 128),
    destinationPort: cleanNumber(event.destinationPort),
    protocol: cleanString(event.protocol, 40).toUpperCase(),
    identity: cleanString(event.identity, 512),
    action: cleanString(event.action || "observed", 256),
    outcome: normalizeOutcome(event.outcome),
    resource: cleanString(event.resource, 512),
    query: cleanString(event.query, 1024),
    severity: normalizeSeverity(event.severity),
    findingType: cleanString(event.findingType, 512),
    signature: cleanString(event.signature, 512),
    bytes: cleanNumber(event.bytes),
    packets: cleanNumber(event.packets),
    application: cleanString(event.application, 160),
    workload: cleanString(event.workload, 256),
    namespace: cleanString(event.namespace, 160),
    cluster: cleanString(event.cluster, 256),
    direction: cleanString(event.direction, 40),
    trafficPath: cleanString(event.trafficPath, 160),
    interfaceId: cleanString(event.interfaceId, 256),
    destinationDomain: cleanString(event.destinationDomain, 512),
    tlsVersion: cleanString(event.tlsVersion, 80),
    cipher: cleanString(event.cipher, 256),
    sni: cleanString(event.sni, 512),
    certificateIssuer: cleanString(event.certificateIssuer, 512),
    certificateExpiresAt: normalizeOptionalTimestamp(event.certificateExpiresAt),
    ja3: cleanString(event.ja3, 256),
    ja4: cleanString(event.ja4, 256),
    ja4Risk: cleanString(event.ja4Risk, 40),
    quicVersion: cleanString(event.quicVersion, 80),
    periodicity: cleanRatio(event.periodicity),
    fingerprintReputation: cleanString(event.fingerprintReputation, 80),
    peerGroup: cleanString(event.peerGroup, 256),
    communityId: cleanString(event.communityId, 256),
    pqcKem: cleanString(event.pqcKem, 256),
    raw
  };
}

export function correlateTelemetry(events, options = {}) {
  const windowMinutes = clampNumber(options.windowMinutes, 5, 1440, 60);
  const windowMs = windowMinutes * 60 * 1000;
  const ordered = (Array.isArray(events) ? events : [])
    .filter((event) => event && Number.isFinite(Date.parse(event.timestamp)))
    .slice(0, MAX_EVENTS_PER_BATCH)
    .sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
  const findings = [
    ...findAuthenticationSprays(ordered, windowMs),
    ...findPrivilegeToNetworkChains(ordered, windowMs),
    ...findGuardDutyCorroboration(ordered, windowMs),
    ...findDnsTunnelingSignals(ordered, windowMs),
    ...findIdsAlertClusters(ordered, windowMs)
  ];
  const unique = new Map();
  findings.forEach((finding) => unique.set(`${finding.ruleId}:${finding.entity}:${finding.evidenceIds.join(",")}`, finding));
  return [...unique.values()].sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity) || b.score - a.score);
}

function expandPayload(input) {
  if (typeof input === "string") {
    const text = input.trim();
    if (!text) return { records: [], errors: [], total: 0 };
    try {
      return expandPayload(JSON.parse(text));
    } catch {
      const lines = text.split(/\r?\n/).filter((line) => line.trim());
      const records = [];
      const errors = [];
      lines.forEach((line, index) => {
        try {
          const parsed = parseTelemetryLine(line, index);
          if (parsed) records.push(parsed);
        } catch (error) {
          errors.push({ index, error: error.message });
        }
      });
      return { records, errors, total: lines.length };
    }
  }
  const records = Array.isArray(input)
    ? input
    : Array.isArray(input?.Records)
      ? input.Records
      : Array.isArray(input?.events)
        ? input.events
        : input && typeof input === "object"
          ? [input]
          : [];
  return { records, errors: [], total: records.length };
}

function parseTelemetryLine(line, index) {
  const text = String(line).trim();
  if (/^version(?:\s|$)/i.test(text)) return null;
  try {
    return JSON.parse(text);
  } catch {
    if (text.startsWith("CEF:")) return parseCefLine(text);
    if (/^\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?:ACCEPT|REJECT|-)\s+\S+/.test(text)) return parseAwsVpcFlowLine(text);
    throw new Error(`Invalid JSON or CEF on telemetry line ${index + 1}`);
  }
}

function parseAwsVpcFlowLine(line) {
  const fields = String(line).trim().split(/\s+/);
  if (fields.length < 14) throw new Error("AWS VPC Flow Log record has fewer than 14 fields");
  return {
    __format: "aws-vpc-flow",
    version: fields[0],
    accountId: fields[1],
    interfaceId: fields[2],
    sourceIp: fields[3],
    destinationIp: fields[4],
    sourcePort: fields[5],
    destinationPort: fields[6],
    protocolNumber: fields[7],
    packets: fields[8],
    bytes: fields[9],
    start: fields[10],
    end: fields[11],
    action: fields[12],
    logStatus: fields[13],
    rawFields: fields.slice(14)
  };
}

function parseCefLine(line) {
  const parts = String(line).split(/(?<!\\)\|/);
  if (parts.length < 8) throw new Error("CEF record has fewer than 8 header fields");
  const extensionText = parts.slice(7).join("|");
  const extension = {};
  const pattern = /(?:^|\s)([A-Za-z][A-Za-z0-9_]*)=([^=]*?)(?=\s[A-Za-z][A-Za-z0-9_]*=|$)/g;
  let match;
  while ((match = pattern.exec(extensionText))) extension[match[1]] = match[2].replace(/\\=/g, "=").replace(/\\n/g, " ").trim();
  return {
    __format: "gigamon",
    cefVersion: parts[0],
    deviceVendor: parts[1],
    deviceProduct: parts[2],
    deviceVersion: parts[3],
    signatureId: parts[4],
    name: parts[5],
    severity: cefSeverity(parts[6]),
    timestamp: extension.rt || extension.start || new Date().toISOString(),
    sourceIp: extension.src,
    destinationIp: extension.dst,
    sourcePort: extension.spt,
    destinationPort: extension.dpt,
    protocol: extension.proto,
    action: extension.act || parts[5],
    outcome: extension.outcome || "observed",
    application: extension.app,
    bytes: Number(extension.in || 0) + Number(extension.out || 0),
    signature: parts[5],
    resource: extension.dhost,
    identity: extension.suser,
    sni: extension.request || extension.dhost
  };
}

function detectFormat(record) {
  if (record.__format) return normalizeFormat(record.__format);
  if (record.eventSource && record.eventName && (record.userIdentity || record.eventVersion)) return "cloudtrail";
  if (record.type && record.service && record.resource && Object.hasOwn(record, "severity")) return "guardduty";
  if (record.event_type || record.alert?.signature || record.flow_id) return "suricata";
  if (record["id.orig_h"] || record.uid || record._path || record.zeek) return "zeek";
  if (record.flowTuples || record.macAddress_s || record.NSGRule_s || record.category === "NetworkSecurityGroupFlowEvent") return "azure-nsg";
  if (record.operationName && (record.resourceId || record.resourceProviderName || record.subscriptionId)) return "azure-activity";
  if (record.activityDisplayName || record.initiatedBy || record.targetResources) return "entra-audit";
  if (record.connection && (record.src_instance || record.dest_instance || record.reporter)) return "gcp-vpc-flow";
  if (record.protoPayload || record.logName?.includes("cloudaudit.googleapis.com")) return "gcp-audit";
  if (record.auditID && record.verb && record.objectRef) return "kubernetes-audit";
  if (record.verdict && (record.source?.pod_name || record.destination?.pod_name || record.node_name)) return "cilium-hubble";
  if (record.gigamon || record.ami || record.ipfix || record.exporterAddress) return "gigamon";
  if (record.extrahop || record.risk_score || record.detection_title) return "extrahop";
  if (record.__format === "aws-vpc-flow" || record.protocolNumber && record.interfaceId && record.logStatus) return "aws-vpc-flow";
  if (record.query_name || record.queryName || record.query_type || record.queryType || record.srcaddr) return "route53-dns";
  return "generic";
}

function normalizeFormat(value) {
  const format = String(value || "generic").trim().toLowerCase();
  const aliases = {
    route53: "route53-dns",
    dns: "route53-dns",
    eve: "suricata",
    nsg: "azure-nsg",
    azure: "azure-activity",
    entra: "entra-audit",
    gcp: "gcp-vpc-flow",
    kubernetes: "kubernetes-audit",
    k8s: "kubernetes-audit",
    hubble: "cilium-hubble",
    ipfix: "gigamon",
    cef: "gigamon"
  };
  const normalized = aliases[format] || format;
  if (!["cloudtrail", "route53-dns", "guardduty", "zeek", "suricata", "azure-nsg", "azure-activity", "entra-audit", "gcp-vpc-flow", "gcp-audit", "kubernetes-audit", "cilium-hubble", "gigamon", "extrahop", "aws-vpc-flow", "generic"].includes(normalized)) {
    throw new Error(`Unsupported telemetry format: ${format}`);
  }
  return normalized;
}

function normalizeCloudTrail(record) {
  const identity = record.userIdentity || {};
  const request = record.requestParameters || {};
  return {
    provider: "aws",
    category: AUTH_FAILURE_ACTIONS.has(record.eventName) ? "authentication" : "identity",
    timestamp: record.eventTime,
    accountId: record.recipientAccountId || identity.accountId,
    region: record.awsRegion,
    sourceIp: record.sourceIPAddress,
    destinationIp: request.destinationIp || request.ipAddress || "",
    destinationPort: request.port,
    protocol: record.eventType,
    identity: identity.arn || identity.principalId || identity.userName || identity.sessionContext?.sessionIssuer?.arn,
    action: record.eventName,
    outcome: record.errorCode || record.errorMessage ? "failure" : "success",
    resource: resourceFromCloudTrail(record),
    severity: PRIVILEGED_ACTIONS.has(record.eventName) ? "high" : "informational",
    findingType: record.eventSource
  };
}

function normalizeRoute53(record) {
  const answers = Array.isArray(record.answers) ? record.answers : [];
  return {
    provider: "aws",
    category: "dns",
    timestamp: record.query_timestamp || record.timestamp || record.time,
    accountId: record.account_id || record.accountId,
    region: record.region,
    sourceIp: record.srcaddr || record.srcAddr || record.sourceIp,
    sourcePort: record.srcport || record.srcPort,
    destinationIp: record.resolverIp || answers[0]?.Rdata || answers[0]?.data,
    destinationPort: 53,
    protocol: record.transport || "udp",
    identity: record.vpc_id || record.vpcId,
    action: record.query_type || record.queryType || "DNS query",
    outcome: record.rcode || record.responseCode || "observed",
    resource: record.hosted_zone_id || record.vpc_id,
    query: record.query_name || record.queryName,
    severity: "informational"
  };
}

function normalizeGuardDuty(record) {
  const action = record.service?.action || {};
  const network = action.networkConnectionAction || action.portProbeAction || {};
  const local = network.localIpDetails || network.portProbeDetails?.[0]?.localIpDetails || {};
  const remote = network.remoteIpDetails || network.portProbeDetails?.[0]?.remoteIpDetails || {};
  const instance = record.resource?.instanceDetails || {};
  return {
    provider: "aws",
    category: "threat-finding",
    timestamp: record.updatedAt || record.createdAt || record.service?.eventLastSeen,
    accountId: record.accountId,
    region: record.region,
    sourceIp: remote.ipAddressV4 || remote.ipAddressV6,
    sourcePort: network.remotePortDetails?.port,
    destinationIp: local.ipAddressV4 || local.ipAddressV6 || instance.networkInterfaces?.[0]?.privateIpAddress,
    destinationPort: network.localPortDetails?.port,
    protocol: network.protocol,
    identity: instance.instanceId || record.resource?.accessKeyDetails?.userName,
    action: action.actionType || "GuardDuty finding",
    outcome: record.service?.archived ? "archived" : "active",
    resource: instance.instanceId || record.resource?.resourceType,
    severity: guardDutySeverity(record.severity),
    findingType: record.type,
    signature: record.title || record.description
  };
}

function normalizeZeek(record) {
  const path = record._path || record.zeek || (record.query ? "dns" : "conn");
  return {
    provider: "zeek",
    category: path === "dns" ? "dns" : "network",
    timestamp: record.ts,
    sourceIp: record["id.orig_h"] || record.orig_h || record.sourceIp,
    sourcePort: record["id.orig_p"] || record.orig_p,
    destinationIp: record["id.resp_h"] || record.resp_h || record.destinationIp,
    destinationPort: record["id.resp_p"] || record.resp_p,
    protocol: record.proto || record.transport_proto,
    identity: record.uid,
    action: path,
    outcome: record.conn_state || record.rcode_name || "observed",
    resource: record.service,
    query: record.query,
    severity: record.notice ? "medium" : "informational",
    signature: record.note || record.msg,
    bytes: Number(record.orig_bytes || 0) + Number(record.resp_bytes || 0),
    tlsVersion: record.version || record.tls_version,
    cipher: record.cipher,
    sni: record.server_name || record.sni,
    certificateIssuer: record.issuer,
    certificateExpiresAt: record.not_valid_after,
    ja3: record.ja3 || record.ja3_hash,
    ja4: record.ja4 || record.ja4_hash,
    quicVersion: record.quic_version,
    communityId: record.community_id
  };
}

function normalizeSuricata(record) {
  return {
    provider: "suricata",
    category: record.event_type === "dns" ? "dns" : record.alert ? "ids-alert" : "network",
    timestamp: record.timestamp,
    sourceIp: record.src_ip,
    sourcePort: record.src_port,
    destinationIp: record.dest_ip,
    destinationPort: record.dest_port,
    protocol: record.proto,
    identity: record.flow_id,
    action: record.event_type || "network",
    outcome: record.alert?.action || record.flow?.state || "observed",
    resource: record.app_proto,
    query: record.dns?.rrname || record.dns?.query?.[0]?.rrname,
    severity: suricataSeverity(record.alert?.severity),
    findingType: record.alert?.category,
    signature: record.alert?.signature,
    bytes: Number(record.flow?.bytes_toserver || 0) + Number(record.flow?.bytes_toclient || 0),
    tlsVersion: record.tls?.version,
    sni: record.tls?.sni,
    certificateIssuer: record.tls?.issuerdn,
    certificateExpiresAt: record.tls?.notafter,
    ja3: record.tls?.ja3?.hash,
    ja4: record.tls?.ja4,
    quicVersion: record.quic?.version,
    communityId: record.community_id
  };
}

function normalizeAwsVpcFlow(record) {
  const action = String(record.action || "").toUpperCase();
  return {
    provider: "aws",
    category: "network",
    timestamp: Number(record.end || record.start || 0) * 1000,
    accountId: record.accountId,
    sourceIp: record.sourceIp,
    sourcePort: record.sourcePort,
    destinationIp: record.destinationIp,
    destinationPort: record.destinationPort,
    protocol: ipProtocolName(record.protocolNumber),
    action: action || "observed",
    outcome: action === "REJECT" ? "failure" : action === "ACCEPT" ? "success" : "observed",
    severity: action === "REJECT" ? "low" : "informational",
    bytes: record.bytes,
    packets: record.packets,
    interfaceId: record.interfaceId,
    resource: record.interfaceId,
    findingType: record.logStatus
  };
}

function normalizeGeneric(record) {
  return {
    provider: record.provider,
    category: record.category || record.type,
    timestamp: record.timestamp || record.time,
    accountId: record.accountId,
    region: record.region,
    sourceIp: record.sourceIp || record.source || record.src_ip,
    sourcePort: record.sourcePort || record.srcPort || record.src_port,
    destinationIp: record.destinationIp || record.destination || record.dest_ip,
    destinationPort: record.destinationPort || record.dstPort || record.dest_port,
    protocol: record.protocol || record.proto,
    identity: record.identity || record.user || record.principal,
    action: record.action || record.eventName,
    outcome: record.outcome || record.status,
    resource: record.resource,
    query: record.query,
    severity: record.severity,
    findingType: record.findingType,
    signature: record.signature,
    bytes: record.bytes,
    packets: record.packets,
    application: record.application || record.app || record.app_proto,
    workload: record.workload || record.pod || record.instance,
    namespace: record.namespace,
    cluster: record.cluster,
    direction: record.direction || record.flow_direction,
    trafficPath: record.trafficPath || record.traffic_path,
    interfaceId: record.interfaceId || record.interface_id,
    destinationDomain: record.destinationDomain || record.domain,
    tlsVersion: record.tlsVersion || record.tls_version,
    cipher: record.cipher || record.cipher_suite,
    sni: record.sni || record.server_name,
    certificateIssuer: record.certificateIssuer || record.certificate_issuer,
    certificateExpiresAt: record.certificateExpiresAt || record.certificate_expires_at,
    ja3: record.ja3 || record.ja3_hash,
    ja4: record.ja4 || record.ja4_hash,
    ja4Risk: record.ja4Risk || record.ja4_risk,
    quicVersion: record.quicVersion || record.quic_version,
    periodicity: record.periodicity,
    fingerprintReputation: record.fingerprintReputation || record.fingerprint_reputation,
    peerGroup: record.peerGroup || record.peer_group,
    communityId: record.communityId || record.community_id,
    pqcKem: record.pqcKem || record.pqc_kem
  };
}

function normalizeAzureNsg(record) {
  const tuple = String(record.flowTuple || record.flowTuples || record.properties?.flows?.[0]?.flows?.[0]?.flowTuples?.[0] || "").split(",");
  return {
    provider: "azure",
    category: "network",
    timestamp: record.time || record.TimeGenerated || (tuple[0] ? Number(tuple[0]) : undefined),
    accountId: record.subscriptionId || record.SubscriptionId,
    region: record.region || record.location,
    sourceIp: record.srcIp || record.SourceIP_s || tuple[1],
    destinationIp: record.dstIp || record.DestinationIP_s || tuple[2],
    sourcePort: record.srcPort || record.SourcePort_d || tuple[3],
    destinationPort: record.dstPort || record.DestinationPort_d || tuple[4],
    protocol: record.protocol || record.Protocol_s || tuple[5],
    action: record.action || record.FlowStatus_s || tuple[7],
    outcome: String(record.action || record.FlowStatus_s || tuple[7] || "").toUpperCase() === "D" ? "failure" : "success",
    resource: record.resourceId || record.ResourceId,
    identity: record.macAddress_s || record.macAddress,
    bytes: record.bytes || record.BytesSent_d,
    packets: record.packets || record.PacketsSent_d,
    direction: record.direction || record.FlowDirection_s || tuple[6],
    interfaceId: record.macAddress_s || record.networkInterfaceId,
    severity: "informational"
  };
}

function normalizeAzureActivity(record) {
  const operation = record.operationName?.value || record.operationName || record.OperationNameValue;
  return {
    provider: "azure",
    category: "identity",
    timestamp: record.eventTimestamp || record.time || record.TimeGenerated,
    accountId: record.subscriptionId || record.SubscriptionId,
    region: record.resourceRegion || record.location,
    sourceIp: record.callerIpAddress || record.httpRequest?.clientIpAddress,
    identity: record.caller || record.claims?.["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"],
    action: operation,
    outcome: String(record.status?.value || record.status || record.ActivityStatusValue || "").toLowerCase().includes("fail") ? "failure" : "success",
    resource: record.resourceId || record.ResourceId,
    severity: /delete|write|roleassignments/i.test(operation || "") ? "medium" : "informational",
    findingType: record.category?.value || record.category
  };
}

function normalizeEntraAudit(record) {
  const initiated = record.initiatedBy?.user || record.initiatedBy?.app || {};
  const targets = Array.isArray(record.targetResources) ? record.targetResources : [];
  return {
    provider: "microsoft-entra",
    category: "identity",
    timestamp: record.activityDateTime || record.createdDateTime || record.TimeGenerated,
    accountId: record.tenantId || record.TenantId,
    sourceIp: initiated.ipAddress || record.ipAddress,
    identity: initiated.userPrincipalName || initiated.displayName || initiated.appId,
    action: record.activityDisplayName || record.operationName,
    outcome: String(record.result || record.resultReason || "success").toLowerCase().includes("fail") ? "failure" : "success",
    resource: targets.map((item) => item.userPrincipalName || item.displayName || item.id).filter(Boolean).join(","),
    severity: /role|credential|consent|owner/i.test(record.activityDisplayName || "") ? "high" : "informational",
    findingType: record.category
  };
}

function normalizeGcpVpcFlow(record) {
  const connection = record.connection || record.jsonPayload?.connection || {};
  const sourceInstance = record.src_instance || record.jsonPayload?.src_instance || {};
  const destinationInstance = record.dest_instance || record.jsonPayload?.dest_instance || {};
  return {
    provider: "gcp",
    category: "network",
    timestamp: record.timestamp || record.receiveTimestamp,
    accountId: record.resource?.labels?.project_id || record.project_id,
    region: record.resource?.labels?.location || record.region,
    sourceIp: connection.src_ip,
    sourcePort: connection.src_port,
    destinationIp: connection.dest_ip,
    destinationPort: connection.dest_port,
    protocol: connection.protocol,
    identity: sourceInstance.vm_name || sourceInstance.instance_id,
    action: record.reporter || "observed",
    outcome: record.disposition || "observed",
    resource: destinationInstance.vm_name || destinationInstance.instance_id,
    bytes: record.bytes_sent || record.jsonPayload?.bytes_sent,
    packets: record.packets_sent || record.jsonPayload?.packets_sent,
    direction: record.reporter,
    workload: sourceInstance.vm_name,
    severity: "informational"
  };
}

function normalizeGcpAudit(record) {
  const payload = record.protoPayload || record.proto_payload || {};
  return {
    provider: "gcp",
    category: "identity",
    timestamp: record.timestamp || record.receiveTimestamp,
    accountId: record.resource?.labels?.project_id || record.project_id,
    region: record.resource?.labels?.location,
    sourceIp: payload.requestMetadata?.callerIp,
    identity: payload.authenticationInfo?.principalEmail,
    action: payload.methodName,
    outcome: payload.status?.code ? "failure" : "success",
    resource: payload.resourceName || payload.serviceName,
    severity: /setIamPolicy|serviceAccountKeys.create|instances.setMetadata/i.test(payload.methodName || "") ? "high" : "informational",
    findingType: payload.serviceName
  };
}

function normalizeKubernetesAudit(record) {
  const object = record.objectRef || {};
  return {
    provider: "kubernetes",
    category: "workload",
    timestamp: record.requestReceivedTimestamp || record.stageTimestamp,
    sourceIp: record.sourceIPs?.[0],
    identity: record.user?.username,
    action: record.verb,
    outcome: Number(record.responseStatus?.code || 200) >= 400 ? "failure" : "success",
    resource: [object.resource, object.namespace, object.name].filter(Boolean).join("/"),
    severity: ["create", "delete", "patch", "update"].includes(record.verb) && ["clusterrolebindings", "secrets", "pods/exec"].includes(object.resource) ? "high" : "informational",
    findingType: object.apiGroup || object.resource,
    workload: object.name,
    namespace: object.namespace,
    cluster: record.cluster || record.clusterName,
    application: object.resource
  };
}

function normalizeCiliumHubble(record) {
  const source = record.source || {};
  const destination = record.destination || {};
  const l4 = record.l4 || {};
  const tcp = l4.TCP || l4.tcp || {};
  const udp = l4.UDP || l4.udp || {};
  return {
    provider: "cilium",
    category: "workload-network",
    timestamp: record.time || record.timestamp,
    sourceIp: record.IP?.source || record.ip?.source,
    sourcePort: tcp.source_port || udp.source_port,
    destinationIp: record.IP?.destination || record.ip?.destination,
    destinationPort: tcp.destination_port || udp.destination_port,
    protocol: tcp.destination_port ? "tcp" : udp.destination_port ? "udp" : record.l4?.protocol,
    identity: source.identity || source.pod_name,
    action: record.verdict || "observed",
    outcome: String(record.verdict || "").toLowerCase() === "dropped" ? "failure" : "success",
    resource: destination.pod_name || destination.workloads?.[0]?.name,
    severity: String(record.verdict || "").toLowerCase() === "dropped" ? "low" : "informational",
    workload: source.pod_name,
    namespace: source.namespace,
    cluster: record.cluster_name,
    direction: record.traffic_direction,
    application: record.l7?.type
  };
}

function normalizeGigamon(record) {
  return {
    ...normalizeGeneric(record),
    provider: "gigamon",
    category: record.category || "network-observability",
    timestamp: record.timestamp || record.flowStartMilliseconds || record.time,
    sourceIp: record.sourceIPv4Address || record.src_ip || record.sourceIp,
    sourcePort: record.sourceTransportPort || record.src_port || record.sourcePort,
    destinationIp: record.destinationIPv4Address || record.dest_ip || record.destinationIp,
    destinationPort: record.destinationTransportPort || record.dest_port || record.destinationPort,
    protocol: record.protocolIdentifier || record.protocol || record.proto,
    application: record.applicationName || record.app || record.application,
    interfaceId: record.exporterAddress || record.observationDomainId,
    bytes: record.octetDeltaCount || record.bytes,
    packets: record.packetDeltaCount || record.packets,
    direction: record.flowDirection || record.direction,
    tlsVersion: record.tlsVersion,
    cipher: record.tlsCipherSuite || record.cipher,
    sni: record.tlsServerName || record.sni,
    ja3: record.ja3,
    pqcKem: record.pqcKem
  };
}

function normalizeExtraHop(record) {
  return {
    ...normalizeGeneric(record),
    provider: "extrahop",
    category: record.detection_title || record.risk_score ? "threat-finding" : "network-observability",
    timestamp: record.update_time || record.create_time || record.timestamp,
    sourceIp: record.participants?.[0]?.object_value || record.src_ip || record.sourceIp,
    destinationIp: record.participants?.[1]?.object_value || record.dst_ip || record.destinationIp,
    action: record.detection_type || record.type || "observed",
    outcome: record.status || "active",
    severity: Number(record.risk_score || 0) >= 80 ? "high" : Number(record.risk_score || 0) >= 50 ? "medium" : "informational",
    findingType: record.detection_title || record.type,
    signature: record.description || record.title,
    application: record.protocol || record.application
  };
}

function findAuthenticationSprays(events, windowMs) {
  const failures = events.filter((event) => event.format === "cloudtrail" && event.outcome === "failure" && AUTH_FAILURE_ACTIONS.has(event.action));
  const groups = groupBy(failures, (event) => event.sourceIp || event.identity || "unknown");
  return [...groups.entries()].flatMap(([entity, group]) => windowedGroups(group, windowMs, 5).map((evidence) => finding({
    ruleId: "SP-CORR-001",
    title: "Cloud identity authentication spray",
    severity: evidence.length >= 10 ? "high" : "medium",
    score: Math.min(95, 55 + evidence.length * 4),
    entity,
    tactic: "Credential Access",
    technique: "T1110 Brute Force",
    summary: `${entity} produced ${evidence.length} failed AWS authentication events inside the correlation window.`,
    evidence
  })));
}

function findPrivilegeToNetworkChains(events, windowMs) {
  const privileged = events.filter((event) => event.format === "cloudtrail" && event.outcome === "success" && PRIVILEGED_ACTIONS.has(event.action));
  const network = events.filter((event) => ["network", "ids-alert", "dns", "threat-finding"].includes(event.category));
  return privileged.flatMap((identityEvent) => {
    const start = Date.parse(identityEvent.timestamp);
    const matches = network.filter((event) => {
      const time = Date.parse(event.timestamp);
      const sameEntity = [identityEvent.sourceIp, identityEvent.identity].filter(Boolean).some((value) => [event.sourceIp, event.destinationIp, event.identity].includes(value));
      return sameEntity && time >= start && time - start <= windowMs;
    }).slice(0, 20);
    if (!matches.length) return [];
    const evidence = [identityEvent, ...matches];
    return [finding({
      ruleId: "SP-CORR-002",
      title: "Privilege change followed by network activity",
      severity: "high",
      score: 88,
      entity: identityEvent.identity || identityEvent.sourceIp,
      tactic: "Privilege Escalation",
      technique: "T1098 Account Manipulation",
      summary: `${identityEvent.action} was followed by related network telemetry within ${Math.round(windowMs / 60000)} minutes.`,
      evidence
    })];
  });
}

function findGuardDutyCorroboration(events, windowMs) {
  const guardDuty = events.filter((event) => event.format === "guardduty");
  const network = events.filter((event) => event.format !== "guardduty" && ["network", "ids-alert", "dns"].includes(event.category));
  return guardDuty.flatMap((guardEvent) => {
    const eventTime = Date.parse(guardEvent.timestamp);
    const addresses = new Set([guardEvent.sourceIp, guardEvent.destinationIp].filter(Boolean));
    const matches = network.filter((event) => Math.abs(Date.parse(event.timestamp) - eventTime) <= windowMs && [event.sourceIp, event.destinationIp].some((value) => addresses.has(value))).slice(0, 25);
    if (!matches.length) return [];
    return [finding({
      ruleId: "SP-CORR-003",
      title: "GuardDuty finding corroborated by network telemetry",
      severity: guardEvent.severity === "critical" || guardEvent.severity === "high" ? "high" : "medium",
      score: Math.min(98, 75 + matches.length),
      entity: guardEvent.resource || guardEvent.destinationIp || guardEvent.sourceIp,
      tactic: "Command and Control",
      technique: "T1071 Application Layer Protocol",
      summary: `${guardEvent.findingType || "GuardDuty activity"} matched ${matches.length} independent network event${matches.length === 1 ? "" : "s"}.`,
      evidence: [guardEvent, ...matches]
    })];
  });
}

function findDnsTunnelingSignals(events, windowMs) {
  const dns = events.filter((event) => event.category === "dns" && event.query);
  const groups = groupBy(dns, (event) => `${event.sourceIp || event.identity || "unknown"}|${baseDomain(event.query)}`);
  return [...groups.entries()].flatMap(([key, group]) => windowedGroups(group, windowMs, 8).flatMap((evidence) => {
    const longQueries = evidence.filter((event) => event.query.length >= 60);
    const labels = new Set(evidence.map((event) => event.query.split(".")[0]));
    if (longQueries.length < 3 && labels.size < 8) return [];
    const [entity, domain] = key.split("|");
    return [finding({
      ruleId: "SP-CORR-004",
      title: "High-entropy DNS query pattern",
      severity: longQueries.length >= 6 ? "high" : "medium",
      score: Math.min(94, 60 + longQueries.length * 4 + labels.size),
      entity,
      tactic: "Exfiltration",
      technique: "T1048 Exfiltration Over Alternative Protocol",
      summary: `${entity} generated ${labels.size} distinct labels for ${domain}, including ${longQueries.length} unusually long queries.`,
      evidence
    })];
  }));
}

function findIdsAlertClusters(events, windowMs) {
  const alerts = events.filter((event) => event.category === "ids-alert" && event.signature);
  const groups = groupBy(alerts, (event) => `${event.sourceIp || "unknown"}|${event.signature}`);
  return [...groups.entries()].flatMap(([key, group]) => windowedGroups(group, windowMs, 3).map((evidence) => {
    const [entity, signature] = key.split("|");
    return finding({
      ruleId: "SP-CORR-005",
      title: "Repeated network IDS signature",
      severity: evidence.some((event) => event.severity === "high" || event.severity === "critical") ? "high" : "medium",
      score: Math.min(92, 58 + evidence.length * 5),
      entity,
      tactic: "Command and Control",
      technique: "T1071 Application Layer Protocol",
      summary: `${signature} fired ${evidence.length} times for ${entity} in the correlation window.`,
      evidence
    });
  }));
}

function windowedGroups(events, windowMs, minimum) {
  const sorted = events.slice().sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
  const groups = [];
  let left = 0;
  for (let right = 0; right < sorted.length; right += 1) {
    while (Date.parse(sorted[right].timestamp) - Date.parse(sorted[left].timestamp) > windowMs) left += 1;
    const window = sorted.slice(left, right + 1);
    if (window.length >= minimum && (groups.length === 0 || window.at(-1).id !== groups.at(-1).at(-1).id)) groups.push(window);
  }
  return groups.length ? [groups.at(-1)] : [];
}

function finding({ ruleId, title, severity, score, entity, tactic, technique, summary, evidence }) {
  const evidenceIds = [...new Set(evidence.map((event) => event.id))].slice(0, 50);
  const firstSeen = evidence.map((event) => event.timestamp).sort()[0];
  const lastSeen = evidence.map((event) => event.timestamp).sort().at(-1);
  return {
    id: `correlation-${stableHash(`${ruleId}|${entity}|${evidenceIds.join("|")}`)}`,
    ruleId,
    title,
    severity,
    score,
    confidence: Math.min(0.99, score / 100),
    entity: entity || "unknown",
    tactic,
    technique,
    summary,
    firstSeen,
    lastSeen,
    evidenceIds,
    sourceFormats: [...new Set(evidence.map((event) => event.format))],
    status: "new",
    createdAt: new Date().toISOString()
  };
}

function groupBy(items, keyFn) {
  const groups = new Map();
  items.forEach((item) => {
    const key = keyFn(item);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  });
  return groups;
}

function resourceFromCloudTrail(record) {
  const resources = Array.isArray(record.resources) ? record.resources : [];
  return resources[0]?.ARN || resources[0]?.resourceName || record.requestParameters?.roleArn || record.requestParameters?.resourceArn || "";
}

function normalizeTimestamp(value) {
  if (typeof value === "number") {
    const milliseconds = value < 100000000000 ? value * 1000 : value;
    if (Number.isFinite(milliseconds)) return new Date(milliseconds).toISOString();
  }
  const parsed = Date.parse(String(value || ""));
  if (!Number.isFinite(parsed)) throw new Error("Telemetry event has an invalid timestamp");
  return new Date(parsed).toISOString();
}

function normalizeOptionalTimestamp(value) {
  if (!value) return "";
  try {
    return normalizeTimestamp(value);
  } catch {
    return "";
  }
}

function cefSeverity(value) {
  const parsed = Number(value);
  if (parsed >= 9) return "critical";
  if (parsed >= 7) return "high";
  if (parsed >= 4) return "medium";
  if (parsed >= 1) return "low";
  return "informational";
}

function providerFor(format) {
  if (["cloudtrail", "route53-dns", "guardduty", "aws-vpc-flow"].includes(format)) return "aws";
  if (format.startsWith("azure") || format === "entra-audit") return "azure";
  if (format.startsWith("gcp")) return "gcp";
  return format === "generic" ? "unknown" : format;
}

function guardDutySeverity(value) {
  const number = Number(value);
  if (number >= 8) return "critical";
  if (number >= 7) return "high";
  if (number >= 4) return "medium";
  return "low";
}

function suricataSeverity(value) {
  const number = Number(value);
  if (number === 1) return "high";
  if (number === 2) return "medium";
  if (number >= 3) return "low";
  return "informational";
}

function normalizeSeverity(value) {
  const severity = String(value || "informational").toLowerCase();
  return ["critical", "high", "medium", "low", "informational"].includes(severity) ? severity : "informational";
}

function normalizeOutcome(value) {
  const outcome = cleanString(value || "observed", 80).toLowerCase();
  if (["denied", "deny", "failed", "failure", "error"].includes(outcome)) return "failure";
  if (["allowed", "accept", "accepted", "success", "succeeded"].includes(outcome)) return "success";
  return outcome;
}

function baseDomain(query) {
  const labels = String(query || "").replace(/\.$/, "").toLowerCase().split(".").filter(Boolean);
  return labels.slice(-2).join(".") || "unknown";
}

function cleanString(value, limit = MAX_STRING_CHARS) {
  return String(value ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, limit);
}

function cleanNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : 0;
}

function cleanRatio(value) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(0, Math.min(1, number)) : 0;
}

function ipProtocolName(value) {
  const number = Number(value);
  if (number === 6) return "TCP";
  if (number === 17) return "UDP";
  if (number === 1) return "ICMP";
  if (number === 58) return "ICMPV6";
  return Number.isFinite(number) ? String(number) : "";
}

function clampNumber(value, minimum, maximum, fallback) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(minimum, Math.min(maximum, number)) : fallback;
}

function safeJson(value, limit) {
  try {
    return JSON.stringify(value).slice(0, limit);
  } catch {
    return "{}";
  }
}

function stableHash(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!value || typeof value !== "object") return JSON.stringify(value);
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function severityWeight(value) {
  return { critical: 5, high: 4, medium: 3, low: 2, informational: 1 }[value] || 0;
}
