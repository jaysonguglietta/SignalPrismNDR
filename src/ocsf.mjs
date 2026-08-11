import { resolveOcsfProfile } from "./advanced-operations.mjs";

const NETWORK_ACTIVITY_CLASS_UID = 4001;
const SECURITY_FINDING_CLASS_UID = 2001;

export function toOcsfNetworkActivity(event = {}, metadata = {}) {
  const time = epochMilliseconds(event.timestamp);
  const action = String(event.outcome || event.action || "observed").toLowerCase();
  return compact({
    class_uid: NETWORK_ACTIVITY_CLASS_UID,
    class_name: "Network Activity",
    category_uid: 4,
    category_name: "Network Activity",
    activity_id: activityId(action),
    activity_name: action,
    type_uid: NETWORK_ACTIVITY_CLASS_UID * 100 + activityId(action),
    time,
    severity_id: severityId(event.severity),
    severity: normalizeSeverity(event.severity),
    status: String(event.outcome || "observed"),
    action: String(event.action || "observed"),
    src_endpoint: endpoint(event.sourceIp, event.sourcePort, event.identity),
    dst_endpoint: endpoint(event.destinationIp, event.destinationPort, event.resource),
    connection_info: compact({
      protocol_name: String(event.protocol || "").toLowerCase(),
      direction: event.direction || event.flowDirection,
      boundary: event.trafficPath
    }),
    traffic: compact({ bytes: number(event.bytes), packets: number(event.packets) }),
    tls: event.tlsVersion || event.cipher || event.sni ? compact({ version: event.tlsVersion, cipher: event.cipher, sni: event.sni, ja3_hash: event.ja3 }) : undefined,
    cloud: compact({ account: event.accountId ? { uid: String(event.accountId) } : undefined, region: event.region, provider: event.provider }),
    device: compact({ uid: event.interfaceId || event.workload, name: event.workload, type: event.category }),
    api: event.action ? { operation: String(event.action), service: { name: String(event.findingType || event.provider || "") } } : undefined,
    query_info: event.query ? { hostname: String(event.query) } : undefined,
    observables: observables(event),
    metadata: ocsfMetadata(event, metadata),
    raw_data: String(event.raw || "").slice(0, 8192),
    unmapped: compact({
      signalprism_event_id: event.id,
      format: event.format,
      signature: event.signature,
      application: event.application,
      namespace: event.namespace,
      cluster: event.cluster,
      pqc_kem: event.pqcKem
    })
  });
}

export function toOcsfSecurityFinding(finding = {}, metadata = {}) {
  const time = epochMilliseconds(finding.lastSeen || finding.createdAt);
  return compact({
    class_uid: SECURITY_FINDING_CLASS_UID,
    class_name: "Security Finding",
    category_uid: 2,
    category_name: "Findings",
    activity_id: 1,
    activity_name: "Create",
    type_uid: SECURITY_FINDING_CLASS_UID * 100 + 1,
    time,
    start_time: epochMilliseconds(finding.firstSeen || finding.createdAt),
    end_time: time,
    severity_id: severityId(finding.severity),
    severity: normalizeSeverity(finding.severity),
    status: String(finding.status || "new"),
    title: String(finding.title || finding.ruleId || "SignalPrism finding"),
    message: String(finding.summary || finding.narrative || "").slice(0, 4096),
    finding_info: compact({
      uid: String(finding.id || ""),
      title: String(finding.title || finding.ruleId || "SignalPrism finding"),
      analytic: finding.ruleId ? { uid: String(finding.ruleId), name: String(finding.title || finding.ruleId), type: "Rule" } : undefined,
      types: [String(finding.tactic || "Network Detection")]
    }),
    attacks: finding.technique || finding.tactic ? [compact({ tactic: { name: finding.tactic }, technique: { name: finding.technique } })] : undefined,
    resources: (finding.entities || [finding.entity]).filter(Boolean).slice(0, 100).map((entity) => ({ uid: String(entity), name: String(entity), type: "Network Entity" })),
    observables: (finding.entities || [finding.entity]).filter(Boolean).slice(0, 100).map((entity) => ({ name: "entity", type: "Unknown", value: String(entity) })),
    metadata: ocsfMetadata(finding, metadata),
    unmapped: compact({
      signalprism_signal_id: finding.id,
      score: number(finding.score),
      confidence: number(finding.confidence),
      evidence_ids: finding.evidenceIds,
      signal_ids: finding.signalIds,
      stages: finding.stages,
      blast_radius: finding.blastRadius
    })
  });
}

export function buildOcsfBatch({ events = [], findings = [], campaigns = [] } = {}, metadata = {}) {
  const profile = resolveOcsfProfile(metadata.profile || "native-current");
  const effectiveMetadata = { ...metadata, profile: profile.id, ocsfVersion: profile.version };
  const records = [
    ...events.map((event) => toOcsfNetworkActivity(event, effectiveMetadata)),
    ...findings.map((finding) => toOcsfSecurityFinding(finding, effectiveMetadata)),
    ...campaigns.map((campaign) => toOcsfSecurityFinding(campaign, effectiveMetadata))
  ].sort((a, b) => a.time - b.time || a.class_uid - b.class_uid);
  const errors = [];
  records.forEach((record, index) => {
    try {
      validateOcsfRecord(record, profile);
    } catch (error) {
      errors.push({ index, error: error.message });
    }
  });
  const accepted = records.filter((_, index) => !errors.some((item) => item.index === index));
  const partitions = [...new Set(accepted.map((record) => securityLakePartition(record, metadata)))];
  const eventClassBatches = [...new Set(accepted.map((record) => record.class_uid))].map((classUid) => {
    const classRecords = accepted.filter((record) => record.class_uid === classUid);
    return {
      classUid,
      className: classRecords[0]?.class_name || "Unknown",
      sourceKey: `${profile.id}-${classUid}`,
      recordCount: classRecords.length,
      firstEventTime: classRecords[0]?.time || null,
      lastEventTime: classRecords.at(-1)?.time || null,
      records: classRecords
    };
  });
  return {
    profile: profile.id,
    ocsfVersion: profile.version,
    destination: profile.destination,
    compression: profile.compression,
    deliveryPolicy: { maxIntervalSeconds: 300, sizeAware: true, orderedByEventTime: true },
    constraints: profile.constraints,
    sourceVersion: metadata.sourceVersion || "1.0.0",
    generatedAt: new Date().toISOString(),
    recordCount: accepted.length,
    rejectedCount: errors.length,
    errors: errors.slice(0, 100),
    partitions,
    eventClassBatches,
    records: accepted
  };
}

export function buildFirehoseRecords(records, maxRecordBytes = 900_000) {
  const output = [];
  for (const record of records || []) {
    const line = `${JSON.stringify(record)}\n`;
    if (Buffer.byteLength(line) > maxRecordBytes) throw new Error("OCSF record exceeds the Firehose record limit");
    output.push({ Data: Buffer.from(line).toString("base64") });
  }
  return output;
}

export function validateOcsfRecord(record, profileInput = "native-current") {
  const profile = typeof profileInput === "string" ? resolveOcsfProfile(profileInput) : profileInput;
  if (!record || typeof record !== "object" || Array.isArray(record)) throw new Error("OCSF record must be an object");
  for (const field of ["class_uid", "category_uid", "activity_id", "type_uid", "time", "metadata"]) {
    if (record[field] === undefined || record[field] === null) throw new Error(`OCSF record is missing ${field}`);
  }
  if (!Number.isInteger(record.class_uid) || !Number.isInteger(record.type_uid)) throw new Error("OCSF class_uid and type_uid must be integers");
  if (!Number.isFinite(record.time) || record.time <= 0) throw new Error("OCSF time must be epoch milliseconds");
  if (record.metadata.version !== profile.version) throw new Error(`OCSF metadata.version must be ${profile.version}`);
  return true;
}

export function securityLakePartition(record, metadata = {}) {
  const date = new Date(record.time);
  const eventDay = Number.isFinite(date.getTime()) ? date.toISOString().slice(0, 10).replaceAll("-", "") : "unknown";
  const region = sanitizePartition(metadata.region || record.cloud?.region || "global");
  const accountId = sanitizePartition(metadata.accountId || record.cloud?.account?.uid || "unknown");
  return `region=${region}/accountId=${accountId}/eventDay=${eventDay}/`;
}

function ocsfMetadata(record, metadata) {
  const profile = resolveOcsfProfile(metadata.profile || "native-current");
  return compact({
    version: metadata.ocsfVersion || profile.version,
    logged_time: Date.now(),
    uid: String(record.id || ""),
    product: {
      name: "SignalPrism NDR",
      vendor_name: "SignalPrism",
      version: metadata.productVersion || "0.3.0",
      feature: { name: record.format || record.ruleId || "NDR Analytics" }
    },
    profiles: ["cloud", "datetime"],
    extension: { name: "signalprism", version: metadata.sourceVersion || "1.0.0", uid: profile.id },
    tenant_uid: metadata.tenantId
  });
}

function endpoint(ip, port, name) {
  return compact({ ip: ip ? String(ip) : undefined, port: number(port) || undefined, name: name ? String(name) : undefined });
}

function observables(event) {
  return [
    event.sourceIp ? { name: "src_endpoint.ip", type: "IP Address", value: String(event.sourceIp) } : null,
    event.destinationIp ? { name: "dst_endpoint.ip", type: "IP Address", value: String(event.destinationIp) } : null,
    event.identity ? { name: "identity", type: "User Name", value: String(event.identity) } : null,
    event.query ? { name: "query_info.hostname", type: "Hostname", value: String(event.query) } : null
  ].filter(Boolean);
}

function activityId(action) {
  if (["allow", "allowed", "accept", "accepted", "success"].includes(action)) return 1;
  if (["deny", "denied", "reject", "rejected", "failure"].includes(action)) return 2;
  return 99;
}

function severityId(value) {
  return { unknown: 0, informational: 1, low: 2, medium: 3, high: 4, critical: 5, fatal: 6 }[normalizeSeverity(value)] || 0;
}

function normalizeSeverity(value) {
  const severity = String(value || "informational").toLowerCase();
  return ["unknown", "informational", "low", "medium", "high", "critical", "fatal"].includes(severity) ? severity : "informational";
}

function epochMilliseconds(value) {
  const parsed = Date.parse(value || "");
  return Number.isFinite(parsed) ? parsed : Number.NaN;
}

function number(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
}

function compact(value) {
  if (Array.isArray(value)) return value.map(compact).filter((item) => item !== undefined);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).flatMap(([key, item]) => {
    if (item === undefined || item === null || item === "") return [];
    const cleaned = compact(item);
    if (Array.isArray(cleaned) && !cleaned.length) return [];
    if (cleaned && typeof cleaned === "object" && !Array.isArray(cleaned) && !Object.keys(cleaned).length) return [];
    return [[key, cleaned]];
  }));
}

function sanitizePartition(value) {
  return String(value || "unknown").replace(/[^a-zA-Z0-9_.-]+/g, "-").slice(0, 128) || "unknown";
}
