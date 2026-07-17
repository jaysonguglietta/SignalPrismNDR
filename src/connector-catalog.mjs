const CATALOG = Object.freeze([
  connector("aws-security-lake", "AWS Security Lake", "data-lake", "outbound", ["ocsf", "firehose"], ["streamName", "region"]),
  connector("aws-security-hub", "AWS Security Hub", "siem", "outbound", ["asff", "eventbridge"], ["region"]),
  connector("gigamon-vseries", "Gigamon V Series / AMI", "network-sensor", "inbound", ["ipfix", "cef", "json"], ["sourceId"]),
  connector("corelight", "Corelight Sensor", "network-sensor", "inbound", ["zeek-json", "kafka", "s3"], ["sourceId"]),
  connector("extrahop", "ExtraHop RevealX", "network-sensor", "bidirectional", ["json", "syslog", "webhook"], ["endpoint", "secretRef"]),
  connector("splunk-hec", "Splunk HEC", "siem", "outbound", ["json", "hec"], ["endpoint", "secretRef"]),
  connector("elastic", "Elastic Security", "siem", "outbound", ["ecs-json", "eventbridge"], ["endpoint", "secretRef"]),
  connector("microsoft-sentinel", "Microsoft Sentinel", "siem", "outbound", ["ocsf", "cef", "eventbridge"], ["endpoint", "secretRef"]),
  connector("servicenow", "ServiceNow SecOps", "case-management", "outbound", ["eventbridge", "webhook"], ["endpoint", "secretRef"]),
  connector("jira", "Jira Service Management", "case-management", "outbound", ["eventbridge", "webhook"], ["endpoint", "secretRef"]),
  connector("slack", "Slack", "notification", "outbound", ["eventbridge", "webhook"], ["endpoint", "secretRef"]),
  connector("microsoft-teams", "Microsoft Teams", "notification", "outbound", ["eventbridge", "webhook"], ["endpoint", "secretRef"]),
  connector("pagerduty", "PagerDuty", "notification", "outbound", ["eventbridge"], ["secretRef"]),
  connector("email-notification", "Email / Amazon SES", "notification", "outbound", ["eventbridge"], ["region"]),
  connector("crowdstrike", "CrowdStrike Falcon", "response", "outbound", ["eventbridge"], ["secretRef"]),
  connector("defender", "Microsoft Defender for Endpoint", "response", "outbound", ["eventbridge"], ["secretRef"]),
  connector("taxii", "TAXII 2.1 Threat Intelligence", "threat-intelligence", "inbound", ["taxii", "stix"], ["endpoint", "secretRef"]),
  connector("misp", "MISP", "threat-intelligence", "inbound", ["stix", "json"], ["endpoint", "secretRef"]),
  connector("kafka", "Apache Kafka", "streaming", "bidirectional", ["json", "ocsf"], ["endpoint", "secretRef"]),
  connector("syslog", "Syslog / CEF", "streaming", "bidirectional", ["cef", "syslog"], ["endpoint"])
]);

export function connectorCatalog() {
  return CATALOG.map((item) => ({ ...item, formats: [...item.formats], requiredFields: [...item.requiredFields] }));
}

export function normalizeConnector(input = {}, principal = {}, existing = null) {
  const catalog = CATALOG.find((item) => item.id === input.catalogId);
  if (!catalog) throw new Error("Select a supported connector type");
  const endpoint = normalizeEndpoint(input.endpoint || existing?.endpoint || "", catalog);
  const secretRef = normalizeSecretReference(input.secretRef || existing?.secretRef || "");
  const now = new Date().toISOString();
  const id = clean(input.id || existing?.id || `connector-${crypto.randomUUID()}`, 180);
  return {
    id,
    catalogId: catalog.id,
    name: clean(input.name || existing?.name || catalog.name, 120),
    category: catalog.category,
    direction: catalog.direction,
    format: normalizeFormat(input.format || existing?.format || catalog.formats[0], catalog),
    endpoint,
    region: clean(input.region || existing?.region || "", 80),
    streamName: clean(input.streamName || existing?.streamName || "", 128),
    sourceId: clean(input.sourceId || existing?.sourceId || "", 180),
    secretRef,
    enabled: input.enabled !== false,
    deliveryMode: "eventbridge",
    status: existing?.status || "configured",
    lastTestAt: existing?.lastTestAt || "",
    lastTestStatus: existing?.lastTestStatus || "never",
    tenantId: principal.tenantId,
    createdBy: existing?.createdBy || actor(principal),
    updatedBy: actor(principal),
    createdAt: existing?.createdAt || now,
    updatedAt: now
  };
}

export function publicConnector(connector = {}) {
  return {
    ...connector,
    secretRef: connector.secretRef ? maskSecretReference(connector.secretRef) : "",
    secretConfigured: Boolean(connector.secretRef)
  };
}

export function connectorTestEvent(connector = {}, principal = {}) {
  if (!connector.id || !connector.catalogId) throw new Error("Connector configuration is incomplete");
  return {
    Source: "signalprism.ndr",
    DetailType: "Connector Test Requested",
    Detail: JSON.stringify({
      version: 1,
      connectorId: connector.id,
      catalogId: connector.catalogId,
      tenantId: principal.tenantId,
      requestedBy: actor(principal),
      requestedAt: new Date().toISOString()
    })
  };
}

function connector(id, name, category, direction, formats, requiredFields) {
  return { id, name, category, direction, formats, requiredFields, executionBoundary: "eventbridge-adapter" };
}

function normalizeEndpoint(value, catalog) {
  const text = clean(value, 512);
  if (!text) return "";
  if (catalog.id === "syslog") {
    if (!/^syslogs?:\/\/[a-zA-Z0-9.-]+:\d{1,5}$/.test(text)) throw new Error("Syslog endpoint must use syslog:// or syslogs:// with an explicit port");
    return text;
  }
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new Error("Connector endpoint must be a valid URL");
  }
  if (url.protocol !== "https:") throw new Error("Connector endpoints must use HTTPS");
  if (url.username || url.password) throw new Error("Connector endpoints cannot contain embedded credentials");
  if (isPrivateHost(url.hostname)) throw new Error("Private or loopback connector endpoints require a separately deployed adapter");
  url.hash = "";
  return url.toString().slice(0, 512);
}

function normalizeSecretReference(value) {
  const text = clean(value, 512);
  if (!text) return "";
  if (!/^arn:(aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:\d{12}:secret:[A-Za-z0-9/_+=.@-]+$/.test(text)) {
    throw new Error("Secrets must be referenced by an AWS Secrets Manager ARN");
  }
  return text;
}

function normalizeFormat(value, catalog) {
  const format = clean(value, 80).toLowerCase();
  if (!catalog.formats.includes(format)) throw new Error(`${catalog.name} does not support format ${format}`);
  return format;
}

function isPrivateHost(hostname) {
  const host = String(hostname || "").toLowerCase();
  return host === "localhost" || host === "::1" || host.endsWith(".local") || /^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host) || /^169\.254\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host);
}

function maskSecretReference(value) {
  const text = String(value);
  const index = text.lastIndexOf(":secret:");
  return index >= 0 ? `${text.slice(0, index + 8)}${text.slice(index + 8, index + 14)}...` : "configured";
}

function clean(value, limit) {
  return String(value ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, limit);
}

function actor(principal) {
  return principal.email || principal.name || principal.subject || "unknown";
}
