const MAX_ANALYTICS_EVENTS = 20_000;
const MAX_RESULTS = 1_000;
const SEVERITY_WEIGHT = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 };

const AI_SERVICES = [
  { provider: "OpenAI", domains: ["openai.com", "chatgpt.com"] },
  { provider: "Anthropic", domains: ["anthropic.com", "claude.ai"] },
  { provider: "Google Gemini", domains: ["gemini.google.com", "generativelanguage.googleapis.com"] },
  { provider: "AWS Bedrock", domains: ["bedrock.amazonaws.com"] },
  { provider: "Microsoft Copilot", domains: ["copilot.microsoft.com"] },
  { provider: "Cohere", domains: ["cohere.ai"] },
  { provider: "Mistral", domains: ["mistral.ai"] },
  { provider: "Hugging Face", domains: ["huggingface.co"] },
  { provider: "Perplexity", domains: ["perplexity.ai"] }
];

export function buildBehaviorAnalytics(events, options = {}) {
  const ordered = validEvents(events);
  const baselineProfiles = new Map((options.baselineProfiles || []).map((profile) => [profile.entity, profile]));
  const groups = groupBy(ordered, entityForEvent);
  const profiles = [];
  const findings = [];

  for (const [entity, entityEvents] of groups.entries()) {
    if (!entity || entity === "unknown") continue;
    const peers = unique(entityEvents.flatMap((event) => peerForEvent(event, entity)).filter(Boolean));
    const ports = unique(entityEvents.map((event) => Number(event.destinationPort || 0)).filter(Boolean));
    const actions = unique(entityEvents.map((event) => event.action).filter(Boolean));
    const totalBytes = sum(entityEvents.map((event) => number(event.bytes)));
    const failures = entityEvents.filter((event) => event.outcome === "failure");
    const activeHours = unique(entityEvents.map((event) => new Date(event.timestamp).getUTCHours())).sort((a, b) => a - b);
    const baseline = baselineProfiles.get(entity);
    const profile = {
      id: `behavior-profile-${stableHash(entity)}`,
      entity,
      eventCount: entityEvents.length,
      totalBytes,
      peerCount: peers.length,
      peers: peers.slice(0, 250),
      ports: ports.slice(0, 100),
      actions: actions.slice(0, 100),
      activeHours,
      firstSeen: entityEvents[0]?.timestamp || "",
      lastSeen: entityEvents.at(-1)?.timestamp || "",
      baselineStatus: baseline ? "compared" : "learning",
      riskScore: 0,
      findingIds: []
    };

    const newPeers = baseline ? peers.filter((peer) => !(baseline.peers || []).includes(peer)) : [];
    if (newPeers.length) {
      findings.push(behaviorFinding({
        ruleId: "SP-UEBA-001",
        title: "New peer relationship",
        severity: newPeers.length >= 5 ? "high" : "medium",
        score: Math.min(92, 58 + newPeers.length * 6),
        entity,
        summary: `${entity} communicated with ${newPeers.length} peer${newPeers.length === 1 ? "" : "s"} absent from its approved baseline.`,
        reason: "peer-set deviation",
        evidence: entityEvents.filter((event) => newPeers.some((peer) => peerForEvent(event, entity).includes(peer))).slice(0, 50),
        attributes: { newPeers: newPeers.slice(0, 25) }
      }));
    }

    const newPorts = baseline ? ports.filter((port) => !(baseline.ports || []).includes(port)) : [];
    if (newPorts.length) {
      findings.push(behaviorFinding({
        ruleId: "SP-UEBA-002",
        title: "New destination service",
        severity: newPorts.some((port) => [22, 3389, 445, 5432, 6379].includes(port)) ? "high" : "medium",
        score: Math.min(90, 55 + newPorts.length * 5),
        entity,
        summary: `${entity} accessed previously unseen destination port${newPorts.length === 1 ? "" : "s"}: ${newPorts.slice(0, 8).join(", ")}.`,
        reason: "service-set deviation",
        evidence: entityEvents.filter((event) => newPorts.includes(Number(event.destinationPort))).slice(0, 50),
        attributes: { newPorts: newPorts.slice(0, 25) }
      }));
    }

    const offHours = entityEvents.filter((event) => {
      const hour = new Date(event.timestamp).getUTCHours();
      return hour < number(options.businessHourStart, 6) || hour >= number(options.businessHourEnd, 20);
    });
    if (offHours.length >= Math.max(3, Math.ceil(entityEvents.length * 0.35))) {
      findings.push(behaviorFinding({
        ruleId: "SP-UEBA-003",
        title: "Off-hours activity concentration",
        severity: offHours.some((event) => event.severity === "high" || event.severity === "critical") ? "high" : "medium",
        score: Math.min(88, 50 + Math.round((offHours.length / entityEvents.length) * 35)),
        entity,
        summary: `${offHours.length} of ${entityEvents.length} events occurred outside the configured UTC business window.`,
        reason: "time-of-day deviation",
        evidence: offHours.slice(0, 50),
        attributes: { businessHourStart: number(options.businessHourStart, 6), businessHourEnd: number(options.businessHourEnd, 20) }
      }));
    }

    const bytes = entityEvents.map((event) => number(event.bytes));
    const average = mean(bytes);
    const deviation = stddev(bytes, average);
    const spikes = entityEvents.filter((event) => number(event.bytes) >= Math.max(1_000_000, average + deviation * 3));
    if (spikes.length) {
      findings.push(behaviorFinding({
        ruleId: "SP-UEBA-004",
        title: "Volume deviation",
        severity: spikes.some((event) => number(event.bytes) >= 50_000_000) ? "high" : "medium",
        score: Math.min(95, 62 + spikes.length * 5),
        entity,
        summary: `${spikes.length} flow${spikes.length === 1 ? "" : "s"} exceeded the learned byte-volume threshold of ${Math.round(Math.max(1_000_000, average + deviation * 3)).toLocaleString()} bytes.`,
        reason: "volume z-score",
        evidence: spikes.slice(0, 50),
        attributes: { averageBytes: Math.round(average), standardDeviation: Math.round(deviation) }
      }));
    }

    const beacon = detectBeacon(entityEvents);
    if (beacon) {
      findings.push(behaviorFinding({
        ruleId: "SP-UEBA-005",
        title: "Periodic connection pattern",
        severity: "high",
        score: Math.min(96, 72 + beacon.events.length * 2),
        entity,
        summary: `${entity} contacted ${beacon.peer} at a median interval of ${Math.round(beacon.intervalSeconds)} seconds with ${Math.round(beacon.regularity * 100)}% regularity.`,
        reason: "low-jitter periodicity",
        evidence: beacon.events.slice(0, 50),
        attributes: { peer: beacon.peer, intervalSeconds: Math.round(beacon.intervalSeconds), regularity: beacon.regularity }
      }));
    }

    if (failures.length >= 5) {
      findings.push(behaviorFinding({
        ruleId: "SP-UEBA-006",
        title: "Repeated failure behavior",
        severity: failures.length >= 15 ? "high" : "medium",
        score: Math.min(91, 55 + failures.length * 2),
        entity,
        summary: `${entity} generated ${failures.length} failed or denied events in the analysis window.`,
        reason: "failure-rate threshold",
        evidence: failures.slice(0, 50),
        attributes: { failureRate: failures.length / entityEvents.length }
      }));
    }

    const entityFindings = findings.filter((finding) => finding.entity === entity);
    profile.findingIds = entityFindings.map((finding) => finding.id);
    profile.riskScore = entityFindings.length ? Math.min(100, Math.round(mean(entityFindings.map((finding) => finding.score)) + entityFindings.length * 2)) : 0;
    profiles.push(profile);
  }

  return {
    generatedAt: new Date().toISOString(),
    eventCount: ordered.length,
    entityCount: profiles.length,
    baselineProfileCount: baselineProfiles.size,
    profiles: profiles.sort((a, b) => b.riskScore - a.riskScore || b.eventCount - a.eventCount),
    findings: findings.sort(compareFindings).slice(0, MAX_RESULTS)
  };
}

export function buildAttackCampaigns({ findings = [], anomalies = [], events = [] } = {}, options = {}) {
  const signals = [...findings, ...anomalies]
    .filter(Boolean)
    .slice(0, 5_000)
    .map((signal, index) => normalizeSignal(signal, index));
  const eventIndex = new Map(validEvents(events).map((event) => [event.id, event]));
  const windowMs = Math.max(5, Math.min(10_080, number(options.windowMinutes, 240))) * 60_000;
  const parent = signals.map((_, index) => index);
  const find = (index) => parent[index] === index ? index : (parent[index] = find(parent[index]));
  const union = (a, b) => {
    const rootA = find(a);
    const rootB = find(b);
    if (rootA !== rootB) parent[rootB] = rootA;
  };

  for (let left = 0; left < signals.length; left += 1) {
    for (let right = left + 1; right < signals.length; right += 1) {
      const related = signals[left].entities.some((entity) => signals[right].entities.includes(entity)) ||
        signals[left].evidenceIds.some((id) => signals[right].evidenceIds.includes(id));
      const distance = Math.abs(Date.parse(signals[left].lastSeen) - Date.parse(signals[right].firstSeen));
      if (related && Number.isFinite(distance) && distance <= windowMs) union(left, right);
    }
  }

  const components = new Map();
  signals.forEach((signal, index) => {
    const root = find(index);
    if (!components.has(root)) components.set(root, []);
    components.get(root).push(signal);
  });

  const campaigns = [...components.values()].map((group) => {
    const evidenceIds = unique(group.flatMap((signal) => signal.evidenceIds));
    const entities = unique(group.flatMap((signal) => signal.entities));
    const stages = unique(group.map((signal) => campaignStage(signal.tactic, signal.title))).sort((a, b) => stageOrder(a) - stageOrder(b));
    const relatedEvents = evidenceIds.map((id) => eventIndex.get(id)).filter(Boolean);
    const score = Math.min(100, Math.round(mean(group.map((signal) => signal.score)) + Math.min(20, group.length * 3) + Math.min(10, stages.length * 2)));
    const firstSeen = group.map((signal) => signal.firstSeen).sort()[0];
    const lastSeen = group.map((signal) => signal.lastSeen).sort().at(-1);
    const id = `campaign-${stableHash(`${entities.join("|")}|${group.map((signal) => signal.id).join("|")}`)}`;
    return {
      id,
      title: campaignTitle(stages, entities),
      severity: score >= 90 ? "critical" : score >= 75 ? "high" : score >= 50 ? "medium" : "low",
      score,
      confidence: Math.min(0.99, 0.45 + group.length * 0.08 + stages.length * 0.05),
      status: "new",
      firstSeen,
      lastSeen,
      stages,
      entities,
      signalIds: group.map((signal) => signal.id),
      evidenceIds: evidenceIds.slice(0, 250),
      sourceFormats: unique(relatedEvents.map((event) => event.format).filter(Boolean)),
      blastRadius: {
        entityCount: entities.length,
        accountCount: unique(relatedEvents.map((event) => event.accountId).filter(Boolean)).length,
        regionCount: unique(relatedEvents.map((event) => event.region).filter(Boolean)).length
      },
      narrative: `${group.length} linked signal${group.length === 1 ? "" : "s"} connect ${entities.length} entit${entities.length === 1 ? "y" : "ies"} across ${stages.join(" -> ")}.`,
      createdAt: new Date().toISOString()
    };
  });

  return campaigns.sort((a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity] || b.score - a.score).slice(0, MAX_RESULTS);
}

export function runRetrospectiveHunt(events, query, options = {}) {
  const expression = parseHuntQuery(query);
  const ordered = validEvents(events);
  const startedAt = new Date().toISOString();
  const matches = ordered.filter((event) => expression.test(event)).slice(0, Math.max(1, Math.min(MAX_RESULTS, number(options.limit, 500))));
  return {
    id: `hunt-${stableHash(`${query}|${startedAt}`)}`,
    query: String(query || "").trim(),
    normalizedQuery: expression.normalized,
    status: "completed",
    startedAt,
    completedAt: new Date().toISOString(),
    scanned: ordered.length,
    matchCount: matches.length,
    truncated: matches.length >= number(options.limit, 500),
    facets: {
      severity: facet(matches, "severity"),
      format: facet(matches, "format"),
      action: facet(matches, "action"),
      destinationPort: facet(matches, "destinationPort")
    },
    matches
  };
}

export function parseHuntQuery(query) {
  const source = String(query || "").trim();
  if (!source) return { normalized: "*", test: () => true };
  if (source.length > 2_000) throw new Error("Hunt query exceeds 2,000 characters");
  const tokens = tokenizeQuery(source);
  let cursor = 0;
  const peek = () => tokens[cursor];
  const consume = () => tokens[cursor++];

  const parsePrimary = () => {
    if (peek() === "(") {
      consume();
      const node = parseOr();
      if (consume() !== ")") throw new Error("Unclosed hunt query group");
      return node;
    }
    const token = consume();
    if (!token || ["AND", "OR", ")"].includes(token)) throw new Error("Expected a hunt query predicate");
    return predicate(token);
  };
  const parseNot = () => peek() === "NOT" ? (consume(), { type: "not", child: parseNot() }) : parsePrimary();
  const parseAnd = () => {
    let node = parseNot();
    while (cursor < tokens.length && peek() !== ")" && peek() !== "OR") {
      if (peek() === "AND") consume();
      node = { type: "and", left: node, right: parseNot() };
    }
    return node;
  };
  const parseOr = () => {
    let node = parseAnd();
    while (peek() === "OR") {
      consume();
      node = { type: "or", left: node, right: parseAnd() };
    }
    return node;
  };
  const ast = parseOr();
  if (cursor !== tokens.length) throw new Error(`Unexpected token ${tokens[cursor]}`);
  return { normalized: tokens.join(" "), test: (event) => evaluate(ast, event) };
}

export function backtestDetectionRule(rule = {}, events = [], labels = {}) {
  const result = runRetrospectiveHunt(events, rule.query || rule.expression || "", { limit: MAX_RESULTS });
  const malicious = new Set(Array.isArray(labels.maliciousEventIds) ? labels.maliciousEventIds : []);
  const benign = new Set(Array.isArray(labels.benignEventIds) ? labels.benignEventIds : []);
  const matched = new Set(result.matches.map((event) => event.id));
  const truePositives = [...matched].filter((id) => malicious.has(id)).length;
  const falsePositives = [...matched].filter((id) => benign.has(id)).length;
  const falseNegatives = [...malicious].filter((id) => !matched.has(id)).length;
  const precision = truePositives + falsePositives ? truePositives / (truePositives + falsePositives) : null;
  const recall = truePositives + falseNegatives ? truePositives / (truePositives + falseNegatives) : null;
  const noiseRate = result.scanned ? result.matchCount / result.scanned : 0;
  return {
    id: `backtest-${stableHash(`${rule.id || rule.name}|${new Date().toISOString()}`)}`,
    ruleId: rule.id || "draft",
    query: result.normalizedQuery,
    status: "completed",
    scanned: result.scanned,
    matched: result.matchCount,
    truePositives,
    falsePositives,
    falseNegatives,
    precision,
    recall,
    noiseRate,
    qualityGate: result.matchCount > 0 && noiseRate <= number(rule.maxNoiseRate, 0.2) && (precision === null || precision >= number(rule.minimumPrecision, 0.6)) ? "pass" : "review",
    evidenceIds: result.matches.slice(0, 100).map((event) => event.id),
    completedAt: new Date().toISOString()
  };
}

export function analyzeAiTraffic(events, policy = {}) {
  const sanctioned = new Set((policy.sanctionedProviders || ["AWS Bedrock"]).map((item) => String(item).toLowerCase()));
  const observations = [];
  for (const event of validEvents(events)) {
    const searchable = [event.query, event.resource, event.sni, event.destinationDomain, event.destinationIp].filter(Boolean).join(" ").toLowerCase();
    const service = AI_SERVICES.find((entry) => entry.domains.some((domain) => searchable.includes(domain)));
    if (!service) continue;
    const approved = sanctioned.has(service.provider.toLowerCase());
    observations.push({
      eventId: event.id,
      timestamp: event.timestamp,
      entity: entityForEvent(event),
      provider: service.provider,
      destination: event.query || event.sni || event.resource || event.destinationIp,
      bytes: number(event.bytes),
      status: approved ? "sanctioned" : "unsanctioned",
      severity: approved ? "informational" : number(event.bytes) >= 10_000_000 ? "high" : "medium"
    });
  }
  return {
    generatedAt: new Date().toISOString(),
    observedEvents: observations.length,
    unsanctionedEvents: observations.filter((item) => item.status === "unsanctioned").length,
    totalBytes: sum(observations.map((item) => item.bytes)),
    providers: countBy(observations, (item) => item.provider),
    users: unique(observations.map((item) => item.entity)),
    observations: observations.slice(0, MAX_RESULTS)
  };
}

export function analyzeCryptoPosture(events) {
  const observations = validEvents(events).filter((event) => event.tlsVersion || event.cipher || event.certificateExpiresAt || event.pqcKem || [443, 8443].includes(Number(event.destinationPort)));
  const findings = [];
  for (const event of observations) {
    const version = String(event.tlsVersion || "").toUpperCase();
    const cipher = String(event.cipher || "").toUpperCase();
    if (["SSLV2", "SSLV3", "TLS1", "TLS1.0", "TLS1.1"].includes(version)) {
      findings.push(cryptoFinding(event, "SP-CRYPTO-001", "Deprecated TLS protocol", "high", `${version} is below the enterprise minimum of TLS 1.2.`));
    }
    if (/RC4|3DES|DES|NULL|EXPORT|MD5/.test(cipher)) {
      findings.push(cryptoFinding(event, "SP-CRYPTO-002", "Weak cipher suite", "high", `${cipher} contains a deprecated cryptographic primitive.`));
    }
    const expiry = Date.parse(event.certificateExpiresAt || "");
    if (Number.isFinite(expiry) && expiry - Date.now() <= 30 * 86400_000) {
      const expired = expiry <= Date.now();
      findings.push(cryptoFinding(event, "SP-CRYPTO-003", expired ? "Expired certificate" : "Certificate expiry approaching", expired ? "critical" : "medium", `Certificate expiry is ${new Date(expiry).toISOString()}.`));
    }
  }
  return {
    generatedAt: new Date().toISOString(),
    observedSessions: observations.length,
    tlsVersions: countBy(observations, (event) => event.tlsVersion || "unknown"),
    ciphers: countBy(observations, (event) => event.cipher || "unknown"),
    pqcCoverage: observations.length ? observations.filter((event) => event.pqcKem).length / observations.length : 0,
    pqcKems: countBy(observations.filter((event) => event.pqcKem), (event) => event.pqcKem),
    findings: dedupe(findings, (item) => `${item.ruleId}|${item.entity}|${item.evidenceIds[0]}`).slice(0, MAX_RESULTS)
  };
}

function validEvents(events) {
  return (Array.isArray(events) ? events : [])
    .filter((event) => event && Number.isFinite(Date.parse(event.timestamp)))
    .slice(0, MAX_ANALYTICS_EVENTS)
    .sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
}

function detectBeacon(events) {
  const peerGroups = groupBy(events, (event) => peerForEvent(event, entityForEvent(event))[0] || "unknown");
  let best = null;
  for (const [peer, group] of peerGroups.entries()) {
    if (peer === "unknown" || group.length < 5) continue;
    const intervals = group.slice(1).map((event, index) => (Date.parse(event.timestamp) - Date.parse(group[index].timestamp)) / 1000).filter((value) => value > 0);
    if (intervals.length < 4) continue;
    const median = intervals.slice().sort((a, b) => a - b)[Math.floor(intervals.length / 2)];
    const jitter = mean(intervals.map((value) => Math.abs(value - median))) / Math.max(1, median);
    const regularity = Math.max(0, 1 - jitter);
    if (median >= 10 && regularity >= 0.88 && (!best || regularity > best.regularity)) best = { peer, events: group, intervalSeconds: median, regularity };
  }
  return best;
}

function behaviorFinding({ ruleId, title, severity, score, entity, summary, reason, evidence, attributes }) {
  const evidenceIds = unique(evidence.map((event) => event.id).filter(Boolean));
  return {
    id: `behavior-${stableHash(`${ruleId}|${entity}|${evidenceIds.join("|")}`)}`,
    ruleId,
    title,
    severity,
    score,
    confidence: Math.min(0.99, score / 100),
    entity,
    tactic: ruleId === "SP-UEBA-004" ? "Exfiltration" : ruleId === "SP-UEBA-005" ? "Command and Control" : "Discovery",
    technique: ruleId === "SP-UEBA-005" ? "T1071 Application Layer Protocol" : "T1087 Account Discovery",
    summary,
    explanation: { reason, attributes },
    firstSeen: evidence.map((event) => event.timestamp).sort()[0] || "",
    lastSeen: evidence.map((event) => event.timestamp).sort().at(-1) || "",
    evidenceIds: evidenceIds.slice(0, 100),
    status: "new",
    createdAt: new Date().toISOString()
  };
}

function normalizeSignal(signal, index) {
  const firstSeen = validTime(signal.firstSeen || signal.createdAt);
  const lastSeen = validTime(signal.lastSeen || signal.updatedAt || firstSeen);
  const entities = unique([signal.entity, signal.sourceIp, signal.destinationIp, ...(signal.entities || [])].filter(Boolean).map(String));
  return {
    id: String(signal.id || `signal-${index}`),
    title: String(signal.title || signal.ruleId || "Security signal"),
    tactic: String(signal.tactic || "Discovery"),
    score: Math.max(0, Math.min(100, number(signal.score, 50))),
    firstSeen,
    lastSeen,
    entities: entities.length ? entities : ["unknown"],
    evidenceIds: unique((signal.evidenceIds || []).map(String))
  };
}

function campaignStage(tactic = "", title = "") {
  const value = `${tactic} ${title}`.toLowerCase();
  if (/initial|phish|public|exploit/.test(value)) return "Initial Access";
  if (/credential|auth|brute|spray/.test(value)) return "Credential Access";
  if (/privilege|account manipulation/.test(value)) return "Privilege Escalation";
  if (/lateral|remote service/.test(value)) return "Lateral Movement";
  if (/command|beacon|c2/.test(value)) return "Command and Control";
  if (/exfil|tunnel|volume/.test(value)) return "Exfiltration";
  return "Discovery";
}

function stageOrder(value) {
  return ["Initial Access", "Credential Access", "Privilege Escalation", "Discovery", "Lateral Movement", "Command and Control", "Exfiltration"].indexOf(value);
}

function campaignTitle(stages, entities) {
  const lead = stages.at(-1) || "Suspicious activity";
  return `${lead} campaign involving ${entities[0] || "unknown entity"}`;
}

function tokenizeQuery(query) {
  const tokens = [];
  const pattern = /\s*(\(|\)|AND\b|OR\b|NOT\b|(?:[^\s()"']+|"[^"]*"|'[^']*')+)\s*/gi;
  let match;
  let consumed = 0;
  while ((match = pattern.exec(query))) {
    if (match.index !== consumed && query.slice(consumed, match.index).trim()) throw new Error("Invalid hunt query syntax");
    const token = match[1];
    tokens.push(/^(AND|OR|NOT)$/i.test(token) ? token.toUpperCase() : token);
    consumed = pattern.lastIndex;
    if (tokens.length > 200) throw new Error("Hunt query has too many terms");
  }
  if (query.slice(consumed).trim()) throw new Error("Invalid hunt query syntax");
  return tokens;
}

function predicate(token) {
  const match = token.match(/^([a-zA-Z][\w.-]*)(:|!=|>=|<=|>|<|=)(.+)$/);
  if (!match) {
    const needle = unquote(token).toLowerCase();
    return { type: "search", needle };
  }
  const [, field, operator, raw] = match;
  if (!["id", "format", "provider", "category", "accountId", "region", "sourceIp", "sourcePort", "destinationIp", "destinationPort", "protocol", "identity", "action", "outcome", "resource", "query", "severity", "findingType", "signature", "bytes", "application", "namespace", "cluster", "sni", "tlsVersion", "cipher"].includes(field)) {
    throw new Error(`Unsupported hunt field: ${field}`);
  }
  return { type: "predicate", field, operator: operator === ":" ? "=" : operator, value: unquote(raw) };
}

function evaluate(node, event) {
  if (node.type === "and") return evaluate(node.left, event) && evaluate(node.right, event);
  if (node.type === "or") return evaluate(node.left, event) || evaluate(node.right, event);
  if (node.type === "not") return !evaluate(node.child, event);
  if (node.type === "search") return Object.values(event).some((value) => typeof value !== "object" && String(value).toLowerCase().includes(node.needle));
  const actual = event[node.field];
  const expected = node.value;
  if ([">", ">=", "<", "<="].includes(node.operator)) {
    const left = Number(actual);
    const right = Number(expected);
    if (!Number.isFinite(left) || !Number.isFinite(right)) return false;
    return node.operator === ">" ? left > right : node.operator === ">=" ? left >= right : node.operator === "<" ? left < right : left <= right;
  }
  const wildcard = String(expected).includes("*");
  const pattern = wildcard ? new RegExp(`^${escapeRegex(expected).replace(/\\\*/g, ".*")}$`, "i") : null;
  const equal = wildcard ? pattern.test(String(actual ?? "")) : String(actual ?? "").toLowerCase() === String(expected).toLowerCase();
  return node.operator === "!=" ? !equal : equal;
}

function cryptoFinding(event, ruleId, title, severity, summary) {
  return {
    id: `crypto-${stableHash(`${ruleId}|${event.id}`)}`,
    ruleId,
    title,
    severity,
    score: severity === "critical" ? 95 : severity === "high" ? 82 : 62,
    entity: entityForEvent(event),
    summary,
    evidenceIds: [event.id],
    firstSeen: event.timestamp,
    lastSeen: event.timestamp,
    status: "new"
  };
}

function entityForEvent(event) {
  if (event.category === "authentication") return String(event.sourceIp || event.identity || event.destinationIp || "unknown");
  if (["workload", "workload-network"].includes(event.category)) return String(event.workload || event.identity || event.sourceIp || "unknown");
  return String(event.identity || event.sourceIp || event.destinationIp || event.resource || "unknown");
}

function peerForEvent(event, entity) {
  return unique([event.sourceIp, event.destinationIp, event.identity].filter((value) => value && String(value) !== entity).map(String));
}

function facet(items, field) {
  return countBy(items, (item) => String(item[field] ?? "unknown"));
}

function countBy(items, keyFn) {
  const counts = {};
  for (const item of items) {
    const key = String(keyFn(item) || "unknown").slice(0, 200);
    counts[key] = (counts[key] || 0) + 1;
  }
  return Object.fromEntries(Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 100));
}

function compareFindings(a, b) {
  return (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0) || b.score - a.score;
}

function groupBy(items, keyFn) {
  const groups = new Map();
  for (const item of items) {
    const key = keyFn(item);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  return groups;
}

function dedupe(items, keyFn) {
  return [...new Map(items.map((item) => [keyFn(item), item])).values()];
}

function unique(items) {
  return [...new Set(items)];
}

function mean(items) {
  return items.length ? sum(items) / items.length : 0;
}

function stddev(items, average = mean(items)) {
  return items.length ? Math.sqrt(mean(items.map((value) => (value - average) ** 2))) : 0;
}

function sum(items) {
  return items.reduce((total, value) => total + number(value), 0);
}

function number(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function validTime(value) {
  const parsed = Date.parse(value || "");
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : new Date().toISOString();
}

function unquote(value) {
  const text = String(value || "");
  return (/^".*"$/.test(text) || /^'.*'$/.test(text)) ? text.slice(1, -1) : text;
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function stableHash(value) {
  let hash = 2166136261;
  for (let index = 0; index < String(value).length; index += 1) {
    hash ^= String(value).charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}
