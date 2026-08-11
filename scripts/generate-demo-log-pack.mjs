import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outputDir = join(root, "samples", "demo-pack");
const accountId = "111122223333";
const sharedAccountId = "444455556666";
const vpcId = "vpc-0a11ce5ec0ffee123";
const headerFields = [
  "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
  "packets", "bytes", "start", "end", "action", "log-status", "vpc-id", "subnet-id", "instance-id",
  "tcp-flags", "type", "pkt-srcaddr", "pkt-dstaddr", "region", "az-id", "sublocation-type",
  "sublocation-id", "pkt-src-aws-service", "pkt-dst-aws-service", "flow-direction", "traffic-path"
];
const header = `#Fields: ${headerFields.join(" ")}`;

const scenarioCatalog = {
  "normal-web-egress": ["normal", "Routine HTTPS and HTTP workload egress across web and application tiers."],
  "normal-internal-application": ["normal", "Expected east-west application and service-mesh communication."],
  "normal-cloud-services": ["normal", "Expected HTTPS traffic to representative cloud service endpoints."],
  "normal-dns-ntp": ["normal", "Routine DNS and NTP traffic to link-local platform resolvers."],
  "normal-background-rejects": ["normal", "Low-rate internet background noise rejected by perimeter controls."],
  "normal-health-checks": ["normal", "Security and load-balancer health checks against web-tier workloads."],
  "attack-reconnaissance": ["malicious", "Concentrated external scanning across administrative and data-service ports."],
  "attack-ssh-bruteforce": ["malicious", "Repeated SSH authentication attempts against the production bastion."],
  "attack-public-ssh-access": ["malicious", "Accepted SSH access from an untrusted public source after brute-force activity."],
  "attack-lateral-movement": ["malicious", "Compromised workload access to internal SSH, SMB, RDP, and database services."],
  "attack-c2-beaconing": ["malicious", "Regular outbound TLS-like callbacks from the compromised application host."],
  "attack-dns-tunneling": ["malicious", "High-volume DNS flows from the compromised host to an unapproved resolver."],
  "attack-data-exfiltration": ["malicious", "Large encrypted transfers from a data-tier workload to an untrusted endpoint."],
  "attack-smb-spread": ["malicious", "High-cardinality SMB fan-out consistent with worm or ransomware propagation."],
  "attack-unusual-gre": ["malicious", "Accepted GRE traffic from a workload without an approved tunneling use case."],
  "attack-data-staging": ["malicious", "Large east-west transfers into the compromised host before external exfiltration."],
  "quality-nodata": ["quality", "Quiet ENI intervals reported as NODATA."],
  "quality-skipdata": ["quality", "Collection intervals reported as SKIPDATA and requiring source-health review."],
  "quality-malformed": ["quality", "Intentionally truncated records used to exercise parser issue handling."]
};

const profiles = [
  {
    slug: "enterprise-clean-baseline-20000",
    title: "Enterprise clean baseline",
    seed: 0x13579bdf,
    baseTime: "2026-07-14T00:00:00Z",
    spanHours: 24,
    counts: {
      "normal-web-egress": 9000,
      "normal-internal-application": 5000,
      "normal-cloud-services": 2500,
      "normal-dns-ntp": 2000,
      "normal-background-rejects": 1200,
      "normal-health-checks": 300
    },
    expectedFindings: ["No obvious NDR detections"],
    analystStory: "Use this file first to save a stable baseline and understand normal entity, port, protocol, and path distributions."
  },
  {
    slug: "ransomware-intrusion-chain-25000",
    title: "Ransomware intrusion chain",
    seed: 0x2468ace0,
    baseTime: "2026-07-15T00:00:00Z",
    spanHours: 24,
    counts: {
      "normal-web-egress": 9000,
      "normal-internal-application": 6000,
      "normal-cloud-services": 3000,
      "normal-dns-ntp": 2500,
      "normal-background-rejects": 1000,
      "normal-health-checks": 500,
      "attack-reconnaissance": 500,
      "attack-ssh-bruteforce": 350,
      "attack-public-ssh-access": 10,
      "attack-lateral-movement": 500,
      "attack-c2-beaconing": 180,
      "attack-dns-tunneling": 300,
      "attack-data-exfiltration": 60,
      "attack-smb-spread": 700,
      "attack-unusual-gre": 100,
      "attack-data-staging": 300
    },
    expectedFindings: [
      "Rejected SSH traffic", "Source fan-out detected", "Public SSH access accepted", "Internal SMB access",
      "Periodic outbound connection pattern", "Suspicious DNS volume", "Large accepted transfer", "Unusual accepted protocol GRE"
    ],
    analystStory: "A public scan and SSH brute force lead to accepted access, east-west spread, C2, staging, DNS tunneling, and large outbound exfiltration."
  },
  {
    slug: "soc-shift-mixed-35000",
    title: "SOC shift mixed workload",
    seed: 0x0ddc0ffe,
    baseTime: "2026-07-16T00:00:00Z",
    spanHours: 24,
    counts: {
      "normal-web-egress": 13000,
      "normal-internal-application": 8000,
      "normal-cloud-services": 4000,
      "normal-dns-ntp": 3000,
      "normal-background-rejects": 2500,
      "normal-health-checks": 500,
      "attack-reconnaissance": 700,
      "attack-ssh-bruteforce": 500,
      "attack-public-ssh-access": 20,
      "attack-lateral-movement": 500,
      "attack-c2-beaconing": 250,
      "attack-dns-tunneling": 500,
      "attack-data-exfiltration": 80,
      "attack-smb-spread": 600,
      "attack-unusual-gre": 150,
      "attack-data-staging": 200,
      "quality-nodata": 250,
      "quality-skipdata": 220,
      "quality-malformed": 30
    },
    expectedFindings: [
      "Some lines were skipped", "Skipped log data", "No-data intervals present", "Source fan-out detected",
      "Public SSH access accepted", "Periodic outbound connection pattern", "Suspicious DNS volume", "Large accepted transfer"
    ],
    analystStory: "A busy production shift combines normal traffic, a high-confidence intrusion, benign reject noise, and source-quality gaps for a full demo."
  },
  {
    slug: "telemetry-quality-failures-12000",
    title: "Telemetry quality failures",
    seed: 0x5e11f00d,
    baseTime: "2026-07-16T00:00:00Z",
    spanHours: 12,
    counts: {
      "normal-web-egress": 4000,
      "normal-internal-application": 3000,
      "normal-cloud-services": 2000,
      "normal-dns-ntp": 1500,
      "normal-background-rejects": 500,
      "quality-nodata": 500,
      "quality-skipdata": 400,
      "quality-malformed": 100
    },
    expectedFindings: ["Some lines were skipped", "Skipped log data", "No-data intervals present"],
    analystStory: "Use this file to demonstrate non-fatal parser errors, coverage blind spots, skipped delivery, and evidence-quality review."
  }
];

function hashId(prefix, value, length = 17) {
  return `${prefix}-${createHash("sha256").update(String(value)).digest("hex").slice(0, length)}`;
}

function createRandom(seed) {
  let state = seed >>> 0;
  return {
    next() {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state / 0x100000000;
    },
    integer(min, max) {
      return Math.floor(this.next() * (max - min + 1)) + min;
    },
    pick(values) {
      return values[this.integer(0, values.length - 1)];
    }
  };
}

function privateIp(tier, index) {
  const subnet = { web: 10, app: 20, data: 30, shared: 40, security: 50 }[tier];
  return `10.40.${subnet}.${10 + (index % 220)}`;
}

function assetFor(address) {
  const match = String(address).match(/^10\.40\.(10|20|30|40|50)\.(\d+)$/);
  if (!match) return null;
  const subnet = Number(match[1]);
  const tier = { 10: "web", 20: "app", 30: "data", 40: "shared", 50: "security" }[subnet];
  return {
    tier,
    eni: hashId("eni", address),
    subnetId: hashId("subnet", `10.40.${subnet}.0/24`),
    instanceId: hashId("i", address),
    azId: subnet % 20 === 0 ? "use1-az4" : "use1-az2"
  };
}

function createDataset(profile) {
  const random = createRandom(profile.seed);
  const baseTime = Math.floor(Date.parse(profile.baseTime) / 1000);
  const spanSeconds = profile.spanHours * 3600;
  const rows = [];
  const scenarioCounts = {};
  let sequence = 0;

  function atRandomTime() {
    return baseTime + random.integer(0, spanSeconds - 181);
  }

  function addFlow(scenario, options) {
    sequence += 1;
    const source = options.source ?? "-";
    const destination = options.destination ?? "-";
    const action = options.action ?? "ACCEPT";
    const logStatus = options.logStatus ?? "OK";
    const start = options.start ?? atRandomTime();
    const end = start + (options.duration ?? random.integer(2, 120));
    const sourceAsset = assetFor(source);
    const destinationAsset = assetFor(destination);
    const observedAsset = options.flowDirection === "ingress" ? destinationAsset : sourceAsset || destinationAsset;
    const flowDirection = options.flowDirection || (sourceAsset && !destinationAsset ? "egress" : !sourceAsset && destinationAsset ? "ingress" : "ingress");
    const account = observedAsset?.tier === "security" ? sharedAccountId : accountId;
    const protocol = options.protocol ?? 6;
    const values = [
      5,
      account,
      observedAsset?.eni || hashId("eni", `${scenario}-${sequence}`),
      source,
      destination,
      options.srcPort ?? "-",
      options.dstPort ?? "-",
      protocol,
      options.packets ?? "-",
      options.bytes ?? "-",
      start,
      end,
      action,
      logStatus,
      vpcId,
      observedAsset?.subnetId || "-",
      observedAsset?.instanceId || "-",
      options.tcpFlags ?? (protocol === 6 && action === "ACCEPT" ? 19 : protocol === 6 ? 2 : 0),
      options.addressType || "IPv4",
      source,
      destination,
      "us-east-1",
      observedAsset?.azId || "use1-az2",
      "-",
      "-",
      options.sourceService || "-",
      options.destinationService || "-",
      flowDirection,
      options.trafficPath ?? (flowDirection === "egress" ? 2 : 1)
    ];
    rows.push({ scenario, start, sequence, line: values.join(" "), valid: true });
    scenarioCounts[scenario] = (scenarioCounts[scenario] || 0) + 1;
  }

  function addMalformed(scenario, index) {
    sequence += 1;
    const start = baseTime + Math.floor(spanSeconds * 0.58) + index;
    rows.push({ scenario, start, sequence, line: `5 ${accountId} truncated-record-${index} missing-columns`, valid: false });
    scenarioCounts[scenario] = (scenarioCounts[scenario] || 0) + 1;
  }

  const builders = {
    "normal-web-egress": (index) => {
      const hostIndex = index % 440;
      const destinationSlot = (hostIndex * 3 + Math.floor(index / 440) % 8) % 64;
      const packets = random.integer(8, 180);
      addFlow("normal-web-egress", {
        source: privateIp(hostIndex < 220 ? "web" : "app", hostIndex),
        destination: `192.0.2.${10 + destinationSlot}`,
        srcPort: random.integer(32768, 60999), dstPort: random.next() < 0.94 ? 443 : 80,
        packets, bytes: packets * random.integer(180, 1300)
      });
    },
    "normal-internal-application": (index) => {
      const hostIndex = index % 440;
      const sourceTier = hostIndex < 220 ? "web" : "app";
      const destinationTier = sourceTier === "web" ? "app" : hostIndex % 2 === 0 ? "app" : "data";
      const destinationSlot = hostIndex * 7 + Math.floor(index / 440) % 4;
      const packets = random.integer(10, 240);
      addFlow("normal-internal-application", {
        source: privateIp(sourceTier, hostIndex), destination: privateIp(destinationTier, destinationSlot),
        srcPort: random.integer(32768, 60999), dstPort: random.pick([443, 8080, 8443]),
        packets, bytes: packets * random.integer(220, 1400)
      });
    },
    "normal-cloud-services": (index) => {
      const hostIndex = index % 440;
      const destinationSlot = (hostIndex + Math.floor(index / 440) % 2) % 24;
      const packets = random.integer(12, 190);
      addFlow("normal-cloud-services", {
        source: privateIp(hostIndex < 220 ? "app" : "data", hostIndex), destination: `198.51.100.${10 + destinationSlot}`,
        srcPort: random.integer(32768, 60999), dstPort: 443, packets, bytes: packets * random.integer(240, 1450),
        destinationService: random.pick(["AMAZON", "S3", "DYNAMODB"])
      });
    },
    "normal-dns-ntp": (index) => {
      const dns = index % 5 !== 0;
      const packets = dns ? random.integer(1, 14) : random.integer(2, 8);
      addFlow("normal-dns-ntp", {
        source: privateIp(random.pick(["web", "app", "data", "shared"]), index * 19),
        destination: dns ? "169.254.169.253" : "169.254.169.123",
        srcPort: random.integer(32768, 60999), dstPort: dns ? 53 : 123, protocol: 17,
        packets, bytes: packets * random.integer(60, 190), trafficPath: 1
      });
    },
    "normal-background-rejects": (index) => addFlow("normal-background-rejects", {
      source: `203.0.113.${10 + (index % 220)}`, destination: privateIp("web", index * 23),
      srcPort: random.integer(1024, 65535), dstPort: random.pick([80, 443]), packets: random.integer(1, 3),
      bytes: random.integer(40, 240), action: "REJECT", flowDirection: "ingress", duration: random.integer(1, 6)
    }),
    "normal-health-checks": (index) => {
      const packets = random.integer(4, 18);
      addFlow("normal-health-checks", {
        source: privateIp("security", index * 3), destination: privateIp("web", index * 29),
        srcPort: random.integer(32768, 60999), dstPort: 443, packets, bytes: packets * random.integer(120, 500), duration: 5
      });
    },
    "attack-reconnaissance": (index) => {
      const ports = [21, 22, 23, 25, 53, 110, 135, 139, 143, 389, 445, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017];
      addFlow("attack-reconnaissance", {
        source: "198.51.100.66", destination: privateIp(random.pick(["web", "app", "data"]), index),
        srcPort: 40000 + (index % 20000), dstPort: ports[index % ports.length], packets: 1, bytes: 60,
        action: "REJECT", flowDirection: "ingress", start: baseTime + 18 * 3600 + index * 2, duration: 1
      });
    },
    "attack-ssh-bruteforce": (index) => addFlow("attack-ssh-bruteforce", {
      source: `203.0.113.${77 + (index % 3)}`, destination: "10.40.50.10", srcPort: 47000 + (index % 18000), dstPort: 22,
      packets: random.integer(1, 4), bytes: random.integer(60, 340), action: "REJECT", flowDirection: "ingress",
      start: baseTime + 18 * 3600 + 1200 + index * 3, duration: 2
    }),
    "attack-public-ssh-access": (index) => addFlow("attack-public-ssh-access", {
      source: "203.0.113.79", destination: "10.40.50.10", srcPort: 58000 + index, dstPort: 22,
      packets: random.integer(80, 180), bytes: random.integer(70000, 240000), action: "ACCEPT", flowDirection: "ingress",
      start: baseTime + 18 * 3600 + 2400 + index * 45, duration: random.integer(30, 180), tcpFlags: 27
    }),
    "attack-lateral-movement": (index) => {
      const ports = [22, 445, 3389, 5432, 6379];
      const destinationTier = index % 2 === 0 ? "data" : "app";
      const packets = random.integer(20, 240);
      addFlow("attack-lateral-movement", {
        source: "10.40.20.44", destination: privateIp(destinationTier, index * 7), srcPort: 43000 + (index % 20000),
        dstPort: ports[index % ports.length], packets, bytes: packets * random.integer(300, 1300),
        start: baseTime + 19 * 3600 + index * 5, duration: random.integer(8, 90)
      });
    },
    "attack-c2-beaconing": (index) => {
      const packets = 4 + (index % 2);
      addFlow("attack-c2-beaconing", {
        source: "10.40.20.44", destination: "203.0.113.200", srcPort: 50000 + (index % 10000), dstPort: 8443,
        packets, bytes: packets * 96, start: baseTime + 17 * 3600 + index * 60, duration: 4
      });
    },
    "attack-dns-tunneling": (index) => {
      const packets = random.integer(140, 360);
      addFlow("attack-dns-tunneling", {
        source: "10.40.20.44", destination: "198.51.100.53", srcPort: 53000 + (index % 10000), dstPort: 53,
        protocol: 17, packets, bytes: packets * random.integer(180, 430),
        start: baseTime + 20 * 3600 + index * 4, duration: 3
      });
    },
    "attack-data-exfiltration": (index) => {
      const bytes = random.integer(24, 90) * 1024 * 1024;
      addFlow("attack-data-exfiltration", {
        source: "10.40.30.90", destination: "198.51.100.250", srcPort: 59000 + (index % 6000), dstPort: 443,
        packets: Math.ceil(bytes / 1200), bytes, start: baseTime + 22 * 3600 + index * 24, duration: random.integer(45, 180), tcpFlags: 27
      });
    },
    "attack-smb-spread": (index) => {
      const packets = random.integer(30, 260);
      addFlow("attack-smb-spread", {
        source: "10.40.20.44", destination: privateIp(random.pick(["app", "data"]), index * 31),
        srcPort: 44500 + (index % 19000), dstPort: 445, packets, bytes: packets * random.integer(500, 1400),
        start: baseTime + 20 * 3600 + 1800 + index * 3, duration: random.integer(8, 100)
      });
    },
    "attack-unusual-gre": (index) => addFlow("attack-unusual-gre", {
      source: "10.40.20.44", destination: "203.0.113.210", protocol: 47, packets: random.integer(20, 120),
      bytes: random.integer(30000, 400000), start: baseTime + 21 * 3600 + index * 9, duration: random.integer(5, 30)
    }),
    "attack-data-staging": (index) => {
      const bytes = random.integer(2, 8) * 1024 * 1024;
      addFlow("attack-data-staging", {
        source: privateIp("data", index * 37), destination: "10.40.20.44", srcPort: 41000 + (index % 20000), dstPort: 443,
        packets: Math.ceil(bytes / 1200), bytes, start: baseTime + 21 * 3600 + index * 6, duration: random.integer(20, 90)
      });
    },
    "quality-nodata": (index) => addFlow("quality-nodata", {
      source: "-", destination: "-", srcPort: "-", dstPort: "-", protocol: "-", packets: "-", bytes: "-",
      action: "-", logStatus: "NODATA", start: baseTime + Math.floor(spanSeconds * 0.45) + index * 60, duration: 60
    }),
    "quality-skipdata": (index) => addFlow("quality-skipdata", {
      source: privateIp("app", index), destination: "-", srcPort: "-", dstPort: "-", protocol: "-", packets: "-", bytes: "-",
      action: "-", logStatus: "SKIPDATA", start: baseTime + Math.floor(spanSeconds * 0.52) + index * 60, duration: 60
    }),
    "quality-malformed": (index) => addMalformed("quality-malformed", index)
  };

  for (const [scenario, count] of Object.entries(profile.counts)) {
    if (!builders[scenario]) throw new Error(`No builder for ${scenario}`);
    for (let index = 0; index < count; index += 1) builders[scenario](index);
  }

  rows.sort((left, right) => left.start - right.start || left.sequence - right.sequence);
  const logText = `${header}\n${rows.map((row) => row.line).join("\n")}\n`;
  const classificationCounts = Object.entries(scenarioCounts).reduce((result, [scenario, count]) => {
    const classification = scenarioCatalog[scenario][0];
    result[classification] = (result[classification] || 0) + count;
    return result;
  }, {});
  const validRows = rows.filter((row) => row.valid);
  const maliciousRows = rows.filter((row) => scenarioCatalog[row.scenario][0] === "malicious");
  const scenarios = Object.fromEntries(Object.keys(scenarioCounts).map((scenario) => [scenario, {
    classification: scenarioCatalog[scenario][0],
    description: scenarioCatalog[scenario][1],
    count: scenarioCounts[scenario]
  }]));

  return {
    logText,
    manifest: {
      schema: "signalprism.demo-evidence.v1",
      product: "SignalPrism NDR",
      title: profile.title,
      file: `${profile.slug}.log`,
      format: "AWS VPC Flow Logs v5 extended 29-field text",
      fixtureVersion: "2026.07.17",
      deterministicSeed: `0x${profile.seed.toString(16).padStart(8, "0")}`,
      analystStory: profile.analystStory,
      physicalRecordLines: rows.length,
      expectedParsedRecords: validRows.length,
      expectedParserIssues: rows.length - validRows.length,
      classificationCounts,
      scenarioCounts,
      timeRange: {
        start: new Date(validRows[0].start * 1000).toISOString(),
        end: new Date((validRows.at(-1).start + 180) * 1000).toISOString()
      },
      attackWindow: maliciousRows.length ? {
        start: new Date(Math.min(...maliciousRows.map((row) => row.start)) * 1000).toISOString(),
        end: new Date((Math.max(...maliciousRows.map((row) => row.start)) + 180) * 1000).toISOString()
      } : null,
      primaryEntities: {
        compromisedApplicationHost: "10.40.20.44",
        dataExfiltrationSource: "10.40.30.90",
        productionBastion: "10.40.50.10",
        reconnaissanceSource: "198.51.100.66",
        bruteForceSource: "203.0.113.79",
        commandAndControl: "203.0.113.200",
        dnsTunnelResolver: "198.51.100.53",
        exfiltrationDestination: "198.51.100.250"
      },
      expectedFindings: profile.expectedFindings,
      scenarios,
      sha256: createHash("sha256").update(logText).digest("hex"),
      sizeBytes: Buffer.byteLength(logText)
    }
  };
}

await mkdir(outputDir, { recursive: true });
const index = { schema: "signalprism.demo-pack.v1", fixtureVersion: "2026.07.17", datasets: [] };

for (const profile of profiles) {
  const { logText, manifest } = createDataset(profile);
  if (manifest.sizeBytes > 16 * 1024 * 1024) throw new Error(`${manifest.file} exceeds the 16 MB browser upload limit`);
  const logPath = join(outputDir, manifest.file);
  const manifestPath = join(outputDir, `${profile.slug}.manifest.json`);
  await writeFile(logPath, logText, "utf8");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  index.datasets.push({
    title: profile.title,
    file: manifest.file,
    manifest: `${profile.slug}.manifest.json`,
    physicalRecordLines: manifest.physicalRecordLines,
    expectedParsedRecords: manifest.expectedParsedRecords,
    expectedParserIssues: manifest.expectedParserIssues,
    sizeBytes: manifest.sizeBytes,
    sha256: manifest.sha256
  });
  console.log(`Generated ${manifest.file}: ${manifest.physicalRecordLines} lines, ${manifest.sizeBytes} bytes`);
}

await writeFile(join(outputDir, "index.json"), `${JSON.stringify(index, null, 2)}\n`, "utf8");
console.log(`Demo evidence pack written to ${outputDir}`);
