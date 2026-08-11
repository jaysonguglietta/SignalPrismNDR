import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outputDir = join(root, "samples");
const logPath = join(outputDir, "sample-vpc-flow-5000.log");
const manifestPath = join(outputDir, "sample-vpc-flow-5000.manifest.json");
const header = "#Fields: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status";
const accountId = "123456789012";
const baseTime = Math.floor(Date.parse("2026-07-15T00:00:00Z") / 1000);
const events = [];

let randomState = 0x51a1f10;
let sequence = 0;

const scenarios = {
  "normal-web-egress": { classification: "normal", description: "Workload HTTPS and HTTP egress to common public services." },
  "normal-internal-application": { classification: "normal", description: "Expected application-tier and service-to-service traffic." },
  "normal-dns-ntp": { classification: "normal", description: "Routine DNS and NTP traffic." },
  "normal-aws-services": { classification: "normal", description: "HTTPS access to representative AWS service endpoints." },
  "normal-background-rejects": { classification: "normal", description: "Low-rate internet background noise rejected by controls." },
  "malicious-port-scan": { classification: "malicious", description: "External reconnaissance across sensitive service ports." },
  "malicious-ssh-bruteforce": { classification: "malicious", description: "Repeated rejected SSH attempts against a bastion target." },
  "malicious-rdp-bruteforce": { classification: "malicious", description: "Repeated rejected RDP attempts against a Windows target." },
  "malicious-lateral-movement": { classification: "malicious", description: "Accepted internal access to administrative and database services." },
  "malicious-beaconing": { classification: "malicious", description: "Regular outbound callbacks to a fixed command-and-control endpoint." },
  "malicious-dns-tunneling": { classification: "malicious", description: "High-volume DNS traffic to an external resolver." },
  "malicious-exfiltration": { classification: "malicious", description: "Large accepted transfers from a database-tier workload to an external endpoint." }
};

function random() {
  randomState = (Math.imul(randomState, 1664525) + 1013904223) >>> 0;
  return randomState / 0x100000000;
}

function integer(min, max) {
  return Math.floor(random() * (max - min + 1)) + min;
}

function pick(values) {
  return values[integer(0, values.length - 1)];
}

function internalIp(subnet, index) {
  return `10.0.${subnet}.${10 + (index % 220)}`;
}

function interfaceId(address) {
  const digest = createHash("sha256").update(address).digest("hex").slice(0, 8);
  return `eni-${digest}`;
}

function publicNoiseIp(index) {
  return `192.0.2.${10 + (index % 240)}`;
}

function addFlow(scenario, {
  source,
  destination,
  srcPort,
  dstPort,
  protocol = 6,
  packets,
  bytes,
  start,
  duration = 60,
  action = "ACCEPT",
  logStatus = "OK",
  eni = interfaceId(source)
}) {
  sequence += 1;
  const end = start + duration;
  const line = [2, accountId, eni, source, destination, srcPort, dstPort, protocol, packets, bytes, start, end, action, logStatus].join(" ");
  events.push({ sequence, scenario, start, line });
}

for (let index = 0; index < 1800; index += 1) {
  const source = internalIp(1 + (index % 3), index);
  const destination = pick(["1.1.1.1", "8.8.4.4", "13.107.42.14", "142.250.72.14", "151.101.1.69"]);
  const dstPort = random() < 0.92 ? 443 : 80;
  const packets = integer(8, 140);
  addFlow("normal-web-egress", {
    source,
    destination,
    srcPort: integer(32768, 60999),
    dstPort,
    packets,
    bytes: packets * integer(180, 1200),
    start: baseTime + integer(0, 86300),
    duration: integer(10, 120)
  });
}

for (let index = 0; index < 1100; index += 1) {
  const source = internalIp(1, index);
  const destination = internalIp(2, index * 3);
  const dstPort = pick([443, 8080, 8443]);
  const packets = integer(12, 220);
  addFlow("normal-internal-application", {
    source,
    destination,
    srcPort: integer(32768, 60999),
    dstPort,
    packets,
    bytes: packets * integer(220, 1300),
    start: baseTime + integer(0, 86300),
    duration: integer(5, 90)
  });
}

for (let index = 0; index < 700; index += 1) {
  const source = internalIp(1 + (index % 4), index * 7);
  const isDns = index % 5 !== 0;
  const packets = isDns ? integer(1, 12) : integer(2, 8);
  addFlow("normal-dns-ntp", {
    source,
    destination: isDns ? pick(["10.0.0.2", "10.0.0.3"]) : "169.254.169.123",
    srcPort: integer(32768, 60999),
    dstPort: isDns ? 53 : 123,
    protocol: 17,
    packets,
    bytes: packets * integer(60, 180),
    start: baseTime + integer(0, 86300),
    duration: integer(1, 10)
  });
}

for (let index = 0; index < 500; index += 1) {
  const source = internalIp(2 + (index % 2), index * 11);
  const destination = pick(["52.95.110.1", "52.95.245.10", "54.239.28.85", "3.2.1.5"]);
  const packets = integer(10, 180);
  addFlow("normal-aws-services", {
    source,
    destination,
    srcPort: integer(32768, 60999),
    dstPort: 443,
    packets,
    bytes: packets * integer(250, 1400),
    start: baseTime + integer(0, 86300),
    duration: integer(10, 180)
  });
}

for (let index = 0; index < 400; index += 1) {
  const destination = internalIp(1 + (index % 4), index * 13);
  addFlow("normal-background-rejects", {
    source: publicNoiseIp(index),
    destination,
    srcPort: integer(1024, 65535),
    dstPort: pick([80, 443, 8080]),
    packets: integer(1, 3),
    bytes: integer(40, 240),
    start: baseTime + integer(0, 86300),
    duration: integer(1, 8),
    action: "REJECT",
    eni: interfaceId(destination)
  });
}

const scanPorts = [21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 9200];
for (let index = 0; index < 150; index += 1) {
  const destination = internalIp(3, index % 12);
  addFlow("malicious-port-scan", {
    source: `198.51.100.${40 + (index % 5)}`,
    destination,
    srcPort: 41000 + index,
    dstPort: scanPorts[index % scanPorts.length],
    packets: 1,
    bytes: 60,
    start: baseTime + 20 * 3600 + index * 4,
    duration: 2,
    action: "REJECT",
    eni: interfaceId(destination)
  });
}

for (let index = 0; index < 100; index += 1) {
  const destination = "10.0.1.15";
  addFlow("malicious-ssh-bruteforce", {
    source: `203.0.113.${20 + (index % 4)}`,
    destination,
    srcPort: 50000 + index,
    dstPort: 22,
    packets: integer(1, 4),
    bytes: integer(60, 320),
    start: baseTime + 20 * 3600 + 900 + index * 6,
    duration: 3,
    action: "REJECT",
    eni: interfaceId(destination)
  });
}

for (let index = 0; index < 50; index += 1) {
  const destination = "10.0.3.44";
  addFlow("malicious-rdp-bruteforce", {
    source: `198.51.100.${90 + (index % 3)}`,
    destination,
    srcPort: 52000 + index,
    dstPort: 3389,
    packets: integer(1, 3),
    bytes: integer(60, 220),
    start: baseTime + 21 * 3600 + index * 8,
    duration: 3,
    action: "REJECT",
    eni: interfaceId(destination)
  });
}

for (let index = 0; index < 70; index += 1) {
  const source = `10.0.1.${200 + (index % 3)}`;
  const destination = internalIp(3, index * 5);
  const dstPort = pick([22, 445, 1433, 3306, 3389, 5432]);
  const packets = integer(15, 90);
  addFlow("malicious-lateral-movement", {
    source,
    destination,
    srcPort: 44000 + index,
    dstPort,
    packets,
    bytes: packets * integer(180, 900),
    start: baseTime + 21 * 3600 + 600 + index * 12,
    duration: integer(10, 45)
  });
}

for (let index = 0; index < 80; index += 1) {
  const packets = integer(2, 5);
  addFlow("malicious-beaconing", {
    source: "10.0.2.28",
    destination: "203.0.113.82",
    srcPort: 55000 + index,
    dstPort: 8443,
    packets,
    bytes: packets * 96,
    start: baseTime + 18 * 3600 + index * 60,
    duration: 5
  });
}

for (let index = 0; index < 25; index += 1) {
  const packets = integer(150, 350);
  addFlow("malicious-dns-tunneling", {
    source: "10.0.2.77",
    destination: "203.0.113.53",
    srcPort: 57000 + index,
    dstPort: 53,
    protocol: 17,
    packets,
    bytes: packets * integer(180, 420),
    start: baseTime + 22 * 3600 + index * 20,
    duration: 15
  });
}

for (let index = 0; index < 25; index += 1) {
  const packets = integer(3000, 9000);
  addFlow("malicious-exfiltration", {
    source: "10.0.3.90",
    destination: "198.51.100.200",
    srcPort: 59000 + index,
    dstPort: 443,
    packets,
    bytes: packets * integer(900, 1400),
    start: baseTime + 23 * 3600 + index * 45,
    duration: integer(30, 120)
  });
}

if (events.length !== 5000) throw new Error(`Expected 5000 events, generated ${events.length}`);

events.sort((left, right) => left.start - right.start || left.sequence - right.sequence);
const logText = `${header}\n${events.map((event) => event.line).join("\n")}\n`;
const scenarioCounts = Object.fromEntries(Object.keys(scenarios).map((name) => [name, events.filter((event) => event.scenario === name).length]));
const classificationCounts = Object.entries(scenarioCounts).reduce((counts, [name, count]) => {
  const classification = scenarios[name].classification;
  counts[classification] = (counts[classification] || 0) + count;
  return counts;
}, {});
const manifest = {
  product: "SignalPrism NDR",
  format: "AWS VPC Flow Logs custom 14-field text",
  generatedAt: new Date().toISOString(),
  deterministicSeed: "0x051a1f10",
  timeRange: {
    start: new Date(events[0].start * 1000).toISOString(),
    end: new Date((events.at(-1).start + 180) * 1000).toISOString()
  },
  entryCount: events.length,
  classificationCounts,
  scenarioCounts,
  scenarios,
  sha256: createHash("sha256").update(logText).digest("hex"),
  file: "sample-vpc-flow-5000.log"
};

await mkdir(outputDir, { recursive: true });
await writeFile(logPath, logText, "utf8");
await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

console.log(`Generated ${events.length} VPC Flow Log entries at ${logPath}`);
console.log(`Normal: ${classificationCounts.normal}; malicious: ${classificationCounts.malicious}`);
console.log(`SHA-256: ${manifest.sha256}`);
