import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outputDir = join(root, "samples", "stitching-demo");
const accountId = "123456789012";
const localIp = "10.0.1.12";
const databaseIp = "10.0.2.28";
const commandIp = "198.51.100.44";
const base = Date.parse("2026-07-16T20:00:00Z");
const at = (seconds) => new Date(base + seconds * 1000).toISOString();
const epoch = (seconds) => Math.floor((base + seconds * 1000) / 1000);

await mkdir(outputDir, { recursive: true });

const cloudTrail = {
  Records: [
    {
      eventVersion: "1.09", eventID: "ct-normal-list", eventTime: at(-120), eventSource: "ec2.amazonaws.com",
      eventName: "DescribeInstances", awsRegion: "us-east-1", recipientAccountId: accountId,
      sourceIPAddress: "10.0.5.10", userIdentity: { arn: `arn:aws:iam::${accountId}:role/InventoryReader` },
      requestParameters: {}
    },
    {
      eventVersion: "1.09", eventID: "ct-privilege", eventTime: at(0), eventSource: "iam.amazonaws.com",
      eventName: "AttachRolePolicy", awsRegion: "us-east-1", recipientAccountId: accountId,
      sourceIPAddress: localIp, userIdentity: { arn: `arn:aws:iam::${accountId}:user/compromised-admin` },
      requestParameters: { roleArn: `arn:aws:iam::${accountId}:role/ProductionAdmin`, policyArn: "arn:aws:iam::aws:policy/AdministratorAccess" }
    },
    {
      eventVersion: "1.09", eventID: "ct-access-key", eventTime: at(18), eventSource: "iam.amazonaws.com",
      eventName: "CreateAccessKey", awsRegion: "us-east-1", recipientAccountId: accountId,
      sourceIPAddress: localIp, userIdentity: { arn: `arn:aws:iam::${accountId}:user/compromised-admin` },
      requestParameters: { userName: "backup-automation" }
    }
  ]
};

const guardDuty = [
  {
    id: "gd-c2", type: "Backdoor:EC2/C&CActivity.B", title: "EC2 instance communicating with a command and control server",
    description: "The production application instance contacted an indicator associated with command and control activity.",
    severity: 8.2, updatedAt: at(120), accountId, region: "us-east-1",
    resource: { resourceType: "Instance", instanceDetails: { instanceId: "i-0compromised12", networkInterfaces: [{ privateIpAddress: localIp }] } },
    service: { action: { actionType: "NETWORK_CONNECTION", networkConnectionAction: { protocol: "TCP", localPortDetails: { port: 443 }, localIpDetails: { ipAddressV4: localIp }, remoteIpDetails: { ipAddressV4: commandIp } } } }
  },
  {
    id: "gd-credential", type: "CredentialAccess:IAMUser/AnomalousBehavior", title: "Unusual IAM credential behavior",
    severity: 6.4, updatedAt: at(35), accountId, region: "us-east-1",
    resource: { resourceType: "AccessKey", accessKeyDetails: { userName: "compromised-admin" } },
    service: { action: { actionType: "AWS_API_CALL" } }
  }
];

const suricata = [
  {
    timestamp: at(88), event_type: "alert", flow_id: 991, src_ip: localIp, src_port: 51234,
    dest_ip: commandIp, dest_port: 443, proto: "TCP", app_proto: "tls", community_id: "1:signalprism-c2",
    tls: { sni: "updates-cdn.example" }, alert: { severity: 1, signature: "Known C2 TLS callback", category: "Command and Control", action: "allowed" }
  },
  {
    timestamp: at(64), event_type: "alert", flow_id: 881, src_ip: localIp, src_port: 49120,
    dest_ip: databaseIp, dest_port: 5432, proto: "TCP", app_proto: "pgsql", community_id: "1:signalprism-lateral",
    alert: { severity: 2, signature: "Unexpected application-to-database administrative session", category: "Potentially Bad Traffic", action: "allowed" }
  },
  ...Array.from({ length: 80 }, (_, index) => ({
    timestamp: at(-3600 + index * 35), event_type: "flow", flow_id: 2000 + index,
    src_ip: `10.0.${10 + (index % 8)}.${20 + (index % 180)}`, src_port: 40000 + index,
    dest_ip: `192.0.2.${10 + (index % 80)}`, dest_port: 443, proto: "TCP", app_proto: "tls",
    community_id: `1:normal-${index}`, flow: { state: "established", bytes_toserver: 1200 + index, bytes_toclient: 8400 + index * 2 }
  }))
];

const route53 = [
  { query_timestamp: at(95), srcaddr: localIp, srcport: 53001, query_name: "updates-cdn.example.", query_type: "A", rcode: "NOERROR", account_id: accountId, region: "us-east-1", answers: [{ Rdata: commandIp }] },
  { query_timestamp: at(145), srcaddr: localIp, srcport: 53002, query_name: `${"x".repeat(64)}.exfil.example.`, query_type: "TXT", rcode: "NOERROR", account_id: accountId, region: "us-east-1" },
  { query_timestamp: at(155), srcaddr: localIp, srcport: 53003, query_name: `${"y".repeat(64)}.exfil.example.`, query_type: "TXT", rcode: "NOERROR", account_id: accountId, region: "us-east-1" },
  ...Array.from({ length: 100 }, (_, index) => ({
    query_timestamp: at(-3500 + index * 31), srcaddr: `10.0.${20 + (index % 5)}.${30 + (index % 180)}`,
    srcport: 54000 + index, query_name: `service-${index % 20}.corp.example.`, query_type: "A", rcode: "NOERROR",
    account_id: accountId, region: "us-east-1", answers: [{ Rdata: `10.0.40.${10 + (index % 20)}` }]
  }))
];

const flowHeader = "#Fields: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status";
const flowRows = [
  `2 ${accountId} eni-compromised ${localIp} ${databaseIp} 49120 5432 6 42 18240 ${epoch(62)} ${epoch(72)} ACCEPT OK`,
  `2 ${accountId} eni-compromised ${localIp} ${commandIp} 51234 443 6 32 15480 ${epoch(86)} ${epoch(96)} ACCEPT OK`,
  `2 ${accountId} eni-database ${databaseIp} ${commandIp} 51888 443 6 42000 42000000 ${epoch(170)} ${epoch(230)} ACCEPT OK`,
  ...Array.from({ length: 120 }, (_, index) => {
    const src = `10.0.${30 + (index % 5)}.${20 + (index % 180)}`;
    const dst = `192.0.2.${20 + (index % 70)}`;
    return `2 ${accountId} eni-normal-${String(index).padStart(3, "0")} ${src} ${dst} ${40000 + index} 443 6 ${10 + index % 30} ${2400 + index * 13} ${epoch(-3400 + index * 27)} ${epoch(-3390 + index * 27)} ACCEPT OK`;
  })
];

const files = [
  ["01-cloudtrail-control-plane.json", `${JSON.stringify(cloudTrail, null, 2)}\n`],
  ["02-vpc-network-flows.log", `${flowHeader}\n${flowRows.join("\n")}\n`],
  ["03-suricata-sensor.jsonl", `${suricata.map((event) => JSON.stringify(event)).join("\n")}\n`],
  ["04-route53-dns.jsonl", `${route53.map((event) => JSON.stringify(event)).join("\n")}\n`],
  ["05-guardduty-findings.jsonl", `${guardDuty.map((event) => JSON.stringify(event)).join("\n")}\n`]
];

const manifest = {
  schema: "signalprism.stitching-demo.v1",
  generatedAt: new Date().toISOString(),
  scenario: "Privilege escalation followed by database access, command and control, DNS tunneling, and exfiltration.",
  accountId,
  importantEntities: { localIp, databaseIp, commandIp, identity: `arn:aws:iam::${accountId}:user/compromised-admin` },
  expectedStages: ["Privilege Escalation", "Lateral Movement", "Command and Control", "Exfiltration"],
  expectedFormats: ["cloudtrail", "aws-vpc-flow", "suricata", "route53-dns", "guardduty"],
  files: files.map(([name, body]) => ({
    name,
    bytes: Buffer.byteLength(body),
    sha256: createHash("sha256").update(body).digest("hex")
  }))
};

await Promise.all(files.map(([name, body]) => writeFile(join(outputDir, name), body, "utf8")));
await writeFile(join(outputDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

console.log(`Generated ${files.length} multi-source stitching files in ${outputDir}`);
