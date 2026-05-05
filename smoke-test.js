const { parseVpcFlowLog, analyzeRecords, SAMPLE_LOG } = require("./app.js");

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

const sample = parseVpcFlowLog(SAMPLE_LOG);
const sampleAnalysis = analyzeRecords(sample.records, sample.errors);
assert(sample.records.length === 11, "Sample log should parse 11 records");
assert(sampleAnalysis.detections.length >= 1, "Sample log should produce detections");
assert(sampleAnalysis.observations.length >= 1, "Sample log should produce observations");
assert(sampleAnalysis.applicationMix.length >= 1, "Sample log should produce application mix");
assert(sampleAnalysis.entityRisk.length >= 1, "Sample log should produce entity risk");

const csv = parseVpcFlowLog(
  "version,account-id,interface-id,srcaddr,dstaddr,srcport,dstport,protocol,packets,bytes,start,end,action,log-status\n" +
    "2,1,eni-1,10.0.0.1,8.8.8.8,53000,53,17,2,180,1714771200,1714771260,ACCEPT,OK"
);
assert(csv.records.length === 1, "CSV should parse one record");

const cloudWatch = parseVpcFlowLog(
  JSON.stringify({
    logEvents: [{ message: "2 1 eni-2 10.0.0.2 8.8.4.4 53001 53 17 2 200 1714771200 1714771260 ACCEPT OK" }]
  })
);
assert(cloudWatch.records.length === 1, "CloudWatch JSON should parse one record");

const azure = parseVpcFlowLog(
  JSON.stringify({
    records: [
      {
        resourceId: "nsg1",
        properties: {
          flows: [{ rule: "AllowWeb", flows: [{ flowTuples: ["1714771200,10.0.0.4,8.8.8.8,50000,443,T,O,A"] }] }]
        }
      }
    ]
  })
);
assert(azure.records.length === 1 && azure.records[0].protocol === "TCP", "Azure NSG JSON should parse one TCP record");

const gcp = parseVpcFlowLog(
  JSON.stringify([
    {
      timestamp: "2024-05-03T00:00:00Z",
      resource: { labels: { project_id: "p1", subnetwork_name: "subnet-a" } },
      jsonPayload: {
        connection: { src_ip: "10.0.0.5", dest_ip: "8.8.4.4", src_port: 53000, dest_port: 53, protocol: 17 },
        bytes_sent: 900,
        packets_sent: 3,
        disposition: "ALLOWED"
      }
    }
  ])
);
assert(gcp.records.length === 1 && gcp.records[0].protocol === "UDP", "GCP VPC JSON should parse one UDP record");

const beaconRows = [0, 60, 120, 180, 240].map(
  (offset, index) =>
    `2 1 eni-9 10.0.5.9 203.0.113.200 ${50000 + index} 443 6 3 300 ${1714771200 + offset} ${1714771260 + offset} ACCEPT OK`
);
const beacon = parseVpcFlowLog(
  ["#Fields: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status", ...beaconRows].join("\n")
);
const beaconAnalysis = analyzeRecords(beacon.records, beacon.errors);
assert(beaconAnalysis.detections.some((detection) => detection.technique === "Beaconing"), "Beaconing detection should fire");

console.log("smoke tests ok");
