# Sample AWS VPC Flow Logs

`sample-vpc-flow-5000.log` contains 5,000 syntactically valid AWS VPC Flow Log records using SignalPrism's supported 14-field format.

- 4,500 normal records cover web egress, internal application traffic, DNS/NTP, AWS service access, and low-rate rejected internet noise.
- 500 malicious records cover port scanning, SSH/RDP brute force, lateral movement, periodic command-and-control beaconing, DNS tunneling, and large external transfers.
- `sample-vpc-flow-5000.manifest.json` records the exact scenario counts and SHA-256 digest.

Upload the `.log` file through the SignalPrism evidence uploader or paste a subset into the input panel. The current detector produces high- and medium-severity findings from this dataset; the manifest is the ground truth for scenario-level validation.

Regenerate both files with:

```bash
npm run sample:generate
```

## Large enterprise demo pack

The `demo-pack/` directory contains four deterministic, browser-safe AWS VPC Flow Log v5 fixtures. Every file stays below SignalPrism's 16 MB drag-and-drop limit and includes a ground-truth manifest with scenario counts, important entities, time windows, expected parser results, expected findings, file size, and SHA-256 digest.

| File | Records | Purpose |
| --- | ---: | --- |
| `enterprise-clean-baseline-20000.log` | 20,000 | Normal production traffic for first-run review and saving a baseline. |
| `ransomware-intrusion-chain-25000.log` | 25,000 | Reconnaissance through access, lateral spread, C2, staging, and exfiltration. |
| `soc-shift-mixed-35000.log` | 35,000 | Full SOC demo with normal traffic, an attack chain, NODATA, SKIPDATA, and parser errors. |
| `telemetry-quality-failures-12000.log` | 12,000 | Collection-health demo with non-fatal malformed records and delivery gaps. |

Recommended demo sequence:

1. Drag in `enterprise-clean-baseline-20000.log` and save it as the environment baseline.
2. Drag in `ransomware-intrusion-chain-25000.log` to investigate the attack timeline and compare drift.
3. Use `soc-shift-mixed-35000.log` for the broadest detection, entity, topology, hunt, AI summary, case, and export walkthrough.
4. Use `telemetry-quality-failures-12000.log` to explain source blind spots and parser-quality controls.

Regenerate the complete pack with:

```bash
npm run sample:demo-pack
```

## Multi-source event stitching demo

The `stitching-demo/` directory is a deterministic five-file investigation bundle. Select all five evidence files together in the upload control, then open `Topology > Event stitching`.

| File | Format | Investigation role |
| --- | --- | --- |
| `01-cloudtrail-control-plane.json` | CloudTrail | Privilege escalation and access-key creation. |
| `02-vpc-network-flows.log` | AWS VPC Flow Logs | Lateral database access, C2 traffic, and large egress. |
| `03-suricata-sensor.jsonl` | Suricata EVE | Independent C2 and administrative-session alerts. |
| `04-route53-dns.jsonl` | Route 53 Resolver | C2 domain resolution and long-label exfiltration candidates. |
| `05-guardduty-findings.jsonl` | GuardDuty | Cloud-native C2 and anomalous credential corroboration. |

The expected chain spans Privilege Escalation, Lateral Movement, Command and Control, and Exfiltration. `manifest.json` records important entities, expected formats, byte sizes, and SHA-256 digests. Regenerate it with:

```bash
npm run sample:stitching
```
