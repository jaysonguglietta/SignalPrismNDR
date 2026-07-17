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
