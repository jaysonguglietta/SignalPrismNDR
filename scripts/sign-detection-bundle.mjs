import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const [inputPath, privateKeyPath, outputPath] = process.argv.slice(2);
if (!inputPath || !privateKeyPath || !outputPath) {
  console.error("Usage: node scripts/sign-detection-bundle.mjs <bundle.json> <ed25519-private-key.pem> <signed-bundle.json>");
  process.exit(1);
}

const draft = JSON.parse(await readFile(inputPath, "utf8"));
if (!draft.manifest || !Array.isArray(draft.rules) || !draft.rules.length) {
  throw new Error("Bundle input requires a manifest and at least one rule");
}
const rulesDigest = createHash("sha256").update(canonicalJson(draft.rules)).digest("hex");
const manifest = { ...draft.manifest, contentHash: rulesDigest };
const privateKey = createPrivateKey(await readFile(privateKeyPath, "utf8"));
if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Detection content must be signed with an Ed25519 private key");
const signature = sign(null, Buffer.from(canonicalJson({ manifest, rules: draft.rules })), privateKey).toString("base64");
const bundle = { manifest, rules: draft.rules, signature };
await writeFile(outputPath, `${JSON.stringify(bundle, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify({ outputPath, bundleId: manifest.id, version: manifest.version, ruleCount: draft.rules.length, contentHash: rulesDigest }));

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
