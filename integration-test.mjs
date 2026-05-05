import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createSignedAwsRequest } from "./src/aws-sigv4.mjs";

const root = dirname(fileURLToPath(import.meta.url));

await testApiAuth();
await testRateLimit();
testAwsSigning();

console.log("integration checks passed");

async function testApiAuth() {
  const dataDir = await mkdtemp(join(tmpdir(), "ndr-auth-"));
  const server = await startServer({
    PORT: "4191",
    NDR_DATA_DIR: dataDir,
    NDR_API_KEY: "integration-key",
    NDR_RATE_LIMIT_MAX: "100",
    NDR_STORE: "local"
  });
  const base = "http://127.0.0.1:4191";
  try {
    assert.equal((await fetch(`${base}/api/health`)).status, 200);
    const aiConfig = await (await fetch(`${base}/api/ai/config`)).json();
    assert.equal(aiConfig.enabled, false);
    assert.equal((await fetch(`${base}/api/jobs`)).status, 401);
    assert.equal((await fetch(`${base}/api/jobs`, { headers: { "x-ndr-api-key": "wrong" } })).status, 401);

    const jobsResponse = await fetch(`${base}/api/jobs`, { headers: { "x-ndr-api-key": "integration-key" } });
    assert.equal(jobsResponse.status, 200);
    assert.deepEqual(await jobsResponse.json(), []);

    const disabledAiResponse = await fetch(`${base}/api/ai/ask`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ question: "What is risky?", context: { records: 0 } })
    });
    assert.equal(disabledAiResponse.status, 403);

    const createResponse = await fetch(`${base}/api/jobs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({
        name: "Integration CloudWatch import",
        type: "cloudwatch",
        intervalMinutes: 5,
        enabled: false,
        config: { region: "us-east-1", logGroupName: "/aws/vpc/flowlogs/prod" }
      })
    });
    assert.equal(createResponse.status, 201);
    const job = await createResponse.json();
    assert.equal(job.name, "Integration CloudWatch import");

    const viewerDelete = await fetch(`${base}/api/jobs/${job.id}`, { method: "DELETE" });
    assert.equal(viewerDelete.status, 401);

    const deleteResponse = await fetch(`${base}/api/jobs/${job.id}`, {
      method: "DELETE",
      headers: { "x-ndr-api-key": "integration-key" }
    });
    assert.equal(deleteResponse.status, 200);
  } finally {
    await stopServer(server);
    await rm(dataDir, { recursive: true, force: true });
  }
}

async function testRateLimit() {
  const dataDir = await mkdtemp(join(tmpdir(), "ndr-rate-"));
  const server = await startServer({
    PORT: "4192",
    NDR_DATA_DIR: dataDir,
    NDR_RATE_LIMIT_MAX: "2",
    NDR_RATE_LIMIT_WINDOW_MS: "60000",
    NDR_STORE: "local"
  });
  const base = "http://127.0.0.1:4192";
  try {
    assert.equal((await fetch(`${base}/api/health`)).status, 200);
    assert.equal((await fetch(`${base}/api/health`)).status, 200);
    assert.equal((await fetch(`${base}/api/health`)).status, 429);
  } finally {
    await stopServer(server);
    await rm(dataDir, { recursive: true, force: true });
  }
}

function testAwsSigning() {
  const signed = createSignedAwsRequest({
    accessKeyId: "AKIDEXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    service: "dynamodb",
    region: "us-east-1",
    method: "POST",
    host: "dynamodb.us-east-1.amazonaws.com",
    path: "/",
    headers: {
      "content-type": "application/x-amz-json-1.1",
      "x-amz-target": "DynamoDB_20120810.Query"
    },
    body: JSON.stringify({ TableName: "ndr-flow-console-dev" }),
    date: new Date("2026-05-05T12:00:00Z")
  });

  assert.equal(signed.url, "https://dynamodb.us-east-1.amazonaws.com/");
  assert.equal(signed.signedHeaderNames, "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-target");
  assert.match(signed.signature, /^[a-f0-9]{64}$/);
  assert.ok(signed.canonicalRequest.includes("content-type:application/x-amz-json-1.1\n"));
  assert.ok(signed.canonicalRequest.includes("x-amz-target:DynamoDB_20120810.Query\n"));
  assert.ok(signed.headers.authorization.includes("Credential=AKIDEXAMPLE/20260505/us-east-1/dynamodb/aws4_request"));
}

async function startServer(env) {
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: root,
    env: { ...process.env, HOST: "127.0.0.1", ...env, AWS_ACCESS_KEY_ID: "", AWS_SECRET_ACCESS_KEY: "", NDR_OIDC_ISSUER: "" },
    stdio: ["ignore", "pipe", "pipe"]
  });
  await waitForStartup(child);
  return child;
}

function waitForStartup(child) {
  return new Promise((resolve, reject) => {
    let output = "";
    const timeout = setTimeout(() => reject(new Error(`Server did not start:\n${output}`)), 5000);
    child.stdout.on("data", (chunk) => {
      output += chunk.toString();
      if (output.includes("server_started")) {
        clearTimeout(timeout);
        resolve();
      }
    });
    child.stderr.on("data", (chunk) => {
      output += chunk.toString();
    });
    child.on("exit", (code) => {
      clearTimeout(timeout);
      reject(new Error(`Server exited with ${code}:\n${output}`));
    });
  });
}

function stopServer(child) {
  return new Promise((resolve) => {
    child.once("exit", resolve);
    child.kill("SIGTERM");
  });
}
