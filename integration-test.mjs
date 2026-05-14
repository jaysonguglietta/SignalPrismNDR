import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createSignedAwsRequest } from "./src/aws-sigv4.mjs";

const root = dirname(fileURLToPath(import.meta.url));

await testApiAuth();
await testTenantScopedRbac();
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

    const workspaceResponse = await fetch(`${base}/api/workspaces`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ name: "Integration workspace", records: 3, detections: 1, evidenceText: "sample" })
    });
    assert.equal(workspaceResponse.status, 201);
    assert.equal((await workspaceResponse.json()).tenantId, "default");

    const sourceResponse = await fetch(`${base}/api/sources`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ name: "Prod Flow Logs", type: "CloudWatch Log Group", region: "us-east-1", scope: ["/aws/vpc/flowlogs/prod"] })
    });
    assert.equal(sourceResponse.status, 201);
    const source = await sourceResponse.json();

    const userResponse = await fetch(`${base}/api/admin/users`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ name: "Integration Analyst", email: "analyst@example.com", role: "analyst", sourceIds: [source.id] })
    });
    assert.equal(userResponse.status, 201);
    const user = await userResponse.json();

    const ownerResponse = await fetch(`${base}/api/admin/source-owners`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ sourceId: source.id, ownerId: user.id })
    });
    assert.equal(ownerResponse.status, 200);
    assert.equal((await ownerResponse.json()).ownerUserId, user.id);

    const caseResponse = await fetch(`${base}/api/cases`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ title: "Integration case", severity: "high", status: "New" })
    });
    assert.equal(caseResponse.status, 201);

    const evidenceResponse = await fetch(`${base}/api/evidence-runs`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({
        fileName: "integration.log",
        recordCount: 1,
        rawEvidenceText: "2 1 eni-1 10.0.0.1 8.8.8.8 1 53 17 1 1 1 2 ACCEPT OK",
        records: [{ source: "10.0.0.1", destination: "8.8.8.8" }]
      })
    });
    assert.equal(evidenceResponse.status, 201);
    const evidence = await evidenceResponse.json();
    assert.equal(evidence.package.mode, "local");
    assert.equal(evidence.package.rawEvidenceStored, true);

    const packageResponse = await fetch(`${base}/api/evidence-runs/${encodeURIComponent(evidence.id)}/package`, { headers: { "x-ndr-api-key": "integration-key" } });
    assert.equal(packageResponse.status, 200);
    assert.equal((await packageResponse.json()).rawEvidenceStored, true);

    const jobRunsResponse = await fetch(`${base}/api/job-runs`, { headers: { "x-ndr-api-key": "integration-key" } });
    assert.equal(jobRunsResponse.status, 200);
    assert.deepEqual(await jobRunsResponse.json(), []);

    const exportResponse = await fetch(`${base}/api/exports/investigation`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-api-key": "integration-key" },
      body: JSON.stringify({ product: "SignalPrism NDR", source: "integration" })
    });
    assert.equal(exportResponse.status, 200);
    assert.equal((await exportResponse.json()).tenantId, "default");
  } finally {
    await stopServer(server);
    await rm(dataDir, { recursive: true, force: true });
  }
}

async function testTenantScopedRbac() {
  const dataDir = await mkdtemp(join(tmpdir(), "ndr-tenant-"));
  const server = await startServer({
    PORT: "4193",
    NDR_DATA_DIR: dataDir,
    NDR_TEST_AUTH_ENABLED: "true",
    NDR_RATE_LIMIT_MAX: "100",
    NDR_STORE: "local"
  });
  const base = "http://127.0.0.1:4193";
  const analyst = testPrincipal({ subject: "analyst-a", roles: ["analyst"], tenantId: "tenant-a" });
  const viewer = testPrincipal({ subject: "viewer-a", roles: ["viewer"], tenantId: "tenant-a" });
  const analystB = testPrincipal({ subject: "analyst-b", roles: ["analyst"], tenantId: "tenant-b" });
  try {
    const createCase = await fetch(`${base}/api/cases`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": analyst },
      body: JSON.stringify({ title: "Tenant A case", severity: "medium" })
    });
    assert.equal(createCase.status, 201);

    const viewerCreate = await fetch(`${base}/api/cases`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": viewer },
      body: JSON.stringify({ title: "Viewer should not write" })
    });
    assert.equal(viewerCreate.status, 403);

    const tenantAList = await fetch(`${base}/api/cases`, { headers: { "x-ndr-test-principal": viewer } });
    assert.equal((await tenantAList.json()).length, 1);

    const tenantBList = await fetch(`${base}/api/cases`, { headers: { "x-ndr-test-principal": analystB } });
    assert.equal((await tenantBList.json()).length, 0);

    const viewerExport = await fetch(`${base}/api/exports/investigation`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": viewer },
      body: JSON.stringify({ product: "SignalPrism NDR" })
    });
    assert.equal(viewerExport.status, 403);

    const viewerAi = await fetch(`${base}/api/ai/ask`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ndr-test-principal": viewer },
      body: JSON.stringify({ question: "summarize", context: {} })
    });
    assert.equal(viewerAi.status, 403);

    const viewerUsers = await fetch(`${base}/api/admin/users`, { headers: { "x-ndr-test-principal": viewer } });
    assert.equal(viewerUsers.status, 403);
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
    env: { ...process.env, HOST: "127.0.0.1", NDR_TEST_AUTH_ENABLED: "false", ...env, AWS_ACCESS_KEY_ID: "", AWS_SECRET_ACCESS_KEY: "", NDR_OIDC_ISSUER: "" },
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

function testPrincipal(principal) {
  return JSON.stringify(principal);
}
