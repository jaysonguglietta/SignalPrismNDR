import { expect, test } from "@playwright/test";

test("dashboard demo visual state", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Demo" }).click();
  await expect(page.locator("#toastRegion")).toContainText("Guided demo workspace loaded");
  await expect(page.locator("#inputMessage")).not.toContainText("Case status is invalid");
  await expect(page.getByRole("heading", { name: "SignalPrism NDR" })).toBeVisible();
  await expect(page.getByText("NDR risk")).toBeVisible();
  await expect(page).toHaveScreenshot("dashboard-demo.png", { fullPage: true });
});

test("topology replay visual state", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Sample" }).click();
  await page.getByRole("tab", { name: "Topology" }).click();
  await page.locator("#replayRangeInput").evaluate((input) => {
    input.value = "55";
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await expect(page.getByText("Entity-to-entity paths")).toBeVisible();
  await expect(page).toHaveScreenshot("topology-replay.png", { fullPage: true });
});

test("analyst learning center visual state", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("tab", { name: "Learn" }).click();
  await expect(page.getByRole("heading", { name: "Understand NDR and SignalPrism" })).toBeVisible();
  await expect(page.getByText("From network activity to response")).toBeVisible();
  await page.getByText("VPC Flow Log", { exact: true }).click();
  await expect(page.getByText("A metadata record describing a network flow")).toBeVisible();
  await expect(page).toHaveScreenshot("analyst-learning-center.png", { fullPage: true });
});

test("learning center links into operational workflows", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("tab", { name: "Learn" }).click();
  await page.getByRole("button", { name: "Open detections" }).click();
  await expect(page.getByRole("tab", { name: "Detections" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "Learn" }).click();
  await page.getByRole("button", { name: "Practice with guided demo" }).click();
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  await expect(page.locator("#statusText")).toContainText("11 records");
});

test("admin tenant management visual state", async ({ page }) => {
  const managedSources = [
    { id: "source-vpc", name: "Prod AWS VPC", type: "AWS VPC", region: "us-east-1", scope: ["eni-0a1b2c3d"], ownerUserId: "", ownerName: "" },
    { id: "source-flow", name: "Prod VPC Flow Logs", type: "CloudWatch Log Group", region: "us-east-1", scope: ["/aws/vpc/flowlogs/prod"], ownerUserId: "", ownerName: "" }
  ];
  const auditEvents = [
    ["case.created", "Demo: High rejection rate"],
    ["workspace.saved", "Demo - Public admin access"],
    ["evidence.saved", "Guided demo VPC flow evidence"],
    ["evidence.saved", "Sample log"],
    ["case.created", "Demo: High rejection rate"],
    ["workspace.saved", "Demo - Public admin access"],
    ["evidence.saved", "Guided demo VPC flow evidence"],
    ["case.created", "Demo: High rejection rate"],
    ["workspace.saved", "Demo - Public admin access"],
    ["evidence.saved", "Guided demo VPC flow evidence"]
  ].map(([action, title], index) => ({
    id: `audit-${index}`,
    action,
    actor: "local-dev",
    tenantId: "default",
    createdAt: "2026-07-15T16:15:13.000Z",
    retentionUntil: "2033-07-13T16:15:13.000Z",
    details: action === "case.created"
      ? { title, caseId: `acb055cb-a933-4190-90ba-6fe487769c${String(index).padStart(2, "0")}` }
      : { title }
  }));
  if ((page.viewportSize()?.width || 0) < 600) {
    auditEvents.push(
      { ...auditEvents[5], id: "audit-10" },
      { ...auditEvents[6], id: "audit-11" }
    );
  }
  await page.route(/\/api\/audit\/events(?:\?.*)?$/, (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ count: auditEvents.length, events: auditEvents })
  }));
  await page.route(/\/api\/sources(?:\?.*)?$/, (route) => {
    if (route.request().method() !== "GET") return route.continue();
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(managedSources) });
  });
  await page.route(/\/api\/export-approvals(?:\?.*)?$/, (route) => {
    if (route.request().method() !== "GET") return route.continue();
    return route.fulfill({ status: 200, contentType: "application/json", body: "[]" });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Demo" }).click();
  await expect(page.locator("#toastRegion")).toContainText("Guided demo workspace loaded");
  await page.getByRole("tab", { name: "Admin" }).click();
  await expect(page.locator("#adminUserNameInput")).toBeVisible();
  await page.locator("#adminUserNameInput").fill("Avery SOC");
  await page.locator("#adminUserEmailInput").fill("avery@example.com");
  await page.locator("#adminUserRoleInput").selectOption("analyst");
  await expect(page.getByText("Users and roles")).toBeVisible();
  await expect(page.locator("#sourceOwnershipList")).toContainText("Prod AWS VPC");
  await expect(page.locator("#exportApprovalList")).toContainText("No export requests");
  await expect(page).toHaveScreenshot("admin-tenant.png", { fullPage: true });
});

test("upload and detection tuning workflow", async ({ page }) => {
  await page.goto("/");
  await page.locator("#fileInput").setInputFiles({
    name: "flow.log",
    mimeType: "text/plain",
    buffer: Buffer.from("2 123456789012 eni-test 10.0.0.5 8.8.8.8 55123 53 17 4 512 1714771200 1714771260 ACCEPT OK\n")
  });
  await expect(page.locator("#statusText")).toContainText("1 record");
  await page.getByRole("tab", { name: "Detections" }).click();
  await page.locator("#ruleProfileSelect").selectOption("focused");
  await page.locator("#applyRuleProfileButton").click();
  await expect(page.locator("#ruleProfileDescription")).toContainText("Focused");
  await expect(page.locator("#toastRegion")).toContainText("Detection profile set to focused");
});

test("AI summary handles enabled backend response", async ({ page }) => {
  await page.route("**/api/health", async (route) => {
    const response = await route.fetch();
    const health = await response.json();
    await route.fulfill({ response, json: { ...health, awsConfigured: true } });
  });
  await page.route("**/api/ai/config", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ enabled: true, provider: "aws-bedrock", region: "us-east-1", modelId: "test-model", modes: ["answer", "summary"] })
  }));
  await page.route("**/api/ai/ask", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ answer: "High-risk entity: 10.0.1.15. Validate the accepted database path.", mode: "summary", evidenceTrust: "untrusted-data" })
  }));
  await page.goto("/");
  await page.getByRole("button", { name: "Sample" }).click();
  await page.getByRole("tab", { name: "Reports" }).click();
  await expect(page.locator("#summarizeAiButton")).toBeEnabled();
  await page.locator("#summarizeAiButton").click();
  await expect(page.locator("#aiAnswerPanel")).toContainText("High-risk entity");
});

test("browser evidence cache is encrypted and session-bound", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#authStatusLabel")).toContainText("Local admin session");
  const result = await page.evaluate(async () => {
    const store = await import("/src/idb-store.js");
    await store.setStorageScope("tenant-a.analyst-a", "session-secret-a");
    await store.setStoragePolicy({ enabled: true, retentionDays: 1, maxRecords: 1000 });
    await store.saveEvidenceRun({ fileName: "sensitive-flow.log", records: [{ source: "10.0.0.5", destination: "198.51.100.10" }], analysis: { detections: [] } });
    const db = await store.openNdrDb();
    const raw = await new Promise((resolve, reject) => {
      const request = db.transaction("records", "readonly").objectStore("records").getAll();
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    const readable = await store.listEvidenceRuns();
    await store.setStorageScope("tenant-a.analyst-a", "different-session-secret");
    const wrongSession = await store.listEvidenceRuns();
    await store.clearAllStorage();
    return { raw, readable, wrongSession };
  });
  expect(result.raw).toHaveLength(1);
  expect(result.raw[0].sealed).toBe(true);
  expect(JSON.stringify(result.raw[0])).not.toContain("10.0.0.5");
  expect(result.readable[0].fileName).toBe("sensitive-flow.log");
  expect(result.wrongSession).toHaveLength(0);
});

test("investigation export enters approval queue", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Sample" }).click();
  await page.getByRole("tab", { name: "Reports" }).click();
  await page.locator("#exportInvestigationPackageButton").click();
  await expect(page.locator("#toastRegion")).toContainText("submitted for approval");
  await page.getByRole("tab", { name: "Admin" }).click();
  await expect(page.locator("#exportApprovalList")).toContainText("Investigation package");
});

test("enterprise signal fusion and governed response workflow", async ({ page }) => {
  let telemetry = [];
  let correlations = [];
  let responseActions = [];
  await page.route(/\/api\/telemetry\/events(?:\?.*)?$/, async (route) => {
    if (route.request().method() === "POST") {
      const body = route.request().postDataJSON();
      const payload = JSON.parse(body.payload);
      telemetry = payload.map((event, index) => ({ id: `event-${index}`, format: event.eventSource ? "cloudtrail" : event.event_type ? "suricata" : event.type ? "guardduty" : "route53-dns", identity: event.userIdentity?.arn || "sensor", timestamp: event.eventTime || event.timestamp || event.updatedAt || event.query_timestamp }));
      return route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify({ accepted: telemetry.length, rejected: 0, events: telemetry.slice(0, 10) }) });
    }
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(telemetry) });
  });
  await page.route(/\/api\/telemetry\/correlate$/, (route) => {
    correlations = [{ id: "correlation-1", title: "Privilege change followed by network activity", severity: "high", summary: "A privileged IAM action was followed by corroborating sensor activity.", technique: "T1098 Account Manipulation", entity: "10.0.1.12", evidenceIds: ["event-1", "event-2"], score: 88 }];
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ eventCount: telemetry.length, findingCount: 1, findings: correlations }) });
  });
  await page.route(/\/api\/correlations$/, (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(correlations) }));
  await page.route(/\/api\/response-actions(?:\/.*)?$/, (route) => {
    if (route.request().method() === "POST" && !route.request().url().endsWith("/approve")) {
      const body = route.request().postDataJSON();
      const action = { id: "response-1", ...body, status: "pending", requestedBy: "local-dev" };
      responseActions = [action];
      return route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify(action) });
    }
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(responseActions) });
  });
  await page.route(/\/api\/detection-content\/bundles$/, (route) => route.fulfill({ status: 200, contentType: "application/json", body: "[]" }));
  await page.route(/\/api\/enterprise\/readiness$/, (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ score: 75, passed: 9, total: 12, checks: [{ name: "Durable ingest queue", status: "pass", remediation: "Control is configured." }] }) }));

  await page.goto("/");
  await page.getByRole("tab", { name: "Enterprise" }).click();
  await page.locator("#loadTelemetrySampleButton").click();
  await expect(page.locator("#telemetryPayloadInput")).not.toHaveValue("");
  await page.locator("#ingestTelemetryButton").click();
  await expect(page.locator("#toastRegion")).toContainText("telemetry events ingested");
  await page.locator("#correlateTelemetryButton").click();
  await expect(page.locator("#correlationList")).toContainText("Privilege change followed by network activity");
  await page.locator("#responseActionTypeInput").selectOption("isolate-entity");
  await page.locator("#responseActionTargetInput").fill("i-0123456789abcdef0");
  await page.locator("#responseActionReasonInput").fill("Contain the correlated workload while the incident owner validates activity.");
  await page.locator("#requestResponseActionButton").click();
  await expect(page.locator("#responseActionList")).toContainText("Isolate entity");
  await expect(page.locator("#responseActionList")).toContainText("pending");
});

test("enterprise platform operations workspace", async ({ page }) => {
  const routes = {
    "/api/stream/status": { mode: "firehose", configured: true, streamName: "signalprism-prod-ocsf", region: "us-east-1", accepted: 12840, published: 12791 },
    "/api/analytics/behavior": { profiles: [{ entity: "10.0.1.12", riskScore: 88 }], findings: [{ id: "behavior-1", ruleId: "SP-UEBA-005", title: "Periodic connection pattern", severity: "high", score: 91, entity: "10.0.1.12", summary: "The workload contacted a new external peer at a regular interval.", explanation: { reason: "low-jitter periodicity" }, evidenceIds: ["event-1"] }] },
    "/api/campaigns": [{ id: "campaign-1", title: "Command and Control campaign involving 10.0.1.12", severity: "high", score: 93, narrative: "Four linked signals connect three entities across Credential Access -> Command and Control.", stages: ["Credential Access", "Command and Control"], blastRadius: { entityCount: 3 } }],
    "/api/hunts/retrospective": [{ id: "hunt-1", normalizedQuery: "outcome:failure OR severity:high", scanned: 5000, matchCount: 27, matches: [{ id: "event-1", sourceIp: "10.0.1.12", destinationIp: "198.51.100.44", action: "connect", format: "suricata", timestamp: "2026-07-16T12:05:00Z" }] }],
    "/api/governance/traffic-posture": [{ id: "posture-1", ai: { unsanctionedEvents: 4, observedEvents: 12, totalBytes: 4820000 }, crypto: { findings: [{ title: "Deprecated TLS protocol", summary: "TLS1.0 is below the enterprise minimum." }], observedSessions: 203, pqcCoverage: 0.18 } }],
    "/api/connectors/catalog": [{ id: "splunk-hec", name: "Splunk HEC", direction: "outbound", formats: ["hec"] }, { id: "gigamon-vseries", name: "Gigamon V Series / AMI", direction: "inbound", formats: ["ipfix"] }],
    "/api/connectors": [{ id: "connector-1", name: "Production Splunk", catalogId: "splunk-hec", status: "healthy", format: "hec", secretConfigured: true }],
    "/api/organization/accounts": [{ id: "123456789012", accountId: "123456789012", name: "Production", status: "active", onboardingStatus: "configured", sourceIds: ["source-1", "source-2"] }],
    "/api/evidence-uploads": [{ id: "upload-1", fileName: "incident-2026-07-16.zip", status: "complete", contentLength: 1834022, retentionUntil: "2027-07-16T00:00:00Z" }],
    "/api/admin/roles": [{ id: "admin", name: "Tenant Administrator", baseRole: "admin", builtIn: true }, { id: "hunter", name: "Threat Hunter", baseRole: "viewer", builtIn: false, permissions: ["hunts:run", "detections:read"] }],
    "/api/admin/service-accounts": [{ id: "service-1", name: "SIEM reader", baseRole: "viewer", status: "active", expiresAt: "2026-10-16T00:00:00Z" }],
    "/api/ai/investigations": [{ id: "ai-1", answer: "The highest-risk entity shows periodic outbound traffic linked to a failed identity sequence.", mode: "deterministic", citations: [{ eventId: "event-1", sourceIp: "10.0.1.12", destinationIp: "198.51.100.44", timestamp: "2026-07-16T12:05:00Z" }], steps: [{ name: "Collect tenant evidence", status: "completed", count: 5000 }] }]
  };
  for (const [path, body] of Object.entries(routes)) {
    await page.route(`**${path}`, (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) }));
  }
  await page.goto("/");
  await page.getByRole("tab", { name: "Platform" }).click();
  await expect(page.getByRole("heading", { name: "Continuous telemetry and analytics" })).toBeVisible();
  await expect(page.locator("#behaviorFindingList")).toContainText("Periodic connection pattern");
  await expect(page.locator("#campaignList")).toContainText("Command and Control campaign");
  await expect(page.locator("#connectorList")).toContainText("Production Splunk");
  await expect(page.locator("#trafficPostureList")).toContainText("unsanctioned AI events");
  await expect(page).toHaveScreenshot("platform-operations.png", { fullPage: true });
});
