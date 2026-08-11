import { readFile } from "node:fs/promises";

const files = Object.fromEntries(await Promise.all([
  "server.mjs",
  "infra/aws/terraform/main.tf",
  "infra/aws/terraform/variables.tf",
  "infra/aws/member-account-role.yaml",
  "src/ocsf.mjs",
  "src/connector-catalog.mjs",
  "src/enterprise-analytics.mjs",
  "src/advanced-operations.mjs",
  "Dockerfile",
  ".github/workflows/ci.yml",
  ".env.example"
].map(async (path) => [path, await readFile(path, "utf8")])));

const checks = [
  ["Production startup hardening", files["server.mjs"].includes("NDR_PRODUCTION_HARDENING") && files["server.mjs"].includes("Production durable ingest requires NDR_QUEUE_URL")],
  ["Durable ingest queue and DLQ", files["infra/aws/terraform/main.tf"].includes('resource "aws_sqs_queue" "ingest"') && files["infra/aws/terraform/main.tf"].includes('resource "aws_sqs_queue" "ingest_dlq"')],
  ["Separate autoscaled worker service", files["infra/aws/terraform/main.tf"].includes('resource "aws_ecs_service" "worker"') && files["infra/aws/terraform/main.tf"].includes('resource "aws_appautoscaling_policy" "worker_queue_depth"')],
  ["Immutable evidence and audit storage", files["infra/aws/terraform/main.tf"].includes('resource "aws_s3_bucket_object_lock_configuration" "audit"') && files["infra/aws/terraform/main.tf"].includes('resource "aws_s3_bucket_object_lock_configuration" "evidence"')],
  ["Customer-managed encryption", files["infra/aws/terraform/main.tf"].includes('resource "aws_kms_key" "app"') && files["infra/aws/terraform/main.tf"].includes("kms:Decrypt")],
  ["OCSF analytics delivery", files["infra/aws/terraform/main.tf"].includes('resource "aws_kinesis_firehose_delivery_stream" "ocsf"') && files["infra/aws/terraform/main.tf"].includes('resource "aws_glue_catalog_table" "ocsf"') && files["src/ocsf.mjs"].includes("Network Activity")],
  ["Dual OCSF compatibility profiles", files["src/advanced-operations.mjs"].includes('"native-current"') && files["src/advanced-operations.mjs"].includes('"security-lake-1.3"') && files["infra/aws/terraform/main.tf"].includes('compression = "ZSTD"')],
  ["Replayable continuous stream", files["infra/aws/terraform/main.tf"].includes('resource "aws_kinesis_stream" "telemetry"') && files["server.mjs"].includes("publishContinuousBatch")],
  ["Durable stream outbox and replay", files["server.mjs"].includes("STREAM_DELIVERY") && files["server.mjs"].includes("/api/stream/deliveries") && files["server.mjs"].includes("streamDeliveriesDeadLettered")],
  ["Advanced operations governance", files["src/advanced-operations.mjs"].includes("scoreAttackUrgency") && files["server.mjs"].includes("/api/response-policy/kill-switch") && files["server.mjs"].includes("/api/packet-manifests/")],
  ["Exact-origin direct evidence uploads", files["infra/aws/terraform/main.tf"].includes('resource "aws_s3_bucket_cors_configuration" "evidence"') && files["infra/aws/terraform/variables.tf"].includes("direct_upload_allowed_origins")],
  ["Signed scanner and packet provenance", files["server.mjs"].includes("NDR_EVIDENCE_SCANNER_SUBJECTS") && files["server.mjs"].includes("NDR_PACKET_ALLOWED_BUCKETS") && files["server.mjs"].includes("verifyEvidenceScanAttestation")],
  ["Organization member trust boundary", files["infra/aws/member-account-role.yaml"].includes("sts:ExternalId") && files["infra/aws/terraform/main.tf"].includes("organizations:ListAccounts") && files["infra/aws/terraform/main.tf"].includes("sts:AssumeRole")],
  ["Governed response bus", files["infra/aws/terraform/main.tf"].includes('resource "aws_cloudwatch_event_bus" "response"') && files["infra/aws/terraform/main.tf"].includes("events:PutEvents")],
  ["Bounded connector policy", files["src/connector-catalog.mjs"].includes("Secrets Manager") && files["src/connector-catalog.mjs"].includes("Private or loopback")],
  ["Deterministic enterprise analytics", files["src/enterprise-analytics.mjs"].includes("buildBehaviorAnalytics") && files["src/enterprise-analytics.mjs"].includes("runRetrospectiveHunt")],
  ["Lifecycle identity secrets", files["infra/aws/terraform/main.tf"].includes("NDR_SCIM_BEARER_TOKEN") && files["infra/aws/terraform/main.tf"].includes("NDR_SERVICE_ACCOUNT_PEPPER")],
  ["Opaque sessions and privileged step-up", files["server.mjs"].includes("SESSION_INDEX") && files["server.mjs"].includes("requireStepUp") && files["server.mjs"].includes("OIDC discovery issuer does not match")],
  ["Fail-closed directory and source authorization", files["server.mjs"].includes("TENANT_DIRECTORY_REQUIRED") && files["server.mjs"].includes("listAuthorizedTenantObjects") && files["server.mjs"].includes("principalIdentity")],
  ["Identifier-only worker messages", files["server.mjs"].includes('version: 2') && files["server.mjs"].includes("jobId: job.id") && !files["server.mjs"].includes("...payload.job")],
  ["Short-lived export payload storage", files["server.mjs"].includes("persistExportApprovalPayload") && files["server.mjs"].includes("deleteExportApprovalPayload") && files["infra/aws/terraform/main.tf"].includes("NDR_EXPORT_PAYLOAD_BUCKET")],
  ["Independent response verification", files["server.mjs"].includes("RESPONSE_VERIFIER_SUBJECTS") && files["infra/aws/terraform/variables.tf"].includes("response_verifier_subjects")],
  ["Distributed tenant limits", files["server.mjs"].includes("DISTRIBUTED_RATE_LIMIT") && files["server.mjs"].includes("reserveAiUsage") && files[".env.example"].includes("NDR_MAX_BEDROCK_CALLS_PER_DAY")],
  ["Signed detection content", files["server.mjs"].includes("verifyDetectionContentBundle") && files["infra/aws/terraform/variables.tf"].includes("detection_content_public_key_b64")],
  ["Non-root read-only container", files.Dockerfile.includes("USER") && files.Dockerfile.includes("NODE_ENV=production")],
  ["Pinned CI actions and dependency audit", files[".github/workflows/ci.yml"].includes("npm audit --audit-level=high") && /uses: [^\s]+@[a-f0-9]{40}/.test(files[".github/workflows/ci.yml"])],
  ["Configuration contract documented", files[".env.example"].includes("NDR_QUEUE_URL") && files[".env.example"].includes("NDR_DETECTION_CONTENT_PUBLIC_KEY_B64") && files[".env.example"].includes("NDR_CONTINUOUS_STREAM_MODE") && files[".env.example"].includes("NDR_DDB_GSI_MIGRATION_MODE")]
];

const failed = checks.filter(([, passed]) => !passed);
checks.forEach(([name, passed]) => console.log(`${passed ? "PASS" : "FAIL"} ${name}`));
if (failed.length) {
  console.error(`${failed.length} enterprise deployment checks failed.`);
  process.exit(1);
}
console.log(`${checks.length} enterprise deployment checks passed.`);
