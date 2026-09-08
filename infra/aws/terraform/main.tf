terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.63"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "app" {
  description             = "SignalPrism NDR tenant data encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.tags
}

resource "aws_kms_alias" "app" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.app.key_id
}

locals {
  name = "ndr-flow-console-${var.environment}"
  ocsf_firehose_classes = {
    network_activity = { suffix = "network", class_uid = 4001 }
    security_finding = { suffix = "finding", class_uid = 2001 }
  }
  hot_search_resource_arns = length(var.hot_search_resource_arns) > 0 ? var.hot_search_resource_arns : [
    "arn:aws:es:${var.region}:${data.aws_caller_identity.current.account_id}:domain/${local.name}-*",
    "arn:aws:aoss:${var.region}:${data.aws_caller_identity.current.account_id}:collection/*"
  ]
  tags = {
    Application = "SignalPrism NDR"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
  runtime_environment = [
    { name = "PORT", value = tostring(var.container_port) },
    { name = "NDR_DATA_DIR", value = "/mnt/ndr-data" },
    { name = "NDR_STORE", value = var.store_mode },
    { name = "NDR_DDB_TABLE", value = aws_dynamodb_table.app.name },
    { name = "NDR_DDB_REGION", value = var.region },
    { name = "NDR_DDB_GSI_MIGRATION_MODE", value = var.ddb_gsi_migration_mode },
    { name = "NDR_SESSION_TTL_SECONDS", value = "28800" },
    { name = "NDR_SESSION_COOKIE_SECURE", value = var.certificate_arn == "" ? "false" : "true" },
    { name = "NDR_SESSION_REGISTRY_REQUIRED", value = "true" },
    { name = "NDR_PRODUCTION_HARDENING", value = var.environment == "prod" ? "true" : "false" },
    { name = "NDR_ALLOW_LOCAL_DEV_ADMIN", value = "false" },
    { name = "NDR_ALLOW_DIRECT_INGEST", value = "false" },
    { name = "NDR_BROWSER_EVIDENCE_CACHE", value = "disabled" },
    { name = "NDR_REQUIRE_OIDC_TENANT_CLAIM", value = "true" },
    { name = "NDR_REQUIRE_SEPARATE_APPROVER", value = "true" },
    { name = "NDR_STEP_UP_REQUIRED", value = var.environment == "prod" ? "true" : "false" },
    { name = "NDR_STEP_UP_MAX_AGE_SECONDS", value = tostring(var.step_up_max_age_seconds) },
    { name = "NDR_TRUST_PROXY", value = "true" },
    { name = "NDR_RATE_LIMIT_MAX", value = tostring(var.rate_limit_max) },
    { name = "NDR_RATE_LIMIT_WINDOW_MS", value = tostring(var.rate_limit_window_ms) },
    { name = "NDR_RATE_LIMIT_MAX_IDENTITIES", value = tostring(var.rate_limit_max_identities) },
    { name = "NDR_DISTRIBUTED_RATE_LIMIT", value = "true" },
    { name = "NDR_MAX_JOBS_PER_TENANT", value = tostring(var.max_jobs_per_tenant) },
    { name = "NDR_MAX_ACTIVE_RUNS_PER_TENANT", value = tostring(var.max_active_runs_per_tenant) },
    { name = "NDR_MAX_PENDING_EXPORT_APPROVALS", value = tostring(var.max_pending_export_approvals) },
    { name = "NDR_ACTIVE_RUN_SLOT_TTL_SECONDS", value = tostring(var.active_run_slot_ttl_seconds) },
    { name = "NDR_MIN_JOB_INTERVAL_MINUTES", value = tostring(var.min_job_interval_minutes) },
    { name = "NDR_MAX_JOB_INTERVAL_MINUTES", value = tostring(var.max_job_interval_minutes) },
    { name = "NDR_AWS_REQUEST_TIMEOUT_MS", value = tostring(var.aws_request_timeout_ms) },
    { name = "NDR_OIDC_REQUEST_TIMEOUT_MS", value = tostring(var.oidc_request_timeout_ms) },
    { name = "NDR_AUDIT_RETENTION_DAYS", value = tostring(var.audit_retention_days) },
    { name = "NDR_AUDIT_BUCKET", value = aws_s3_bucket.audit.bucket },
    { name = "NDR_AUDIT_PREFIX", value = "signalprism/audit" },
    { name = "NDR_AUDIT_REGION", value = var.region },
    { name = "NDR_AUDIT_OBJECT_LOCK_MODE", value = "COMPLIANCE" },
    { name = "NDR_AUDIT_OBJECT_STORAGE_REQUIRED", value = "true" },
    { name = "NDR_EVIDENCE_BUCKET", value = aws_s3_bucket.evidence.bucket },
    { name = "NDR_EVIDENCE_STAGING_BUCKET", value = aws_s3_bucket.evidence_staging.bucket },
    { name = "NDR_EXPORT_PAYLOAD_BUCKET", value = aws_s3_bucket.evidence_staging.bucket },
    { name = "NDR_TENANT_DIRECTORY_REQUIRED", value = var.environment == "prod" ? "true" : "false" },
    { name = "NDR_OIDC_SESSION_TTL_SECONDS", value = var.environment == "prod" ? "900" : "28800" },
    { name = "NDR_EVIDENCE_SCAN_REQUIRED", value = "true" },
    { name = "NDR_EVIDENCE_STORAGE_REQUIRED", value = "true" },
    { name = "NDR_EVIDENCE_CHECKSUM_REQUIRED", value = "true" },
    { name = "NDR_EVIDENCE_SCAN_ATTESTATION_REQUIRED", value = "true" },
    { name = "NDR_EVIDENCE_SCANNER_SUBJECTS", value = join(",", var.evidence_scanner_subjects) },
    { name = "NDR_EVIDENCE_PREFIX", value = "signalprism/evidence-packages" },
    { name = "NDR_EVIDENCE_REGION", value = var.region },
    { name = "NDR_EVIDENCE_RETENTION_DAYS", value = tostring(var.evidence_retention_days) },
    { name = "NDR_EVIDENCE_OBJECT_LOCK_MODE", value = var.evidence_object_lock_mode },
    { name = "NDR_EVIDENCE_ATTESTATION_KEY_ID", value = var.evidence_attestation_key_id },
    { name = "NDR_MAX_EVIDENCE_UPLOAD_BYTES", value = tostring(var.max_evidence_upload_bytes) },
    { name = "NDR_MAX_ACTIVE_EVIDENCE_UPLOADS", value = tostring(var.max_active_evidence_uploads) },
    { name = "NDR_MAX_TENANT_EVIDENCE_RESERVED_BYTES", value = tostring(var.max_tenant_evidence_reserved_bytes) },
    { name = "NDR_PACKET_ALLOWED_BUCKETS", value = aws_s3_bucket.evidence.bucket },
    { name = "NDR_PACKET_ALLOWED_PREFIXES", value = "signalprism/evidence-packages" },
    { name = "NDR_PACKET_OBJECT_VERIFICATION_REQUIRED", value = "true" },
    { name = "NDR_OIDC_ISSUER", value = var.oidc_issuer },
    { name = "NDR_OIDC_AUDIENCE", value = var.oidc_audience },
    { name = "NDR_OIDC_CLIENT_ID", value = var.oidc_client_id },
    { name = "NDR_OIDC_REDIRECT_URI", value = var.oidc_redirect_uri },
    { name = "NDR_OIDC_SCOPES", value = var.oidc_scopes },
    { name = "NDR_ADMIN_GROUP", value = var.admin_group },
    { name = "NDR_ANALYST_GROUP", value = var.analyst_group },
    { name = "NDR_VIEWER_GROUP", value = var.viewer_group },
    { name = "NDR_DEFAULT_TENANT", value = var.default_tenant },
    { name = "NDR_TENANT_CLAIM", value = var.tenant_claim },
    { name = "NDR_BEDROCK_ENABLED", value = tostring(var.bedrock_enabled) },
    { name = "NDR_BEDROCK_REGION", value = var.bedrock_region },
    { name = "NDR_BEDROCK_MODEL_ID", value = var.bedrock_model_id },
    { name = "NDR_BEDROCK_MAX_TOKENS", value = tostring(var.bedrock_max_tokens) },
    { name = "NDR_BEDROCK_TEMPERATURE", value = tostring(var.bedrock_temperature) },
    { name = "NDR_BEDROCK_MAX_CONTEXT_CHARS", value = tostring(var.bedrock_max_context_chars) },
    { name = "NDR_QUEUE_URL", value = aws_sqs_queue.ingest.url },
    { name = "NDR_QUEUE_ARN", value = aws_sqs_queue.ingest.arn },
    { name = "NDR_QUEUE_REGION", value = var.region },
    { name = "NDR_SCHEDULER_MODE", value = "eventbridge" },
    { name = "NDR_SCHEDULER_ROLE_ARN", value = aws_iam_role.scheduler.arn },
    { name = "NDR_QUEUE_VISIBILITY_SECONDS", value = tostring(var.queue_visibility_timeout_seconds) },
    { name = "NDR_REQUIRE_DURABLE_QUEUE", value = "true" },
    { name = "NDR_RESPONSE_EVENT_BUS", value = aws_cloudwatch_event_bus.response.name },
    { name = "NDR_RESPONSE_EXECUTION_ENABLED", value = tostring(var.response_execution_enabled) },
    { name = "NDR_RESPONSE_VERIFIER_SUBJECTS", value = join(",", var.response_verifier_subjects) },
    { name = "NDR_DETECTION_CONTENT_PUBLIC_KEY_B64", value = var.detection_content_public_key_b64 },
    { name = "NDR_FIREHOSE_STREAM_NAME", value = "" },
    { name = "NDR_FIREHOSE_NETWORK_STREAM_NAME", value = aws_kinesis_firehose_delivery_stream.ocsf["network_activity"].name },
    { name = "NDR_FIREHOSE_FINDING_STREAM_NAME", value = aws_kinesis_firehose_delivery_stream.ocsf["security_finding"].name },
    { name = "NDR_FIREHOSE_REGION", value = var.region },
    { name = "NDR_CONTINUOUS_STREAM_MODE", value = var.continuous_stream_mode },
    { name = "NDR_STREAM_DELIVERY_MAX_ATTEMPTS", value = tostring(var.stream_delivery_max_attempts) },
    { name = "NDR_STREAM_RETRY_INTERVAL_SECONDS", value = tostring(var.stream_retry_interval_seconds) },
    { name = "NDR_STREAM_RETRY_BATCH_SIZE", value = tostring(var.stream_retry_batch_size) },
    { name = "NDR_KINESIS_STREAM_NAME", value = aws_kinesis_stream.telemetry.name },
    { name = "NDR_HOT_SEARCH_MODE", value = var.hot_search_mode },
    { name = "NDR_HOT_SEARCH_ENDPOINT", value = var.hot_search_endpoint },
    { name = "NDR_SECURITY_LAKE_ASSIGNED_PREFIX", value = var.security_lake_assigned_prefix },
    { name = "NDR_SECURITY_LAKE_PROVIDER_ACCOUNT_ID", value = var.security_lake_provider_account_id },
    { name = "NDR_SECURITY_LAKE_CRAWLER_ROLE_ARN", value = var.security_lake_crawler_role_arn },
    { name = "NDR_SECURITY_LAKE_REGION", value = var.region },
    { name = "NDR_RESPONSE_KILL_SWITCH", value = tostring(var.response_kill_switch) },
    { name = "NDR_PLATFORM_KMS_KEY_ARN", value = aws_kms_key.app.arn },
    { name = "NDR_TENANT_BYOK_KEY_ARN", value = var.tenant_byok_key_arn },
    { name = "NDR_AIR_GAPPED", value = tostring(var.air_gapped) },
    { name = "NDR_ORGANIZATION_DISCOVERY_ENABLED", value = tostring(var.organization_discovery_enabled) },
    { name = "NDR_ORGANIZATION_REGION", value = var.organization_region },
    { name = "NDR_ORGANIZATION_MEMBER_ROLE_NAME", value = var.organization_member_role_name },
    { name = "NDR_ORGANIZATION_EXTERNAL_ID", value = var.organization_external_id },
    { name = "NDR_SCIM_TENANT_ID", value = var.default_tenant },
    { name = "NDR_MAX_AI_AGENT_RUNS_PER_DAY", value = tostring(var.max_ai_agent_runs_per_day) },
    { name = "NDR_MAX_BEDROCK_CALLS_PER_DAY", value = tostring(var.max_bedrock_calls_per_day) },
    { name = "NDR_MAX_BEDROCK_RESERVED_TOKENS_PER_DAY", value = tostring(var.max_bedrock_reserved_tokens_per_day) },
    { name = "NDR_DETECTION_BACKTEST_MAX_AGE_DAYS", value = tostring(var.detection_backtest_max_age_days) },
    { name = "NDR_DIRECT_UPLOAD_TTL_SECONDS", value = tostring(var.direct_upload_ttl_seconds) }
  ]
  runtime_secrets = concat(
    var.api_key_secret_arn == "" ? [] : [{ name = "NDR_API_KEY", valueFrom = var.api_key_secret_arn }],
    [
      { name = "NDR_SESSION_SECRET", valueFrom = var.session_secret_arn },
      { name = "NDR_EVIDENCE_ATTESTATION_SECRET", valueFrom = var.evidence_attestation_secret_arn }
    ],
    var.oidc_client_secret_arn == "" ? [] : [{ name = "NDR_OIDC_CLIENT_SECRET", valueFrom = var.oidc_client_secret_arn }],
    var.scim_bearer_token_secret_arn == "" ? [] : [{ name = "NDR_SCIM_BEARER_TOKEN", valueFrom = var.scim_bearer_token_secret_arn }],
    var.service_account_pepper_secret_arn == "" ? [] : [{ name = "NDR_SERVICE_ACCOUNT_PEPPER", valueFrom = var.service_account_pepper_secret_arn }],
    var.security_lake_provider_external_id_secret_arn == "" ? [] : [{ name = "NDR_SECURITY_LAKE_PROVIDER_EXTERNAL_ID", valueFrom = var.security_lake_provider_external_id_secret_arn }]
  )
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/ndr-flow-console/${var.environment}"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

resource "aws_ecr_repository" "app" {
  name                 = "ndr-flow-console"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = local.tags
}

resource "aws_dynamodb_table" "app" {
  name         = local.name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "gsi1pk"
    type = "S"
  }

  attribute {
    name = "gsi1sk"
    type = "S"
  }

  attribute {
    name = "gsi2pk"
    type = "S"
  }

  attribute {
    name = "gsi2sk"
    type = "S"
  }

  global_secondary_index {
    name            = "kind-createdAt-index"
    hash_key        = "gsi1pk"
    range_key       = "gsi1sk"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "tenant-kind-createdAt-index"
    hash_key        = "gsi2pk"
    range_key       = "gsi2sk"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.app.arn
  }

  tags = local.tags
}

resource "aws_sqs_queue" "ingest_dlq" {
  name                      = "${local.name}-ingest-dlq"
  message_retention_seconds = 1209600
  kms_master_key_id         = aws_kms_key.app.arn
  tags                      = local.tags
}

resource "aws_sqs_queue" "ingest" {
  name                       = "${local.name}-ingest"
  visibility_timeout_seconds = var.queue_visibility_timeout_seconds
  receive_wait_time_seconds  = 20
  message_retention_seconds  = var.queue_message_retention_seconds
  kms_master_key_id          = aws_kms_key.app.arn
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.ingest_dlq.arn
    maxReceiveCount     = var.queue_max_receive_count
  })
  tags = local.tags
}

resource "aws_iam_role" "scheduler" {
  name = "${local.name}-scheduler"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "scheduler.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "scheduler" {
  name = "${local.name}-scheduler-send"
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["sqs:SendMessage"], Resource = aws_sqs_queue.ingest.arn },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.app.arn }
    ]
  })
}

resource "aws_sqs_queue_redrive_allow_policy" "ingest" {
  queue_url = aws_sqs_queue.ingest_dlq.id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.ingest.arn]
  })
}

resource "aws_kinesis_stream" "telemetry" {
  name             = "${local.name}-telemetry"
  retention_period = var.stream_retention_hours
  encryption_type  = "KMS"
  kms_key_id       = aws_kms_key.app.arn
  stream_mode_details { stream_mode = "ON_DEMAND" }
  tags = local.tags
}

resource "aws_cloudwatch_event_bus" "response" {
  name = "${local.name}-response"
  tags = local.tags
}

resource "aws_cloudwatch_event_archive" "response" {
  name             = "${local.name}-response"
  event_source_arn = aws_cloudwatch_event_bus.response.arn
  retention_days   = var.response_archive_retention_days
  description      = "Approved SignalPrism response actions for audit and replay"
}

resource "aws_s3_bucket" "audit" {
  bucket_prefix       = "${local.name}-audit-"
  object_lock_enabled = true
  force_destroy       = false
  tags                = local.tags
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.app.arn
    }
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket     = aws_s3_bucket.audit.id
  depends_on = [aws_s3_bucket_versioning.audit]

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.audit_retention_days
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_bucket" "evidence" {
  bucket_prefix       = "${local.name}-evidence-"
  object_lock_enabled = true
  force_destroy       = false
  tags                = local.tags
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.app.arn
    }
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket     = aws_s3_bucket.evidence.id
  depends_on = [aws_s3_bucket_versioning.evidence]

  rule {
    default_retention {
      mode = var.evidence_object_lock_mode
      days = var.evidence_retention_days
    }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_bucket_cors_configuration" "evidence" {
  count  = length(var.direct_upload_allowed_origins) > 0 ? 1 : 0
  bucket = aws_s3_bucket.evidence.id

  cors_rule {
    allowed_headers = ["content-type", "x-amz-checksum-sha256", "x-amz-meta-signalprism-tenant", "x-amz-meta-signalprism-upload-id", "x-amz-object-lock-mode", "x-amz-object-lock-retain-until-date"]
    allowed_methods = ["PUT"]
    allowed_origins = var.direct_upload_allowed_origins
    expose_headers  = ["etag", "x-amz-checksum-sha256", "x-amz-version-id"]
    max_age_seconds = 900
  }
}

resource "aws_s3_bucket" "evidence_staging" {
  bucket_prefix = "${local.name}-evidence-staging-"
  force_destroy = true
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "evidence_staging" {
  bucket                  = aws_s3_bucket.evidence_staging.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_staging" {
  bucket = aws_s3_bucket.evidence_staging.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.app.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "evidence_staging" {
  bucket = aws_s3_bucket.evidence_staging.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence_staging" {
  bucket     = aws_s3_bucket.evidence_staging.id
  depends_on = [aws_s3_bucket_versioning.evidence_staging]
  rule {
    id     = "expire-quarantine"
    status = "Enabled"
    expiration { days = 3 }
    noncurrent_version_expiration { noncurrent_days = 3 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

resource "aws_s3_bucket_policy" "evidence_staging" {
  bucket = aws_s3_bucket.evidence_staging.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.evidence_staging.arn, "${aws_s3_bucket.evidence_staging.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_bucket_cors_configuration" "evidence_staging" {
  count  = length(var.direct_upload_allowed_origins) > 0 ? 1 : 0
  bucket = aws_s3_bucket.evidence_staging.id
  cors_rule {
    allowed_headers = ["content-type", "x-amz-checksum-sha256", "x-amz-meta-signalprism-tenant", "x-amz-meta-signalprism-upload-id"]
    allowed_methods = ["PUT"]
    allowed_origins = var.direct_upload_allowed_origins
    expose_headers  = ["etag", "x-amz-checksum-sha256", "x-amz-version-id"]
    max_age_seconds = 900
  }
}

resource "aws_s3_bucket" "analytics" {
  bucket_prefix = "${local.name}-ocsf-"
  force_destroy = false
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "analytics" {
  bucket                  = aws_s3_bucket.analytics.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "analytics" {
  bucket = aws_s3_bucket.analytics.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "analytics" {
  bucket = aws_s3_bucket.analytics.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.app.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "analytics" {
  bucket = aws_s3_bucket.analytics.id
  rule {
    id     = "tier-and-expire-ocsf"
    status = "Enabled"
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }
    expiration { days = var.analytics_retention_days }
    noncurrent_version_expiration { noncurrent_days = 30 }
  }
}

resource "aws_s3_bucket_policy" "analytics" {
  bucket = aws_s3_bucket.analytics.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.analytics.arn, "${aws_s3_bucket.analytics.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_glue_catalog_database" "ocsf" {
  name        = replace("${local.name}-ocsf", "-", "_")
  description = "SignalPrism OCSF analytics catalog"
}

resource "aws_glue_catalog_table" "ocsf" {
  name          = "network_activity_and_findings"
  database_name = aws_glue_catalog_database.ocsf.name
  table_type    = "EXTERNAL_TABLE"
  parameters = {
    classification = "parquet"
    EXTERNAL       = "TRUE"
  }

  partition_keys {
    name = "region"
    type = "string"
  }
  partition_keys {
    name = "accountid"
    type = "string"
  }
  partition_keys {
    name = "eventday"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.analytics.bucket}/${trim(var.security_lake_assigned_prefix, "/")}/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }

    columns {
      name = "class_uid"
      type = "int"
    }
    columns {
      name = "class_name"
      type = "string"
    }
    columns {
      name = "category_uid"
      type = "int"
    }
    columns {
      name = "category_name"
      type = "string"
    }
    columns {
      name = "activity_id"
      type = "int"
    }
    columns {
      name = "activity_name"
      type = "string"
    }
    columns {
      name = "type_uid"
      type = "bigint"
    }
    columns {
      name = "time"
      type = "bigint"
    }
    columns {
      name = "start_time"
      type = "bigint"
    }
    columns {
      name = "end_time"
      type = "bigint"
    }
    columns {
      name = "severity_id"
      type = "int"
    }
    columns {
      name = "severity"
      type = "string"
    }
    columns {
      name = "status"
      type = "string"
    }
    columns {
      name = "action"
      type = "string"
    }
    columns {
      name = "title"
      type = "string"
    }
    columns {
      name = "message"
      type = "string"
    }
    columns {
      name = "raw_data"
      type = "string"
    }
    columns {
      name = "metadata"
      type = "struct<version:string,logged_time:bigint,uid:string,tenant_uid:string,product:struct<name:string,vendor_name:string,version:string,feature:struct<name:string>>,profiles:array<string>>"
    }
    columns {
      name = "src_endpoint"
      type = "struct<ip:string,port:int,name:string>"
    }
    columns {
      name = "dst_endpoint"
      type = "struct<ip:string,port:int,name:string>"
    }
    columns {
      name = "connection_info"
      type = "struct<protocol_name:string,direction:string,boundary:string>"
    }
    columns {
      name = "traffic"
      type = "struct<bytes:bigint,packets:bigint>"
    }
    columns {
      name = "cloud"
      type = "struct<account:struct<uid:string>,region:string,provider:string>"
    }
    columns {
      name = "finding_info"
      type = "struct<uid:string,title:string,analytic:struct<uid:string,name:string,type:string>,types:array<string>>"
    }
  }
}

resource "aws_cloudwatch_log_stream" "firehose" {
  name           = "ocsf-firehose"
  log_group_name = aws_cloudwatch_log_group.app.name
}

resource "aws_iam_role" "firehose" {
  name = "${local.name}-firehose"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "firehose.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "firehose" {
  name = "${local.name}-firehose"
  role = aws_iam_role.firehose.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"]
        Resource = [aws_s3_bucket.analytics.arn, "${aws_s3_bucket.analytics.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["glue:GetTable", "glue:GetTableVersion", "glue:GetTableVersions"]
        Resource = [aws_glue_catalog_database.ocsf.arn, aws_glue_catalog_table.ocsf.arn, "arn:aws:glue:${var.region}:${data.aws_caller_identity.current.account_id}:catalog"]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.app.arn
      },
      {
        Effect   = "Allow"
        Action   = ["logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.app.arn}:log-stream:${aws_cloudwatch_log_stream.firehose.name}"
      }
    ]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "ocsf" {
  for_each    = local.ocsf_firehose_classes
  name        = "${local.name}-ocsf-${each.value.suffix}"
  destination = "extended_s3"
  tags        = local.tags

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose.arn
    bucket_arn          = aws_s3_bucket.analytics.arn
    prefix              = "${trim(var.security_lake_assigned_prefix, "/")}/classUid=${each.value.class_uid}/region=!{partitionKeyFromQuery:region}/accountId=!{partitionKeyFromQuery:accountId}/eventDay=!{partitionKeyFromQuery:eventDay}/"
    error_output_prefix = "errors/classUid=${each.value.class_uid}/type=!{firehose:error-output-type}/day=!{timestamp:yyyyMMdd}/"
    buffering_size      = 64
    buffering_interval  = 300
    compression_format  = "UNCOMPRESSED"

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.app.name
      log_stream_name = aws_cloudwatch_log_stream.firehose.name
    }

    dynamic_partitioning_configuration {
      enabled        = true
      retry_duration = 300
    }

    processing_configuration {
      enabled = true
      processors {
        type = "MetadataExtraction"
        parameters {
          parameter_name  = "MetadataExtractionQuery"
          parameter_value = "{region:(.cloud.region // \"global\"),accountId:(.cloud.account.uid // \"unknown\"),eventDay:(.time/1000|strftime(\"%Y%m%d\"))}"
        }
        parameters {
          parameter_name  = "JsonParsingEngine"
          parameter_value = "JQ-1.6"
        }
      }
      processors { type = "AppendDelimiterToRecord" }
    }

    data_format_conversion_configuration {
      enabled = true
      input_format_configuration {
        deserializer {
          open_x_json_ser_de {}
        }
      }
      output_format_configuration {
        serializer {
          parquet_ser_de {
            compression = "ZSTD"
          }
        }
      }
      schema_configuration {
        database_name = aws_glue_catalog_database.ocsf.name
        role_arn      = aws_iam_role.firehose.arn
        table_name    = aws_glue_catalog_table.ocsf.name
        version_id    = "LATEST"
        region        = var.region
      }
    }
  }

  depends_on = [aws_iam_role_policy.firehose, aws_s3_bucket_server_side_encryption_configuration.analytics]
}

resource "aws_s3_bucket" "alb_logs" {
  bucket_prefix = "${local.name}-alb-logs-"
  force_destroy = false
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    id     = "expire-access-logs"
    status = "Enabled"
    expiration { days = var.alb_log_retention_days }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowALBLogDelivery"
        Effect    = "Allow"
        Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.alb_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.alb_logs.arn, "${aws_s3_bucket.alb_logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

resource "aws_iam_role" "task_execution" {
  name = "ndr-flow-console-${var.environment}-task-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "task_execution" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "task_execution_secrets" {
  name = "${local.name}-execution-secrets"
  role = aws_iam_role.task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["secretsmanager:GetSecretValue"]
      Resource = compact([
        var.api_key_secret_arn,
        var.session_secret_arn,
        var.evidence_attestation_secret_arn,
        var.oidc_client_secret_arn,
        var.scim_bearer_token_secret_arn,
        var.service_account_pepper_secret_arn,
        var.security_lake_provider_external_id_secret_arn
      ])
    }]
  })
}

resource "aws_iam_role" "task" {
  name = "ndr-flow-console-${var.environment}-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "ingest" {
  name = "ndr-flow-console-${var.environment}-ingest"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = var.flow_log_bucket_arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${var.flow_log_bucket_arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:FilterLogEvents"]
        Resource = var.cloudwatch_log_group_arns
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:BatchWriteItem",
          "dynamodb:Query",
          "dynamodb:UpdateItem"
        ]
        Resource = [aws_dynamodb_table.app.arn, "${aws_dynamodb_table.app.arn}/index/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:DeleteItem"]
        Resource = aws_dynamodb_table.app.arn
        Condition = {
          "ForAllValues:StringLike" = {
            "dynamodb:LeadingKeys" = ["TENANT#*"]
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:PutObjectRetention", "s3:PutObjectLegalHold"]
        Resource = "${aws_s3_bucket.audit.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:PutObjectRetention", "s3:PutObjectLegalHold"]
        Resource = "${aws_s3_bucket.evidence.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.evidence_staging.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"]
        Resource = aws_efs_file_system.app.arn
      },
      {
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel"]
        Resource = var.bedrock_model_arns
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.ingest.arn
      },
      {
        Effect   = "Allow"
        Action   = ["events:PutEvents"]
        Resource = aws_cloudwatch_event_bus.response.arn
      },
      {
        Effect   = "Allow"
        Action   = ["firehose:PutRecord", "firehose:PutRecordBatch"]
        Resource = values(aws_kinesis_firehose_delivery_stream.ocsf)[*].arn
      },
      {
        Effect   = "Allow"
        Action   = ["kinesis:PutRecord", "kinesis:PutRecords", "kinesis:DescribeStreamSummary"]
        Resource = aws_kinesis_stream.telemetry.arn
      },
      {
        Effect   = "Allow"
        Action   = ["es:ESHttpPost", "aoss:APIAccessAll"]
        Resource = local.hot_search_resource_arns
      },
      {
        Effect   = "Allow"
        Action   = ["organizations:ListAccounts"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["securitylake:CreateCustomLogSource"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["scheduler:CreateSchedule", "scheduler:UpdateSchedule", "scheduler:DeleteSchedule", "scheduler:GetSchedule"]
        Resource = "arn:aws:scheduler:${var.region}:${data.aws_caller_identity.current.account_id}:schedule/default/signalprism-*"
      },
      {
        Effect    = "Allow"
        Action    = ["iam:PassRole"]
        Resource  = aws_iam_role.scheduler.arn
        Condition = { StringEquals = { "iam:PassedToService" = "scheduler.amazonaws.com" } }
      },
      {
        Effect    = "Allow"
        Action    = ["iam:PassRole"]
        Resource  = var.security_lake_crawler_role_arn == "" ? "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/SignalPrismSecurityLakeCrawler-*" : var.security_lake_crawler_role_arn
        Condition = { StringEquals = { "iam:PassedToService" = "securitylake.amazonaws.com" } }
      },
      {
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = "arn:aws:iam::*:role/${var.organization_member_role_name}"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = aws_kms_key.app.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ingest" {
  role       = aws_iam_role.task.name
  policy_arn = aws_iam_policy.ingest.arn
}

resource "aws_iam_role" "worker_task" {
  name = "ndr-flow-console-${var.environment}-worker"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "worker_task" {
  name = "${local.name}-worker-least-privilege"
  role = aws_iam_role.worker_task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = var.flow_log_bucket_arn },
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = "${var.flow_log_bucket_arn}/*" },
      { Effect = "Allow", Action = ["logs:FilterLogEvents"], Resource = var.cloudwatch_log_group_arns },
      { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:BatchWriteItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:UpdateItem"], Resource = [aws_dynamodb_table.app.arn, "${aws_dynamodb_table.app.arn}/index/*"] },
      { Effect = "Allow", Action = ["s3:PutObject", "s3:GetObject", "s3:PutObjectRetention", "s3:PutObjectLegalHold"], Resource = ["${aws_s3_bucket.audit.arn}/*", "${aws_s3_bucket.evidence.arn}/*"] },
      { Effect = "Allow", Action = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"], Resource = aws_efs_file_system.app.arn },
      { Effect = "Allow", Action = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"], Resource = aws_sqs_queue.ingest.arn },
      { Effect = "Allow", Action = ["firehose:PutRecord", "firehose:PutRecordBatch"], Resource = values(aws_kinesis_firehose_delivery_stream.ocsf)[*].arn },
      { Effect = "Allow", Action = ["kinesis:PutRecord", "kinesis:PutRecords", "kinesis:DescribeStreamSummary"], Resource = aws_kinesis_stream.telemetry.arn },
      { Effect = "Allow", Action = ["sts:AssumeRole"], Resource = "arn:aws:iam::*:role/${var.organization_member_role_name}" },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"], Resource = aws_kms_key.app.arn }
    ]
  })
}

resource "aws_security_group" "alb" {
  name        = "${local.name}-alb"
  description = "Ingress to the SignalPrism NDR ALB"
  vpc_id      = var.vpc_id
  tags        = local.tags

  dynamic "ingress" {
    for_each = toset([80, 443])
    content {
      description = "Client HTTP(S)"
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = var.allowed_ingress_cidrs
    }
  }

}

resource "aws_security_group" "app" {
  name        = "${local.name}-app"
  description = "Fargate task ingress from ALB"
  vpc_id      = var.vpc_id
  tags        = local.tags

  ingress {
    description     = "ALB to app"
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

}

resource "aws_security_group" "efs" {
  name        = "${local.name}-efs"
  description = "EFS ingress from Fargate tasks"
  vpc_id      = var.vpc_id
  tags        = local.tags

  ingress {
    description     = "NFS from tasks"
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id            = aws_security_group.alb.id
  referenced_security_group_id = aws_security_group.app.id
  description                  = "ALB to SignalPrism tasks only"
  ip_protocol                  = "tcp"
  from_port                    = var.container_port
  to_port                      = var.container_port
}

resource "aws_vpc_security_group_egress_rule" "app_https" {
  for_each          = toset(var.https_egress_cidrs)
  security_group_id = aws_security_group.app.id
  description       = "HTTPS to AWS APIs and approved OIDC providers"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value

  lifecycle {
    precondition {
      condition     = var.environment != "prod" || var.production_allow_unrestricted_https_egress || each.value != "0.0.0.0/0"
      error_message = "Production HTTPS egress cannot use 0.0.0.0/0 unless production_allow_unrestricted_https_egress is explicitly true. Prefer an egress proxy or approved endpoint CIDRs."
    }
  }
}

resource "aws_vpc_security_group_egress_rule" "app_dns_udp" {
  for_each          = toset(length(var.dns_resolver_cidrs) > 0 ? var.dns_resolver_cidrs : ["${cidrhost(data.aws_vpc.selected.cidr_block, 2)}/32"])
  security_group_id = aws_security_group.app.id
  description       = "DNS resolution"
  ip_protocol       = "udp"
  from_port         = 53
  to_port           = 53
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "app_dns_tcp" {
  for_each          = toset(length(var.dns_resolver_cidrs) > 0 ? var.dns_resolver_cidrs : ["${cidrhost(data.aws_vpc.selected.cidr_block, 2)}/32"])
  security_group_id = aws_security_group.app.id
  description       = "DNS resolution fallback"
  ip_protocol       = "tcp"
  from_port         = 53
  to_port           = 53
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "app_ecs_credentials" {
  security_group_id = aws_security_group.app.id
  description       = "ECS task credential endpoint"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "169.254.170.2/32"
}

resource "aws_vpc_security_group_egress_rule" "app_to_efs" {
  security_group_id            = aws_security_group.app.id
  referenced_security_group_id = aws_security_group.efs.id
  description                  = "NFS to the application EFS mount"
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
}

resource "aws_efs_file_system" "app" {
  creation_token = local.name
  encrypted      = true
  kms_key_id     = aws_kms_key.app.arn
  tags           = local.tags

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }
}

resource "aws_efs_backup_policy" "app" {
  file_system_id = aws_efs_file_system.app.id
  backup_policy { status = "ENABLED" }
}

resource "aws_efs_mount_target" "app" {
  for_each        = toset(var.private_subnet_ids)
  file_system_id  = aws_efs_file_system.app.id
  subnet_id       = each.value
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_access_point" "app" {
  file_system_id = aws_efs_file_system.app.id

  posix_user {
    gid = 1000
    uid = 1000
  }

  root_directory {
    path = "/ndr-data"

    creation_info {
      owner_gid   = 1000
      owner_uid   = 1000
      permissions = "0750"
    }
  }

  tags = local.tags
}

resource "aws_lb" "app" {
  name                       = local.name
  internal                   = var.alb_internal
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = var.public_subnet_ids
  drop_invalid_header_fields = true
  xff_header_processing_mode = "append"
  enable_deletion_protection = var.environment == "prod"

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.bucket
    enabled = true
  }

  depends_on = [aws_s3_bucket_policy.alb_logs]
  tags       = local.tags
}

resource "aws_wafv2_web_acl" "app" {
  name  = local.name
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedCommonRules"
    priority = 10
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "PerIpRateLimit"
    priority = 20
    action {
      block {}
    }
    statement {
      rate_based_statement {
        aggregate_key_type = "IP"
        limit              = var.waf_rate_limit
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-rate"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = local.name
    sampled_requests_enabled   = true
  }
  tags = local.tags
}

resource "aws_wafv2_web_acl_association" "app" {
  resource_arn = aws_lb.app.arn
  web_acl_arn  = aws_wafv2_web_acl.app.arn
}

resource "aws_lb_target_group" "app" {
  name        = local.name
  port        = var.container_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id
  tags        = local.tags

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/api/health"
    timeout             = 5
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  dynamic "default_action" {
    for_each = var.certificate_arn == "" ? [1] : []
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.app.arn
    }
  }

  dynamic "default_action" {
    for_each = var.certificate_arn == "" ? [] : [1]
    content {
      type = "redirect"

      redirect {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }
}

resource "aws_lb_listener" "https" {
  count             = var.certificate_arn == "" ? 0 : 1
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_ecs_cluster" "app" {
  name = local.name
  tags = local.tags

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "app" {
  family                   = local.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.task.arn
  tags                     = local.tags

  volume {
    name = "ndr-data"

    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.app.id
      transit_encryption = "ENABLED"

      authorization_config {
        access_point_id = aws_efs_access_point.app.id
        iam             = "ENABLED"
      }
    }
  }

  container_definitions = jsonencode([
    {
      name                   = "app"
      image                  = var.container_image
      essential              = true
      user                   = "10001:10001"
      readonlyRootFilesystem = true
      linuxParameters = {
        initProcessEnabled = true
        capabilities       = { drop = ["ALL"] }
      }
      portMappings = [{
        containerPort = var.container_port
        hostPort      = var.container_port
        protocol      = "tcp"
      }]
      mountPoints = [{
        sourceVolume  = "ndr-data"
        containerPath = "/mnt/ndr-data"
        readOnly      = false
      }]
      environment = concat(local.runtime_environment, [{ name = "NDR_PROCESS_ROLE", value = "api" }])
      secrets     = local.runtime_secrets
      healthCheck = {
        command     = ["CMD-SHELL", "node -e \"fetch('http://127.0.0.1:${var.container_port}/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))\""]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 20
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.app.name
          awslogs-region        = var.region
          awslogs-stream-prefix = "app"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = var.api_key_secret_arn != "" || (var.oidc_issuer != "" && var.oidc_client_id != "")
      error_message = "Configure an API key secret ARN or OIDC issuer/client ID before deploying."
    }
    precondition {
      condition     = var.environment != "prod" || var.certificate_arn != ""
      error_message = "Production requires an ACM certificate and HTTPS listener."
    }
    precondition {
      condition     = var.environment != "prod" || can(regex("@sha256:[a-f0-9]{64}$", var.container_image))
      error_message = "Production container_image must be pinned by sha256 digest."
    }
    precondition {
      condition     = var.environment != "prod" || var.oidc_issuer == "" || startswith(var.oidc_issuer, "https://")
      error_message = "Production OIDC issuer must use HTTPS."
    }
    precondition {
      condition     = var.environment != "prod" || var.detection_content_public_key_b64 != ""
      error_message = "Production requires a trusted Ed25519 detection_content_public_key_b64."
    }
    precondition {
      condition     = var.environment != "prod" || var.service_account_pepper_secret_arn != ""
      error_message = "Production requires service_account_pepper_secret_arn for service-account token digests."
    }
    precondition {
      condition     = var.environment != "prod" || length(var.direct_upload_allowed_origins) > 0
      error_message = "Production requires at least one exact direct_upload_allowed_origins HTTPS origin."
    }
    precondition {
      condition     = var.environment != "prod" || length(var.evidence_scanner_subjects) > 0
      error_message = "Production requires at least one dedicated evidence_scanner_subjects identity."
    }
    precondition {
      condition     = var.environment != "prod" || !var.response_execution_enabled || length(var.response_verifier_subjects) > 0
      error_message = "Production response execution requires at least one independent response_verifier_subjects identity."
    }
    precondition {
      condition     = !var.organization_discovery_enabled || var.organization_external_id != ""
      error_message = "Organization discovery requires an external ID for member-account role trust policies."
    }
  }
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "${local.name}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.worker_task_cpu
  memory                   = var.worker_task_memory
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.worker_task.arn
  tags                     = local.tags

  volume {
    name = "ndr-data"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.app.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.app.id
        iam             = "ENABLED"
      }
    }
  }

  container_definitions = jsonencode([
    {
      name                   = "worker"
      image                  = var.container_image
      essential              = true
      user                   = "10001:10001"
      readonlyRootFilesystem = true
      linuxParameters = {
        initProcessEnabled = true
        capabilities       = { drop = ["ALL"] }
      }
      mountPoints = [{
        sourceVolume  = "ndr-data"
        containerPath = "/mnt/ndr-data"
        readOnly      = false
      }]
      environment = concat(local.runtime_environment, [{ name = "NDR_PROCESS_ROLE", value = "worker" }])
      secrets     = local.runtime_secrets
      healthCheck = {
        command     = ["CMD-SHELL", "node -e \"fetch('http://127.0.0.1:${var.container_port}/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))\""]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 20
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.app.name
          awslogs-region        = var.region
          awslogs-stream-prefix = "worker"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "app" {
  name                              = local.name
  cluster                           = aws_ecs_cluster.app.id
  task_definition                   = aws_ecs_task_definition.app.arn
  desired_count                     = var.desired_count
  launch_type                       = "FARGATE"
  platform_version                  = "1.4.0"
  health_check_grace_period_seconds = 60
  enable_execute_command            = false
  tags                              = local.tags

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "app"
    container_port   = var.container_port
  }

  network_configuration {
    assign_public_ip = false
    security_groups  = [aws_security_group.app.id]
    subnets          = var.private_subnet_ids
  }

  depends_on = [
    aws_lb_listener.http,
    aws_efs_mount_target.app
  ]
}

resource "aws_ecs_service" "worker" {
  name                   = "${local.name}-worker"
  cluster                = aws_ecs_cluster.app.id
  task_definition        = aws_ecs_task_definition.worker.arn
  desired_count          = var.worker_desired_count
  launch_type            = "FARGATE"
  platform_version       = "1.4.0"
  enable_execute_command = false
  tags                   = local.tags

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    assign_public_ip = false
    security_groups  = [aws_security_group.app.id]
    subnets          = var.private_subnet_ids
  }

  depends_on = [aws_efs_mount_target.app]
}

resource "aws_appautoscaling_target" "ecs" {
  max_capacity       = var.max_capacity
  min_capacity       = var.min_capacity
  resource_id        = "service/${aws_ecs_cluster.app.name}/${aws_ecs_service.app.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${local.name}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace

  target_tracking_scaling_policy_configuration {
    target_value = 60

    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}

resource "aws_appautoscaling_target" "worker" {
  max_capacity       = var.worker_max_capacity
  min_capacity       = var.worker_min_capacity
  resource_id        = "service/${aws_ecs_cluster.app.name}/${aws_ecs_service.worker.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "worker_queue_depth" {
  name               = "${local.name}-worker-queue-depth"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.worker.resource_id
  scalable_dimension = aws_appautoscaling_target.worker.scalable_dimension
  service_namespace  = aws_appautoscaling_target.worker.service_namespace

  target_tracking_scaling_policy_configuration {
    target_value       = var.worker_messages_per_task
    scale_in_cooldown  = 120
    scale_out_cooldown = 30

    customized_metric_specification {
      metric_name = "ApproximateNumberOfMessagesVisible"
      namespace   = "AWS/SQS"
      statistic   = "Average"
      unit        = "Count"

      dimensions {
        name  = "QueueName"
        value = aws_sqs_queue.ingest.name
      }
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "ecs_cpu_high" {
  alarm_name          = "${local.name}-ecs-cpu-high"
  alarm_description   = "SignalPrism ECS CPU remains high"
  namespace           = "AWS/ECS"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_topic_arns
  dimensions = {
    ClusterName = aws_ecs_cluster.app.name
    ServiceName = aws_ecs_service.app.name
  }
  tags = local.tags
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "${local.name}-alb-5xx"
  alarm_description   = "SignalPrism ALB is returning server errors"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_topic_arns
  dimensions = {
    LoadBalancer = aws_lb.app.arn_suffix
    TargetGroup  = aws_lb_target_group.app.arn_suffix
  }
  tags = local.tags
}

resource "aws_cloudwatch_metric_alarm" "ingest_queue_age" {
  alarm_name          = "${local.name}-ingest-queue-age"
  alarm_description   = "SignalPrism ingest work is waiting too long for a worker"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateAgeOfOldestMessage"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 5
  threshold           = var.queue_age_alarm_seconds
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_topic_arns
  dimensions = {
    QueueName = aws_sqs_queue.ingest.name
  }
  tags = local.tags
}

resource "aws_cloudwatch_metric_alarm" "ingest_dlq_messages" {
  alarm_name          = "${local.name}-ingest-dlq-messages"
  alarm_description   = "SignalPrism ingest messages reached the dead-letter queue"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_topic_arns
  dimensions = {
    QueueName = aws_sqs_queue.ingest_dlq.name
  }
  tags = local.tags
}

output "ecr_repository_url" {
  value = aws_ecr_repository.app.repository_url
}

output "task_role_arn" {
  value = aws_iam_role.task.arn
}

output "task_execution_role_arn" {
  value = aws_iam_role.task_execution.arn
}

output "alb_dns_name" {
  value = aws_lb.app.dns_name
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.app.name
}

output "ecs_service_name" {
  value = aws_ecs_service.app.name
}

output "ecs_worker_service_name" {
  value = aws_ecs_service.worker.name
}

output "ingest_queue_url" {
  value = aws_sqs_queue.ingest.url
}

output "ingest_dead_letter_queue_url" {
  value = aws_sqs_queue.ingest_dlq.url
}

output "response_event_bus_arn" {
  value = aws_cloudwatch_event_bus.response.arn
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.app.name
}

output "audit_bucket_name" {
  value = aws_s3_bucket.audit.bucket
}

output "evidence_bucket_name" {
  value = aws_s3_bucket.evidence.bucket
}

output "alb_access_log_bucket_name" {
  value = aws_s3_bucket.alb_logs.bucket
}

output "ocsf_firehose_stream_name" {
  value = { for key, stream in aws_kinesis_firehose_delivery_stream.ocsf : key => stream.name }
}

output "telemetry_kinesis_stream_name" {
  value = aws_kinesis_stream.telemetry.name
}

output "ocsf_analytics_bucket_name" {
  value = aws_s3_bucket.analytics.bucket
}

output "ocsf_glue_table" {
  value = "${aws_glue_catalog_database.ocsf.name}.${aws_glue_catalog_table.ocsf.name}"
}

output "application_kms_key_arn" {
  value = aws_kms_key.app.arn
}
