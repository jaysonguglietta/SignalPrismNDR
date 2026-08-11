variable "region" {
  type        = string
  description = "AWS region."
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment name."
  default     = "dev"
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch log retention for the application."
  default     = 30
}

variable "flow_log_bucket_arn" {
  type        = string
  description = "ARN of the S3 bucket containing flow logs."
  default     = "arn:aws:s3:::replace-me"
}

variable "cloudwatch_log_group_arns" {
  type        = list(string)
  description = "CloudWatch log group ARNs allowed for ingest."
  default     = ["arn:aws:logs:us-east-1:123456789012:log-group:/aws/vpc/flowlogs/*"]
}

variable "vpc_id" {
  type        = string
  description = "VPC where the ALB, ECS service, and EFS mount targets are deployed."
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Public subnet IDs for the application load balancer."
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnet IDs for Fargate tasks and EFS mount targets."
}

variable "container_image" {
  type        = string
  description = "Fully qualified image URI to deploy. Use the ECR repository output after publishing an image."
}

variable "container_port" {
  type        = number
  description = "Container port exposed by the Node server."
  default     = 4173
}

variable "desired_count" {
  type        = number
  description = "Initial ECS task count."
  default     = 2
}

variable "min_capacity" {
  type        = number
  description = "Minimum autoscaled ECS task count."
  default     = 2
}

variable "max_capacity" {
  type        = number
  description = "Maximum autoscaled ECS task count."
  default     = 6
}

variable "task_cpu" {
  type        = number
  description = "Fargate CPU units."
  default     = 512
}

variable "task_memory" {
  type        = number
  description = "Fargate memory in MiB."
  default     = 1024
}

variable "worker_desired_count" {
  type        = number
  description = "Initial number of durable ingest workers."
  default     = 1
}

variable "worker_min_capacity" {
  type        = number
  description = "Minimum autoscaled ingest worker count."
  default     = 1
}

variable "worker_max_capacity" {
  type        = number
  description = "Maximum autoscaled ingest worker count."
  default     = 10
}

variable "worker_task_cpu" {
  type        = number
  description = "Fargate CPU units for each ingest worker."
  default     = 1024
}

variable "worker_task_memory" {
  type        = number
  description = "Fargate memory in MiB for each ingest worker."
  default     = 2048
}

variable "worker_messages_per_task" {
  type        = number
  description = "Target visible SQS messages per worker for autoscaling."
  default     = 5
}

variable "queue_visibility_timeout_seconds" {
  type        = number
  description = "SQS visibility timeout for evidence import work."
  default     = 900

  validation {
    condition     = var.queue_visibility_timeout_seconds >= 30 && var.queue_visibility_timeout_seconds <= 43200
    error_message = "queue_visibility_timeout_seconds must be between 30 and 43200."
  }
}

variable "queue_message_retention_seconds" {
  type        = number
  description = "Retention for pending ingest messages."
  default     = 345600
}

variable "queue_max_receive_count" {
  type        = number
  description = "Worker attempts before an ingest message moves to the DLQ."
  default     = 5
}

variable "queue_age_alarm_seconds" {
  type        = number
  description = "Oldest-message age that triggers an operations alarm."
  default     = 300
}

variable "response_execution_enabled" {
  type        = bool
  description = "Emit independently approved response actions to the EventBridge response bus."
  default     = false
}

variable "response_verifier_subjects" {
  type        = list(string)
  description = "Stable OIDC or service-account subjects allowed to independently verify response outcomes."
  default     = []

  validation {
    condition     = alltrue([for subject in var.response_verifier_subjects : length(trimspace(subject)) >= 3 && length(subject) <= 512])
    error_message = "response_verifier_subjects entries must contain 3 to 512 characters."
  }
}

variable "response_archive_retention_days" {
  type        = number
  description = "Retention for approved response events in the EventBridge archive."
  default     = 365
}

variable "detection_content_public_key_b64" {
  type        = string
  description = "Base64-encoded Ed25519 public key (PEM or SPKI DER) trusted for detection content bundles."
  default     = ""
  sensitive   = false
}

variable "certificate_arn" {
  type        = string
  description = "ACM certificate ARN for HTTPS on the ALB. Required in production."
  default     = ""
}

variable "allowed_ingress_cidrs" {
  type        = list(string)
  description = "CIDR ranges allowed to reach the ALB."
  default     = ["10.0.0.0/8"]
}

variable "alb_internal" {
  type        = bool
  description = "Whether the application load balancer is private. Use true for VPN, Direct Connect, or private access deployments."
  default     = false
}

variable "https_egress_cidrs" {
  type        = list(string)
  description = "CIDRs reachable from application tasks over HTTPS. In production, prefer an egress proxy or approved endpoint CIDRs."
  default     = ["0.0.0.0/0"]

  validation {
    condition     = length(var.https_egress_cidrs) > 0 && alltrue([for cidr in var.https_egress_cidrs : can(cidrnetmask(cidr))])
    error_message = "https_egress_cidrs must contain at least one valid IPv4 CIDR."
  }
}

variable "production_allow_unrestricted_https_egress" {
  type        = bool
  description = "Explicit production risk acceptance for 0.0.0.0/0 HTTPS egress. Keep false when an egress proxy or endpoint CIDRs are available."
  default     = false
}

variable "api_key_secret_arn" {
  type        = string
  description = "Existing Secrets Manager ARN containing NDR_API_KEY. Optional when OIDC is configured. Secret values never enter Terraform state."
  default     = ""
}

variable "session_secret_arn" {
  type        = string
  description = "Existing Secrets Manager ARN containing a dedicated, randomly generated NDR_SESSION_SECRET."

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:secretsmanager:", var.session_secret_arn))
    error_message = "session_secret_arn must be a Secrets Manager ARN."
  }
}

variable "evidence_attestation_secret_arn" {
  type        = string
  description = "Existing Secrets Manager ARN containing the HMAC key used to attest evidence manifests."

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:secretsmanager:", var.evidence_attestation_secret_arn))
    error_message = "evidence_attestation_secret_arn must be a Secrets Manager ARN."
  }
}

variable "evidence_attestation_key_id" {
  type        = string
  description = "Non-secret key identifier recorded in evidence attestations."
  default     = "signalprism-evidence-v1"
}

variable "store_mode" {
  type        = string
  description = "Backend persistence mode."
  default     = "dynamodb"

  validation {
    condition     = contains(["local", "dynamodb"], var.store_mode)
    error_message = "store_mode must be local or dynamodb."
  }
}

variable "rate_limit_max" {
  type        = number
  description = "Requests allowed per rate limit window per remote address."
  default     = 120
}

variable "rate_limit_window_ms" {
  type        = number
  description = "Rate limit window in milliseconds."
  default     = 60000
}

variable "rate_limit_max_identities" {
  type        = number
  description = "Maximum in-memory rate-limit identity buckets retained by each task."
  default     = 10000
}

variable "max_jobs_per_tenant" {
  type        = number
  description = "Maximum scheduled ingest jobs per tenant."
  default     = 50
}

variable "max_active_runs_per_tenant" {
  type        = number
  description = "Maximum concurrent asynchronous imports per tenant."
  default     = 3
}

variable "max_pending_export_approvals" {
  type        = number
  description = "Maximum unexpired pending export requests per tenant."
  default     = 100
}

variable "active_run_slot_ttl_seconds" {
  type        = number
  description = "Fail-safe TTL for conditional tenant import slots after a task crash."
  default     = 3600
}

variable "min_job_interval_minutes" {
  type        = number
  description = "Minimum scheduled ingest interval."
  default     = 5
}

variable "max_job_interval_minutes" {
  type        = number
  description = "Maximum scheduled ingest interval."
  default     = 10080
}

variable "aws_request_timeout_ms" {
  type        = number
  description = "Timeout for signed AWS API requests."
  default     = 15000
}

variable "oidc_request_timeout_ms" {
  type        = number
  description = "Timeout for OIDC discovery, JWKS, and token requests."
  default     = 10000
}

variable "dns_resolver_cidrs" {
  type        = list(string)
  description = "CIDRs containing DNS resolvers reachable by Fargate. Empty uses the selected VPC's Amazon-provided resolver address."
  default     = []
}

variable "tenant_byok_key_arn" {
  type        = string
  description = "Optional tenant-provided or imported KMS key ARN used to report true BYOK posture. The stack-managed platform key is exposed separately."
  default     = ""

  validation {
    condition     = var.tenant_byok_key_arn == "" || can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[a-fA-F0-9-]+$", var.tenant_byok_key_arn))
    error_message = "tenant_byok_key_arn must be an AWS KMS key ARN when supplied."
  }
}

variable "waf_rate_limit" {
  type        = number
  description = "AWS WAF five-minute request limit per client IP."
  default     = 2000
}

variable "alb_log_retention_days" {
  type        = number
  description = "Retention for ALB access logs."
  default     = 365
}

variable "alarm_topic_arns" {
  type        = list(string)
  description = "SNS topic ARNs notified by production CloudWatch alarms."
  default     = []
}

variable "audit_retention_days" {
  type        = number
  description = "Immutable audit retention period for audit records and S3 Object Lock exports."
  default     = 2555
}

variable "evidence_retention_days" {
  type        = number
  description = "Retention period for raw evidence packages stored with S3 Object Lock."
  default     = 90
}

variable "evidence_object_lock_mode" {
  type        = string
  description = "S3 Object Lock mode for raw evidence packages."
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.evidence_object_lock_mode)
    error_message = "evidence_object_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "oidc_issuer" {
  type        = string
  description = "OIDC issuer URL for SSO."
  default     = ""
}

variable "oidc_audience" {
  type        = string
  description = "OIDC audience expected in tokens."
  default     = ""
}

variable "oidc_client_id" {
  type        = string
  description = "OIDC public client ID."
  default     = ""
}

variable "oidc_client_secret_arn" {
  type        = string
  description = "Optional existing Secrets Manager ARN containing NDR_OIDC_CLIENT_SECRET."
  default     = ""
}

variable "oidc_redirect_uri" {
  type        = string
  description = "OIDC redirect URI registered with the identity provider."
  default     = ""
}

variable "oidc_scopes" {
  type        = string
  description = "OIDC scopes requested during login."
  default     = "openid profile email groups"
}

variable "admin_group" {
  type        = string
  description = "OIDC group mapped to NDR admin."
  default     = "ndr-admin"
}

variable "analyst_group" {
  type        = string
  description = "OIDC group mapped to NDR analyst."
  default     = "ndr-analyst"
}

variable "viewer_group" {
  type        = string
  description = "OIDC group mapped to NDR viewer."
  default     = "ndr-viewer"
}

variable "default_tenant" {
  type        = string
  description = "Tenant ID used for API-key and local-dev sessions."
  default     = "default"
}

variable "tenant_claim" {
  type        = string
  description = "OIDC claim used to resolve tenant ownership."
  default     = "tenant_id"
}

variable "bedrock_enabled" {
  type        = bool
  description = "Feature flag for AWS Bedrock AI assistant endpoints."
  default     = false
}

variable "bedrock_region" {
  type        = string
  description = "AWS region for Bedrock Runtime."
  default     = "us-east-1"
}

variable "bedrock_model_id" {
  type        = string
  description = "Bedrock model ID used by the Converse API."
  default     = "anthropic.claude-3-haiku-20240307-v1:0"
}

variable "bedrock_model_arns" {
  type        = list(string)
  description = "Bedrock foundation model or inference profile ARNs allowed for InvokeModel."
  default     = ["*"]
}

variable "bedrock_max_tokens" {
  type        = number
  description = "Maximum tokens returned by the Bedrock assistant."
  default     = 900
}

variable "bedrock_temperature" {
  type        = number
  description = "Temperature used by Bedrock assistant calls."
  default     = 0.2
}

variable "bedrock_max_context_chars" {
  type        = number
  description = "Maximum evidence context characters sent to Bedrock."
  default     = 24000
}

variable "analytics_retention_days" {
  type        = number
  description = "Retention for OCSF Parquet analytics objects."
  default     = 365
}

variable "continuous_stream_mode" {
  type        = string
  description = "Continuous normalized telemetry delivery mode. Kinesis is provisioned by this stack; MSK requires a separately managed Kafka bridge."
  default     = "kinesis"

  validation {
    condition     = contains(["local", "firehose", "kinesis", "msk"], var.continuous_stream_mode)
    error_message = "continuous_stream_mode must be local, firehose, kinesis, or msk."
  }
}

variable "stream_retention_hours" {
  type        = number
  description = "Kinesis retention used for replay and downstream recovery."
  default     = 168

  validation {
    condition     = var.stream_retention_hours >= 24 && var.stream_retention_hours <= 8760
    error_message = "stream_retention_hours must be between 24 and 8760."
  }
}

variable "hot_search_mode" {
  type        = string
  description = "Interactive hunt tier used by the API."
  default     = "local"

  validation {
    condition     = contains(["local", "opensearch", "clickhouse"], var.hot_search_mode)
    error_message = "hot_search_mode must be local, opensearch, or clickhouse."
  }
}

variable "hot_search_endpoint" {
  type        = string
  description = "Managed hot-search endpoint. Keep empty for the bounded local hunt tier."
  default     = ""
}

variable "hot_search_resource_arns" {
  type        = list(string)
  description = "OpenSearch domain or Serverless collection ARNs the task role may query. Defaults to SignalPrism-prefixed domains and account collections."
  default     = []
}

variable "security_lake_assigned_prefix" {
  type        = string
  description = "Prefix assigned to the custom source by the Amazon Security Lake delegated administrator."
  default     = "ext/SignalPrismNDR"

  validation {
    condition     = can(regex("^[A-Za-z0-9!_.*'()/-]{3,512}$", var.security_lake_assigned_prefix))
    error_message = "security_lake_assigned_prefix contains unsupported characters."
  }
}

variable "security_lake_provider_account_id" {
  type        = string
  description = "Twelve-digit provider account ID registered for the Security Lake custom source."
  default     = ""

  validation {
    condition     = var.security_lake_provider_account_id == "" || can(regex("^[0-9]{12}$", var.security_lake_provider_account_id))
    error_message = "security_lake_provider_account_id must be empty or contain 12 digits."
  }
}

variable "security_lake_provider_external_id_secret_arn" {
  type        = string
  description = "Secrets Manager ARN containing the external ID associated with the Security Lake provider identity."
  default     = ""
}

variable "security_lake_crawler_role_arn" {
  type        = string
  description = "IAM role ARN that Amazon Security Lake may use for the custom-source Glue crawler."
  default     = ""

  validation {
    condition     = var.security_lake_crawler_role_arn == "" || can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$", var.security_lake_crawler_role_arn))
    error_message = "security_lake_crawler_role_arn must be empty or a valid IAM role ARN."
  }
}

variable "response_kill_switch" {
  type        = bool
  description = "Deployment-level fail-closed switch that prevents automated response dispatch."
  default     = false
}

variable "air_gapped" {
  type        = bool
  description = "Marks the deployment as disconnected and disables assumptions about external delivery adapters."
  default     = false
}

variable "direct_upload_allowed_origins" {
  type        = list(string)
  description = "Exact HTTPS origins allowed to use presigned direct evidence uploads. Leave empty to disable browser CORS."
  default     = []

  validation {
    condition     = alltrue([for origin in var.direct_upload_allowed_origins : can(regex("^https://", origin))])
    error_message = "Direct upload origins must use HTTPS."
  }
}

variable "direct_upload_ttl_seconds" {
  type        = number
  description = "Lifetime of direct evidence upload presigned URLs."
  default     = 900

  validation {
    condition     = var.direct_upload_ttl_seconds >= 60 && var.direct_upload_ttl_seconds <= 3600
    error_message = "direct_upload_ttl_seconds must be between 60 and 3600."
  }
}

variable "organization_discovery_enabled" {
  type        = bool
  description = "Allow the control plane to inventory AWS Organizations accounts."
  default     = false
}

variable "organization_region" {
  type        = string
  description = "Regional endpoint used for AWS Organizations requests."
  default     = "us-east-1"
}

variable "organization_member_role_name" {
  type        = string
  description = "Read-only role deployed in member accounts for SignalPrism ingest."
  default     = "SignalPrismReadOnlyRole"
}

variable "organization_external_id" {
  type        = string
  description = "External ID required by member-account trust policies. Treat as deployment configuration, not an authentication secret."
  default     = ""
}

variable "scim_bearer_token_secret_arn" {
  type        = string
  description = "Optional Secrets Manager ARN containing the tenant SCIM bearer token."
  default     = ""
}

variable "service_account_pepper_secret_arn" {
  type        = string
  description = "Optional Secrets Manager ARN containing the HMAC pepper for service-account token digests. Required for production service accounts."
  default     = ""
}

variable "max_ai_agent_runs_per_day" {
  type        = number
  description = "Daily AI investigation run quota per tenant."
  default     = 100
}

variable "ddb_gsi_migration_mode" {
  type        = string
  description = "DynamoDB index migration read mode. Keep dual-read until the GSI backfill is verified."
  default     = "dual-read"

  validation {
    condition     = contains(["dual-read", "gsi-only", "legacy-only"], var.ddb_gsi_migration_mode)
    error_message = "ddb_gsi_migration_mode must be dual-read, gsi-only, or legacy-only."
  }
}

variable "evidence_scanner_subjects" {
  type        = list(string)
  description = "OIDC or service-account subjects authorized to submit signed malware scan attestations."
  default     = []

  validation {
    condition     = alltrue([for subject in var.evidence_scanner_subjects : length(trimspace(subject)) >= 3 && length(subject) <= 512])
    error_message = "evidence_scanner_subjects entries must contain 3 to 512 characters."
  }
}

variable "max_evidence_upload_bytes" {
  type        = number
  description = "Maximum direct evidence upload size per object."
  default     = 1073741824
}

variable "max_active_evidence_uploads" {
  type        = number
  description = "Maximum concurrent evidence upload reservations per tenant."
  default     = 20
}

variable "max_tenant_evidence_reserved_bytes" {
  type        = number
  description = "Maximum bytes reserved by active evidence uploads per tenant."
  default     = 21474836480
}

variable "stream_delivery_max_attempts" {
  type        = number
  description = "Maximum durable stream delivery attempts before dead-lettering."
  default     = 12
}

variable "stream_retry_interval_seconds" {
  type        = number
  description = "Base interval for exponential stream delivery retries."
  default     = 30
}

variable "stream_retry_batch_size" {
  type        = number
  description = "Maximum due stream outbox records processed by each worker poll."
  default     = 50
}

variable "max_bedrock_calls_per_day" {
  type        = number
  description = "Maximum Bedrock calls reserved per tenant per UTC day."
  default     = 250
}

variable "max_bedrock_reserved_tokens_per_day" {
  type        = number
  description = "Maximum Bedrock output tokens conservatively reserved per tenant per UTC day."
  default     = 250000
}

variable "detection_backtest_max_age_days" {
  type        = number
  description = "Maximum age of an immutable passing backtest eligible for production promotion."
  default     = 30
}

variable "step_up_max_age_seconds" {
  type        = number
  description = "Maximum age of MFA-backed OIDC authentication for privileged approvals."
  default     = 900

  validation {
    condition     = var.step_up_max_age_seconds >= 60 && var.step_up_max_age_seconds <= 86400
    error_message = "step_up_max_age_seconds must be between 60 and 86400."
  }
}
