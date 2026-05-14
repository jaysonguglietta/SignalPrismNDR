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

variable "certificate_arn" {
  type        = string
  description = "Optional ACM certificate ARN for HTTPS on the ALB."
  default     = ""
}

variable "allowed_ingress_cidrs" {
  type        = list(string)
  description = "CIDR ranges allowed to reach the ALB."
  default     = ["10.0.0.0/8"]
}

variable "api_key_value" {
  type        = string
  description = "Initial NDR_API_KEY stored in Secrets Manager. Rotate before production use."
  sensitive   = true
  default     = "replace-me-rotate-before-production"
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

variable "oidc_client_secret" {
  type        = string
  description = "Optional OIDC client secret stored in Secrets Manager."
  sensitive   = true
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
