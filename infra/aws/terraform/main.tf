terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

locals {
  name = "ndr-flow-console-${var.environment}"
  tags = {
    Application = "SignalPrism NDR"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/ndr-flow-console/${var.environment}"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

resource "aws_ecr_repository" "app" {
  name                 = "ndr-flow-console"
  image_tag_mutability = "MUTABLE"

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

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = local.tags
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
      sse_algorithm = "AES256"
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

resource "aws_secretsmanager_secret" "api_key" {
  name = "${local.name}/api-key"
  tags = local.tags
}

resource "aws_secretsmanager_secret_version" "api_key" {
  secret_id     = aws_secretsmanager_secret.api_key.id
  secret_string = var.api_key_value
}

resource "aws_secretsmanager_secret" "oidc_client_secret" {
  count = var.oidc_client_secret == "" ? 0 : 1
  name  = "${local.name}/oidc-client-secret"
  tags  = local.tags
}

resource "aws_secretsmanager_secret_version" "oidc_client_secret" {
  count         = var.oidc_client_secret == "" ? 0 : 1
  secret_id     = aws_secretsmanager_secret.oidc_client_secret[0].id
  secret_string = var.oidc_client_secret
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
      Resource = concat(
        [aws_secretsmanager_secret.api_key.arn],
        var.oidc_client_secret == "" ? [] : [aws_secretsmanager_secret.oidc_client_secret[0].arn]
      )
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
          "dynamodb:DeleteItem",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Query",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.app.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.audit.arn}/*"
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
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ingest" {
  role       = aws_iam_role.task.name
  policy_arn = aws_iam_policy.ingest.arn
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

  egress {
    description = "ALB egress to tasks"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
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

  egress {
    description = "Task egress for AWS APIs and IdP"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
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

resource "aws_efs_file_system" "app" {
  creation_token = local.name
  encrypted      = true
  tags           = local.tags

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }
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
  name               = local.name
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids
  tags               = local.tags
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

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
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
      name      = "app"
      image     = var.container_image
      essential = true
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
      environment = [
        { name = "PORT", value = tostring(var.container_port) },
        { name = "NDR_DATA_DIR", value = "/mnt/ndr-data" },
        { name = "NDR_STORE", value = var.store_mode },
        { name = "NDR_DDB_TABLE", value = aws_dynamodb_table.app.name },
        { name = "NDR_DDB_REGION", value = var.region },
        { name = "NDR_RATE_LIMIT_MAX", value = tostring(var.rate_limit_max) },
        { name = "NDR_RATE_LIMIT_WINDOW_MS", value = tostring(var.rate_limit_window_ms) },
        { name = "NDR_AUDIT_RETENTION_DAYS", value = tostring(var.audit_retention_days) },
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
        { name = "NDR_BEDROCK_MAX_CONTEXT_CHARS", value = tostring(var.bedrock_max_context_chars) }
      ]
      secrets = concat(
        [{ name = "NDR_API_KEY", valueFrom = aws_secretsmanager_secret.api_key.arn }],
        var.oidc_client_secret == "" ? [] : [{ name = "NDR_OIDC_CLIENT_SECRET", valueFrom = aws_secretsmanager_secret.oidc_client_secret[0].arn }]
      )
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
}

resource "aws_ecs_service" "app" {
  name            = local.name
  cluster         = aws_ecs_cluster.app.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"
  tags            = local.tags

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

output "dynamodb_table_name" {
  value = aws_dynamodb_table.app.name
}

output "audit_bucket_name" {
  value = aws_s3_bucket.audit.bucket
}

output "api_key_secret_arn" {
  value     = aws_secretsmanager_secret.api_key.arn
  sensitive = true
}
