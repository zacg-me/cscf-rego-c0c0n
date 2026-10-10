# ============================================================================
# SWIFT CSCF v2026 (NON-COMPLIANT Environment
# Framework v1.2) Phase I
# 91 Assertions across 5 Controls, Expected: 90+ deny violations
# WARNING: DO NOT DEPLOY, Deliberately insecure test fixture
# ============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = var.region
  access_key                  = "mock-access-key"
  secret_key                  = "mock-secret-key"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  default_tags {
    tags = {
      Project      = "swift-cscf-NONCOMPLIANT"
      Environment  = "test"
      "swift:zone" = "secure"
    }
  }
}

variable "account_id" { default = "123456789012" }
variable "region" { default = "eu-west-1" }

# 1.1-A15: the trust boundary is the Swift account alone.
variable "swift_trust_boundary_accounts" {
  type    = list(string)
  default = ["123456789012"]
}

locals {
  tags = { "swift:zone" = "secure", Project = "swift-cscf-NONCOMPLIANT" }
}

# ============================================================================
# CONTROL 1.1 VIOLATIONS: Swift Environment Protection
# ============================================================================

resource "aws_vpc" "bad" {
  cidr_block = "10.0.0.0/16"
  tags       = merge(local.tags, { Name = "bad-vpc" })
}

# VIOLATES 1.1-A1: Default SG has rules
resource "aws_default_security_group" "bad" {
  vpc_id = aws_vpc.bad.id
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

# VIOLATES 1.1-A2: Inbound 0.0.0.0/0
# VIOLATES 1.1-A3: SSH+RDP open to internet
# VIOLATES 1.1-A4: Egress all to 0.0.0.0/0
resource "aws_security_group" "bad" {
  name_prefix = "bad-"
  vpc_id      = aws_vpc.bad.id

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

# VIOLATES 1.1-A5: Public IP auto-assign
resource "aws_subnet" "bad1" {
  vpc_id                  = aws_vpc.bad.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  tags                    = local.tags
}

resource "aws_subnet" "bad2" {
  vpc_id            = aws_vpc.bad.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.region}b"
  tags              = local.tags
}

# VIOLATES 1.1-A6: Route to Internet Gateway
resource "aws_internet_gateway" "bad" {
  vpc_id = aws_vpc.bad.id
  tags   = local.tags
}

resource "aws_route_table" "bad" {
  vpc_id = aws_vpc.bad.id
  tags   = local.tags
}

resource "aws_route" "bad_igw" {
  route_table_id         = aws_route_table.bad.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.bad.id
}

# VIOLATES 1.1-A7: Default NACL allows all inbound
# VIOLATES 1.1-A8: Default NACL allows all outbound
resource "aws_default_network_acl" "bad" {
  default_network_acl_id = aws_vpc.bad.default_network_acl_id
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  tags = local.tags
}

# VIOLATES 1.1-A9: No VPC Flow Logs (absence)

# VIOLATES 1.1-A10: VPN with federated-only auth (not certificate/directory)
resource "aws_ec2_client_vpn_endpoint" "bad" {
  description            = "Bad VPN"
  server_certificate_arn = "arn:aws:acm:${var.region}:${var.account_id}:certificate/bad"
  client_cidr_block      = "10.200.0.0/22"
  authentication_options {
    type              = "federated-authentication"
    saml_provider_arn = "arn:aws:iam::${var.account_id}:saml-provider/bad"
  }
  connection_log_options { enabled = false }
  tags = local.tags
}

# VIOLATES 1.1-A11: VPN auth to 0.0.0.0/0 without access group
resource "aws_ec2_client_vpn_authorization_rule" "bad" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.bad.id
  target_network_cidr    = "0.0.0.0/0"
  authorize_all_groups   = true
}

# VIOLATES 1.1-A12: No MFA condition in trust policy
# VIOLATES 1.1-A13: No permissions boundary
resource "aws_iam_role" "bad_app" {
  name = "bad-app-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

# VIOLATES 1.1-A14: No MFA deny statement (also violates 5.1-A1)
resource "aws_iam_role_policy" "bad_jump" {
  name = "bad-jump"
  role = aws_iam_role.bad_app.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

# ============================================================================
# CONTROL 2.1 VIOLATIONS: Internal Data Flow Security
# ============================================================================

# VIOLATES 2.1-A1: HTTP listener
resource "aws_lb" "bad" {
  name               = "bad-alb"
  internal           = true
  load_balancer_type = "application"
  subnets            = [aws_subnet.bad1.id, aws_subnet.bad2.id]
  security_groups    = [aws_security_group.bad.id]
  tags               = local.tags
}

resource "aws_lb_listener" "bad_http" {
  load_balancer_arn = aws_lb.bad.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "OK"
      status_code  = "200"
    }
  }
}

# VIOLATES 2.1-A2: Weak TLS policy
resource "aws_lb_listener" "bad_https" {
  load_balancer_arn = aws_lb.bad.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:${var.region}:${var.account_id}:certificate/bad"
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "OK"
      status_code  = "200"
    }
  }
}

# VIOLATES 2.1-A3: PostgreSQL without force SSL
resource "aws_db_parameter_group" "bad_pg" {
  name   = "bad-postgres"
  family = "postgres16"
  tags   = local.tags
}

# VIOLATES 2.1-A4: MySQL without force SSL
resource "aws_db_parameter_group" "bad_mysql" {
  name   = "bad-mysql"
  family = "mysql8.0"
  tags   = local.tags
}

# VIOLATES 2.1-A5: Redshift without SSL
resource "aws_redshift_parameter_group" "bad" {
  name   = "bad-redshift"
  family = "redshift-1.0"
  tags   = local.tags
}

# VIOLATES 2.1-A6: ElastiCache without transit encryption
resource "aws_elasticache_replication_group" "bad" {
  replication_group_id       = "bad-cache"
  description                = "Non-compliant"
  node_type                  = "cache.t3.small"
  num_cache_clusters         = 1
  transit_encryption_enabled = false
  tags                       = local.tags
}

# VIOLATES 2.1-A7: MSK TLS_PLAINTEXT
# VIOLATES 2.1-A8: MSK in_cluster false
resource "aws_msk_cluster" "bad" {
  cluster_name           = "bad-kafka"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = 2
  broker_node_group_info {
    instance_type  = "kafka.t3.small"
    client_subnets = [aws_subnet.bad1.id, aws_subnet.bad2.id]
    storage_info {
      ebs_storage_info {
        volume_size = 10
      }
    }
    security_groups = [aws_security_group.bad.id]
  }
  encryption_info {
    encryption_in_transit {
      client_broker = "TLS_PLAINTEXT"
      in_cluster    = false
    }
  }
  tags = local.tags
}

# VIOLATES 2.1-A9: OpenSearch HTTPS not enforced
# VIOLATES 2.1-A10: Weak TLS policy
# VIOLATES 2.1-A11: Node-to-node disabled
# VIOLATES 4.1-A17: Fine-grained access disabled
resource "aws_opensearch_domain" "bad" {
  domain_name    = "bad-search"
  engine_version = "OpenSearch_2.11"
  cluster_config {
    instance_type  = "t3.small.search"
    instance_count = 1
  }
  domain_endpoint_options {
    enforce_https       = false
    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
  }
  node_to_node_encryption { enabled = false }
  advanced_security_options { enabled = false }
  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
  tags = local.tags
}

# VIOLATES 2.1-A12: EFS without TLS enforcement
resource "aws_efs_file_system" "bad" { tags = local.tags }

resource "aws_efs_file_system_policy" "bad" {
  file_system_id = aws_efs_file_system.bad.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Sid = "AllowAll", Effect = "Allow", Principal = { AWS = "*" }, Action = "*", Resource = aws_efs_file_system.bad.arn }]
  })
}

# VIOLATES 2.1-A13: API Gateway TLS 1.0
resource "aws_api_gateway_domain_name" "bad" {
  domain_name              = "api.bad.example.com"
  regional_certificate_arn = "arn:aws:acm:${var.region}:${var.account_id}:certificate/bad"
  security_policy          = "TLS_1_0"
  endpoint_configuration { types = ["REGIONAL"] }
  tags = local.tags
}

# VIOLATES 2.1-A14: KMS no rotation
# VIOLATES 2.1-A15: KMS 7-day deletion (< 14)
resource "aws_kms_key" "bad" {
  description             = "Non-compliant key"
  enable_key_rotation     = false
  deletion_window_in_days = 7
  tags                    = local.tags
}

# VIOLATES 2.1-A16: S3 without TLS enforcement
resource "aws_s3_bucket" "bad_data" {
  bucket = "bad-data-${var.account_id}"
  tags   = local.tags
}

resource "aws_s3_bucket_policy" "bad_data" {
  bucket = aws_s3_bucket.bad_data.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Sid = "OpenAccess", Effect = "Allow", Principal = "*", Action = "s3:*", Resource = "${aws_s3_bucket.bad_data.arn}/*" }]
  })
}

# VIOLATES 1.1-A15: a reporting partner's account is granted read on a
# Swift-zone bucket. The bucket and its policy pass every per-resource check
# (TLS enforced, no wildcard principal); only the grant crosses the boundary.
resource "aws_s3_bucket" "partner_share" {
  bucket = "partner-share-${var.account_id}"
  tags   = local.tags
}

resource "aws_s3_bucket_policy" "partner_share" {
  bucket = aws_s3_bucket.partner_share.bucket
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PartnerRead"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::444455556666:root" }
        Action    = ["s3:GetObject"]
        Resource  = "arn:aws:s3:::partner-share-${var.account_id}/*"
      },
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = ["arn:aws:s3:::partner-share-${var.account_id}", "arn:aws:s3:::partner-share-${var.account_id}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

# ============================================================================
# CONTROL 4.1 VIOLATIONS: Password Policy
# ============================================================================

# VIOLATES 4.1-A2 through A10: Every parameter wrong
resource "aws_iam_account_password_policy" "bad" {
  minimum_password_length        = 8
  require_uppercase_characters   = false
  require_lowercase_characters   = false
  require_numbers                = false
  require_symbols                = false
  max_password_age               = 0
  password_reuse_prevention      = 3
  hard_expiry                    = false
  allow_users_to_change_password = false
}

# VIOLATES 4.1-A11, A12, A13: Cognito weak
resource "aws_cognito_user_pool" "bad" {
  name = "bad-pool"
  password_policy {
    minimum_length                   = 6
    require_uppercase                = false
    require_lowercase                = false
    require_numbers                  = false
    require_symbols                  = false
    temporary_password_validity_days = 30
  }
  tags = local.tags
}

# VIOLATES 4.1-A14: RDS without Secrets Manager
resource "aws_db_subnet_group" "bad" {
  name       = "bad-db"
  subnet_ids = [aws_subnet.bad1.id, aws_subnet.bad2.id]
}

resource "aws_db_instance" "bad" {
  identifier             = "bad-db"
  engine                 = "postgres"
  engine_version         = "16.4"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  db_subnet_group_name   = aws_db_subnet_group.bad.name
  publicly_accessible    = true # VIOLATES 2.3-A1
  vpc_security_group_ids = [aws_security_group.bad.id]
  # Deliberately unmanaged: a hardcoded password, no Secrets Manager.
  # (manage_master_user_password is omitted rather than set false, the
  # provider rejects it alongside `password`, and both policies treat the
  # attribute's absence as unmanaged.)
  username            = "admin"
  password            = "plaintext-123"
  skip_final_snapshot = true
  # No log exports: VIOLATES 6.4-A6
  tags = local.tags
}

# VIOLATES 4.1-A15: Redshift without Secrets Manager
resource "aws_redshift_cluster" "bad" {
  cluster_identifier  = "bad-redshift"
  database_name       = "baddb"
  master_username     = "admin"
  master_password     = "Plaintext-123!"
  node_type           = "dc2.large"
  number_of_nodes     = 1
  skip_final_snapshot = true
  tags                = local.tags
}

# VIOLATES 4.1-A16: Secrets Manager 180-day rotation (> 90)
resource "aws_secretsmanager_secret" "bad" {
  name = "bad/db/creds"
  tags = local.tags
}

resource "aws_secretsmanager_secret_rotation" "bad" {
  secret_id           = aws_secretsmanager_secret.bad.id
  rotation_lambda_arn = "arn:aws:lambda:eu-west-1:${var.account_id}:function:bad-rotation"
  rotation_rules { automatically_after_days = 180 }
}

# VIOLATES 4.1-A19: Static IAM access key
resource "aws_iam_user" "bad" {
  name = "bad-service-user"
  tags = local.tags
}

resource "aws_iam_access_key" "bad" {
  user = aws_iam_user.bad.name
}

# ============================================================================
# CONTROL 5.1 VIOLATIONS: Logical Access Control
# ============================================================================

# VIOLATES 5.1-A1: Wildcard Action
# VIOLATES 5.1-A2: Sensitive actions on Resource *
resource "aws_iam_policy" "bad_wildcard" {
  name = "bad-wildcard"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Sid = "All", Effect = "Allow", Action = "*", Resource = "*" }]
  })
  tags = local.tags
}

# VIOLATES 5.1-A3: Direct user policy attachment
# VIOLATES 5.1-A5: AdministratorAccess on user
resource "aws_iam_user_policy_attachment" "bad" {
  user       = aws_iam_user.bad.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# VIOLATES 5.1-A4: Direct user inline policy
resource "aws_iam_user_policy" "bad" {
  name   = "bad-inline"
  user   = aws_iam_user.bad.name
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "*" }] })
}

# VIOLATES 5.1-A6: AdministratorAccess on role
resource "aws_iam_role_policy_attachment" "bad_admin" {
  role       = aws_iam_role.bad_app.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# VIOLATES 5.1-A7: AdministratorAccess on group
resource "aws_iam_group" "bad" { name = "bad-admins" }

resource "aws_iam_group_policy_attachment" "bad" {
  group      = aws_iam_group.bad.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# VIOLATES 5.1-A8: PowerUserAccess
resource "aws_iam_role_policy_attachment" "bad_power" {
  role       = aws_iam_role.bad_app.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# VIOLATES 5.1-A9: Trust policy Principal *
resource "aws_iam_role" "bad_wildcard_trust" {
  name = "bad-wildcard-trust"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = "*", Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

# VIOLATES 5.1-A10: Unrestricted iam:PassRole
resource "aws_iam_policy" "bad_passrole" {
  name = "bad-passrole"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "iam:PassRole", Resource = "*" }]
  })
  tags = local.tags
}

# VIOLATES 5.1-A11: S3 Principal * without condition
resource "aws_s3_bucket" "bad_open" {
  bucket = "bad-open-${var.account_id}"
  tags   = local.tags
}

resource "aws_s3_bucket_policy" "bad_open" {
  bucket = aws_s3_bucket.bad_open.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Sid = "Open", Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "${aws_s3_bucket.bad_open.arn}/*" }]
  })
}

# VIOLATES 5.1-A12: CreateUser + AttachUserPolicy
# VIOLATES 5.1-A13: CreateRole + AttachRolePolicy
# VIOLATES 5.1-A14: CreatePolicy + AttachGroupPolicy
# VIOLATES 5.1-A15: UpdateAccountPasswordPolicy + CreateUser
resource "aws_iam_policy" "bad_sod" {
  name = "bad-sod"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "Everything"
      Effect = "Allow"
      Action = [
        "iam:CreateUser", "iam:AttachUserPolicy",
        "iam:CreateRole", "iam:AttachRolePolicy",
        "iam:CreatePolicy", "iam:AttachGroupPolicy",
        "iam:UpdateAccountPasswordPolicy"
      ]
      Resource = "*"
    }]
  })
  tags = local.tags
}

# VIOLATES 5.1-A16: Lambda with AdministratorAccess
resource "aws_iam_role" "bad_lambda" {
  name = "bad-lambda"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "bad_lambda" {
  role       = aws_iam_role.bad_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_lambda_function" "bad" {
  function_name = "bad-lambda"
  role          = aws_iam_role.bad_lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "placeholder.zip"

  # VIOLATES 5.4-A5: a credential inline in the environment
  environment {
    variables = {
      DB_PASSWORD  = "hunter2-in-the-environment"
      API_ENDPOINT = "https://backoffice.example.com"
    }
  }

  tags = local.tags
}

# VIOLATES 5.1-A17: ECS with PowerUserAccess
resource "aws_iam_role" "bad_ecs" {
  name = "bad-ecs"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "bad_ecs" {
  role       = aws_iam_role.bad_ecs.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

resource "aws_ecs_task_definition" "bad" {
  family                   = "bad-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.bad_ecs.arn
  task_role_arn            = aws_iam_role.bad_ecs.arn
  container_definitions    = jsonencode([{ name = "bad", image = "${var.account_id}.dkr.ecr.${var.region}.amazonaws.com/bad:latest", essential = true }])
  tags                     = local.tags
}

# VIOLATES 5.1-A18: Cross-account without ExternalId
resource "aws_iam_role" "bad_cross" {
  name = "bad-cross-account"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::987654321098:root" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

# ============================================================================
# CONTROL 6.4 VIOLATIONS: Logging and Monitoring
# ============================================================================

# VIOLATES 6.4-A1: Not multi-region
# VIOLATES 6.4-A2: Logging disabled
# VIOLATES 6.4-A3: No global events
# VIOLATES 6.4-A4: WriteOnly events
# VIOLATES 6.4-A7: No CloudWatch forwarding
# VIOLATES 6.4-A10: No log file validation
# VIOLATES 6.4-A11: No KMS encryption
resource "aws_cloudtrail" "bad" {
  name                          = "bad-trail"
  s3_bucket_name                = aws_s3_bucket.bad_trail.id
  is_multi_region_trail         = false
  enable_logging                = false
  include_global_service_events = false
  enable_log_file_validation    = false
  event_selector {
    read_write_type           = "WriteOnly"
    include_management_events = true
  }
  tags = local.tags
}

# VIOLATES 6.4-A5: No VPC Flow Logs (absence)

# VIOLATES 6.4-A6: RDS no log exports (covered in 4.1 section, aws_db_instance.bad)

# VIOLATES 6.4-A8: Log group retention 30 days (< 365)
# VIOLATES 6.4-A12: No KMS on log group
resource "aws_cloudwatch_log_group" "bad" {
  name              = "/bad/logs"
  retention_in_days = 30
  tags              = local.tags
}

# VIOLATES 6.4-A13: S3 public access not blocked
# VIOLATES 6.4-A14: Versioning disabled
# VIOLATES 6.4-A15: No Object Lock
# VIOLATES 6.4-A16: Lifecycle expires at 30 days
# VIOLATES 6.4-A17: No deletion deny policy
# VIOLATES 6.4-A18: AES256 not KMS
resource "aws_s3_bucket" "bad_trail" {
  bucket = "bad-trail-logs-${var.account_id}"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "bad_trail" {
  bucket                  = aws_s3_bucket.bad_trail.id
  block_public_acls       = false
  block_public_policy     = false
  restrict_public_buckets = false
  ignore_public_acls      = false
}

resource "aws_s3_bucket_versioning" "bad_trail" {
  bucket = aws_s3_bucket.bad_trail.id
  versioning_configuration { status = "Disabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "bad_trail" {
  bucket = aws_s3_bucket.bad_trail.id
  rule {
    id     = "delete-fast"
    status = "Enabled"

    # Required from provider v6: a rule must state what it applies to.
    filter {}

    expiration {
      days = 30
    }
  }
}

resource "aws_s3_bucket_policy" "bad_trail" {
  bucket = aws_s3_bucket.bad_trail.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Sid = "Open", Effect = "Allow", Principal = "*", Action = "s3:*", Resource = "${aws_s3_bucket.bad_trail.arn}/*" }]
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bad_trail" {
  bucket = aws_s3_bucket.bad_trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# VIOLATES 6.4-A19: No root usage metric filter (absence)
# VIOLATES 6.4-A20: No IAM change metric filter (absence)
# VIOLATES 6.4-A21: No sign-in failure metric filter (absence)

# VIOLATES 6.4-A22: Alarm with empty actions
resource "aws_cloudwatch_metric_alarm" "bad" {
  alarm_name          = "bad-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BadMetric"
  namespace           = "Bad"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = []
  tags                = local.tags
}

# VIOLATES 6.4-A23: No GuardDuty (absence)
# VIOLATES 6.4-A24: No AWS Config recorder (absence)

# ============================================================================
# PHASE II CONTROL VIOLATIONS: 1.2, 1.3, 1.4, 2.3, 2.4, 2.6, 5.4
# DELIBERATELY INSECURE. Added so the Phase II controls are exercised on a
# generated plan rather than on hand-written fixture JSON (review finding R4).
# ============================================================================

# 1.4-A3, 1.4-A6: a security group that lets the zone browse the Internet
resource "aws_security_group" "bad_browsing" {
  name        = "bad-browsing"
  description = "Unrestricted outbound web access"
  vpc_id      = aws_vpc.bad.id

  egress {
    description = "VIOLATES 1.4-A3: web egress to anywhere"
    from_port   = 80
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

# 1.2-A1, 1.2-A2, 1.3-A1, 1.3-A2, 1.3-A3, 1.3-A5, 1.4-A5, 1.4-A6
# A jump server with an SSH key instead of Session Manager, no instance
# profile, IMDSv1 permitted, an extra metadata hop, an unencrypted root volume,
# shared tenancy, and a public address.
resource "aws_instance" "bad_jump" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "t3.medium"
  subnet_id                   = aws_subnet.bad1.id
  vpc_security_group_ids      = [aws_security_group.bad_browsing.id]
  key_name                    = "shared-ops-key"
  associate_public_ip_address = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 2
  }

  root_block_device {
    encrypted   = false
    volume_type = "gp2"
    volume_size = 30
  }

  tags = merge(local.tags, {
    Name         = "bad-jump-server"
    "swift:role" = "jump_server"
  })
}

# 1.3-A4: unencrypted data volume
resource "aws_ebs_volume" "bad_data" {
  availability_zone = "${var.region}a"
  size              = 50
  encrypted         = false
  tags              = merge(local.tags, { Name = "bad-unencrypted-volume" })
}

# 1.4-A1, 1.4-A2: general-purpose Internet egress paths
resource "aws_eip" "bad_nat" {
  domain = "vpc"
  tags   = local.tags
}

resource "aws_nat_gateway" "bad" {
  allocation_id = aws_eip.bad_nat.id
  subnet_id     = aws_subnet.bad1.id
  tags          = merge(local.tags, { Name = "bad-nat" })
}

resource "aws_route" "bad_nat" {
  route_table_id         = aws_route_table.bad.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.bad.id
}

resource "aws_egress_only_internet_gateway" "bad" {
  vpc_id = aws_vpc.bad.id
  tags   = local.tags
}

resource "aws_route" "bad_eigw" {
  route_table_id              = aws_route_table.bad.id
  destination_ipv6_cidr_block = "::/0"
  egress_only_gateway_id      = aws_egress_only_internet_gateway.bad.id
}

# 2.3-A4: a privileged container
resource "aws_ecs_task_definition" "bad_privileged" {
  family                   = "bad-privileged"
  requires_compatibilities = ["EC2"]
  cpu                      = "512"
  memory                   = "1024"

  container_definitions = jsonencode([{
    name       = "bad-agent"
    image      = "bad-agent:latest"
    essential  = true
    privileged = true
  }])

  tags = local.tags
}

# 2.4-A1, 2.4-A2: a back-office tunnel on legacy crypto
resource "aws_vpn_gateway" "bad" {
  vpc_id = aws_vpc.bad.id
  tags   = local.tags
}

resource "aws_customer_gateway" "bad_back_office" {
  bgp_asn    = 65000
  ip_address = "198.51.100.20"
  type       = "ipsec.1"
  tags       = local.tags
}

resource "aws_vpn_connection" "bad_back_office" {
  vpn_gateway_id      = aws_vpn_gateway.bad.id
  customer_gateway_id = aws_customer_gateway.bad_back_office.id
  type                = "ipsec.1"

  tunnel1_ike_versions                 = ["ikev1", "ikev2"]
  tunnel2_ike_versions                 = ["ikev1", "ikev2"]
  tunnel1_phase2_encryption_algorithms = ["AES128"]
  tunnel2_phase2_encryption_algorithms = ["AES128"]

  tags = local.tags
}

# 2.4-A4: unencrypted Direct Connect
resource "aws_dx_connection" "bad_back_office" {
  name      = "bad-back-office-dx"
  bandwidth = "1Gbps"
  location  = "EqDC2"
  tags      = local.tags
}

# 1.2-A3, 2.6-A2, 2.6-A3: unlogged, unbounded, unencrypted sessions
resource "aws_ssm_document" "bad_session" {
  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "1.0"
    description   = "No logging, no idle timeout, no KMS"
    sessionType   = "Standard_Stream"
    inputs = {
      runAsEnabled       = true
      maxSessionDuration = "1440"
    }
  })

  tags = local.tags
}

# 5.4-A2: a secret in a plaintext parameter
resource "aws_ssm_parameter" "bad_password" {
  name  = "/swift/app/db_password"
  type  = "String"
  value = "plaintext-in-parameter-store"
  tags  = local.tags
}

# 5.4-A3: a secret readable by anyone
resource "aws_secretsmanager_secret_policy" "bad_open" {
  secret_arn = aws_secretsmanager_secret.bad.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OpenToWorld"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["secretsmanager:GetSecretValue"]
      Resource  = "*"
    }]
  })
}

# ============================================================================
# COVERAGE EXTENSION VIOLATIONS (review finding R5, R9.5)
# DELIBERATELY INSECURE. These use the resource shapes the Phase I bindings
# never looked at: standalone security-group rules, a custom network ACL, and a
# group inline policy.
# ============================================================================

# VIOLATES 1.1-A2, 1.1-A3: SSH from anywhere, via the modern rule resource.
resource "aws_vpc_security_group_ingress_rule" "bad_ssh" {
  security_group_id = aws_security_group.bad.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  description       = "SSH from the internet"
  tags              = local.tags
}

# VIOLATES 1.1-A4: all protocols, all destinations, via the modern resource.
resource "aws_vpc_security_group_egress_rule" "bad_all" {
  security_group_id = aws_security_group.bad.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Unrestricted egress"
  tags              = local.tags
}

# VIOLATES 1.1-A2: the legacy standalone rule resource.
resource "aws_security_group_rule" "bad_legacy_ingress" {
  security_group_id = aws_security_group.bad.id
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Everything from anywhere"
}

# VIOLATES 1.1-A7, 1.1-A8: a custom NACL that allows everything both ways.
resource "aws_network_acl" "bad" {
  vpc_id = aws_vpc.bad.id

  ingress {
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = local.tags
}

# VIOLATES 1.1-A7: the standalone NACL rule resource.
resource "aws_network_acl_rule" "bad_inbound" {
  network_acl_id = aws_network_acl.bad.id
  rule_number    = 200
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

# VIOLATES 5.1-A1, 5.1-A2: a group inline policy granting everything.
resource "aws_iam_group" "bad_ops" {
  name = "bad-ops"
}

resource "aws_iam_group_policy" "bad_ops" {
  name  = "bad-ops-everything"
  group = aws_iam_group.bad_ops.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Everything", Effect = "Allow", Action = "*", Resource = "*" },
      # A wildcard Action does not start with a sensitive prefix, so 5.1-A2
      # needs a named one to fire.
      { Sid = "IamAdmin", Effect = "Allow", Action = ["iam:*", "sts:AssumeRole"], Resource = "*" },
    ]
  })
}
