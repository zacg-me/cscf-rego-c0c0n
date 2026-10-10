# ============================================================================
# SWIFT CSCF v2026 (COMPLIANT Environment
# Framework v1.2) Phase I
# 91 Assertions across 5 Controls, Expected: ZERO deny violations
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
      Project      = "swift-cscf-compliant"
      Environment  = "test"
      "swift:zone" = "secure"
    }
  }
}

variable "account_id" { default = "123456789012" }
variable "region" { default = "eu-west-1" }
variable "swift_vpc_cidr" { default = "10.100.0.0/16" }
variable "admin_cidrs" { default = ["10.200.0.0/16"] }

# 1.1-A15: the Swift trust boundary -- the Swift account and its DR account.
variable "swift_trust_boundary_accounts" {
  type    = list(string)
  default = ["123456789012", "210987654321"]
}

locals {
  tags = { "swift:zone" = "secure", Project = "swift-cscf" }
  azs  = ["${var.region}a", "${var.region}b"]
}

# ============================================================================
# CONTROL 1.1: Swift Environment Protection (A1-A14)
# ============================================================================

# VPC

resource "aws_vpc" "swift" {
  cidr_block           = var.swift_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = "swift-secure-zone" })
}

# A1: Default SG locked, no rules
resource "aws_default_security_group" "swift" {
  vpc_id = aws_vpc.swift.id
  tags   = merge(local.tags, { Name = "swift-default-sg-LOCKED" })
}

# A2, A3, A4: Explicit SG, restricted inbound, restricted egress
resource "aws_security_group" "swift_app" {
  name_prefix = "swift-app-"
  vpc_id      = aws_vpc.swift.id
  description = "Swift application: restricted"

  ingress {
    description = "SSH from admin only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }
  ingress {
    description = "HTTPS internal"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.swift_vpc_cidr]
  }
  egress {
    description = "HTTPS outbound internal"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.swift_vpc_cidr]
  }
  egress {
    description = "DNS internal"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.swift_vpc_cidr]
  }

  tags = merge(local.tags, { Name = "swift-app-sg" })
}

# A5: Private subnets, no public IP
resource "aws_subnet" "swift" {
  count                   = 2
  vpc_id                  = aws_vpc.swift.id
  cidr_block              = cidrsubnet(var.swift_vpc_cidr, 8, count.index + 1)
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "swift-private-${count.index + 1}" })
}

# A6: Route table, no internet gateway route
resource "aws_route_table" "swift" {
  vpc_id = aws_vpc.swift.id
  tags   = merge(local.tags, { Name = "swift-private-rt" })
}

resource "aws_route_table_association" "swift" {
  count          = 2
  subnet_id      = aws_subnet.swift[count.index].id
  route_table_id = aws_route_table.swift.id
}

# A7, A8: Default NACL, restricted (no protocol -1 from 0.0.0.0/0)
resource "aws_default_network_acl" "swift" {
  default_network_acl_id = aws_vpc.swift.default_network_acl_id

  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.swift_vpc_cidr
    from_port  = 443
    to_port    = 443
  }
  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = var.swift_vpc_cidr
    from_port  = 22
    to_port    = 22
  }
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.swift_vpc_cidr
    from_port  = 443
    to_port    = 443
  }
  egress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = var.swift_vpc_cidr
    from_port  = 1024
    to_port    = 65535
  }

  tags = merge(local.tags, { Name = "swift-default-nacl" })
}

# A9: VPC Flow Logs, traffic_type ALL
resource "aws_flow_log" "swift" {
  vpc_id               = aws_vpc.swift.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn         = aws_iam_role.flow_log.arn
  tags                 = merge(local.tags, { Name = "swift-vpc-flow-log" })
}

# A10: Client VPN, certificate authentication
resource "aws_ec2_client_vpn_endpoint" "swift" {
  description            = "Swift secure zone VPN"
  server_certificate_arn = "arn:aws:acm:${var.region}:${var.account_id}:certificate/swift-vpn-server"
  client_cidr_block      = "10.200.0.0/22"
  session_timeout_hours  = 8

  authentication_options {
    type                       = "certificate-authentication"
    root_certificate_chain_arn = "arn:aws:acm:${var.region}:${var.account_id}:certificate/swift-vpn-root"
  }
  connection_log_options {
    enabled              = true
    cloudwatch_log_group = aws_cloudwatch_log_group.vpn.name
  }

  tags = merge(local.tags, { Name = "swift-vpn" })
}

# A11: VPN auth rule, scoped CIDR + access group
resource "aws_ec2_client_vpn_authorization_rule" "swift" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.swift.id
  target_network_cidr    = var.swift_vpc_cidr
  access_group_id        = "swift-admins"
}

# A12, A13: Swift app role, MFA condition + permissions boundary
resource "aws_iam_role" "swift_app" {
  name                 = "swift-app-role"
  permissions_boundary = "arn:aws:iam::${var.account_id}:policy/SwiftZoneBoundary"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
      Action    = "sts:AssumeRole"
      Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })

  tags = local.tags
}

# A14: Jump server role, MFA deny policy
resource "aws_iam_role" "jump_server" {
  name                 = "swift-jump-server"
  permissions_boundary = "arn:aws:iam::${var.account_id}:policy/SwiftZoneBoundary"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })

  tags = local.tags
}

resource "aws_iam_role_policy" "jump_mfa_deny" {
  name = "swift-jump-mfa-deny"
  role = aws_iam_role.jump_server.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyWithoutMFA"
        Effect    = "Deny"
        Action    = "*"
        Resource  = "*"
        Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" } }
      },
      {
        Sid      = "AllowSSM"
        Effect   = "Allow"
        Action   = ["ssm:StartSession", "ssm:TerminateSession", "ec2:DescribeInstances"]
        Resource = "arn:aws:ec2:*:${var.account_id}:instance/*"
      }
    ]
  })
}

# ============================================================================
# CONTROL 2.1: Internal Data Flow Security (A1-A16)
# ============================================================================

# A1, A2: ALB, HTTPS + TLS 1.3 policy
resource "aws_lb" "swift" {
  name               = "swift-internal-alb"
  internal           = true
  load_balancer_type = "application"
  subnets            = aws_subnet.swift[*].id
  security_groups    = [aws_security_group.swift_app.id]
  tags               = local.tags
}

resource "aws_lb_listener" "swift_https" {
  load_balancer_arn = aws_lb.swift.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = "arn:aws:acm:${var.region}:${var.account_id}:certificate/swift-alb"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "OK"
      status_code  = "200"
    }
  }
  tags = local.tags
}

# A3: PostgreSQL, force SSL
resource "aws_db_parameter_group" "postgres" {
  name   = "swift-postgres"
  family = "postgres16"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  tags = local.tags
}

# A4: MySQL, force SSL
resource "aws_db_parameter_group" "mysql" {
  name   = "swift-mysql"
  family = "mysql8.0"
  parameter {
    name  = "require_secure_transport"
    value = "1"
  }
  tags = local.tags
}

# A5: Redshift, require SSL
resource "aws_redshift_parameter_group" "swift" {
  name   = "swift-redshift"
  family = "redshift-1.0"
  parameter {
    name  = "require_ssl"
    value = "true"
  }
  tags = local.tags
}

# A6: ElastiCache, transit encryption
resource "aws_elasticache_subnet_group" "swift" {
  name       = "swift-cache-subnet"
  subnet_ids = aws_subnet.swift[*].id
}

resource "aws_elasticache_replication_group" "swift" {
  replication_group_id       = "swift-cache"
  description                = "Swift session cache"
  node_type                  = "cache.r6g.large"
  num_cache_clusters         = 2
  subnet_group_name          = aws_elasticache_subnet_group.swift.name
  transit_encryption_enabled = true
  at_rest_encryption_enabled = true
  tags                       = local.tags
}

# A7, A8: MSK, TLS client-broker + in-cluster
resource "aws_msk_cluster" "swift" {
  cluster_name           = "swift-kafka"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = 2

  broker_node_group_info {
    instance_type  = "kafka.m5.large"
    client_subnets = aws_subnet.swift[*].id
    storage_info {
      ebs_storage_info {
        volume_size = 100
      }
    }
    security_groups = [aws_security_group.swift_app.id]
  }
  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }

  tags = local.tags
}

# A9, A10, A11: OpenSearch, HTTPS + TLS 1.2 + node-to-node
resource "aws_opensearch_domain" "swift" {
  domain_name    = "swift-logs"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type  = "r6g.large.search"
    instance_count = 2
  }
  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
  node_to_node_encryption { enabled = true }
  encrypt_at_rest { enabled = true }

  # 2.3-A3: private endpoint only -- no public dashboard.
  vpc_options {
    subnet_ids         = aws_subnet.swift[*].id
    security_group_ids = [aws_security_group.swift_app.id]
  }

  # 4.1-A17 fine-grained access control, 4.2-A4 federated auth. Authentication
  # is delegated to the operator identity provider, so there is no internal user
  # database and no master password in this configuration.
  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = false
    master_user_options {
      master_user_arn = aws_iam_role.swift_app.arn
    }
  }

  cognito_options {
    enabled          = true
    user_pool_id     = aws_cognito_user_pool.swift.id
    identity_pool_id = aws_cognito_identity_pool.swift.id
    role_arn         = aws_iam_role.opensearch_cognito.arn
  }
  ebs_options {
    ebs_enabled = true
    volume_size = 100
  }

  tags = local.tags
}

# A12: EFS, TLS enforcement policy
resource "aws_efs_file_system" "swift" {
  encrypted = true
  tags      = merge(local.tags, { Name = "swift-shared-fs" })
}

resource "aws_efs_file_system_policy" "swift" {
  file_system_id = aws_efs_file_system.swift.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyNonTLS"
      Effect    = "Deny"
      Principal = { AWS = "*" }
      Action    = "*"
      Resource  = aws_efs_file_system.swift.arn
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# A13: API Gateway, TLS 1.2
resource "aws_api_gateway_domain_name" "swift" {
  domain_name              = "api.swift.example.com"
  regional_certificate_arn = "arn:aws:acm:${var.region}:${var.account_id}:certificate/swift-api"
  security_policy          = "TLS_1_2"
  endpoint_configuration { types = ["REGIONAL"] }

  # 2.4-A3: the connecting back-office party presents a client certificate.
  mutual_tls_authentication {
    truststore_uri = "s3://${aws_s3_bucket.swift_data.id}/truststore/backoffice.pem"
  }
  tags = local.tags
}

# A14, A15: KMS, rotation enabled, 30-day deletion window
resource "aws_kms_key" "swift_data" {
  description             = "Swift data flow encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.tags
}

# A16: S3 data exchange, TLS-only policy
resource "aws_s3_bucket" "swift_data" {
  bucket = "swift-data-exchange-${var.account_id}"
  tags   = local.tags
}

resource "aws_s3_bucket_policy" "swift_data_tls" {
  bucket = aws_s3_bucket.swift_data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyNonTLS"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = ["${aws_s3_bucket.swift_data.arn}", "${aws_s3_bucket.swift_data.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# 1.1-A15: a Swift-zone bucket shared only inside the trust boundary (the DR
# account). The document is built from variables alone, so it is known at plan
# time and the assertion is decided rather than undetermined.
resource "aws_s3_bucket" "swift_dr_exchange" {
  bucket = "swift-dr-exchange-${var.account_id}"
  tags   = local.tags
}

resource "aws_s3_bucket_policy" "swift_dr_exchange" {
  bucket = aws_s3_bucket.swift_dr_exchange.bucket
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DrReplicaRead"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::210987654321:root" }
        Action    = ["s3:GetObject"]
        Resource  = "arn:aws:s3:::swift-dr-exchange-${var.account_id}/*"
      },
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = ["arn:aws:s3:::swift-dr-exchange-${var.account_id}", "arn:aws:s3:::swift-dr-exchange-${var.account_id}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

# ============================================================================
# CONTROL 4.1: Password Policy (A1-A19)
# ============================================================================

# A1-A10: IAM account password policy
resource "aws_iam_account_password_policy" "swift" {
  minimum_password_length        = 15
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = true
  allow_users_to_change_password = true
}

# A11, A12, A13: Cognito, strong password policy
resource "aws_cognito_user_pool" "swift" {
  name = "swift-operators"

  # 4.2-A1, 4.2-A2: MFA required, with a TOTP possession factor rather than SMS.
  mfa_configuration = "ON"
  software_token_mfa_configuration {
    enabled = true
  }

  password_policy {
    minimum_length                   = 15
    require_uppercase                = true
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 3
  }
  tags = local.tags
}

# A14: RDS, Secrets Manager master password
resource "aws_db_subnet_group" "swift" {
  name       = "swift-db"
  subnet_ids = aws_subnet.swift[*].id
  tags       = local.tags
}

resource "aws_db_instance" "swift" {
  identifier                          = "swift-db"
  iam_database_authentication_enabled = true
  engine                              = "postgres"
  engine_version                      = "16.4"
  instance_class                      = "db.r6g.large"
  allocated_storage                   = 100
  db_subnet_group_name                = aws_db_subnet_group.swift.name
  parameter_group_name                = aws_db_parameter_group.postgres.name
  vpc_security_group_ids              = [aws_security_group.swift_app.id]
  manage_master_user_password         = true
  username                            = "swiftadmin"
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.swift_data.arn
  skip_final_snapshot                 = true
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]
  tags                                = local.tags
}

# A15: Redshift, Secrets Manager master password
resource "aws_redshift_subnet_group" "swift" {
  name       = "swift-redshift"
  subnet_ids = aws_subnet.swift[*].id
  tags       = local.tags
}

resource "aws_redshift_cluster" "swift" {
  cluster_identifier        = "swift-analytics"
  database_name             = "swiftdb"
  master_username           = "swiftadmin"
  manage_master_password    = true
  node_type                 = "ra3.xlplus"
  number_of_nodes           = 2
  cluster_subnet_group_name = aws_redshift_subnet_group.swift.name
  vpc_security_group_ids    = [aws_security_group.swift_app.id]
  encrypted                 = true
  kms_key_id                = aws_kms_key.swift_data.arn
  skip_final_snapshot       = true
  tags                      = local.tags
}

# A16: Secrets Manager, 60-day rotation
resource "aws_secretsmanager_secret" "swift_db" {
  name       = "swift/db/master"
  kms_key_id = aws_kms_key.swift_data.arn
  tags       = local.tags
}

resource "aws_secretsmanager_secret_rotation" "swift_db" {
  secret_id           = aws_secretsmanager_secret.swift_db.id
  rotation_lambda_arn = "arn:aws:lambda:eu-west-1:${var.account_id}:function:secret-rotation"
  rotation_rules { automatically_after_days = 60 }
}

# A17, A18: OpenSearch, fine-grained access (covered above in 2.1 section)
# A19: No aws_iam_access_key resources, compliant by absence

# ============================================================================
# CONTROL 5.1: Logical Access Control (A1-A18)
# ============================================================================

# A1, A2: Scoped IAM policy, no wildcard action/resource
resource "aws_iam_policy" "swift_operator" {
  name = "swift-operator"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "S3Access"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = ["arn:aws:s3:::swift-data-exchange-${var.account_id}", "arn:aws:s3:::swift-data-exchange-${var.account_id}/*"]
      },
      {
        Sid      = "LogsRead"
        Effect   = "Allow"
        Action   = ["logs:GetLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
        Resource = "arn:aws:logs:eu-west-1:${var.account_id}:log-group:/swift/*"
      }
    ]
  })
  tags = local.tags
}

# A3, A4: No direct user attachments, group-based access
resource "aws_iam_group" "swift_operators" { name = "swift-operators" }

resource "aws_iam_group_policy_attachment" "swift_operators" {
  group      = aws_iam_group.swift_operators.name
  policy_arn = aws_iam_policy.swift_operator.arn
}

# A5-A8: No AdministratorAccess/PowerUserAccess anywhere
resource "aws_iam_role_policy_attachment" "swift_app" {
  role       = aws_iam_role.swift_app.name
  policy_arn = aws_iam_policy.swift_operator.arn
}

# A9: Trust policies use specific principals (defined in 1.1 section)

# A10: PassRole scoped to specific role
resource "aws_iam_policy" "swift_deploy" {
  name = "swift-deploy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PassRoleScoped"
      Effect   = "Allow"
      Action   = "iam:PassRole"
      Resource = aws_iam_role.swift_app.arn
    }]
  })
  tags = local.tags
}

# A11: S3 bucket policies use Deny with condition, not Allow with Principal * (covered in 2.1)

# A12-A15: Separated IAM policies, provisioner vs security officer
resource "aws_iam_policy" "swift_provisioner" {
  name = "swift-iam-provisioner"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "UserProvisioning"
      Effect   = "Allow"
      Action   = ["iam:CreateUser", "iam:DeleteUser", "iam:ListUsers", "iam:GetUser", "iam:AddUserToGroup", "iam:RemoveUserFromGroup"]
      Resource = "arn:aws:iam::${var.account_id}:user/swift-*"
    }]
  })
  tags = local.tags
}

# Separation of duties: authoring a policy and attaching one are held by two
# principals, so neither role can write a permission and grant it to itself.
resource "aws_iam_policy" "swift_policy_author" {
  name = "swift-policy-author"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PolicyAuthoring"
      Effect   = "Allow"
      Action   = ["iam:CreatePolicy", "iam:DeletePolicy", "iam:UpdateAccountPasswordPolicy"]
      Resource = "arn:aws:iam::${var.account_id}:*"
    }]
  })
  tags = local.tags
}

resource "aws_iam_policy" "swift_policy_attacher" {
  name = "swift-policy-attacher"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PolicyAttachment"
      Effect   = "Allow"
      Action   = ["iam:AttachGroupPolicy", "iam:DetachGroupPolicy"]
      Resource = "arn:aws:iam::${var.account_id}:*"
    }]
  })
  tags = local.tags
}

# A16: Lambda with scoped role
resource "aws_iam_role" "swift_lambda" {
  name = "swift-lambda"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "swift_lambda" {
  role       = aws_iam_role.swift_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "swift" {
  function_name = "swift-processor"
  role          = aws_iam_role.swift_lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "placeholder.zip"
  tags          = local.tags
}

# A17: ECS with scoped role
resource "aws_iam_role" "swift_ecs" {
  name = "swift-ecs-task"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "swift_ecs" {
  role       = aws_iam_role.swift_ecs.name
  policy_arn = aws_iam_policy.swift_operator.arn
}

resource "aws_ecs_task_definition" "swift" {
  family                   = "swift-worker"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.swift_ecs.arn
  task_role_arn            = aws_iam_role.swift_ecs.arn
  container_definitions = jsonencode([{
    name      = "swift-worker"
    image     = "${var.account_id}.dkr.ecr.${var.region}.amazonaws.com/swift-worker:latest"
    essential = true
  }])
  tags = local.tags
}

# A18: Cross-account trust with ExternalId
resource "aws_iam_role" "swift_cross_account" {
  name                 = "swift-cross-account-audit"
  permissions_boundary = "arn:aws:iam::${var.account_id}:policy/SwiftZoneBoundary"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::987654321098:root" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "sts:ExternalId" = "swift-audit-2024-secure" }
        Bool         = { "aws:MultiFactorAuthPresent" = "true" }
      }
    }]
  })
  tags = local.tags
}

# ============================================================================
# CONTROL 6.4: Logging and Monitoring (A1-A24)
# ============================================================================

# KMS for logs

resource "aws_kms_key" "swift_logs" {
  description             = "Swift audit log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Root", Effect = "Allow", Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }, Action = "kms:*", Resource = "*" },
      { Sid = "CloudTrail", Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = ["kms:GenerateDataKey*", "kms:DescribeKey"], Resource = "*" },
      { Sid = "CloudWatch", Effect = "Allow", Principal = { Service = "logs.${var.region}.amazonaws.com" }, Action = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"], Resource = "*" }
    ]
  })
  tags = local.tags
}

# A1-A4, A7, A10, A11: CloudTrail

resource "aws_cloudtrail" "swift" {
  name                          = "swift-audit-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  enable_logging                = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.swift_logs.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.trail_cw.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = local.tags
}

# A8, A12: CloudWatch log groups

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/swift/cloudtrail"
  retention_in_days = 400
  kms_key_id        = aws_kms_key.swift_logs.arn
  tags              = local.tags
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/swift/vpc-flow-logs"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.swift_logs.arn
  tags              = local.tags
}

resource "aws_cloudwatch_log_group" "vpn" {
  name              = "/swift/vpn"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.swift_logs.arn
  tags              = local.tags
}

# A13-A18: CloudTrail S3 bucket protections

resource "aws_s3_bucket" "trail" {
  bucket              = "swift-audit-trail-logs-${var.account_id}"
  object_lock_enabled = true
  tags                = local.tags
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    id     = "archive-and-retain"
    status = "Enabled"

    # Required from provider v6: a rule must state what it applies to.
    filter {}
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    expiration { days = 730 }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "TrailWrite", Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "s3:PutObject", Resource = "${aws_s3_bucket.trail.arn}/*", Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } } },
      { Sid = "TrailBucket", Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "s3:GetBucketAcl", Resource = aws_s3_bucket.trail.arn },
      { Sid = "DenyDeletion", Effect = "Deny", Principal = "*", Action = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket"], Resource = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"] },
      # 2.1-A16: the audit-log bucket must refuse non-TLS access like any other
      # bucket in the zone. Missing here until the re-scoped assertion found it.
      { Sid = "DenyNonTLS", Effect = "Deny", Principal = "*", Action = "s3:*", Resource = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"], Condition = { Bool = { "aws:SecureTransport" = "false" } } }
    ]
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.swift_logs.arn
    }
    bucket_key_enabled = true
  }
}

# A19-A22: Metric filters + alarms

resource "aws_sns_topic" "alerts" {
  name              = "swift-security-alerts"
  kms_master_key_id = aws_kms_key.swift_logs.arn
  tags              = local.tags
}

resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  name           = "swift-root-usage"
  log_group_name = aws_cloudwatch_log_group.trail.name
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "SwiftCSCF"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "swift-root-usage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "SwiftCSCF"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CSCF 6.4: Root account usage"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = local.tags
}

resource "aws_cloudwatch_log_metric_filter" "iam_changes" {
  name           = "swift-iam-changes"
  log_group_name = aws_cloudwatch_log_group.trail.name
  pattern        = "{ ($.eventName = \"CreatePolicy\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"AttachRolePolicy\") || ($.eventName = \"DetachRolePolicy\") || ($.eventName = \"PutGroupPolicy\") || ($.eventName = \"DeleteGroupPolicy\") }"
  metric_transformation {
    name      = "IAMPolicyChanges"
    namespace = "SwiftCSCF"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_changes" {
  alarm_name          = "swift-iam-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "IAMPolicyChanges"
  namespace           = "SwiftCSCF"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CSCF 6.4: IAM policy change"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = local.tags
}

resource "aws_cloudwatch_log_metric_filter" "signin_failures" {
  name           = "swift-signin-failures"
  log_group_name = aws_cloudwatch_log_group.trail.name
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.errorMessage = \"Failed authentication\") }"
  metric_transformation {
    name      = "ConsoleSignInFailures"
    namespace = "SwiftCSCF"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "signin_failures" {
  alarm_name          = "swift-signin-failures"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ConsoleSignInFailures"
  namespace           = "SwiftCSCF"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  alarm_description   = "CSCF 6.4: Console sign-in failures"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = local.tags
}

# A23: GuardDuty

resource "aws_guardduty_detector" "swift" {
  enable = true
  tags   = local.tags
}

# A24: AWS Config

resource "aws_config_configuration_recorder" "swift" {
  name     = "swift-config"
  role_arn = aws_iam_role.config.arn
  recording_group { all_supported = true }
}

# ============================================================================
# SUPPORTING IAM ROLES (not directly asserted)
# ============================================================================

resource "aws_iam_role" "flow_log" {
  name = "swift-flow-log"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "vpc-flow-logs.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role" "trail_cw" {
  name = "swift-cloudtrail-cw"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role" "config" {
  name = "swift-config"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "config.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

# ============================================================================
# PHASE II CONTROLS: 1.2, 1.3, 1.4, 2.2, 2.3, 2.4, 2.6, 2.7, 4.2, 5.4
# Added so this environment is a compliant reference for the whole library
# rather than for the five Phase I controls only (review finding R3).
# ============================================================================

# 1.4-A4: AWS-service traffic stays on the AWS network

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.swift.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.swift.id]
  tags              = merge(local.tags, { Name = "swift-s3-endpoint" })
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.swift.id
  service_name        = "com.amazonaws.${var.region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.swift[*].id
  security_group_ids  = [aws_security_group.swift_app.id]
  private_dns_enabled = true
  tags                = merge(local.tags, { Name = "swift-ssm-endpoint" })
}

# 2.2-A1, 2.2-A2: patching mechanism and its schedule

resource "aws_ssm_patch_baseline" "swift" {
  name             = "swift-baseline"
  operating_system = "AMAZON_LINUX_2"
  approval_rule {
    approve_after_days = 7
    compliance_level   = "CRITICAL"
    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Security", "Bugfix"]
    }
  }
  tags = local.tags
}

resource "aws_ssm_association" "patch_scan" {
  name                = "AWS-RunPatchBaseline"
  schedule_expression = "cron(0 2 ? * SUN *)"
  parameters = {
    Operation = "Install"
  }
  targets {
    key    = "tag:swift:zone"
    values = ["secure"]
  }
}

# 2.7-A1: continuous vulnerability scanning

resource "aws_inspector2_enabler" "swift" {
  account_ids    = [var.account_id]
  resource_types = ["EC2", "ECR"]
}

# 1.2, 1.3, 1.4: the operator jump server
# 1.2-A1 no SSH key pair (access via Session Manager), 1.2-A2 an instance
# profile, 1.3-A1/A2 IMDSv2 with no hop, 1.3-A3 encrypted root volume,
# 1.3-A5 dedicated tenancy, 1.4-A5 no public address.

resource "aws_iam_role" "jump_ssm" {
  name                 = "swift-jump-ssm"
  permissions_boundary = "arn:aws:iam::${var.account_id}:policy/SwiftZoneBoundary"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}

resource "aws_iam_instance_profile" "jump" {
  name = "swift-jump-profile"
  role = aws_iam_role.jump_ssm.name
  tags = local.tags
}

resource "aws_instance" "jump_server" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "m5.large"
  subnet_id                   = aws_subnet.swift[0].id
  vpc_security_group_ids      = [aws_security_group.swift_app.id]
  iam_instance_profile        = aws_iam_instance_profile.jump.name
  associate_public_ip_address = false
  tenancy                     = "dedicated"
  monitoring                  = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.swift_data.arn
    volume_type = "gp3"
    volume_size = 50
  }

  tags = merge(local.tags, {
    Name         = "swift-jump-server"
    "swift:role" = "jump_server"
  })
}

# 1.3-A4: additional volumes are encrypted too.
resource "aws_ebs_volume" "jump_data" {
  availability_zone = local.azs[0]
  size              = 100
  encrypted         = true
  kms_key_id        = aws_kms_key.swift_data.arn
  tags              = merge(local.tags, { Name = "swift-jump-data" })
}

# 1.2-A3, 2.6-A2, 2.6-A3: Session Manager preferences
# Operator sessions are logged, idle-bounded, and encrypted in transit.

resource "aws_ssm_document" "session_preferences" {
  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "1.0"
    description   = "Swift secure zone session preferences"
    sessionType   = "Standard_Stream"
    inputs = {
      cloudWatchLogGroupName      = aws_cloudwatch_log_group.sessions.name
      cloudWatchEncryptionEnabled = true
      cloudWatchStreamingEnabled  = true
      s3BucketName                = aws_s3_bucket.swift_data.id
      kmsKeyId                    = aws_kms_key.swift_data.arn
      idleSessionTimeout          = "15"
      maxSessionDuration          = "60"
      runAsEnabled                = false
    }
  })

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "sessions" {
  name              = "/swift/session-manager"
  retention_in_days = 400
  kms_key_id        = aws_kms_key.swift_logs.arn
  tags              = local.tags
}

# 2.4-A1, 2.4-A2, 2.4-A4: back-office connectivity

resource "aws_vpn_gateway" "swift" {
  vpc_id = aws_vpc.swift.id
  tags   = merge(local.tags, { Name = "swift-vgw" })
}

resource "aws_customer_gateway" "back_office" {
  bgp_asn    = 65000
  ip_address = "198.51.100.10"
  type       = "ipsec.1"
  tags       = merge(local.tags, { Name = "swift-back-office-cgw" })
}

resource "aws_vpn_connection" "back_office" {
  vpn_gateway_id      = aws_vpn_gateway.swift.id
  customer_gateway_id = aws_customer_gateway.back_office.id
  type                = "ipsec.1"

  tunnel1_ike_versions                 = ["ikev2"]
  tunnel2_ike_versions                 = ["ikev2"]
  tunnel1_phase2_encryption_algorithms = ["AES256", "AES256-GCM-16"]
  tunnel2_phase2_encryption_algorithms = ["AES256", "AES256-GCM-16"]

  tags = merge(local.tags, { Name = "swift-back-office-vpn" })
}

resource "aws_dx_connection" "back_office" {
  name            = "swift-back-office-dx"
  bandwidth       = "1Gbps"
  location        = "EqDC2"
  encryption_mode = "must_encrypt"
  tags            = merge(local.tags, { Name = "swift-back-office-dx" })
}

# 5.4-A2, 5.4-A3: secret storage

resource "aws_ssm_parameter" "app_api_key" {
  name   = "/swift/app/api_key"
  type   = "SecureString"
  key_id = aws_kms_key.swift_data.arn
  value  = "placeholder-rotated-out-of-band"
  tags   = local.tags
}

resource "aws_secretsmanager_secret_policy" "app" {
  secret_arn = aws_secretsmanager_secret.swift_db.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AppRoleOnly"
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.swift_app.arn }
      Action    = ["secretsmanager:GetSecretValue"]
      Resource  = "*"
    }]
  })
}

# 4.2-A4: the identity pool and service role behind OpenSearch federated access.
resource "aws_cognito_identity_pool" "swift" {
  identity_pool_name               = "swift-operators"
  allow_unauthenticated_identities = false
  tags                             = local.tags
}

resource "aws_iam_role" "opensearch_cognito" {
  name = "swift-opensearch-cognito"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "opensearchservice.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}
