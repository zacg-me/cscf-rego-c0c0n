variable "vpc_id" { type = string }

# VIOLATES 1.1-A2 and 1.1-A3: SSH open to the internet, three modules deep.
resource "aws_security_group" "edge" {
  name        = "swift-edge"
  description = "Edge access"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { "swift:zone" = "secure" }
}
