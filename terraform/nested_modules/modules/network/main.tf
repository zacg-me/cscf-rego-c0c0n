variable "vpc_id" { type = string }

module "edge" {
  source = "../edge"
  vpc_id = var.vpc_id
}
