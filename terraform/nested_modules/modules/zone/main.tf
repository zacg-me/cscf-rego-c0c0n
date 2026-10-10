variable "vpc_id" { type = string }

module "network" {
  source = "../network"
  vpc_id = var.vpc_id
}
