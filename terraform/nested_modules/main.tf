# R8 demonstration: a Swift zone built the way real estates are built, from
# nested modules. The only violation sits three modules deep.
#
#   root -> module.zone -> module.network -> module.edge -> aws_security_group
#
# helpers.all_resources walks the root and two levels of child_modules, so a
# resource at depth three is invisible to every rule in the Phase I library.

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
  region                      = "eu-west-1"
  access_key                  = "mock-access-key"
  secret_key                  = "mock-secret-key"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

resource "aws_vpc" "swift" {
  cidr_block = "10.100.0.0/16"
  tags       = { "swift:zone" = "secure", Name = "swift-nested" }
}

module "zone" {
  source = "./modules/zone"
  vpc_id = aws_vpc.swift.id
}
