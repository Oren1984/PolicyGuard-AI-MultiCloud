# Reference architecture only -- see docs/MULTI_CLOUD_REFERENCE.md (Phase 6).
# `terraform validate`/`fmt -check` only; never `apply` against this config.

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # No remote backend is configured for this POC reference architecture --
  # state stays local. A real deployment would add an S3 + DynamoDB backend
  # here. See docs/MULTI_CLOUD_REFERENCE.md.
}

provider "aws" {
  region = var.aws_region
}
