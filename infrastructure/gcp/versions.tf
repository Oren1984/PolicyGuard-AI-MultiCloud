# Reference architecture only -- see docs/MULTI_CLOUD_REFERENCE.md (Phase 6).
# `terraform validate`/`fmt -check` only; never `apply` against this config.

terraform {
  required_version = ">= 1.6"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # No remote backend is configured for this POC reference architecture --
  # state stays local. A real deployment would add a GCS backend here.
  # See docs/MULTI_CLOUD_REFERENCE.md.
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}
