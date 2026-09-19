variable "gcp_project_id" {
  description = "GCP project ID to deploy the reference architecture into."
  type        = string
  default     = "REPLACE_WITH_GCP_PROJECT_ID"
}

variable "gcp_region" {
  description = "GCP region for Cloud Run, Cloud SQL, and Artifact Registry."
  type        = string
  default     = "us-central1"
}

variable "project_name" {
  description = "Short name used to prefix all created resources."
  type        = string
  default     = "policyguard"
}

variable "environment" {
  description = "Deployment environment tag (dev/staging/production)."
  type        = string
  default     = "dev"
}

variable "container_image" {
  description = "Full Artifact Registry image URI for the PolicyGuard app container. Left as a placeholder -- no image is pushed or deployed by this POC."
  type        = string
  default     = "REPLACE_WITH_ARTIFACT_REGISTRY_IMAGE_URI"
}

variable "container_port" {
  description = "Port the PolicyGuard app listens on inside the container."
  type        = number
  default     = 8000
}

variable "db_tier" {
  description = "Cloud SQL machine tier for the PostgreSQL 16 instance."
  type        = string
  default     = "db-custom-1-3840"
}

variable "db_name" {
  description = "Application database name."
  type        = string
  default     = "policyguard"
}

variable "db_username" {
  description = "Application database user. The password is generated and stored only in Secret Manager."
  type        = string
  default     = "policyguard"
}

variable "allow_unauthenticated" {
  description = "Whether Cloud Run allows unauthenticated invocations. POC default is true for local demo convenience; a real deployment should front this with IAP or a load balancer and set this to false."
  type        = bool
  default     = true
}
