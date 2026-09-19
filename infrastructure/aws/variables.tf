variable "aws_region" {
  description = "AWS region to deploy the reference architecture into."
  type        = string
  default     = "us-east-1"
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

variable "vpc_cidr" {
  description = "CIDR block for the PolicyGuard VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "container_image" {
  description = "Full ECR image URI for the PolicyGuard app container. Left as a placeholder -- no image is pushed or deployed by this POC."
  type        = string
  default     = "REPLACE_WITH_ECR_IMAGE_URI"
}

variable "container_port" {
  description = "Port the PolicyGuard app listens on inside the container."
  type        = number
  default     = 8000
}

variable "db_instance_class" {
  description = "RDS instance class for the PostgreSQL 16 database."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_name" {
  description = "Application database name."
  type        = string
  default     = "policyguard"
}

variable "db_username" {
  description = "Master username for RDS. The password is generated and stored only in Secrets Manager -- never in state as plaintext output."
  type        = string
  default     = "policyguard"
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for the ALB's HTTPS listener. Must be replaced with a real, validated certificate before any real deployment."
  type        = string
  default     = "arn:aws:acm:us-east-1:000000000000:certificate/REPLACE_WITH_REAL_CERTIFICATE_ID"
}
