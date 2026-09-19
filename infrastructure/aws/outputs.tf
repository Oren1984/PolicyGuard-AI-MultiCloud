output "alb_dns_name" {
  description = "Public DNS name of the ALB fronting the ECS service."
  value       = aws_lb.this.dns_name
}

output "ecr_repository_url" {
  description = "ECR repository to push the PolicyGuard app image to."
  value       = aws_ecr_repository.app.repository_url
}

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint (private; reachable only from ECS tasks)."
  value       = aws_db_instance.this.address
  sensitive   = true
}

output "db_credentials_secret_arn" {
  description = "Secrets Manager ARN holding the generated DB credentials."
  value       = aws_secretsmanager_secret.db_credentials.arn
}
