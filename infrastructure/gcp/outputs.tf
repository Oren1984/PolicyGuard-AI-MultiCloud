output "cloud_run_url" {
  description = "URL of the deployed Cloud Run service."
  value       = google_cloud_run_v2_service.app.uri
}

output "artifact_registry_repository" {
  description = "Artifact Registry repository to push the PolicyGuard app image to."
  value       = google_artifact_registry_repository.app.name
}

output "cloud_sql_private_ip" {
  description = "Private IP address of the Cloud SQL PostgreSQL instance."
  value       = google_sql_database_instance.this.private_ip_address
  sensitive   = true
}

output "db_credentials_secret_id" {
  description = "Secret Manager secret ID holding the generated DB credentials."
  value       = google_secret_manager_secret.db_credentials.secret_id
}
