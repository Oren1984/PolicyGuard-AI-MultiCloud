# Least-privilege direction: the Cloud Run service account can only read the
# one secret it needs and write its own logs/metrics -- nothing else.

resource "google_service_account" "run" {
  account_id   = "${var.project_name}-run-sa"
  display_name = "PolicyGuard Cloud Run service account"
}

resource "google_secret_manager_secret_iam_member" "run_reads_db_secret" {
  secret_id = google_secret_manager_secret.db_credentials.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run.email}"
}

resource "google_project_iam_member" "run_logging" {
  project = var.gcp_project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.run.email}"
}

resource "google_project_iam_member" "run_metrics" {
  project = var.gcp_project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.run.email}"
}

resource "google_project_iam_member" "run_cloudsql_client" {
  project = var.gcp_project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.run.email}"
}
