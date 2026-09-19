resource "google_artifact_registry_repository" "app" {
  repository_id = "${var.project_name}-app"
  location      = var.gcp_region
  format        = "DOCKER"
}

resource "google_cloud_run_v2_service" "app" {
  name     = "${var.project_name}-app"
  location = var.gcp_region

  template {
    service_account = google_service_account.run.email

    vpc_access {
      network_interfaces {
        network    = google_compute_network.this.id
        subnetwork = google_compute_subnetwork.run.id
      }
      egress = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = var.container_image

      ports {
        container_port = var.container_port
      }

      env {
        name  = "POLICYGUARD_ENVIRONMENT"
        value = var.environment
      }
      env {
        name  = "POLICYGUARD_AI_PROVIDER"
        value = "mock"
      }
      env {
        name = "POLICYGUARD_DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.db_credentials.secret_id
            version = "latest"
          }
        }
      }

      startup_probe {
        http_get {
          path = "/health"
        }
        period_seconds    = 5
        failure_threshold = 5
      }
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.run_reads_db_secret]
}

resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  count    = var.allow_unauthenticated ? 1 : 0
  location = google_cloud_run_v2_service.app.location
  name     = google_cloud_run_v2_service.app.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
