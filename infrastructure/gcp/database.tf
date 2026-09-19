# Cloud SQL PostgreSQL 16 on a private IP only (no public IP), reachable
# from Cloud Run via the private services connection in network.tf.

resource "random_password" "db" {
  length  = 32
  special = false
}

resource "google_sql_database_instance" "this" {
  name                = "${var.project_name}-postgres"
  database_version    = "POSTGRES_16"
  region              = var.gcp_region
  deletion_protection = false # POC simplification; enable for production

  settings {
    tier = var.db_tier

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.this.id
    }

    backup_configuration {
      enabled = true
    }
  }

  depends_on = [google_service_networking_connection.private_services]
}

resource "google_sql_database" "app" {
  name     = var.db_name
  instance = google_sql_database_instance.this.name
}

resource "google_sql_user" "app" {
  name     = var.db_username
  instance = google_sql_database_instance.this.name
  password = random_password.db.result
}

resource "google_secret_manager_secret" "db_credentials" {
  secret_id = "${var.project_name}-db-credentials"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "db_credentials" {
  secret = google_secret_manager_secret.db_credentials.id
  secret_data = jsonencode({
    username = var.db_username
    password = random_password.db.result
    host     = google_sql_database_instance.this.private_ip_address
    port     = 5432
    dbname   = var.db_name
    url      = "postgresql+psycopg://${var.db_username}:${random_password.db.result}@${google_sql_database_instance.this.private_ip_address}:5432/${var.db_name}"
  })
}
