# Minimal VPC with a private-services-access range for Cloud SQL, and a
# direct VPC egress subnet for Cloud Run v2 so the service can reach Cloud
# SQL over a private IP instead of the (deprecated) Cloud SQL Auth Proxy
# sidecar pattern.
#
# POC tradeoff, documented rather than silently chosen: private-IP Cloud
# SQL + a VPC connector/direct-egress subnet is more moving parts than a
# public-IP Cloud SQL instance restricted by authorized networks, but it
# never exposes the database to the public internet even transiently. For
# a POC reference architecture that's the safer default to document; see
# docs/MULTI_CLOUD_REFERENCE.md for the tradeoff against the simpler
# public-IP-with-authorized-networks alternative.

resource "google_compute_network" "this" {
  name                    = "${var.project_name}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "run" {
  name          = "${var.project_name}-run-subnet"
  ip_cidr_range = "10.50.0.0/24"
  region        = var.gcp_region
  network       = google_compute_network.this.id
}

resource "google_compute_global_address" "private_services" {
  name          = "${var.project_name}-private-services"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.this.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.this.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]
}

# Least-privilege direction: no ingress firewall rules are defined here.
# Cloud Run is a managed ingress surface (fronted by var.allow_unauthenticated
# / IAM), and Cloud SQL is reached over the private services connection
# above rather than a firewall-mediated path.
