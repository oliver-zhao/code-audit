resource "google_storage_bucket_iam_member" "reader" {
  bucket = google_storage_bucket.site.name
  role   = "roles/storage.objectViewer"
  member = "group:readers@example.com"
}

resource "google_container_cluster" "main" {
  name               = "main"
  enable_legacy_abac = false
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block = "203.0.113.0/24"
    }
  }
}

resource "google_sql_database_instance" "db" {
  settings {
    ip_configuration {
      ssl_mode = "ENCRYPTED_ONLY"
    }
  }
}

resource "google_container_cluster" "current" {
  name            = "current"
  logging_service = "logging.googleapis.com/kubernetes"
}
