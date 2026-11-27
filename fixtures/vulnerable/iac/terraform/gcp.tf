resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.site.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_storage_object_acl" "report" {
  bucket         = google_storage_bucket.site.name
  object         = "report.pdf"
  predefined_acl = "publicRead"
}

resource "google_container_cluster" "main" {
  name               = "main"
  enable_legacy_abac = true
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block = "0.0.0.0/0"
    }
  }
}

resource "google_sql_database_instance" "db" {
  settings {
    ip_configuration {
      require_ssl = false
    }
  }
}

resource "google_container_cluster" "legacy" {
  name            = "legacy"
  logging_service = "none"
}

resource "google_compute_ssl_policy" "legacy" {
  name            = "legacy"
  min_tls_version = "TLS_1_0"
}
