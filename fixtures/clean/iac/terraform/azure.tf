resource "azurerm_storage_account" "data" {
  name                            = "datastore"
  allow_nested_items_to_be_public = false
  https_traffic_only_enabled      = true
  min_tls_version                 = "TLS1_2"
  public_network_access_enabled   = false

  network_rules {
    default_action = "Deny"
    ip_rules       = ["203.0.113.0/24"]
  }
}

resource "azurerm_mssql_firewall_rule" "office" {
  name             = "office"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "203.0.113.1"
  end_ip_address   = "203.0.113.254"
}

resource "azurerm_postgresql_server" "db" {
  name                    = "db"
  ssl_enforcement_enabled = true
}
