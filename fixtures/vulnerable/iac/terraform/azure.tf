resource "azurerm_storage_account" "data" {
  name                            = "datastore"
  allow_nested_items_to_be_public = true
  https_traffic_only_enabled      = false
  min_tls_version                 = "TLS1_0"
  public_network_access_enabled   = true

  network_rules {
    default_action = "Allow"
  }
}

resource "azurerm_mssql_firewall_rule" "all" {
  name             = "all"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_postgresql_server" "db" {
  name                    = "db"
  ssl_enforcement_enabled = false
}
