### VARIABLES

variable "location" {}
variable "environment" {}
variable "disk_size" {}
variable "backup_retention_days" {}
variable "admin_username" {}
variable "admin_password" {}
variable "database_name" {}

variable "subnet_id" {}

resource "azurerm_resource_group" "database" {
  name     = "${var.environment}-tfe-database"
  location = "${var.location}"
}

resource "azurerm_postgresql_server" "tfe" {
  name                = "${var.environment}-tfe-psql-server"
  location            = "${var.location}"
  resource_group_name = "${azurerm_resource_group.database.name}"

  sku {
    name     = "gp_gen5_4"
    capacity = 4
    tier     = "GeneralPurpose" # Case Sensitive
    family   = "Gen5"           # Case Sensitive
  }

  storage_profile {
    storage_mb            = "${var.disk_size}"
    backup_retention_days = "${var.backup_retention_days}"
    geo_redundant_backup  = "Enabled"
  }

  administrator_login          = "${var.admin_username}"
  administrator_login_password = "${var.admin_password}"
  version                      = "10.0"
  ssl_enforcement              = "Enabled"
}

resource "azurerm_postgresql_database" "terraform" {
  name                = "${var.database_name}"
  resource_group_name = "${azurerm_resource_group.database.name}"
  server_name         = "${azurerm_postgresql_server.tfe.name}"
  charset             = "UTF8"
  collation           = "English_United States.1252"
}

resource "azurerm_postgresql_firewall_rule" "tfe_1" {
  name                = "tfe_1_postgresql_firewall_rule"
  resource_group_name = "${azurerm_resource_group.database.name}"
  server_name         = "${azurerm_postgresql_server.tfe.name}"
  start_ip_address    = "0.0.0.0"                                 # Allows access to internal Azure services
  end_ip_address      = "0.0.0.0"                                 # Allows access to internal Azure services
}

resource "azurerm_postgresql_virtual_network_rule" "tfe" {
  name                = "postgresql-vnet-rule"
  resource_group_name = "${azurerm_resource_group.database.name}"
  server_name         = "${azurerm_postgresql_server.tfe.name}"
  subnet_id           = "${var.subnet_id}"
}

output "hostname" {
  value = "${azurerm_postgresql_server.tfe.fqdn}"
}

output "admin_username" {
  value = "${var.admin_username}@${element(split(".", azurerm_postgresql_server.tfe.fqdn), 0)}"
}

output "database_name" {
  value = "${azurerm_postgresql_database.terraform.name}"
}
