### VARIABLES
variable "location" {}

variable "environment" {}
variable "subnet_id" {}

variable "additional_ip_rules" {
  type    = "list"
  default = [""]
}

### RESOURCES
resource "azurerm_resource_group" "terraform" {
  name     = "${var.environment}-tfe-storage"
  location = "${var.location}"
}

resource "random_id" "storage_id" {
  byte_length = 6
}

locals {
  ip_rules = ["", "${var.additional_ip_rules}"]
}

resource "azurerm_storage_account" "terraform" {
  name                      = "tfeapp${random_id.storage_id.hex}"
  resource_group_name       = "${azurerm_resource_group.terraform.name}"
  location                  = "${var.location}"
  account_kind              = "BlobStorage"
  account_tier              = "Standard"
  account_replication_type  = "LRS"
  enable_https_traffic_only = true

  network_rules {
    ip_rules                   = ["${compact(local.ip_rules)}"]
    virtual_network_subnet_ids = ["${var.subnet_id}"]
    bypass                     = ["Logging", "Metrics", "AzureServices"]
  }

  tags {
    environment = "${var.environment}"
  }
}

resource "azurerm_storage_container" "terraform" {
  name                  = "terraform"
  resource_group_name   = "${azurerm_resource_group.terraform.name}"
  storage_account_name  = "${azurerm_storage_account.terraform.name}"
  container_access_type = "private"
}

resource "azurerm_storage_account" "diagnostics" {
  name                      = "tfediag${random_id.storage_id.hex}"
  resource_group_name       = "${azurerm_resource_group.terraform.name}"
  location                  = "${var.location}"
  account_kind              = "StorageV2"
  account_tier              = "Standard"
  account_replication_type  = "LRS"
  enable_https_traffic_only = true

  network_rules {
    ip_rules                   = ["${compact(local.ip_rules)}"]
    virtual_network_subnet_ids = ["${var.subnet_id}"]
    bypass                     = ["Logging", "Metrics", "AzureServices"]
  }

  tags {
    environment = "${var.environment}"
  }
}

output "storage_account_name" {
  value = "${azurerm_storage_account.terraform.name}"
}

output "storage_access_key" {
  value = "${azurerm_storage_account.terraform.primary_access_key}"
}

output "storage_endpoint" {
  value = "${azurerm_storage_account.terraform.primary_blob_endpoint}"
}

output "storage_container_name" {
  value = "${azurerm_storage_container.terraform.name}"
}

output "diagnostics_storage_endpoint" {
  value = "${azurerm_storage_account.diagnostics.primary_blob_endpoint}"
}
