variable "location" {}
variable "environment" {}
variable "tfe_organization" {}
variable "storage_ip_rules" {
  type = "list"
}

data "terraform_remote_state" "tfe_network" {
  backend = "atlas"

  config {
    name = "${var.tfe_organization}/private-terraform-network"
  }
}

module "storage" {
  source = "../_modules/storage"

  location            = "${var.location}"
  environment         = "${var.environment}"
  subnet_id           = "${data.terraform_remote_state.tfe_network.subnet_id}"
  additional_ip_rules = ["${var.storage_ip_rules}"]
}


output "diagnostics_storage_endpoint" {
  value = "${module.storage.diagnostics_storage_endpoint}"
}
output "information" {
  value = <<EOF


Storage Account:    ${module.storage.storage_account_name}
Storage Access Key: ${module.storage.storage_access_key}
Storage Container:  ${module.storage.storage_container_name}
Storage Endpoint:   core.windows.net
EOF
}
