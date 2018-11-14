variable "location" {}
variable "environment" {}
variable "ssh_public_key" {}
variable "image_id" {}
variable "tfe_organization" {}

data "terraform_remote_state" "tfe_network" {
  backend = "atlas"

  config {
    name = "${var.tfe_organization}/private-terraform-network"
  }
}

data "terraform_remote_state" "tfe_storage" {
  backend = "atlas"

  config {
    name = "${var.tfe_organization}/private-terraform-storage"
  }
}

module "compute" {
  source = "../_modules/compute"

  location                     = "${var.location}"
  environment                  = "${var.environment}"
  network_interface_id         = "${data.terraform_remote_state.tfe_network.network_interface_id}"
  public_ip_address            = "${data.terraform_remote_state.tfe_network.public_ip_address}"
  ssh_public_key               = "${var.ssh_public_key}"
  diagnostics_storage_endpoint = "${data.terraform_remote_state.tfe_storage.diagnostics_storage_endpoint}"
  image_id                     = "${var.image_id}"
}
