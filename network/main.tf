variable "location" {}
variable "environment" {}
variable "vnet_resource_group_name" {}
variable "vnet_name" {}
variable "subnet_address_prefix" {}
variable "enable_setup_port" {}

module "network" {
  source = "../_modules/network"

  location                 = "${var.location}"
  environment              = "${var.environment}"
  vnet_resource_group_name = "${var.vnet_resource_group_name}"
  vnet_name                = "${var.vnet_name}"
  subnet_address_prefix    = "${var.subnet_address_prefix}"
  enable_setup_port        = "${var.enable_setup_port}"
}

output "subnet_id" {
  value = "${module.network.subnet_id}"
}
output "network_interface_id" {
  value = "${module.network.network_interface_id}"
}

output "public_ip_address" {
  value = "${module.network.public_ip_address}"
}
