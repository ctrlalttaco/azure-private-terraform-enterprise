variable "location" {}
variable "environment" {}
variable "tenant_id" {}

module "security" {
  source = "../_modules/security"

  location    = "${var.location}"
  environment = "${var.environment}"
  tenant_id   = "${var.tenant_id}"
}
