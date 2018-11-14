variable "azure_client_id" {}
variable "azure_client_secret" {}
variable "azure_tenant_id" {}
variable "azure_subscription_id" {}
variable "azure_location" {}
variable "azure_environment" {}
variable "tfe_organization" {}

variable "tfe_token" {}
variable "terraform_version" {}
variable "source_repo" {}
variable "github_oauth_token_id" {}

provider "tfe" {
  token = "${var.tfe_token}"
}

module "workspaces" {
  source = "modules/workspace"

  tfe_modules = [
    "network",
    "security",
    "storage",
    "database",
    "compute"
  ]

  organization            = "${var.tfe_organization}"
  source_repo             = "${var.source_repo}"
  github_oauth_token_id   = "${var.github_oauth_token_id}"
  terraform_version       = "${var.terraform_version}"
  azure_subscription_name = "${var.azure_subscription_name}"
  azure_subscription_id   = "${var.azure_subscription_id}"
  azure_client_id         = "${var.azure_client_id}"
  azure_client_secret     = "${var.azure_client_secret}"
  azure_tenant_id         = "${var.azure_tenant_id}"
  azure_location          = "${var.azure_location}"
  azure_environment       = "${var.azure_environment}"
}
