variable "tfe_modules" {
  type = "list"
}
variable "azure_environment" {}
variable "azure_location" {}
variable "azure_subscription_id" {}
variable "azure_client_id" {}
variable "azure_client_secret" {}
variable "azure_tenant_id" {}
variable "tfe_organization" {}
variable "source_repo" {}
variable "github_oauth_token_id" {}
variable "terraform_version" {}


resource "tfe_workspace" "workspace" {
  count             = "${length(var.tfe_modules)}"
  name              = "private-terraform-${element(var.tfe_modules, count.index)}"
  organization      = "${var.tfe_organization}"
  terraform_version = "${var.terraform_version}"
  working_directory = "${var.working_directory}"

  vcs_repo {
    identifier     = "${var.source_repo}"
    oauth_token_id = "${var.github_oauth_token_id}"
  }
}

resource "tfe_variable" "environment" {
  count        = "${length(var.tfe_modules)}"
  workspace_id = "${element(tfe_workspace.workspace.*.id, count.index)}"
  key          = "environment"
  value        = "${var.azure_environment}"
  category     = "terraform"
}

resource "tfe_variable" "location" {
  count        = "${length(var.tfe_modules)}"
  workspace_id = "${element(tfe_workspace.workspace.*.id, count.index)}"
  key          = "location"
  value        = "${var.azure_location}"
  category     = "terraform"
}

resource "tfe_variable" "arm_tenant_id" {
  count        = "${length(var.tfe_modules)}"
  workspace_id = "${element(tfe_workspace.workspace.*.id, count.index)}"
  key          = "ARM_TENANT_ID"
  value        = "${var.azure_tenant_id}"
  category     = "env"
}

resource "tfe_variable" "arm_subscription_id" {
  count        = "${length(var.tfe_modules)}"
  workspace_id = "${element(tfe_workspace.workspace.*.id, count.index)}"
  key          = "ARM_SUBSCRIPTION_ID"
  value        = "${var.azure_subscription_id}"
  category     = "env"
}

resource "tfe_variable" "arm_client_id" {
  count        = "${length(var.tfe_modules)}"
  workspace_id = "${element(tfe_workspace.workspace.*.id, count.index)}"
  key          = "ARM_CLIENT_ID"
  value        = "${var.azure_client_id}"
  category     = "env"
}

resource "tfe_variable" "arm_client_secret" {
  count        = "${length(var.tfe_modules)}"
  workspace_id = "${element(tfe_workspace.workspace.*.id, count.index)}"
  key          = "ARM_CLIENT_SECRET"
  value        = "${var.azure_client_secret}"
  category     = "env"
  sensitive    = true
}
