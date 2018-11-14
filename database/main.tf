variable "location" {}
variable "environment" {}
variable "tfe_organization" {}

data "terraform_remote_state" "tfe_network" {
  backend = "atlas"

  config {
    name = "${var.tfe_organization}/private-terraform-network"
  }
}

resource "random_string" "password" {
  length  = 64
  special = true
}

module "database" {
  source = "../_modules/database"

  location              = "${var.location}"
  environment           = "${var.environment}"
  subnet_id             = "${data.terraform_remote_state.tfe_network.subnet_id}"
  admin_username        = "terraform"
  admin_password        = "${random_string.password.result}"
  database_name         = "terraform"
  disk_size             = 51200
  backup_retention_days = 7
}

output "information" {
  value = <<EOF


PostgreSQL Hostname:       ${module.database.hostname}
PostgreSQL Admin Username: ${module.database.admin_username}
PostgreSQL Admin Password: ${random_string.password.result}
PostgreSQL Database Name:  ${module.database.database_name}

!!! Don't forget to create the schemas

`psql -h ${module.database.hostname} -d ${module.database.database_name} -U ${module.database.admin_username}`

CREATE SCHEMA rails;
CREATE SCHEMA vault;
CREATE SCHEMA registry;
EOF
}
