### VARIABLES

variable "location" {}
variable "environment" {}
variable "enable_setup_port" {}
variable "vnet_resource_group_name" {}
variable "vnet_name" {}
variable "subnet_address_prefix" {}

### Resource Groups
resource "azurerm_resource_group" "tfe" {
  name     = "${var.environment}-tfe-network"
  location = "${var.location}"
}

### Subnets

resource "azurerm_subnet" "tfe" {
  name                      = "${var.environment}-tfe"
  resource_group_name       = "${var.vnet_resource_group_name}"
  virtual_network_name      = "${var.vnet_name}"
  address_prefix            = "${var.subnet_address_prefix}"
  service_endpoints         = ["Microsoft.Sql", "Microsoft.Storage"]
  network_security_group_id = "${azurerm_network_security_group.tfe.id}"
}

### Public IPs

resource "azurerm_public_ip" "tfe" {
  name                         = "${var.environment}-tfe-public-ip"
  location                     = "${var.location}"
  resource_group_name          = "${azurerm_resource_group.tfe.name}"
  public_ip_address_allocation = "static"
}

locals {
  public_frontend_pool_name = "tfe-public-frontend"
}

### Load Balancers

resource "azurerm_lb" "tfe_public" {
  name                = "${var.environment}-tfe-public-lb"
  location            = "${var.location}"
  resource_group_name = "${azurerm_resource_group.tfe.name}"

  frontend_ip_configuration {
    name                 = "${local.public_frontend_pool_name}"
    public_ip_address_id = "${azurerm_public_ip.tfe.id}"
  }
}

resource "azurerm_lb_backend_address_pool" "tfe_public" {
  resource_group_name = "${azurerm_resource_group.tfe.name}"
  loadbalancer_id     = "${azurerm_lb.tfe_public.id}"
  name                = "tfe-public-bep"
}

resource "azurerm_lb_probe" "tfe_public_setup" {
  name                = "tfe-public-setup-probe"
  resource_group_name = "${azurerm_resource_group.tfe.name}"
  loadbalancer_id     = "${azurerm_lb.tfe_public.id}"
  port                = 8800
}

resource "azurerm_lb_probe" "tfe_public_http" {
  name                = "tfe-public-http-probe"
  resource_group_name = "${azurerm_resource_group.tfe.name}"
  loadbalancer_id     = "${azurerm_lb.tfe_public.id}"
  port                = 80
}

resource "azurerm_lb_probe" "tfe_public_https" {
  name                = "tfe-public-https-probe"
  resource_group_name = "${azurerm_resource_group.tfe.name}"
  loadbalancer_id     = "${azurerm_lb.tfe_public.id}"
  port                = 443
}

resource "azurerm_lb_rule" "tfe_public_http" {
  name                           = "tfe-public-lb-http-rule"
  resource_group_name            = "${azurerm_resource_group.tfe.name}"
  loadbalancer_id                = "${azurerm_lb.tfe_public.id}"
  protocol                       = "Tcp"
  frontend_port                  = 80
  backend_port                   = 80
  probe_id                       = "${azurerm_lb_probe.tfe_public_http.id}"
  frontend_ip_configuration_name = "${local.public_frontend_pool_name}"
  backend_address_pool_id        = "${azurerm_lb_backend_address_pool.tfe_public.id}"
}

resource "azurerm_lb_rule" "tfe_public_https" {
  name                           = "tfe-public-lb-https-rule"
  resource_group_name            = "${azurerm_resource_group.tfe.name}"
  loadbalancer_id                = "${azurerm_lb.tfe_public.id}"
  protocol                       = "Tcp"
  frontend_port                  = 443
  backend_port                   = 443
  probe_id                       = "${azurerm_lb_probe.tfe_public_https.id}"
  frontend_ip_configuration_name = "${local.public_frontend_pool_name}"
  backend_address_pool_id        = "${azurerm_lb_backend_address_pool.tfe_public.id}"
}

resource "azurerm_lb_rule" "tfe_public_setup" {
  name                           = "tfe-public-lb-setup-rule"
  resource_group_name            = "${azurerm_resource_group.tfe.name}"
  loadbalancer_id                = "${azurerm_lb.tfe_public.id}"
  protocol                       = "Tcp"
  frontend_port                  = 8800
  backend_port                   = 8800
  probe_id                       = "${azurerm_lb_probe.tfe_public_setup.id}"
  frontend_ip_configuration_name = "${local.public_frontend_pool_name}"
  backend_address_pool_id        = "${azurerm_lb_backend_address_pool.tfe_public.id}"
}

### Network and Application Security Groups

resource "azurerm_network_security_group" "tfe" {
  name                = "${var.environment}-tfe-nsg"
  resource_group_name = "${azurerm_resource_group.tfe.name}"
  location            = "${var.location}"

  tags {
    environment = "${var.environment}"
  }
}

resource "azurerm_subnet_network_security_group_association" "tfe" {
  subnet_id                 = "${azurerm_subnet.tfe.id}"
  network_security_group_id = "${azurerm_network_security_group.tfe.id}"
}

resource "azurerm_application_security_group" "tfe" {
  name                = "${var.environment}-tfe-asg"
  location            = "${var.location}"
  resource_group_name = "${azurerm_resource_group.tfe.name}"

  tags {
    environment = "${var.environment}"
  }
}

### Network Security Rules

resource "azurerm_network_security_rule" "tfe_http_in" {
  name                        = "tfe-http-in"
  resource_group_name         = "${azurerm_resource_group.tfe.name}"
  network_security_group_name = "${azurerm_network_security_group.tfe.name}"

  priority                                   = 200
  direction                                  = "Inbound"
  access                                     = "Allow"
  protocol                                   = "Tcp"
  source_port_range                          = "*"
  destination_port_range                     = 80
  source_address_prefix                      = "*"
  destination_application_security_group_ids = ["${azurerm_application_security_group.tfe.id}"]
}

resource "azurerm_network_security_rule" "tfe_https_in" {
  name                        = "tfe-https-in"
  resource_group_name         = "${azurerm_resource_group.tfe.name}"
  network_security_group_name = "${azurerm_network_security_group.tfe.name}"

  priority                                   = 210
  direction                                  = "Inbound"
  access                                     = "Allow"
  protocol                                   = "Tcp"
  source_port_range                          = "*"
  destination_port_range                     = 443
  source_address_prefix                      = "*"
  destination_application_security_group_ids = ["${azurerm_application_security_group.tfe.id}"]
}

resource "azurerm_network_security_rule" "tfe_setup_in" {
  count                       = "${var.enable_setup_port ? 1 : 0}"
  name                        = "tfe-setup-in"
  resource_group_name         = "${azurerm_resource_group.tfe.name}"
  network_security_group_name = "${azurerm_network_security_group.tfe.name}"

  priority                                   = 220
  direction                                  = "Inbound"
  access                                     = "Allow"
  protocol                                   = "Tcp"
  source_port_range                          = "*"
  destination_port_range                     = 8800
  source_address_prefix                      = "*"
  destination_application_security_group_ids = ["${azurerm_application_security_group.tfe.id}"]
}

### Network Interfaces

resource "azurerm_network_interface" "tfe" {
  name                = "${var.environment}-tfe-ni"
  location            = "${var.location}"
  resource_group_name = "${azurerm_resource_group.tfe.name}"
  depends_on          = ["azurerm_subnet.tfe"]

  ip_configuration {
    name                           = "tfe-ip-config"
    subnet_id                      = "${azurerm_subnet.tfe.id}"
    private_ip_address_allocation  = "dynamic"
    application_security_group_ids = ["${azurerm_application_security_group.tfe.id}"]
  }

  tags {
    environment = "${var.environment}"
  }
}

resource "azurerm_network_interface_backend_address_pool_association" "tfe" {
  network_interface_id    = "${azurerm_network_interface.tfe.id}"
  ip_configuration_name   = "tfe-ip-config"
  backend_address_pool_id = "${azurerm_lb_backend_address_pool.tfe_public.id}"
}

### OUTPUTS

output "subnet_id" {
  value = "${azurerm_subnet.tfe.id}"
}
output "network_interface_id" {
  value = "${azurerm_network_interface.tfe.id}"
}

output "network_security_group_id" {
  value = "${azurerm_network_security_group.tfe.id}"
}
output "application_security_group_id" {
  value = "${azurerm_application_security_group.tfe.id}"
}

output "public_ip_address" {
  value = "${azurerm_public_ip.tfe.ip_address}"
}
