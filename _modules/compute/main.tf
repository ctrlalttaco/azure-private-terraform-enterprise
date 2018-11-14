variable "location" {}
variable "environment" {}
variable "network_interface_id" {}
variable "public_ip_address" {}
variable "vm_size" {
  default = "Standard_F4s_v2"
}
variable "ssh_public_key" {}
variable "diagnostics_storage_endpoint" {}
variable "image_id" {}

resource "azurerm_resource_group" "tfe" {
  name     = "${var.environment}-tfe-compute"
  location = "${var.location}"
}

resource "azurerm_availability_set" "tfe" {
  name                = "${var.environment}-tfe-as"
  location            = "${var.location}"
  resource_group_name = "${azurerm_resource_group.tfe.name}"
  managed             = true

  tags {
    environment = "${var.environment}"
  }
}

data "template_file" "custom_data" {
  template = "${file("${path.module}/custom_data.tpl")}"

  vars {
    public_ip_address = "${var.public_ip_address}"
  }
}
resource "random_id" "tfe" {
  byte_length = 4
}

resource "azurerm_virtual_machine" "tfe" {
  name                          = "${var.environment}-tfe-vm-${random_id.tfe.hex}"
  location                      = "${var.location}"
  resource_group_name           = "${azurerm_resource_group.tfe.name}"
  network_interface_ids         = ["${var.network_interface_id}"]
  vm_size                       = "${var.vm_size}"
  availability_set_id           = "${azurerm_availability_set.tfe.id}"
  delete_os_disk_on_termination = true

  boot_diagnostics {
    enabled     = true
    storage_uri = "${var.diagnostics_storage_endpoint}"
  }

  storage_image_reference {
    id = "${var.image_id}"
  }

  storage_os_disk {
    name              = "${var.environment}-tfe-osdisk-${random_id.tfe.hex}"
    caching           = "ReadWrite"
    create_option     = "FromImage"
    managed_disk_type = "Premium_LRS"
    disk_size_gb      = 256                                                  # Need moar IOPS!
  }

  os_profile {
    computer_name  = "terraform-${random_id.tfe.hex}"
    admin_username = "terraform"
    admin_password = ""
    custom_data    = "${data.template_file.custom_data.rendered}"
  }

  os_profile_linux_config {
    disable_password_authentication = true

    ssh_keys {
      path     = "/home/terraform/.ssh/authorized_keys"
      key_data = "${var.ssh_public_key}"
    }
  }

  tags {
    environment = "${var.environment}"
  }
}
