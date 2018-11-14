#!/bin/sh -x

CONSUL_MODULE="v0.0.5"
CONSUL_VERSION="1.3.0"
VAULT_MODULE="v0.0.2"
VAULT_VERSION="1.0.0-beta1"

curl -Lo /tmp/packages-microsoft-prod.deb https://packages.microsoft.com/config/ubuntu/16.04/packages-microsoft-prod.deb
dpkg -i /tmp/packages-microsoft-prod.deb
echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli xenial main" | tee /etc/apt/sources.list.d/azure-cli.list
apt-get update
apt-get -y install git libssl-dev libffi-dev python-dev build-essential apt-transport-https azure-cli

git clone --branch $CONSUL_MODULE https://github.com/hashicorp/terraform-azurerm-consul.git /tmp/terraform-consul-azure
/tmp/terraform-consul-azure/modules/install-consul/install-consul --version $CONSUL_VERSION
/tmp/terraform-consul-azure/modules/install-dnsmasq/install-dnsmasq

git clone --branch $VAULT_MODULE https://github.com/hashicorp/terraform-azurerm-vault.git /tmp/terraform-vault-azure
/tmp/terraform-vault-azure/modules/install-vault/install-vault --version $VAULT_VERSION
