# Private Terraform Enterprise Base Images for Azure

Contains Packer template and scripts to install and create a hardened Ubuntu 16.04-LTS Azure VM image for Terraform Enterprise

## Required Environment Variables

| Environment Variable | Description                    |
|----------------------|--------------------------------|
| ARM_TENANT_ID        | Azure Tenant ID                |
| ARM_CLIENT_ID        | Azure Client/Application ID    |
| ARM_CLIENT_SECRET    | Azure Client/Application token |
| ARM_SUBSCRIPTION_ID  | Azure Subscription ID          |
| ARM_LOCATION         | Azure location abbreviation    |
| ARM_RESOURCE_GROUP   | Azure image resource group     |
