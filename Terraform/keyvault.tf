provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
  }
}

data "azurerm_client_config" "current" {}

data "external" "my_ip" {
  program = ["curl", "http://icanhazip.com"]
}

locals {
  my_ip = "${chomp(data.external.my_ip.result)}/32"
}


resource "azurerm_resource_group" "vault_rg" {
  name     = var.resource_group
  location = var.location
}

resource "azurerm_key_vault" "vault" {
  name                        = var.vault_name
  location                    = azurerm_resource_group.vault_rg.location
  resource_group_name         = azurerm_resource_group.vault_rg.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = ["Get"]
    secret_permissions = ["Get"]
    storage_permissions = ["Get"]
  }

  network_acls {
    bypass = "AzureServices"
    default_action = "Deny"

    ip_rules = [var.my_ip]
  }
}
