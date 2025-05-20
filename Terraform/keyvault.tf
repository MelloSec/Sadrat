data "azurerm_client_config" "current" {}

data "external" "my_ip" {
  program = ["powershell", "-Command", "(Invoke-RestMethod http://icanhazip.com).Trim() | ForEach-Object { @{ result = $_ } | ConvertTo-Json -Compress }"]
}

locals {
  my_ip = "${data.external.my_ip.result["result"]}/32"
}

resource "azurerm_key_vault" "vault" {
  name                        = var.vault_name
  location                    = azurerm_resource_group.rg.location
  resource_group_name         = azurerm_resource_group.rg.name
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

    # ip_rules = [var.my_ip]
    ip_rules = [local.my_ip]
  }
}
