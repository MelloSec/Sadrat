
data "archive_file" "function_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../ServerlessC2/"
  output_path = "${path.module}/sorrowsync.zip"
}


resource "azurerm_storage_account" "func" {
  name                     = var.storage_account_name
  resource_group_name      = var.resource_group
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_role_assignment" "func_kv_reader" {
  principal_id         = azurerm_linux_function_app.functionapp.identity[0].principal_id
  role_definition_name = "Key Vault Secrets User"
  scope                = azurerm_key_vault.vault.id
}

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  numeric  = true
  special = false
}

resource "azurerm_app_service_plan" "plan" {
  name                = "${var.func_name}${random_string.suffix.result}"
  location            = var.location
  resource_group_name = var.resource_group
  kind                = "Linux"
  reserved            = true

  sku {
    tier = "Basic" 
    size = "B1"    
  }
}


resource "azurerm_linux_function_app" "functionapp" {
  name                       = var.func_name
  location                   = var.location
  resource_group_name        = var.resource_group
  service_plan_id            = azurerm_app_service_plan.plan.id
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key
  depends_on                 = [azurerm_storage_account.func]
  zip_deploy_file = data.archive_file.function_zip.output_path
  
  app_settings = {
    FUNCTIONS_WORKER_RUNTIME = "dotnet"
  }

  

  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      dotnet_version = "6"
    }

    ip_restriction {
      ip_address = var.my_ip
    }

    # ip_restriction {
    #   service_tag = "AzureCloud"
    # }

    ip_restriction {
      ip_address = "0.0.0.0/0" # deny everyone else, Microsoft way of handling implicit deny is if the last rule is 0.0.0.0/0 it Denies everything else
    }
  }
}

