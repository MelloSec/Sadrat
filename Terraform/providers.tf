provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = false
    }
  }

  subscription_id = var.subscription_id
}

# provider "github" {
#   token = var.github_token
#   token = var.secret_values.ghToken
#   owner = var.github_owner
# }
