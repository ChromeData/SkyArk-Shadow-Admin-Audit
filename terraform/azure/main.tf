# ---------------------------------------------------------------------------
# DELIBERATELY VULNERABLE. Throwaway Entra tenant + subscription only.
#
# Azure escalation is less about "iam:*" primitives and more about the split
# between the Azure control plane (RBAC on resources) and Entra ID (directory
# roles + Graph app permissions). The dangerous accounts live in the seam.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.9.0"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
    azuread = { source = "hashicorp/azuread", version = "~> 3.0" }
  }
}

provider "azurerm" {
  features {}
}
provider "azuread" {}

data "azurerm_subscription" "current" {}
data "azuread_client_config" "current" {}

# -- Shadow admin #1: custom role that hides roleAssignments/write ----------
# Named to look like a scoped operations role. Actually lets the holder grant
# themselves Owner, because it can write role assignments.
resource "azurerm_role_definition" "sneaky_ops" {
  name        = "lab-vm-operations"
  scope       = data.azurerm_subscription.current.id
  description = "Looks like VM ops. Includes roleAssignments/write. This is the trap."

  permissions {
    actions = [
      "Microsoft.Compute/virtualMachines/*",
      "Microsoft.Authorization/roleAssignments/write", # <-- the escalation
      "Microsoft.Authorization/roleAssignments/read",
    ]
    not_actions = []
  }

  assignable_scopes = [data.azurerm_subscription.current.id]
}

resource "azuread_user" "ops" {
  user_principal_name = "lab-shadow-ops@${var.tenant_domain}"
  display_name        = "Lab Shadow Ops"
  password            = var.throwaway_password
}

resource "azurerm_role_assignment" "ops" {
  scope              = data.azurerm_subscription.current.id
  role_definition_id = azurerm_role_definition.sneaky_ops.role_definition_resource_id
  principal_id       = azuread_user.ops.object_id
}

# -- Shadow admin #2: service principal with Directory.ReadWrite.All --------
# An app registration that can rewrite the directory — add members to privileged
# groups, reset credentials. A very common real-world finding.
resource "azuread_application" "overprivileged" {
  display_name = "lab-shadow-graph-app"
}

resource "azuread_service_principal" "overprivileged" {
  client_id = azuread_application.overprivileged.client_id
}

# Note: granting Graph app roles requires admin consent and the well-known Graph
# app role IDs. Left as a documented manual step in the README rather than
# auto-consented, because auto-granting Directory.ReadWrite.All in code is exactly
# the reflex this lab is teaching you to distrust.
#   az ad app permission add ...
#   az ad app permission admin-consent ...

# -- Shadow admin #3: Contributor + a group that grants more ----------------
resource "azuread_group" "priv_group" {
  display_name     = "lab-privileged-group"
  security_enabled = true
}

resource "azuread_user" "group_member" {
  user_principal_name = "lab-shadow-groupmember@${var.tenant_domain}"
  display_name        = "Lab Shadow Group Member"
  password            = var.throwaway_password
}

resource "azuread_group_member" "member" {
  group_object_id  = azuread_group.priv_group.object_id
  member_object_id = azuread_user.group_member.object_id
}
