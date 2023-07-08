# Refuse to run anywhere that looks like it matters.
#
# This lab creates real privilege-escalation paths. The guardrail is cheap and the
# failure mode it prevents is career-defining, so it runs before anything else.

data "aws_caller_identity" "current" {}
data "aws_organizations_organization" "current" {
  count = var.skip_org_check ? 0 : 1
}

locals {
  in_an_org = var.skip_org_check ? false : length(data.aws_organizations_organization.current) > 0
  is_mgmt_account = local.in_an_org ? (
    data.aws_organizations_organization.current[0].master_account_id == data.aws_caller_identity.current.account_id
  ) : false
}

resource "null_resource" "guardrail_not_management_account" {
  lifecycle {
    precondition {
      condition     = !local.is_mgmt_account
      error_message = "This is an AWS Organizations MANAGEMENT account. Absolutely not. Use a throwaway."
    }
  }
}

resource "null_resource" "guardrail_account_allowlist" {
  lifecycle {
    precondition {
      condition     = contains(var.allowed_account_ids, data.aws_caller_identity.current.account_id)
      error_message = "Current account is not in allowed_account_ids. Add it explicitly, no accidental applies."
    }
  }
}
