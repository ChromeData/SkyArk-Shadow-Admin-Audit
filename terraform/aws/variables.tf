# Variables for the AWS side of the shadow-admin lab.
# The guardrails in guardrails.tf refuse to apply unless the current account is
# explicitly allowlisted here — a deliberate speed bump in front of a config that
# creates real escalation paths.

variable "allowed_account_ids" {
  description = <<-EOT
    Account IDs where this lab is permitted to run. Has no default on purpose:
    you must name your throwaway account explicitly. An empty list means every
    apply fails the guardrail, which is the safe default.
  EOT
  type    = list(string)
  default = []
}

variable "skip_org_check" {
  description = <<-EOT
    Set true only if the throwaway account is standalone (not in an AWS
    Organization) and the org lookup would otherwise error. The management-account
    guardrail is skipped when true, so leave it false unless you know why.
  EOT
  type    = bool
  default = false
}
