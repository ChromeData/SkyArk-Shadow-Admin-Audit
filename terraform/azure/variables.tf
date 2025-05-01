variable "tenant_domain" {
  description = "Your throwaway Entra tenant domain, e.g. labcontoso.onmicrosoft.com"
  type        = string
}

variable "throwaway_password" {
  description = <<-EOT
    Initial password for lab users. Passed via TF_VAR_throwaway_password, never
    committed. These are disposable accounts in a disposable tenant — but still
    do not hardcode it, because the muscle memory matters.
  EOT
  type        = string
  sensitive   = true
}
