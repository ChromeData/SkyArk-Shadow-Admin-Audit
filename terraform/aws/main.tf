# ---------------------------------------------------------------------------
# DELIBERATELY VULNERABLE. Throwaway account only.
#
# Each principal below embeds one well-known IAM privilege-escalation primitive.
# The point is not that these are exotic — it is that none of them carry the word
# "admin", so an access review that greps for AdministratorAccess misses all of
# them, and SkyArk should not.
#
# Techniques modelled here map to the Rhino Security Labs IAM escalation taxonomy.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.9.0"
  required_providers {
    aws  = { source = "hashicorp/aws", version = "~> 5.60" }
    null = { source = "hashicorp/null", version = "~> 3.2" }
  }
}

provider "aws" {
  default_tags {
    tags = {
      Purpose = "security-lab"
      Lab     = "02-skyark-shadow-admin-audit"
      Danger  = "intentionally-insecure"
    }
  }
}

# aws_caller_identity.current lives in guardrails.tf, which runs first and
# refuses to apply in an org management account or any account not explicitly
# allowlisted. Referenced here, declared there.

# A genuinely privileged role, so the escalation paths have a target to reach.
resource "aws_iam_role" "real_admin" {
  name = "lab-real-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = data.aws_caller_identity.current.account_id }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "real_admin" {
  role       = aws_iam_role.real_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# -- Shadow admin #1: PassRole + RunInstances -------------------------------
# Can launch an EC2 instance with the admin role attached, then use the instance
# profile credentials. Looks like "some EC2 permissions." Is actually admin.
resource "aws_iam_user" "passrole" {
  name = "lab-shadow-passrole"
  tags = { Technique = "iam-passrole-ec2" }
}

resource "aws_iam_user_policy" "passrole" {
  name = "ec2-and-passrole"
  user = aws_iam_user.passrole.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ec2:RunInstances",
        "iam:PassRole",
        "iam:ListInstanceProfiles",
      ]
      Resource = "*"
    }]
  })
}

# -- Shadow admin #2: CreatePolicyVersion -----------------------------------
# Can write a new default version of a policy attached to a privileged principal.
# Rewrites its own permissions to *. Classic, still everywhere.
resource "aws_iam_user" "policyversion" {
  name = "lab-shadow-policyversion"
  tags = { Technique = "iam-createpolicyversion" }
}

resource "aws_iam_policy" "editable" {
  name = "lab-editable-policy"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "s3:ListAllMyBuckets", Resource = "*" }]
  })
}

resource "aws_iam_user_policy_attachment" "policyversion" {
  user       = aws_iam_user.policyversion.name
  policy_arn = aws_iam_policy.editable.arn
}

resource "aws_iam_user_policy" "policyversion_grant" {
  name = "can-edit-own-policy"
  user = aws_iam_user.policyversion.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"]
      Resource = aws_iam_policy.editable.arn
    }]
  })
}

# -- Shadow admin #3: AttachUserPolicy self-grant ---------------------------
# Can attach any managed policy to itself, including AdministratorAccess.
resource "aws_iam_user" "attach" {
  name = "lab-shadow-attach"
  tags = { Technique = "iam-attachuserpolicy" }
}

resource "aws_iam_user_policy" "attach" {
  name = "can-attach-policies"
  user = aws_iam_user.attach.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "iam:AttachUserPolicy"
      Resource = "*"
    }]
  })
}

# -- Shadow admin #4: over-permissive assume-role trust ---------------------
# A low-privilege user that can assume the admin role because the trust policy
# is scoped to the whole account instead of a specific principal.
resource "aws_iam_user" "assumer" {
  name = "lab-shadow-assumer"
  tags = { Technique = "sts-assumerole-broad-trust" }
}

resource "aws_iam_user_policy" "assumer" {
  name = "can-assume-admin"
  user = aws_iam_user.assumer.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.real_admin.arn
    }]
  })
}
