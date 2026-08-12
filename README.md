# Lab 02 — Shadow-Admin Discovery Across AWS + Azure

**Stand up two deliberately misconfigured cloud tenants, run CyberArk's SkyArk
against them, and analyse the privilege-escalation paths it surfaces — the
accounts that are effectively admin without being labelled admin.**

| | |
|---|---|
| **Domains** | CyberArk/Idira · AWS · Azure |
| **Built on** | [cyberark/SkyArk](https://github.com/cyberark/SkyArk) (MIT) — `AWStealth` + `AzureStealth` |
| **Runtime** | ~5 hours · < $2 in cloud spend (IAM/IdP objects are free; only the test EC2/VM cost) |
| **Status** | 🟡 In progress |

---

## Why this lab exists

"Shadow admin" is the account that can `iam:PassRole` onto an admin role, or holds
`iam:CreatePolicyVersion` on a policy attached to a privileged principal, or has
`Contributor` plus `Microsoft.Authorization/roleAssignments/write` in Azure. None
of them are named `admin`. All of them are game over. SkyArk exists to find them,
and most people run it once against production, get a scary list, and never build
the intuition for *why* each finding is dangerous.

This lab inverts that. You **build the misconfigurations yourself** as Terraform,
so you know exactly what the ground truth is, then run SkyArk and check whether it
catches what you planted — and whether it catches anything you did not intend.
That is the difference between running a tool and understanding it.

## What I built

- **`terraform/aws`** — a set of IAM principals seeded with classic escalation
  primitives: `PassRole` + `RunInstances`, `CreatePolicyVersion` on an attached
  managed policy, `AttachUserPolicy` self-grant, an over-permissive assume-role
  trust. Each is tagged with the escalation technique it represents.
- **`terraform/azure`** — Entra ID principals and role assignments modelling the
  Azure equivalents: a custom role that looks scoped but includes
  `roleAssignments/write`, a service principal with `Directory.ReadWrite.All`.
- **A ground-truth manifest** (`findings/ground-truth.yml`) listing every path I
  planted, so I can score SkyArk's output against it: true positives, and anything
  it missed.
- **A scoring script** that diffs SkyArk output against ground truth.

## What I did not build

SkyArk is CyberArk Labs' tool — I did not write the detection logic. My work is the
deliberately-vulnerable environment, the ground-truth manifest, the scoring, and
the write-up of which escalation classes the tool catches well and which it misses.

---

## ⚠ Safety

This lab **intentionally creates insecure IAM and Entra configurations.**

- Run it only in a **dedicated throwaway account / tenant.** Never an account with
  anything real in it.
- Every resource is tagged `Purpose=security-lab`. The teardown filters on that tag.
- Do not leave it running. `make destroy` when you finish the session.
- The trust policies here would be genuinely dangerous if internet-reachable
  principals could assume them. Keep the external IDs and account conditions intact.

---

## Running it

### Prerequisites

```bash
terraform >= 1.9
pwsh      >= 7.4      # SkyArk is PowerShell
az        >= 2.60     # Azure CLI
aws-cli   >= 2.15
git                    # to clone SkyArk
```

### Setup

```bash
make clone-skyark      # git clone cyberark/SkyArk into ./vendor (gitignored)
make aws-up            # plant the AWS escalation paths
make azure-up          # plant the Azure ones
```

### Run the scans

```bash
make scan-aws          # AWStealth  -> findings/awstealth-raw.csv
make scan-azure        # AzureStealth -> findings/azurestealth-raw.csv
make score             # diff against findings/ground-truth.yml
```

### Teardown

```bash
make destroy           # destroys both, filtered on Purpose=security-lab
```

---

## Findings

The deliverable. Suggested framing — score the tool, do not just repeat its output:

| Escalation path planted | Cloud | SkyArk caught it? | Notes |
|-------------------------|-------|-------------------|-------|
| PassRole + RunInstances | AWS | | |
| CreatePolicyVersion | AWS | | |
| AttachUserPolicy self-grant | AWS | | |
| roleAssignments/write in custom role | Azure | | |
| Directory.ReadWrite.All SP | Azure | | |

Then the analysis worth writing:
- **Coverage:** which escalation *classes* does it detect vs. miss?
- **False positives:** did it flag anything you did not plant? Were they real?
- **Cross-cloud:** does AWStealth's model of "privileged" match AzureStealth's, or
  are they measuring different things under the same banner?

## What broke

See [LAB-NOTES.md](./LAB-NOTES.md).

## What I would do differently

_End._
