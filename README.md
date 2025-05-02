# Lab 02: Shadow Admin Discovery Across AWS and Azure

[![tests](https://github.com/ChromeData/SkyArk-Shadow-Admin-Audit/actions/workflows/tests.yml/badge.svg)](https://github.com/ChromeData/SkyArk-Shadow-Admin-Audit/actions/workflows/tests.yml)

**Some accounts are not named "admin" but can turn themselves into admin. I plant six of them on purpose across AWS and Azure, run CyberArk's SkyArk to hunt them, and score what it catches against what I buried.**

| | |
|---|---|
| **Domains** | CyberArk/Idira, AWS, Azure |
| **Built on** | [cyberark/SkyArk](https://github.com/cyberark/SkyArk) (AWStealth + AzureStealth) |
| **Cost** | Under $2. **Runtime** ~5 hours |
| **Status** | Built, validated, not yet scanned |

## Situation

A shadow admin is an account that can quietly become admin. It might pass a role onto an admin, rewrite its own policy, or grant itself Owner in Azure. None of them are named admin. All of them are game over. Most people run SkyArk once against production, get a scary list, and never learn why each finding is dangerous.

## Task

Turn that scan into a graded test. If I know exactly what is planted, I can measure what the tool actually catches.

## Action

I built two cloud tenants with six escalation paths planted, each using one known trick and each looking harmless in a permission review:

| Principal | Trick | Looks like | Actually |
|---|---|---|---|
| passrole | PassRole + RunInstances | some EC2 access | launches an instance wearing the admin role |
| policyversion | CreatePolicyVersion | can list S3 buckets | rewrites its own policy to allow everything |
| attach | AttachUserPolicy | policy management | attaches full admin to itself |
| assumer | broad trust policy | a low access user | assumes admin through a loose trust |
| ops (Azure) | roleAssignments write | vm operations | grants itself Owner |
| graph app (Azure) | Directory.ReadWrite.All | a service principal | resets any user's credentials |

Then I wrote a scorer that diffs SkyArk's output against a ground truth file into three buckets: caught, missed, and extra.

## Result

The scoring core has 9 offline tests (no cloud, no SkyArk) because if the name matching is wrong, a real catch scores as a miss and the tool looks broken. CI runs the tests plus `terraform validate` on both clouds. Building it caught a duplicate data source that `terraform validate` flagged.

The missed bucket is the point. It is the gap between what a tool claims and what it does.

## Safety

This lab creates real escalation paths. The guardrails refuse to run in an Organizations management account or any account not on an explicit allowlist, and everything is tagged as intentionally insecure. Throwaway account only. `make destroy` when done.

## What I did not build

SkyArk is CyberArk's. The planted environment, the ground truth, the scorer, and the tests are mine.

## Run it

```bash
make deploy-aws
make deploy-azure
make scan
make score
make destroy
```

Needs Terraform 1.9+, PowerShell 7+, Python 3, AWS and Azure test tenants.

## Findings

`findings/scorecard.md` comes from `make score`. [LAB-NOTES.md](./LAB-NOTES.md) is the log.

## License

Lab code: MIT ([LICENSE](./LICENSE)). SkyArk stays MIT, credited above.
