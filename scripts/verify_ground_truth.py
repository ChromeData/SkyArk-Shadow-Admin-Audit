#!/usr/bin/env python3
"""Check that findings/ground-truth.yml matches what is actually deployed.

Ground truth is the baseline SkyArk gets scored against. Nothing in this lab
verified it. If a path is described there but never deploys, or deploys with a
different principal name, or is missing the permission that makes it dangerous,
then every score computed against it is wrong and the lab reports success while
measuring nothing.

That is the same failure this repo has now hit repeatedly: a number that looks
authoritative and was produced by reading the wrong thing. The scoring baseline
deserves the same suspicion as a scanner's zero.

Runs against LocalStack or a real account. It only reads IAM.

    AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
    python scripts/verify_ground_truth.py --endpoint http://localhost:4566
"""

import argparse
import sys
from pathlib import Path

import boto3
import yaml
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parent.parent


def client(endpoint):
    """IAM client. boto3 rather than shelling out to the CLI, so this runs
    anywhere Python does and does not depend on aws-cli being installed."""
    return boto3.client("iam", endpoint_url=endpoint)


def inline_policies(iam, user):
    out = {}
    try:
        names = iam.list_user_policies(UserName=user)["PolicyNames"]
    except ClientError:
        return out
    for n in names:
        out[n] = iam.get_user_policy(UserName=user, PolicyName=n)["PolicyDocument"]
    return out


def attached_policies(iam, user):
    try:
        return [p["PolicyArn"] for p in
                iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]]
    except ClientError:
        return []


def user_exists(iam, user):
    try:
        iam.get_user(UserName=user)
        return True
    except ClientError:
        return False


def actions_of(doc):
    """Flatten every Action string in a policy document."""
    acts = []
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for st in stmts:
        a = st.get("Action", [])
        acts.extend([a] if isinstance(a, str) else a)
    return [x.lower() for x in acts]


# The permission that makes each planted path dangerous. If the principal exists
# but lacks these, the path is not actually plantable and the ground-truth entry
# is describing something that is not there.
REQUIRED = {
    "passrole-ec2": ["iam:passrole", "ec2:runinstances"],
    "createpolicyversion": ["iam:createpolicyversion"],
    "attachuserpolicy": ["iam:attachuserpolicy"],
    "assumerole-broad-trust": ["sts:assumerole"],
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", default=None, help="e.g. http://localhost:4566")
    args = ap.parse_args()
    iam = client(args.endpoint)

    truth = yaml.safe_load((ROOT / "findings" / "ground-truth.yml").read_text(encoding="utf-8"))
    entries = truth.get("aws", [])

    print(f"Checking {len(entries)} planted AWS paths against live IAM\n")
    problems = []

    for e in entries:
        pid, principal = e["id"], e["principal"]
        if not user_exists(iam, principal):
            print(f"  MISSING   {pid:24} {principal} does not exist")
            problems.append(f"{pid}: principal {principal} not deployed")
            continue

        acts = []
        for doc in inline_policies(iam, principal).values():
            acts += actions_of(doc)
        attached = attached_policies(iam, principal)

        need = REQUIRED.get(pid, [])
        missing = [n for n in need
                   if not any(n == a or a == "*" or
                              (a.endswith("*") and n.startswith(a[:-1])) for a in acts)]

        if missing and not attached:
            print(f"  INCOMPLETE {pid:24} {principal} lacks {missing}")
            problems.append(f"{pid}: missing {missing}")
        else:
            extra = f", attached={len(attached)}" if attached else ""
            print(f"  OK        {pid:24} {principal} ({len(acts)} actions{extra})")

    # A path present in IAM that ground truth does not describe is just as bad:
    # SkyArk would flag it and the diff would call it a false positive.
    all_users = iam.list_users()
    lab_users = [u["UserName"] for u in all_users.get("Users", [])
                 if u["UserName"].startswith("lab-shadow-")]
    described = {e["principal"] for e in entries}
    undocumented = sorted(set(lab_users) - described)
    if undocumented:
        print(f"\n  UNDOCUMENTED principals deployed but absent from ground truth: {undocumented}")
        problems.append(f"undocumented principals: {undocumented}")

    print()
    if problems:
        print(f"{len(problems)} ground-truth problem(s). The scoring baseline is wrong.")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"Ground truth matches deployed IAM: {len(entries)}/{len(entries)} paths verified.")
    print("SkyArk scores computed against this baseline are measuring the right thing.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
