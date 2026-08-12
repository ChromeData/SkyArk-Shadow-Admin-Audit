#!/usr/bin/env python3
"""Score SkyArk output against the ground-truth manifest.

This is the analytical core of the lab. SkyArk tells you what it thinks is
privileged; ground-truth.yml records what you actually planted. The interesting
result is the diff:

  - true positives : planted AND caught
  - false negatives : planted, NOT caught   <- the finding worth writing about
  - false positives : caught, NOT planted   <- investigate each; some are real

Run after both scans. Reads findings/*-raw.csv and findings/ground-truth.yml,
prints a scorecard, and writes findings/scorecard.md.
"""

import csv
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml  # needed to read ground-truth.yml")

FINDINGS = Path(__file__).resolve().parent.parent / "findings"


def load_ground_truth():
    with open(FINDINGS / "ground-truth.yml") as f:
        return yaml.safe_load(f)


def load_scan(name):
    """Load a SkyArk CSV. Returns the set of principal names it flagged.

    SkyArk's column names differ between AWStealth and AzureStealth and have
    changed across versions — this deliberately searches for a name-like column
    rather than hardcoding one, and prints what it found so you can correct it.
    """
    path = FINDINGS / name
    if not path.exists():
        print(f"  (no {name} yet — run the scan)")
        return set()

    flagged = set()
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        cols = reader.fieldnames or []
        name_col = next(
            (c for c in cols if c and c.lower() in
             ("name", "username", "principalname", "displayname", "entityname")),
            cols[0] if cols else None,
        )
        print(f"  {name}: using column '{name_col}' from {cols}")
        for row in reader:
            if name_col and row.get(name_col):
                flagged.add(row[name_col].strip())
    return flagged


def match(principal, flagged):
    """A planted principal counts as caught if any flagged name contains it.

    Substring both ways because SkyArk decorates names: it may report
    "lab-shadow-passrole (IAM User)" or "arn:aws:iam::123:user/lab-shadow-passrole".
    An exact-equality check would score every real catch as a miss, which is the
    kind of bug that makes a tool look worse than it is. Kept as its own function
    so tests/ can pin this behaviour without a live scan.
    """
    return any(principal in f or f in principal for f in flagged)


def classify(planted, flagged):
    """Pure scoring core: split planted principals into caught vs missed and find
    extras. Returns (caught, missed, extra) as lists of names. No I/O, so the
    tests exercise exactly the logic the report depends on."""
    planted_names = [e["principal"] for e in planted]
    caught = [e for e in planted if match(e["principal"], flagged)]
    missed = [e for e in planted if not match(e["principal"], flagged)]
    extra = [f for f in flagged
             if not any(p in f or f in p for p in planted_names)]
    return caught, missed, extra


def score_cloud(cloud, entries, flagged):
    print(f"\n=== {cloud.upper()} ===")
    tp, fn, fp = classify(entries, flagged)
    for e in tp:
        print(f"  [CAUGHT ] {e['principal']:32} {e['technique']}")
    for e in fn:
        print(f"  [MISSED ] {e['principal']:32} {e['technique']}")
    for f in fp:
        print(f"  [EXTRA  ] {f}   <- not planted; investigate")
    return tp, fn, fp


def main():
    gt = load_ground_truth()
    print("Loading scans:")
    aws_flagged = load_scan("awstealth-raw.csv")
    az_flagged = load_scan("azurestealth-raw.csv")

    a_tp, a_fn, a_fp = score_cloud("aws", gt.get("aws", []), aws_flagged)
    z_tp, z_fn, z_fp = score_cloud("azure", gt.get("azure", []), az_flagged)

    planted = len(gt.get("aws", [])) + len(gt.get("azure", []))
    caught = len(a_tp) + len(z_tp)
    missed = len(a_fn) + len(z_fn)
    extra = len(a_fp) + len(z_fp)

    print("\n" + "=" * 40)
    print(f"  planted:         {planted}")
    print(f"  caught:          {caught}")
    print(f"  missed:          {missed}")
    print(f"  false positives: {extra}")
    print("=" * 40)

    lines = [
        "# SkyArk Scorecard\n",
        f"- **Planted:** {planted}",
        f"- **Caught:** {caught}",
        f"- **Missed:** {missed}",
        f"- **False positives:** {extra}\n",
        "## Missed (write about these)\n",
    ]
    for e in a_fn + z_fn:
        lines.append(f"- `{e['principal']}` — {e['technique']} — {e['why_dangerous'].strip()}")
    (FINDINGS / "scorecard.md").write_text("\n".join(lines) + "\n")
    print("\nWrote findings/scorecard.md")


if __name__ == "__main__":
    main()
