# Lab Notes — 02 Shadow-Admin Discovery

Running log. Errors, dead ends, fixes, surprises. Dated, newest at the bottom.

---

## Format

```
### YYYY-MM-DD — what I was trying to do

**Expected:**
**Got:**
**Cause:**
**Fix:**
```

---

## Design decisions

### Name matching is substring-both-ways

SkyArk decorates names — "lab-shadow-passrole (IAM User)", or a full ARN. Exact
equality would score every real catch as a miss. Substring both ways handles it.
Limitation: single-character principal names would collide; real lab-shadow-*
names never do. Pinned by tests.

### Guardrails run before the vulnerable resources

The escalation paths are real. `guardrails.tf` uses lifecycle preconditions to
refuse an org management account and require an explicit account allowlist. A
lab that plants AttachUserPolicy self-grants must not run where it matters.

### The value is the MISSED list

A clean 6/6 catch is a fine result but a boring one. The interesting write-up is
any path SkyArk misses, and *why* — that's the sentence that shows judgement
rather than tool-operation.

---

## Known traps (confirm on first scan)

- **SkyArk column names drift between versions and between AWStealth/AzureStealth.**
  `score.py` searches for a name-like column and prints which one it used —
  check that line matches reality before trusting the score.
- **The Azure graph app needs manual admin consent.** `lab-shadow-graph-app`
  isn't fully live until the consent step in the README is done. Until then it
  may not surface, which reads as a false miss.
- **PassRole path may need the instance profile to exist.** Confirm SkyArk flags
  the user on the permission alone, not only once an instance is running.

---

## Open questions

- [ ] Which of the six does SkyArk actually catch? Record verbatim labels.
- [ ] Does it rank the PassRole path as high as the direct AttachUserPolicy one?
- [ ] Any false positives from the benign-looking `lab-editable-policy`?
- [ ] Does AzureStealth see the graph app before admin consent?

---

## Log

### 2026-08-12 — first validate on the AWS tenant

**Expected:** clean.

**Got:**

```
Error: Duplicate data "aws_caller_identity" configuration
A aws_caller_identity data resource named "current" was already declared at
guardrails.tf:6,1-37. Resource names must be unique per type in each module.
```

**Cause:** I declared the caller-identity lookup in `main.tf` without noticing
`guardrails.tf` already had it.

**Fix:** Removed it from `main.tf` and left a comment pointing at `guardrails.tf`.
Deliberately kept it in the guardrails file rather than the other way round: that file
is the one that refuses to run in an org management account or an unallowlisted
account, and it should own the account lookup it gates on.

---

### 2026-08-12 — a test caught a real property of the matcher

**Expected:** the false-positive test to pass.

**Got:**

```
>       assert extra == ["mystery-admin"]
E       AssertionError: assert [] == ['mystery-admin']
```

**Cause:** I'd written the test with single-character principal names. Matching is
substring-both-ways (SkyArk decorates names, e.g. `lab-shadow-passrole (IAM User)` or
a full ARN), so `"a"` matches inside `"mystery-admin"` and the extra was swallowed.

**Fix:** Rewrote the test with realistic `lab-shadow-*` names, and documented the
limitation in the matcher's docstring: substring matching genuinely can't distinguish
very short names. It's a real constraint, not a bug, and real principal names never
hit it.

**Note:** exact-equality matching would be "safer" here and would be much worse. It
would score every decorated SkyArk hit as a miss and make the tool look broken. The
loose match is the correct trade.

Final run: **9 passed** (`findings/test-run.txt`).
