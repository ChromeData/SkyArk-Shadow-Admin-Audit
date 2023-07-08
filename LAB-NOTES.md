# Lab Notes, 02 Shadow-Admin Discovery

Running log. Errors, dead ends, fixes, surprises. Dated, newest at the bottom.

---

## Format

```
### YYYY-MM-DD, what I was trying to do

**Expected:**
**Got:**
**Cause:**
**Fix:**
```

---

## Design decisions

### Name matching is substring-both-ways

SkyArk decorates names, "lab-shadow-passrole (IAM User)", or a full ARN. Exact
equality would score every real catch as a miss. Substring both ways handles it.
Limitation: single-character principal names would collide; real lab-shadow-*
names never do. Pinned by tests.

### Guardrails run before the vulnerable resources

The escalation paths are real. `guardrails.tf` uses lifecycle preconditions to
refuse an org management account and require an explicit account allowlist. A
lab that plants AttachUserPolicy self-grants must not run where it matters.

### The value is the MISSED list

A clean 6/6 catch is a fine result but a boring one. The interesting write-up is
any path SkyArk misses, and *why*, that's the sentence that shows judgement
rather than tool-operation.

---

## Known traps (confirm on first scan)

- **SkyArk column names drift between versions and between AWStealth/AzureStealth.**
  `score.py` searches for a name-like column and prints which one it used, check that line matches reality before trusting the score.
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

### 2026-08-12, first validate on the AWS tenant

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

### 2026-08-12, a test caught a real property of the matcher

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

### 2026-08-12, planted the paths for free, and found the baseline was unchecked

Added `use_localstack` and deployed all four AWS escalation paths against
LocalStack. 14 resources, no account, no cost.

**AWStealth still cannot run here.** It reads credentials from the SDK chain and
exposes no endpoint override, so it cannot be aimed at LocalStack. Scoring the
scanner remains a real-account job. Patching vendored SkyArk to inject an
endpoint was considered and dropped: it is upstream code whose behaviour is the
thing under test, and editing it to make the test run changes what the test
measures.

**But the more interesting gap was somewhere else.** `findings/ground-truth.yml`
is the baseline AWStealth gets scored against, and nothing in this lab had ever
checked it. If a path is described there but never deploys, or deploys under a
different principal name, or lacks the permission that makes it dangerous, every
score computed against it is wrong and nothing says so. The scoring baseline
deserves exactly the suspicion I have been applying to scanner output.

`scripts/verify_ground_truth.py` now checks it against live IAM, in both
directions: described-but-absent, and deployed-but-undescribed. The second
matters just as much, because an undocumented `lab-shadow-*` principal gets
scored as a false positive against a scanner that was actually right.

Result: 4/4 verified.

**And I ran the negative controls rather than trusting that.** Induced both
failure modes deliberately, confirmed each is caught with exit 1, confirmed the
clean case exits 0, and restored the file byte-for-byte. A verifier that cannot
fail is not a verifier, and after five tools in these labs reported success
while reading nothing, writing a sixth checker and trusting its green would have
been the least defensible thing here.

Detail in `findings/localstack-plant-run.txt`.

---

### 2026-08-12, exercised the escalation path against real AWS

LocalStack planted the paths and verified ground truth, but it evaluates no
policy at request time, so it could never answer the only question that matters:
does the path actually work. A permission string is not an escalation until
something escalates with it.

So I took the `attachuserpolicy` path end to end on a real account, using only
the shadow user's own key:

```
# as lab-shadow-attach, whose ONLY permission is iam:AttachUserPolicy
aws iam attach-user-policy --user-name lab-shadow-attach \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
# -> succeeded
# AttachedPolicies -> AdministratorAccess
```

A user with one innocuous-looking permission made itself a full administrator in
a single call. That is the entire thesis of the lab, demonstrated rather than
asserted: none of these users are named "admin", and an access review that greps
for `AdministratorAccess` misses every one of them.

Ground truth verified 4/4 against real IAM first.

**Cleanup needed care.** The self-granted admin was attached *outside* Terraform,
so `destroy` would not have known about it, and destroying a user with a managed
policy still attached fails. Detached it explicitly, confirmed no attached
policies remained, then destroyed. The temporary access key was deleted right
after the test. 14 resources destroyed, account verified empty.

**Cost: $0**, IAM only. AWStealth (the scanner) still needs a Windows/PowerShell
run, and the Azure half still needs a subscription. Full output in
`findings/real-aws-escalation-proven.txt`.

---
