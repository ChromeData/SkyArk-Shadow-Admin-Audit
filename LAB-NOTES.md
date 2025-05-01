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

_(first entry goes here on the first real scan)_
