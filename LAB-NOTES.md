# Lab Notes — SkyArk Shadow-Admin Audit

> Running log, newest first.

---

## Known traps (pre-seeded — confirm or replace with real entries)

### AzureStealth needs the right consent

The `Directory.ReadWrite.All` service principal (shadow admin #2) is only fully
live after the manual admin-consent step. Until then AzureStealth may not flag it
as reachable, which is itself a useful finding to note: the tool sees granted
permissions, not requested ones.

### AWStealth column names drift between versions

`score.py` searches for a name-like column rather than hardcoding one, and prints
which column it used. If scoring looks wrong, check that line first — the CSV
schema has changed across SkyArk releases.

### Read-only creds are enough

Run both scans with read-only credentials. If you find yourself reaching for write
access to make a scan work, stop — discovery tooling that needs write access is a
red flag, and noticing that instinct is part of the lab.

### The "extra" findings are the interesting ones

Anything SkyArk flags that you did not plant (`[EXTRA]` in the scorecard) is either
a real escalation path you created by accident, or a default account in the tenant.
Both are worth a paragraph. Do not just dismiss them as noise.

---

## YYYY-MM-DD — <first real entry>

**Goal:**

**What happened:**

```
```

**Why:**

**Fix:**

**Time lost:**

---

## Open questions

- [ ] Does AWStealth's "privileged" definition include indirect PassRole paths, or
      only direct policy grants?
- [ ] How do AWStealth and AzureStealth differ in what they call "shadow admin"?
- [ ] Which of the 6 planted paths would a standard CSPM (Prowler) also catch?
      Cross-reference with Lab 04.

## What I would do differently

_End._
