# GitHub org & branch protection

## Current home

**https://github.com/radio-tracer/radio-tracer-java**

Transferred from `mayaba/radio-tracer-java` to org `radio-tracer`.

Local remote:

```bash
git remote set-url origin https://github.com/radio-tracer/radio-tracer-java.git
```

## Branch protection (`main`) — repo level

Applied on `main`:

| Rule | Setting |
|------|---------|
| Required status check | `Build & test (Java 25)` (CI workflow) |
| Require branch up to date before merge | yes (`strict`) |
| Require a pull request before merging | **yes** (0 approvals — solo-friendly) |
| Linear history | yes (squash/rebase OK) |
| Force push | **blocked** |
| Delete branch | **blocked** |
| Conversation resolution | required before merge |
| Enforce for admins | **on** (you cannot bypass; must use PR + green CI) |
| Required approving reviews | **0** (raise to 1 when you have collaborators) |

### Org-level rulesets

Not configured (needs `admin:org` API scope and org rulesets UI).  
For a free org, **repo-level** protection on `main` is the usual approach.

To tighten later (Settings → Branches / Rules):

- Require a pull request before merging  
- Require 1 approval (when you have collaborators)  
- Turn on **Do not allow bypassing the above settings** (enforce admins)

## Suggested workflow for changes

```text
git checkout -b feature/… 
# work, commit
git push -u origin HEAD
gh pr create
# wait for CI (Build & test Java 25)
gh pr merge --squash
```
