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
| Linear history | yes (no merge commits required; rebases/squash OK) |
| Force push | **blocked** |
| Delete branch | **blocked** |
| Conversation resolution | required before merge |
| Enforce for admins | **off** (owner can still push directly in emergencies) |
| Required PR reviews | **off** (solo-friendly; Dependabot can open PRs and you merge when CI is green) |

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
