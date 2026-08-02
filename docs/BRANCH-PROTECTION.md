# Branch protection (`main`)

Configured via **repository ruleset** `main-protection` (not classic branch protection).

## Rules (everyone except bypass actors)

1. **Pull request required** before merging into `main`
2. **At least 1 approving review**
3. **Code owner review required** — approval must come from [@radio-tracer/approvers](https://github.com/orgs/radio-tracer/teams/approvers) (whitelist)
4. **You cannot approve your own PR** (GitHub platform rule)
5. **Status check** must pass: `Build & test (Java 25)`
6. Branch must be **up to date** with `main` before merge
7. **No force-push** to `main`; **no deleting** `main`
8. Review threads must be resolved

## Exception (you)

**@mayaba** is a ruleset **bypass actor** (`always`):

- Can merge/push without waiting for another approver when needed
- Still should use PRs + CI for normal work
- Use bypass sparingly (e.g. emergency, solo bootstrapping)

## Managing the whitelist

Add or remove reviewers:

1. https://github.com/orgs/radio-tracer/teams/approvers  
2. Members of that team are the only ones whose approval satisfies **code owner** review  
3. File: [`.github/CODEOWNERS`](../.github/CODEOWNERS)

## Normal contributor flow

```bash
git checkout -b feature/…
git push -u origin HEAD
gh pr create
# wait for CI
# get approval from @radio-tracer/approvers (not yourself)
gh pr merge --squash
```
