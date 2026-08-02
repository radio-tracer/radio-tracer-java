# Move repo to `radio-tracer` organization

## 1. Create the organization (one-time, browser)

1. Open https://github.com/account/organizations/new  
2. Choose **Free** plan  
3. Organization name: **`radio-tracer`**  
4. Complete creation (you become owner)

CLI cannot create personal orgs without interactive OAuth + `admin:org` scopes.

## 2. Transfer this repository

**Option A — UI**

1. https://github.com/mayaba/radio-tracer-java/settings  
2. Scroll to **Danger Zone** → **Transfer ownership**  
3. New owner: `radio-tracer`  
4. Type the repo name to confirm  

**Option B — CLI** (after org exists and token has access)

```bash
gh auth refresh -h github.com -s admin:org,repo,workflow
gh api -X POST repos/mayaba/radio-tracer-java/transfer -f new_owner=radio-tracer
```

New URL: https://github.com/radio-tracer/radio-tracer-java

## 3. Update local remote

```bash
cd /path/to/radio-tracer-java
git remote set-url origin https://github.com/radio-tracer/radio-tracer-java.git
git fetch origin
git branch -u origin/main main
```

## 4. Optional: GitHub Project board

```bash
gh project create --owner radio-tracer --title "RadioTracer"
```

Link the `radio-tracer-java` repo in the project UI.
