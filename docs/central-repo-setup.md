# Central Hub Setup

Run **one script** to create and fully configure the `security-scans` hub repo.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| `git`, `curl`, `jq` | Standard CLI tools |
| `python3` | Needed only if adding source-repo secrets in the same run |
| `GITHUB_TOKEN` | Classic PAT with `repo` scope, or a fine-grained PAT with **Administration:Write + Contents:Write** (+ **Secrets:Write** on source repos if adding secrets in the same run) |

---

## Run the setup script

```bash
# Hub only — owner resolved automatically from the token
GITHUB_TOKEN=ghp_xxxx ./scripts/setup-central-repo.sh

# Hub + configure SECURITY_SCAN_TOKEN on source repos in one shot
GITHUB_TOKEN=ghp_xxxx ./scripts/setup-central-repo.sh <your-username> my-app my-api
```

List as many source repo names as you want. The script will prompt you to paste
the `SECURITY_SCAN_TOKEN` value mid-run (see below).

### What the script does

| Step | Action |
|------|--------|
| 1 | Creates `<your-username>/security-scans` on GitHub (private; skips if it exists) |
| 2 | Pushes the hub files from `central-repo/` (workflow, report script, directory layout) |
| 3 | Enables **Read and write** workflow permissions on the hub repo |
| 4 | Guides you through creating the narrow `SECURITY_SCAN_TOKEN` PAT, then encrypts and stores it on every source repo you named |

---

## The two tokens explained

| Token | Who uses it | Scope needed |
|-------|-------------|-------------|
| `GITHUB_TOKEN` (set in env before running the script) | The setup script — runs once | `repo` scope (classic) or Administration + Contents + Secrets (fine-grained) |
| `SECURITY_SCAN_TOKEN` (created during step 4) | Source-repo CI workflows on every scan | Contents:Write on `security-scans` only |

---

## Adding more source repos later

Re-run the script with additional repo names. It skips hub creation (already
exists) and goes straight to the secret step:

```bash
GITHUB_TOKEN=ghp_xxxx ./scripts/setup-central-repo.sh <your-username> new-repo
```

Or add the secret manually:
**Repo → Settings → Secrets and variables → Actions → New repository secret**
- Name: `SECURITY_SCAN_TOKEN`
- Value: the PAT created during initial setup

---

## After setup

Add the scanning workflow to each source repo:

```bash
GITHUB_TOKEN=ghp_xxxx ./scripts/add-scanning-to-repo.sh <your-username>/my-app
```

This opens a pull request. Merge it, and scans start running immediately.

---

## Token Rotation

When `SECURITY_SCAN_TOKEN` expires (1 year):

1. Generate a replacement at **GitHub → Settings → Developer settings →
   Personal access tokens → Fine-grained tokens**.
   Same settings: Contents:Write on `security-scans` only.
2. Re-run the setup script to update all source repos at once:
   ```bash
   GITHUB_TOKEN=ghp_xxxx ./scripts/setup-central-repo.sh <your-username> \
     my-app my-api other-repo
   ```
3. Delete the expired token from GitHub Developer Settings.
