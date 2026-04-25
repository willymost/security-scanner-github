# Scripts Reference

Complete documentation for all scripts in the `security-scanner-github` project.

## Overview

```
scripts/
  setup-central-repo.sh        # One-time hub setup
  add-scanning-to-repo.sh      # Enable scanning on a target repo
  update-scanning-in-repo.sh   # Push workflow updates to a target repo
  remove-scanning-from-repo.sh # Disable scanning and clean up a target repo
  manage-semgrep-tokens.sh     # Set Semgrep App API tokens
  generate-reports.js          # Generate markdown reports from artifacts (JS version)
  central-repo/scripts/
    generate_report.py         # Generate markdown reports from findings (Python version)
```

All scripts read configuration from `.env` at the project root (created by `setup-central-repo.sh`). Environment variables passed on the command line override `.env` values.

---

## setup-central-repo.sh

**Purpose:** One-time setup of the central hub repository and the scanning token.

**What it does:**
1. Creates or initialises the hub repo (default: `<owner>/security-scans`)
2. Pushes the hub's `.github/workflows/validate.yml` for PR checks
3. Creates the `SECURITY_SCAN_TOKEN` PAT if not already provided
4. Provisions hub branch protection / default permissions
5. Writes resolved configuration to `.env` at the project root
6. Optionally adds scanning to specified source repos in one go

**Usage:**
```bash
GITHUB_TOKEN=<pat> ./scripts/setup-central-repo.sh [source-repo ...]
```

**Arguments:**
| Arg | Required | Description |
|-----|----------|-------------|
| `source-repo` | No | Repo **name** (not owner/repo) to enable scanning on immediately |

**Environment variables:**
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GITHUB_TOKEN` | Yes | — | PAT with repo scope for hub creation |
| `OWNER` | No | prompted | GitHub username or org |
| `HUB_NAME` | No | `security-scans` | Central hub repo name |
| `SECURITY_SCAN_TOKEN` | No | prompted | The PAT used by source repo workflows |

**Examples:**
```bash
# Interactive — prompts for OWNER and token
GITHUB_TOKEN=ghp_xxxx ./scripts/setup-central-repo.sh

# Non-interactive with all values supplied
OWNER=myorg HUB_NAME=sec-hub SECURITY_SCAN_TOKEN=ghp_yyy GITHUB_TOKEN=ghp_xxxx ./scripts/setup-central-repo.sh myapp myapi myweb

# Create hub only, add repos later
GITHUB_TOKEN=ghp_xxxx ./scripts/setup-central-repo.sh
./scripts/add-scanning-to-repo.sh myorg/myapp
```

**Requires:** `git`, `curl`, `jq`, GitHub CLI (`gh`) optional

---

## add-scanning-to-repo.sh

**Purpose:** Enable security scanning on a target repository.

**What it does:**
1. Copies `templates/security-scan.yml` to `.github/workflows/security-scan.yml` in the target repo
2. Sets the `SECURITY_SCAN_TOKEN` repository secret (used by the workflow to push results back)
3. Optionally sets `SEMGREP_APP_TOKEN` if provided
4. Opens a pull request with the workflow file on a `security-scanning-setup` branch

**Usage:**
```bash
GITHUB_TOKEN=<pat> ./scripts/add-scanning-to-repo.sh <owner/repo>
```

**Arguments:**
| Arg | Required | Description |
|-----|----------|-------------|
| `owner/repo` | Yes | Full GitHub repo identifier |

**Environment variables:**
| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_TOKEN` | from `.env` | PAT with Contents:Write, Pull-requests:Write, Secrets:Write |
| `SECURITY_SCAN_TOKEN` | from `.env` | Token pushed as a repo secret |
| `SEMGREP_APP_TOKEN` | — | Optional Semgrep token for SAST |
| `CENTRAL_HUB` | from `.env` | If set to `username/custom-hub`, overrides the hub repo name |

**Secrets set on target repo:**
| Secret | Value | Purpose |
|--------|-------|---------|
| `SECURITY_SCAN_TOKEN` | PAT | Used by workflow to push findings to central hub |
| `SEMGREP_APP_TOKEN` | (optional) | Semgrep SaaS API key for cloud rules |

**Examples:**
```bash
# Standard — uses .env config
./scripts/add-scanning-to-repo.sh myorg/myapp

# Override the hub for this repo only
CENTRAL_HUB=myorg/custom-hub ./scripts/add-scanning-to-repo.sh myorg/myapp

# Set a custom scan token for this repo
SECURITY_SCAN_TOKEN=ghp_custom ./scripts/add-scanning-to-repo.sh myorg/myapp
```

---

## update-scanning-in-repo.sh

**Purpose:** Push the latest workflow template to a repository that already has scanning enabled.

**What it does:**
1. Fetches latest `templates/security-scan.yml` from this project
2. Checks out the target repo, overwrites the workflow file
3. Opens (or re-opens) a pull request with the changes

**Usage:**
```bash
GITHUB_TOKEN=<pat> ./scripts/update-scanning-in-repo.sh <owner/repo>
```

**Arguments:**
| Arg | Required | Description |
|-----|----------|-------------|
| `owner/repo` | Yes | Full GitHub repo identifier |

**Environment variables:** Same as `add-scanning-to-repo.sh`

**Note:** This does **not** modify secrets — it only updates the workflow file. Use `add-scanning-to-repo.sh` if you also need to set or update secrets.

**Examples:**
```bash
./scripts/update-scanning-in-repo.sh myorg/myapp
./scripts/update-scanning-in-the-repo.sh myorg/api-service
```

---

## remove-scanning-from-repo.sh

**Purpose:** Completely remove security scanning from a repository.

**What it does:**
1. Deletes the `SECURITY_SCAN_TOKEN` secret from the target repo
2. Creates a pull request to delete `.github/workflows/security-scan.yml`
3. With `--purge-hub`: also removes all findings for this repo from the central hub

**Usage:**
```bash
GITHUB_TOKEN=<pat> ./scripts/remove-scanning-from-repo.sh <owner/repo> [--purge-hub]
```

**Arguments:**
| Arg | Required | Description |
|-----|----------|-------------|
| `owner/repo` | Yes | Full GitHub repo identifier |
| `--purge-hub` | No | Also delete all findings for this repo from the central hub |

**Requires:** `git`, `curl`, `jq`, `gh` CLI (recommended for secret deletion)

**Examples:**
```bash
# Remove workflow and secret only
./scripts/remove-scanning-from-repo.sh myorg/myapp

# Full cleanup including historical findings
./scripts/remove-scanning-from-repo.sh myorg/myapp --purge-hub
```

---

## manage-semgrep-tokens.sh

**Purpose:** Set or rotate the `SEMGREP_APP_TOKEN` secret on a target repository.

**What it does:**
1. Calls the GitHub Secrets API to set `SEMGREP_APP_TOKEN` on the target repo
2. Encrypts the token using libsodium (via `pynacl` or `gh secret`) for the repository

**Usage:**
```bash
GITHUB_TOKEN=<pat> ./scripts/manage-semgrep-tokens.sh <owner/repo> <semgrep-token>
```

**Arguments:**
| Arg | Required | Description |
|-----|----------|-------------|
| `owner/repo` | Yes | Full GitHub repo identifier |
| `semgrep-token` | Yes | The Semgrep App API token to store |

**Requires:** `curl`, `jq`, and either `gh` CLI or `python3` with `pynacl`

**Examples:**
```bash
./scripts/manage-semgrep-tokens.sh myorg/myapp sgp_abc123
./scripts/manage-semgrep-tokens.sh myorg/api-service "$SEMGREP_APP_TOKEN"
```

---

## generate-reports.js

**Purpose:** Generate consolidated markdown security reports from local scan artifacts.

**What it does:**
1. Reads raw scan output from `artifacts/` directory
2. Produces two markdown files:
   - `reports/{repo}/latest-security.md` — consolidated security findings (Semgrep SAST + SCA + Grype + Gitleaks)
   - `reports/{repo}/latest-sbom.md` — SBOM component inventory with vulnerability status

**Artifacts read from:**
```
artifacts/
  metadata.json
  semgrep-sast.json
  semgrep-sca.json
  grype-results.json
  gitleaks-report.json
  sbom.cyclonedx.json
```

**Usage:**
```bash
node scripts/generate-reports.js <central-repo-dir>
```

**Note:** This is the **local/in-repo** version of report generation. The workflow file includes an equivalent inline version that runs during CI.

---

## generate_report.py (central-repo/scripts/)

**Purpose:** Generate repository-level and cross-repo aggregate reports from stored findings.

**What it does:**
1. Walks `findings/{repo}/{date}/{run-id}/` directory tree
2. Produces:
   - `reports/latest.md` — cross-repo aggregate summary
   - `reports/{repo}/latest.md` — most recent run per repo
   - `reports/{repo}/{date}-{run-id-short}.md` — detailed report per upload

**Run from:** The root of the central hub repository.

**Usage:**
```bash
cd ~/code/security-scanner-github/central-repo
python3 scripts/generate_report.py
```

**Note:** This is a more comprehensive version than `generate-reports.js` — it operates on the full findings history rather than just the latest artifacts.

---

## Permissions Summary

| Script | Required GitHub PAT Permissions |
|--------|-------------------------------|
| `setup-central-repo.sh` | `repo` (full) |
| `add-scanning-to-repo.sh` | `repo` + `repo:secrets` |
| `update-scanning-in-repo.sh` | `repo` |
| `remove-scanning-from-repo.sh` | `repo` + `repo:secrets` |
| `manage-semgrep-tokens.sh` | `repo:secrets` |

A single `repo`-scoped PAT covers all scripts; `repo:secrets` is included in the `repo` scope.

---

## Configuration (.env)

After running `setup-central-repo.sh`, the `.env` file at the project root contains:

```
OWNER=<github-username>
HUB_NAME=security-scans
SECURITY_SCAN_TOKEN=ghp_xxxx
CENTRAL_HUB=<owner>/security-scans
```

All scripts source this file automatically. Override any value by passing it as an environment variable on the command line.
