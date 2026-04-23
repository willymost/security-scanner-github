# Security Scanning Templates

This repository provides GitHub Actions workflow templates and documentation for
automated security scanning across your personal repositories. It is the
**template library** — not the findings store.

## Architecture

```
┌── <your-username>/security-scanner-v1 (this repo) ─────────────┐
│  templates/security-scan.yml   ← copy to each source repo       │
│  docs/central-repo-setup.md    ← one-time hub setup guide       │
│  docs/add-scanning-to-repo.md  ← per-repo onboarding guide      │
└────────────────────────────────────────────────────────────────-┘
                    ↑ developers reference this repo

Source Repo A  ──┐
Source Repo B  ──┼──► (PAT push on merge) ──► <your-username>/security-scans
Source Repo C  ──┘                                ├── findings/
                                                  ├── reports/latest.md
                                                  └── .github/workflows/
```

## What Gets Scanned

| Tool | Type | Finds |
|------|------|-------|
| Semgrep SAST | Static Analysis | Code vulnerabilities, injection, insecure patterns |
| Semgrep SCA | Supply Chain Analysis | Vulnerable/reachable dependencies |
| Grype + Syft | Dependency Scanning | CVEs in dependencies, generates CycloneDX SBOM |
| Gitleaks | Secret Scanning | Hardcoded secrets, API keys, credentials in code and git history |

## Per-PR Behaviour

On every pull request the workflow posts a comment with a severity summary
table and, when any High or Critical findings exist, a per-tool detail section
listing exactly what was found and where — no manual review step needed.

**Summary table** (always present):

```
## 🟠 Security Scan Results

| Tool         | Critical | High | Medium | Low |
|--------------|----------|------|--------|-----|
| Semgrep SAST | 0        | 1    | 3      | 2   |
| Semgrep SCA  | 0        | 0    | 1      | 0   |
| Grype        | 0        | 2    | 1      | 4   |
| Gitleaks     | 0        | 1    | 0      | 0   |
| **Total**    | **0**    | **4**| **5**  | **6** |
```

**High & Critical Findings** (only when High/Critical findings exist):

```
### High & Critical Findings

#### Semgrep SAST
| Sev     | Rule            | File        | Line | Description                       |
|---------|-----------------|-------------|------|-----------------------------------|
| 🟠 HIGH | `sql-injection` | `app/db.py` | 42   | Unsanitised input passed to query |

#### Grype
| Sev     | CVE            | Package    | Version | Fixed In |
|---------|----------------|------------|---------|----------|
| 🟠 HIGH | CVE-2023-12345 | `requests` | 2.28.0  | 2.31.0   |

#### Gitleaks
| Rule               | File        | Line | Commit     | Description      |
|--------------------|-------------|------|------------|------------------|
| `aws-access-token` | `config.py` | 15   | `abc12345` | AWS Access Token |
```

Findings are pushed to the central hub only when code merges to `main`/`master`.
Each tool shows up to 20 rows in the PR comment; a link to the full Actions run
is provided when there are more.

## Quick Start

### Step 1 — Set up the central hub (once)

```bash
GITHUB_TOKEN=ghp_xxxx ./scripts/setup-central-repo.sh
```

Follow **[docs/central-repo-setup.md](docs/central-repo-setup.md)** for details.

### Step 2 — Add scanning to a repo

```bash
GITHUB_TOKEN=ghp_xxxx ./scripts/add-scanning-to-repo.sh <owner>/my-app
```

Follow **[docs/add-scanning-to-repo.md](docs/add-scanning-to-repo.md)** for details.

## Repository Layout

```
scripts/
  setup-central-repo.sh        ← creates the hub, provisions SECURITY_SCAN_TOKEN
  add-scanning-to-repo.sh      ← installs workflow + secret, opens add PR
  update-scanning-in-repo.sh   ← updates workflow to latest template, opens update PR
  remove-scanning-from-repo.sh ← removes workflow + secret, opens remove PR

templates/
  security-scan.yml          ← the workflow; installed by add-scanning-to-repo.sh

docs/
  central-repo-setup.md      ← hub setup reference
  add-scanning-to-repo.md    ← per-repo onboarding reference

central-repo/                ← files pushed into the security-scans hub by setup script
```

## Token Flow

```
setup-central-repo.sh
  → prompts for SECURITY_SCAN_TOKEN (browser UI — GitHub API cannot create PATs)
  → validates token against the hub
  → saves to .env (project root, gitignored)

add-scanning-to-repo.sh
  → reads SECURITY_SCAN_TOKEN from .env
  → sets it as a secret on the target repo automatically
  → opens PR

remove-scanning-from-repo.sh
  → deletes SECURITY_SCAN_TOKEN secret from the target repo immediately
  → opens PR to remove the workflow file
  → --purge-hub also deletes findings/{repo}/ from security-scans
```

## Notes on Severity

Semgrep community rules (`--config auto`) do not emit a CRITICAL severity level —
findings top out at HIGH. To unlock CRITICAL-tagged rules and more precise severity
metadata, add a `SEMGREP_APP_TOKEN` secret (from semgrep.dev) to the source repo.
