# Adding Security Scanning to a Repository

Follow these steps for **each repository** you want to scan.

**Prerequisite**: Complete [central-repo-setup.md](central-repo-setup.md) first
and ensure `SECURITY_SCAN_TOKEN` is available to this repo.

---

## Option A — Automated (recommended)

Run the onboarding script from the `security-scanner-v1` repo root. It clones the
target repo, installs the workflow, and opens a pull request:

```bash
GITHUB_TOKEN=ghp_xxxx ./scripts/add-scanning-to-repo.sh <owner>/my-app
```

`GITHUB_TOKEN` needs Contents:Write + Pull-requests:Write on the target repo.

The script automatically sets `CENTRAL_REPO` in the workflow to
`<owner>/security-scans`. Override the hub if yours has a different name:

```bash
CENTRAL_HUB=<owner>/my-security-hub \
GITHUB_TOKEN=ghp_xxxx \
  ./scripts/add-scanning-to-repo.sh <owner>/my-app
```

Review and merge the PR, then proceed to Step 2.

---

## Option B — Manual

1. Copy `templates/security-scan.yml` to `.github/workflows/security-scan.yml`
   in the target repo.
2. Edit the file and replace `__OWNER__` on the `CENTRAL_REPO` line with your
   GitHub username:
   ```yaml
   env:
     CENTRAL_REPO: your-username/security-scans
   ```
3. Commit and push.

---

## Step 2: Confirm the Secret Is Available

If you used an organization secret during hub setup, confirm this repo is in the
allowed list. If using per-repo secrets:

1. Go to **Repo → Settings → Secrets and variables → Actions**.
2. Confirm `SECURITY_SCAN_TOKEN` appears. If not, add it (value = the PAT from
   the hub setup guide).

---

## Step 3: Enable Code Scanning (for SARIF upload, optional)

The workflow uploads SARIF results to GitHub Code Scanning for per-finding
annotations on the Security tab.

- **Public repos**: Enabled by default, no action needed.
- **Private repos with GitHub Advanced Security (GHAS)**: Enable at
  **Settings → Security & analysis → Code scanning → Set up**.
- **Private repos without GHAS**: The `upload-sarif` steps already have
  `continue-on-error: true` so they fail gracefully. Findings still push to
  the central hub.

---

## Step 4: Trigger the First Scan

**Option A** — push any commit to `main` or `master`.

**Option B** — manual trigger:
1. Go to **Source Repo → Actions → Security Scan**.
2. Click **Run workflow → Run workflow**.

---

## Step 5: Verify

1. Watch the **Actions** run. All five jobs should pass:
   `semgrep-sast`, `semgrep-sca`, `sca`, `gitleaks`, `push-to-central`
   *(no `pr-annotation` on a push event — that only runs on PRs)*
2. In `<your-username>/security-scans`, check `findings/{repo}/` for a
   new directory.
3. Check `reports/{repo}/latest-security.md` and `reports/{repo}/latest-sbom.md`
   in the central hub for the generated markdown reports.
4. In the source repo, go to **Security → Code scanning alerts** to see
   per-finding detail (if SARIF upload is enabled).

---

## Pull Request Behaviour

When you open a PR, the workflow runs all four scans and posts a comment on the PR containing:

1. **Severity summary table** — counts per tool (Semgrep SAST, Semgrep SCA, Grype, Gitleaks)
2. **High & Critical Findings** — when any exist, a per-tool detail table showing:
   - *Semgrep SAST/SCA*: rule name, file path, line number, description
   - *Grype*: CVE ID, package name, installed version, fixed-in version
   - *Gitleaks*: rule ID, file path, line, commit SHA (short), description

Each tool shows up to 20 findings in the comment; a link to the full Actions run
is included when there are more.

Findings are **not** pushed to the central hub for PRs — only merges to
`main`/`master` trigger the central push.

PRs from forks cannot access repository secrets, so the annotation comment will
not appear for external contributors' PRs. This is a GitHub security restriction.

---

## SBOM Behaviour

The workflow generates a CycloneDX SBOM using Syft. Key details:

- **Syft excludes `.github/**` and `.git/**` directories** — this means GitHub
  Actions used by the repo (e.g. `actions/checkout`) are not catalogued as
  packages. Only actual software dependencies appear.
- **Syft scans `node_modules/`** but requires `package-lock.json` to detect npm
  packages. Without a lockfile, npm dependencies may be missing from the SBOM.
- **Python dependencies** need version pins (e.g. `requests==2.31.0`) in
  `requirements.txt` to be catalogued. Unpinned entries (`requests>=2.0`) are
  silently skipped (syft v1.43.0 limitation).
- **False positive cleanup**: If the repo contains an embedded Go binary (like
  `bin/syft`), the workflow removes Go toolchain dependencies from the SBOM.

---

## Customization

Edit `.github/workflows/security-scan.yml` in the source repo after installing:

| What to change | Location | Example |
|----------------|----------|---------|
| Semgrep rule set | `semgrep-sast` job | `--config p/owasp-top-ten` instead of `--config auto` |
| Additional SCA rules | `semgrep-sca` job | add `--config p/python` |
| Grype DB update | `sca` job | set `GRYPE_DB_AUTO_UPDATE=false` to pin DB |
| Gitleaks config file | `gitleaks` job | add `--config .gitleaks.toml` to allow-list false positives |
| Scan schedule | `on.schedule` | change cron expression |
| Branches scanned | `on.push.branches` | add `develop` |
| Enable Semgrep Pro rules | env section | add `SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}` |
| PR detail cap | each job's PR comment step | change `MAX_PER_TOOL` constant (default 20) |

---

## Removing a Repo from Scanning

1. Delete `.github/workflows/security-scan.yml` from the source repo.
2. Remove `SECURITY_SCAN_TOKEN` from the repo's secrets (if per-repo).
3. Optionally delete `findings/{repo}/` from the hub to stop that repo
   from appearing in reports. Use `./scripts/remove-scanning-from-repo.sh --purge-hub`.
