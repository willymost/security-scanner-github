# Security Scans — Central Findings Hub

This repository aggregates automated security scan results from all repositories
in the account. It is populated by GitHub Actions workflows running in each
source repository.

## Architecture

```
Source Repo A  ──┐
Source Repo B  ──┼──► (PAT push on merge) ──► <your-username>/security-scans (this repo)
Source Repo C  ──┘                                ├── findings/
                                                  │   └── {repo}/
                                                  │       └── {YYYY-MM-DD}/
                                                  │           └── {run-id}/
                                                  ├── reports/
                                                  │   └── {repo}/
                                                  │       ├── latest-security.md
                                                  │       └── latest-sbom.md
                                                  └── .github/workflows/
```

## Viewing Results

| Where | What you'll find |
|-------|-----------------|
| `findings/{repo}/{date}/{run-id}/` | Raw scan output (SARIF + JSON + markdown reports) |
| `reports/{repo}/latest-security.md` | Consolidated security report for a repo (updated each run) |
| `reports/{repo}/latest-sbom.md` | SBOM summary for a repo (updated each run) |
| Source repo → Security → Code scanning | Per-finding annotations with line numbers |

## Findings Structure

```
findings/
  {repo-name}/
    {YYYY-MM-DD}/
      {github-run-id}/
        semgrep-sast.sarif     ← Semgrep SAST findings (SARIF format)
        semgrep-sast.json      ← Semgrep SAST findings (JSON format)
        semgrep-sca.sarif      ← Semgrep SCA findings  (SARIF format)
        semgrep-sca.json       ← Semgrep SCA findings  (JSON format)
        sbom.cyclonedx.json    ← Syft CycloneDX software bill of materials
        grype-results.json     ← Grype vulnerability scan results
        gitleaks-report.json   ← Gitleaks secret scan results (redacted)
        security.md            ← Consolidated markdown security report
        sbom.md                ← Summary of SBOM contents
        metadata.json          ← repo, branch, commit SHA, run URL, timestamp
```

## Report Generation

Reports are generated automatically:

- **On each new findings push**: triggered by the `findings/**` path filter in the hub workflow
- **Manually**: Actions → Generate Security Report → Run workflow

Each run creates reports in both locations:
- `findings/{repo}/{date}/{run-id}/security.md` and `sbom.md`
- `reports/{repo}/latest-security.md` and `latest-sbom.md` (updated copy)

### Security Report Format

- Severity summary table (counts per tool: Semgrep SAST, Semgrep SCA, Grype, Gitleaks)
- Per-tool sections with collapsible `<details>` for individual findings
- Up to 20 findings per tool in each section

### SBOM Report Format

- Total component count and direct dependency count (from SBOM metadata)
- Direct dependencies (components with no dependents in BOM)
- License summary (unique licenses sorted by frequency)

## Onboarding New Repositories

See the `security-scanner-v1` repository in your account for the workflow template
and step-by-step setup guides.

## Severity Note

Semgrep community rules (`--config auto`, `--config p/supply-chain`) do not
produce CRITICAL-severity findings in SARIF — the maximum is HIGH. CRITICAL
findings appear only when source repos provide a `SEMGREP_APP_TOKEN` for Semgrep
Pro rules. Grype does produce CRITICAL findings for CVEs with CVSS ≥ 9.0.
