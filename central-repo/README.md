# Security Scans — Central Findings Hub

This repository aggregates automated security scan results from all repositories
in the account. It is populated by GitHub Actions workflows running in each
source repository.

## Architecture

```
Source Repo A  ──┐
Source Repo B  ──┼──► (PAT push on merge) ──► <your-username>/security-scans (this repo)
Source Repo C  ──┘                                ├── findings/
                                                  ├── reports/latest.md
                                                  └── .github/workflows/
```

## Viewing Results

| Where | What you'll find |
|-------|-----------------|
| `reports/latest.md` | Aggregated severity summary across all repos |
| `reports/summary-YYYY-MM-DD.md` | Dated report snapshots |
| `findings/{repo}/{date}/{run-id}/` | Raw scan output (SARIF + JSON) |
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
        grype-results.json     ← Grype vulnerability scan results (JSON)
        sbom.cyclonedx.json    ← Syft CycloneDX software bill of materials
        gitleaks-report.json   ← Gitleaks secret scan results (redacted)
        metadata.json          ← repo, branch, commit SHA, run URL, timestamp
```

## Report Generation

Reports are generated automatically:

- **Weekly**: every Monday at 06:00 UTC (after source scans run at 02:00 UTC)
- **On each new findings push**: triggered by the `findings/**` path filter
- **Manually**: Actions → Generate Security Report → Run workflow

## Onboarding New Repositories

See the `security-scanner-v1` repository in your account for the workflow template
and step-by-step setup guides.

## Severity Note

Semgrep community rules (`--config auto`, `--config p/supply-chain`) do not
produce CRITICAL-severity findings in SARIF — the maximum is HIGH. CRITICAL
findings appear only when source repos provide a `SEMGREP_APP_TOKEN` for Semgrep
Pro rules. Grype does produce CRITICAL findings for CVEs with CVSS ≥ 9.0.
