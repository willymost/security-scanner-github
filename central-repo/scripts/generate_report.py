#!/usr/bin/env python3
"""
generate_report.py

Walks findings/{repo}/{date}/{run-id}/ and writes:
  reports/latest.md                          cross-repo aggregate summary
  reports/{repo}/latest.md                   most recent run for that repo
  reports/{repo}/{date}-{run-id-short}.md    one detailed report per upload

Run from the root of security-scans:
  python scripts/generate_report.py
"""

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SARIF_LEVEL_MAP = {"error": "HIGH", "warning": "MEDIUM", "note": "INFO", "none": "INFO"}
SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


def empty_counts():
    return {s: 0 for s in SEVERITIES}


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


# ---------------------------------------------------------------------------
# SARIF parsing — severity counts + structured findings
# ---------------------------------------------------------------------------

def _sarif_severity(result: dict, rules_by_id: dict) -> str:
    for source in (
        result.get("properties", {}),
        rules_by_id.get(result.get("ruleId", ""), {}).get("properties", {}),
    ):
        val = source.get("security-severity")
        if val is not None:
            try:
                return cvss_to_severity(float(val))
            except (TypeError, ValueError):
                pass
    rule = rules_by_id.get(result.get("ruleId", ""), {})
    for tag in rule.get("properties", {}).get("tags", []):
        if tag.upper() in SEVERITIES:
            return tag.upper()
    return SARIF_LEVEL_MAP.get((result.get("level") or "note").lower(), "INFO")


def parse_sarif(path: Path) -> dict:
    """Returns {'counts': {...}, 'findings': [...]}"""
    out = {"counts": empty_counts(), "findings": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return out
    for run in data.get("runs", []):
        rules_by_id = {
            r.get("id", ""): r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            sev = _sarif_severity(result, rules_by_id)
            out["counts"][sev] += 1
            rule = rules_by_id.get(result.get("ruleId", ""), {})
            loc = (result.get("locations") or [{}])[0]
            phys = loc.get("physicalLocation", {})
            region = phys.get("region", {})
            out["findings"].append({
                "rule_id":   result.get("ruleId", ""),
                "rule_name": rule.get("name") or rule.get("shortDescription", {}).get("text", ""),
                "severity":  sev,
                "path":      phys.get("artifactLocation", {}).get("uri", ""),
                "line":      region.get("startLine", ""),
                "col":       region.get("startColumn", ""),
                "message":   (result.get("message") or {}).get("text", ""),
                "help_uri":  rule.get("helpUri", ""),
                "tags":      rule.get("properties", {}).get("tags", []),
            })
    return out


# ---------------------------------------------------------------------------
# Semgrep JSON parsing — scanned file list + code snippets + CWE metadata
# ---------------------------------------------------------------------------

SEMGREP_SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def parse_semgrep_json(path: Path) -> dict:
    """Returns {'scanned': [...], 'snippet_map': {(path,line): snippet},
                 'meta_map': {rule_id: {...}}, 'counts': {...}, 'findings': [...]}
    """
    out = {"scanned": [], "snippet_map": {}, "meta_map": {},
           "counts": empty_counts(), "findings": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return out
    out["scanned"] = (data.get("paths") or {}).get("scanned") or []
    for r in data.get("results") or []:
        extra   = r.get("extra") or {}
        meta    = extra.get("metadata") or {}
        file_path = r.get("path", "")
        line      = (r.get("start") or {}).get("line", "")
        snippet   = (extra.get("lines") or "").strip()
        rule_id   = r.get("check_id", "")

        if snippet:
            out["snippet_map"][(file_path, line)] = snippet
        if rule_id and rule_id not in out["meta_map"]:
            out["meta_map"][rule_id] = {
                "cwe":   meta.get("cwe", ""),
                "owasp": meta.get("owasp", ""),
                "refs":  meta.get("references") or [],
                "tags":  extra.get("metadata", {}).get("tags") or [],
            }

        # Severity & finding
        sev = SEMGREP_SEVERITY_MAP.get(extra.get("severity", ""), "INFO")
        out["counts"][sev] += 1
        out["findings"].append({
            "rule_id":  rule_id,
            "rule_name": extra.get("message", ""),
            "severity":  sev,
            "path":      file_path,
            "line":      line,
            "col":       (r.get("start") or {}).get("col", ""),
            "message":   extra.get("message", ""),
            "help_uri":  (meta.get("references") or [""])[0] if meta.get("references") else "",
            "tags":      meta.get("tags") or [],
        })
    return out


# ---------------------------------------------------------------------------
# Gitleaks JSON parsing — secret / credential findings
# ---------------------------------------------------------------------------

def parse_gitleaks(path: Path) -> dict:
    """Returns {'counts': {...}, 'findings': [...]}"""
    out = {"counts": empty_counts(), "findings": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return out
    if not isinstance(data, list):
        return out
    for f in data:
        # All gitleaks findings are HIGH — exposed secrets are serious
        out["counts"]["HIGH"] += 1
        out["findings"].append({
            "rule_id":     f.get("RuleID", ""),
            "description": f.get("Description", ""),
            "file":        f.get("File", ""),
            "line":        f.get("StartLine", ""),
            "commit":      (f.get("Commit") or "")[:8],
            "author":      f.get("Author", ""),
            "date":        (f.get("Date") or "")[:10],
            "match":       f.get("Match", ""),
            "tags":        f.get("Tags") or [],
        })
    return out


# ---------------------------------------------------------------------------
# Grype JSON parsing — detailed vulnerability findings
# ---------------------------------------------------------------------------

def _grype_severity(raw: str) -> str:
    sev = (raw or "Unknown").upper()
    if sev in ("NEGLIGIBLE", "UNKNOWN"):
        sev = "INFO"
    if sev not in SEVERITIES:
        sev = "INFO"
    return sev


def parse_grype(path: Path) -> dict:
    """Returns {'counts': {...}, 'findings': [...]}"""
    out = {"counts": empty_counts(), "findings": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return out
    for m in data.get("matches") or []:
        vuln     = m.get("vulnerability") or {}
        artifact = m.get("artifact") or {}
        sev      = _grype_severity(vuln.get("severity", ""))
        out["counts"][sev] += 1
        fix = vuln.get("fix") or {}
        out["findings"].append({
            "cve_id":      vuln.get("id", ""),
            "severity":    sev,
            "package":     artifact.get("name", ""),
            "version":     artifact.get("version", ""),
            "pkg_type":    artifact.get("type", ""),
            "fixed_in":    ", ".join(fix.get("versions") or []) or "no fix available",
            "description": (vuln.get("description") or "").replace("\n", " "),
            "urls":        vuln.get("urls") or [],
            "locations":   [loc.get("path", "") for loc in (artifact.get("locations") or [])],
        })
    return out


def add_counts(a: dict, b: dict) -> dict:
    return {s: a.get(s, 0) + b.get(s, 0) for s in SEVERITIES}


# ---------------------------------------------------------------------------
# Findings collection
# ---------------------------------------------------------------------------

def collect_findings(findings_root: Path) -> dict:
    """
    Returns dict keyed by repo name.  Each value has:
      latest_date, scan_count, totals, runs: [per-run dicts with full detail]
    """
    repos = defaultdict(lambda: {
        "latest_date": "",
        "scan_count": 0,
        "totals": empty_counts(),
        "runs": [],
    })

    if not findings_root.exists():
        return repos

    for repo_dir in sorted(findings_root.iterdir()):
        if not repo_dir.is_dir():
            continue
        repo = repo_dir.name

        for date_dir in sorted(repo_dir.iterdir()):
            if not date_dir.is_dir():
                continue

            for run_dir in sorted(date_dir.iterdir()):
                if not run_dir.is_dir():
                    continue

                sast      = parse_semgrep_json(run_dir / "semgrep-sast.json") \
                    if (run_dir / "semgrep-sast.json").exists() \
                    else {"scanned": [], "snippet_map": {}, "meta_map": {}, "counts": empty_counts(), "findings": []}
                sca       = parse_semgrep_json(run_dir / "semgrep-sca.json") \
                    if (run_dir / "semgrep-sca.json").exists() \
                    else {"scanned": [], "snippet_map": {}, "meta_map": {}, "counts": empty_counts(), "findings": []}

                grype = parse_grype(run_dir / "grype-results.json") \
                    if (run_dir / "grype-results.json").exists() \
                    else {"counts": empty_counts(), "findings": []}

                gitleaks = parse_gitleaks(run_dir / "gitleaks-report.json") \
                    if (run_dir / "gitleaks-report.json").exists() \
                    else {"counts": empty_counts(), "findings": []}

                counts = add_counts(
                    add_counts(
                        add_counts(sast["counts"], sca["counts"]),
                        grype["counts"],
                    ),
                    gitleaks["counts"],
                )

                meta = {}
                meta_path = run_dir / "metadata.json"
                if meta_path.exists():
                    try:
                        meta = json.loads(meta_path.read_text(encoding="utf-8"))
                    except json.JSONDecodeError:
                        pass

                run_record = {
                    "date":              date_dir.name,
                    "run_id":            run_dir.name,
                    "counts":            counts,
                    "metadata":          meta,
                    "sast_findings":     sast["findings"],
                    "sast_scanned":      sast["scanned"],
                    "sast_snippets":     sast["snippet_map"],
                    "sast_meta":         sast["meta_map"],
                    "sca_findings":      sca["findings"],
                    "sca_scanned":       sca["scanned"],
                    "sca_snippets":      sca["snippet_map"],
                    "sca_meta":          sca["meta_map"],
                    "grype_findings":    grype["findings"],
                    "gitleaks_findings": gitleaks["findings"],
                }
                repos[repo]["runs"].append(run_record)
                repos[repo]["scan_count"] += 1
                repos[repo]["totals"] = add_counts(repos[repo]["totals"], counts)
                if date_dir.name > repos[repo]["latest_date"]:
                    repos[repo]["latest_date"] = date_dir.name

    return repos


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _badge(sev: str) -> str:
    return f"{SEV_ICON.get(sev, '')} {sev}"


def _truncate_path(p: str, max_len: int = 70) -> str:
    return ("…" + p[-(max_len - 1):]) if len(p) > max_len else p


def _render_semgrep_section(findings, scanned, snippets, meta_map, tool_label) -> list:
    lines = []
    n = len(findings)
    lines += [f"#### {tool_label} — {n} finding{'s' if n != 1 else ''}", ""]

    if scanned:
        lines += [
            f"<details><summary>Files scanned ({len(scanned)})</summary>",
            "", "```",
        ]
        lines += sorted(scanned)
        lines += ["```", "", "</details>", ""]
    else:
        lines += ["_Scanned file list not available._", ""]

    if not findings:
        lines += ["_No findings._", ""]
        return lines

    sev_order = {s: i for i, s in enumerate(SEVERITIES)}
    sorted_f = sorted(findings, key=lambda f: (sev_order.get(f["severity"], 99), f["path"], f["line"]))

    lines += [
        "| Severity | Rule | File | Line | Description |",
        "|----------|------|------|------|-------------|",
    ]
    for f in sorted_f:
        rule_id = f["rule_id"]
        short   = rule_id.split(".")[-1] if "." in rule_id else rule_id
        rule_cell = f"[`{short}`]({f['help_uri']})" if f.get("help_uri") else f"`{short}`"
        msg  = f["message"].replace("|", "\\|").replace("\n", " ")
        msg  = msg[:117] + "…" if len(msg) > 120 else msg
        path_cell = f"`{_truncate_path(f['path'])}`" if f["path"] else "—"
        lines.append(
            f"| {_badge(f['severity'])} | {rule_cell} | {path_cell} | {f['line'] or '—'} | {msg} |"
        )
    lines.append("")

    lines += ["<details><summary>Finding details</summary>", ""]
    for f in sorted_f:
        extra   = meta_map.get(f["rule_id"], {})
        snippet = snippets.get((f["path"], f["line"]), "")
        lines += ["---", ""]
        lines += [f"**{_badge(f['severity'])} `{f['rule_id']}`**", ""]
        if f["path"]:
            lines += [f"📄 `{f['path']}`" + (f"  line {f['line']}" if f["line"] else ""), ""]
        if f["message"]:
            lines += [f"> {f['message']}", ""]
        if extra.get("cwe"):
            lines += [f"  **CWE**: {extra['cwe']}", ""]
        if extra.get("owasp"):
            lines += [f"  **OWASP**: {extra['owasp']}", ""]
        if f.get("tags"):
            lines += ["  **Tags**: " + ", ".join(f"`{t}`" for t in f["tags"]), ""]
        if snippet:
            lines += ["```", snippet, "```", ""]
        if extra.get("refs"):
            lines += ["**References**: " + " · ".join(f"[link]({r})" for r in extra["refs"][:3]), ""]
    lines += ["</details>", ""]
    return lines


def _render_grype_section(findings: list) -> list:
    lines = []
    n = len(findings)
    lines += [f"#### Grype — {n} finding{'s' if n != 1 else ''}", ""]

    if not findings:
        lines += ["_No findings._", ""]
        return lines

    sev_order = {s: i for i, s in enumerate(SEVERITIES)}
    sorted_f  = sorted(findings, key=lambda f: (sev_order.get(f["severity"], 99), f["package"]))

    lines += [
        "| Severity | CVE | Package | Installed | Fixed In | Type |",
        "|----------|-----|---------|-----------|----------|------|",
    ]
    for f in sorted_f:
        url      = f["urls"][0] if f.get("urls") else ""
        cve_cell = f"[{f['cve_id']}]({url})" if url else f["cve_id"]
        lines.append(
            f"| {_badge(f['severity'])} | {cve_cell} | `{f['package']}` "
            f"| {f['version']} | {f['fixed_in']} | {f['pkg_type']} |"
        )
    lines.append("")

    lines += ["<details><summary>Vulnerability details</summary>", ""]
    for f in sorted_f:
        url   = f["urls"][0] if f.get("urls") else ""
        title = f"[{f['cve_id']}]({url})" if url else f["cve_id"]
        lines += ["---", ""]
        lines += [f"**{_badge(f['severity'])} {title}** — `{f['package']}` {f['version']}", ""]
        if f["description"]:
            desc = f["description"][:397] + "…" if len(f["description"]) > 400 else f["description"]
            lines += [f"> {desc}", ""]
        if f["fixed_in"] != "no fix available":
            lines += [f"✅ **Fix available**: upgrade to `{f['fixed_in']}`", ""]
        else:
            lines += ["⚠️ **No fix available**", ""]
        if f.get("locations"):
            lines += ["📄 Found in: " + ", ".join(f"`{loc}`" for loc in f["locations"][:5]), ""]
        if f.get("urls"):
            lines += ["**References**: " + " · ".join(f"[link]({u})" for u in f["urls"][:3]), ""]
        lines.append("")
    lines += ["</details>", ""]
    return lines


# ---------------------------------------------------------------------------
# Gitleaks rendering — secret / credential findings
# ---------------------------------------------------------------------------

def _render_gitleaks_section(findings: list) -> list:
    lines = []
    n = len(findings)
    lines += [f"#### Gitleaks — {n} secret{'s' if n != 1 else ''} detected", ""]

    if not findings:
        lines += ["_No secrets detected._", ""]
        return lines

    lines += [
        "| Rule | File | Line | Commit | Description |",
        "|------|------|------|--------|-------------|",
    ]
    for f in findings:
        file_cell   = f"`{_truncate_path(f['file'])}`" if f["file"] else "—"
        commit_cell = f"`{f['commit']}`" if f.get("commit") else "—"
        lines.append(
            f"| `{f['rule_id']}` | {file_cell} | {f['line'] or '—'} | {commit_cell} | {f['description']} |"
        )
    lines.append("")

    lines += ["<details><summary>Finding details</summary>", ""]
    for f in findings:
        lines += ["---", ""]
        lines += [f"**{_badge('HIGH')} `{f['rule_id']}`** — {f['description']}", ""]
        if f["file"]:
            lines += [f"📄 `{f['file']}`" + (f"  line {f['line']}" if f["line"] else ""), ""]
        if f.get("commit"):
            author_str = f" by {f['author']}" if f.get("author") else ""
            date_str   = f" on {f['date']}" if f.get("date") else ""
            lines += [f"🔖 Commit `{f['commit']}`{author_str}{date_str}", ""]
        if f.get("match"):
            lines += ["```", f["match"], "```", ""]
        if f.get("tags"):
            lines += ["**Tags**: " + ", ".join(f"`{t}`" for t in f["tags"]), ""]
        lines.append("")
    lines += ["</details>", ""]
    return lines


# ---------------------------------------------------------------------------
# Per-run report
# ---------------------------------------------------------------------------

def render_run_report(repo: str, run: dict, generated_at: str) -> str:
    c       = run["counts"]
    sha     = (run["metadata"].get("commit_sha") or "")[:8] or "unknown"
    run_url = run["metadata"].get("run_url", "")
    branch  = run["metadata"].get("branch", "unknown")
    run_id  = run["run_id"]
    run_link = f"[{run_id}]({run_url})" if run_url else run_id

    sev_parts   = [f"{c[s]} {s.lower()}" for s in SEVERITIES if c[s] > 0]
    sev_summary = " · ".join(sev_parts) if sev_parts else "no findings"
    total       = sum(c.values())

    lines = [
        f"# Security Scan — {repo}",
        "",
        f"**Date**: {run['date']}  ",
        f"**Run**: {run_link}  ",
        f"**Branch**: `{branch}`  ",
        f"**Commit**: `{sha}`  ",
        f"**Total findings**: {total} ({sev_summary})",
        "",
        "| Critical | High | Medium | Low | Info |",
        "|----------|------|--------|-----|------|",
        f"| **{c['CRITICAL']}** | **{c['HIGH']}** | **{c['MEDIUM']}** | **{c['LOW']}** | {c['INFO']} |",
        "",
        f"_Generated: {generated_at}_",
        "",
        "---",
        "",
    ]

    lines += _render_semgrep_section(
        run["sast_findings"], run["sast_scanned"],
        run["sast_snippets"], run["sast_meta"],
        "Semgrep SAST",
    )
    lines += _render_semgrep_section(
        run["sca_findings"], run["sca_scanned"],
        run["sca_snippets"], run["sca_meta"],
        "Semgrep SCA",
    )
    lines += _render_grype_section(run["grype_findings"])
    lines += _render_gitleaks_section(run["gitleaks_findings"])
    lines += ["---", f"_Generated by `scripts/generate_report.py` at {generated_at}_", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Aggregate summary report (cross-repo overview only — no per-finding detail)
# ---------------------------------------------------------------------------

def render_summary(repos: dict, generated_at: str) -> str:
    lines = [
        "# Security Scan Summary",
        "",
        f"**Generated**: {generated_at}",
        f"**Repositories tracked**: {len(repos)}",
        "",
    ]

    if not repos:
        lines.append("_No findings data yet. Ensure source repos are pushing to `findings/`._")
        return "\n".join(lines)

    grand = empty_counts()
    for info in repos.values():
        grand = add_counts(grand, info["totals"])

    lines += [
        "## Overall Totals",
        "",
        "| Critical | High | Medium | Low | Info |",
        "|----------|------|--------|-----|------|",
        f"| **{grand['CRITICAL']}** | **{grand['HIGH']}** | **{grand['MEDIUM']}** | **{grand['LOW']}** | {grand['INFO']} |",
        "",
        "## Findings by Repository",
        "",
        "| Repository | Last Scan | Scans | Critical | High | Medium | Low | Info | Report |",
        "|------------|-----------|-------|----------|------|--------|-----|------|--------|",
    ]
    for repo in sorted(repos):
        t      = repos[repo]["totals"]
        c_cell = f"**{t['CRITICAL']}**" if t["CRITICAL"] > 0 else str(t["CRITICAL"])
        h_cell = f"**{t['HIGH']}**"     if t["HIGH"]     > 0 else str(t["HIGH"])
        lines.append(
            f"| {repo} | {repos[repo]['latest_date']} | {repos[repo]['scan_count']} | "
            f"{c_cell} | {h_cell} | {t['MEDIUM']} | {t['LOW']} | {t['INFO']} "
            f"| [latest]({repo}/latest.md) |"
        )
    lines.append("")

    attn = [
        (r, v["totals"]["CRITICAL"], v["totals"]["HIGH"])
        for r, v in repos.items()
        if v["totals"]["CRITICAL"] > 0 or v["totals"]["HIGH"] > 0
    ]
    if attn:
        attn.sort(key=lambda x: (-x[1], -x[2]))
        lines += ["## Repositories Requiring Attention", ""]
        for repo, crits, highs in attn:
            lines.append(f"- **[{repo}]({repo}/latest.md)**: {crits} Critical, {highs} High")
        lines.append("")

    # Per-repo run index
    lines += ["## Scan History", ""]
    for repo in sorted(repos):
        runs = sorted(repos[repo]["runs"], key=lambda r: (r["date"], r["run_id"]), reverse=True)
        lines += [f"### {repo}", ""]
        lines += [
            "| Date | Run | Branch | Commit | Critical | High | Medium | Low | Info |",
            "|------|-----|--------|--------|----------|------|--------|-----|------|",
        ]
        for run in runs:
            c        = run["counts"]
            sha      = (run["metadata"].get("commit_sha") or "")[:8] or "—"
            branch   = run["metadata"].get("branch", "—")
            run_url  = run["metadata"].get("run_url", "")
            fname    = f"{run['date']}-{run['run_id'][:12]}.md"
            run_link = f"[{run['run_id'][:12]}]({repo}/{fname})"
            if run_url:
                run_link = f"[{run['run_id'][:12]}]({run_url}) ([report]({repo}/{fname}))"
            lines.append(
                f"| {run['date']} | {run_link} | `{branch}` | `{sha}` | "
                f"{c['CRITICAL']} | {c['HIGH']} | {c['MEDIUM']} | {c['LOW']} | {c['INFO']} |"
            )
        lines.append("")

    lines += ["---", f"_Generated by `scripts/generate_report.py` at {generated_at}_", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    root         = Path(__file__).resolve().parent.parent
    findings_root = root / "findings"
    reports_dir  = root / "reports"
    reports_dir.mkdir(exist_ok=True)

    now          = datetime.now(tz=timezone.utc)
    generated_at = now.strftime("%Y-%m-%d %H:%M UTC")

    print(f"Scanning: {findings_root}")
    repos = collect_findings(findings_root)
    print(f"Repositories found: {len(repos)}")

    written = 0

    for repo, info in repos.items():
        repo_dir = reports_dir / repo
        repo_dir.mkdir(exist_ok=True)

        latest_run = None
        for run in sorted(info["runs"], key=lambda r: (r["date"], r["run_id"])):
            report   = render_run_report(repo, run, generated_at)
            filename = f"{run['date']}-{run['run_id'][:12]}.md"
            (repo_dir / filename).write_text(report, encoding="utf-8")
            written += 1
            latest_run = run

        if latest_run:
            (repo_dir / "latest.md").write_text(
                render_run_report(repo, latest_run, generated_at),
                encoding="utf-8",
            )

    summary = render_summary(repos, generated_at)
    (reports_dir / "latest.md").write_text(summary, encoding="utf-8")

    print(f"Reports written: {written} run reports + {len(repos)} latest.md + reports/latest.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
