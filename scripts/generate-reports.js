#!/usr/bin/env node
// Generate latest-security.md and latest-sbom.md in the central repo
// Run from the workspace root where artifacts/ exists
// Usage: node generate-reports.js <CENTRAL_REPO_DIR>

import fs from "fs";
import path from "path";

const centralRepoDir = process.argv[2] || "central-repo";
const now = new Date().toISOString();

// ── helpers ──
function load(p) {
  return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, "utf8")) : null;
}
const SEV = c => {
  const icons = { CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🔵", INFO: "⚪" };
  return (icons[c] || "⚪") + ` ${c}`;
};
const sevRank = s => ({ CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1, UNKNOWN: 0, NEGLIGIBLE: 0 }[s] || 0);
const safe = s => String(s).replace(/\|/g, "\\|");
const mkd = p => fs.mkdirSync(p, { recursive: true });

// ── load data ──
const meta     = load("artifacts/metadata.json");
const repo     = meta?.repository           || "unknown";
const commit   = meta?.commit_sha           || "unknown";
const branch   = meta?.branch               || "unknown";
const runUrl   = meta?.run_url              || "";
const event    = meta?.event                || "push";

const semSast  = load("artifacts/semgrep-sast/semgrep-sast.json");
const semSca   = load("artifacts/semgrep-sca/semgrep-sca.json");
const grype    = load("artifacts/sca/grype-results.json");
const gitleaks = load("artifacts/gitleaks/gitleaks-report.json");
const sbom     = load("artifacts/sca/sbom.cyclonedx.json");

const results  = arr => (arr?.results) || [];
const semap    = { ERROR: "HIGH", WARNING: "MEDIUM", INFO: "LOW" };

function sevCounts(resArr) {
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const r of resArr) {
    const s = semap[r.extra?.severity] || "INFO";
    c[s]++;
  }
  return c;
}

const sastC = sevCounts(results(semSast));
const scaC  = sevCounts(results(semSca));

const grypeArr = grype?.matches || [];
const gArr     = Array.isArray(gitleaks) ? gitleaks : [];

const grypeC = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
for (const m of grypeArr) {
  let s = (m.vulnerability?.severity || "unknown").toUpperCase();
  if (s === "NEGLIGIBLE" || s === "UNKNOWN") s = "INFO";
  if (grypeC[s] !== undefined) grypeC[s]++; else grypeC.INFO++;
}
const gC = { CRITICAL: 0, HIGH: gArr.length, MEDIUM: 0, LOW: 0, INFO: 0 };

const totalC = {};
for (const k of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
  totalC[k] = (sastC[k] || 0) + (scaC[k] || 0) + (grypeC[k] || 0) + (gC[k] || 0);
}

function findingsRow(label, c) {
  return `| ${label} | ${c.CRITICAL} | ${c.HIGH} | ${c.MEDIUM} | ${c.LOW} |`;
}

// ────────────────────────────────────────────────
// SECURITY REPORT
// ────────────────────────────────────────────────
let secLines = [];

if (Object.values(totalC).some(v => v > 0)) {
  const icon = totalC.CRITICAL > 0 ? "🔴" : totalC.HIGH > 0 ? "🟠" : totalC.MEDIUM > 0 ? "🟡" : "🟢";
  secLines.push(
    `## ${icon} Security Scan Results`,
    "",
    "| Tool | Critical | High | Medium | Low |",
    "|------|----------|------|--------|-----|",
    findingsRow("Semgrep SAST", sastC),
    findingsRow("Semgrep SCA", scaC),
    findingsRow("Grype", grypeC),
    findingsRow("Gitleaks", gC),
    `| **Total** | **${totalC.CRITICAL}** | **${totalC.HIGH}** | **${totalC.MEDIUM}** | **${totalC.LOW}** |`,
  );
} else {
  secLines.push("## 🟢 Security Scan Results — No Findings", "", "No vulnerabilities or secrets detected in this run.");
}

// Detail tables
const maxRows = 50;

function addSemgrepDetail(label, resArr) {
  const items = results(resArr).filter(r => {
    const s = semap[r.extra?.severity] || "INFO";
    return s === "HIGH" || s === "CRITICAL";
  });
  if (!items.length) return;
  secLines.push("\n### " + label + " — High / Critical");
  secLines.push("| Severity | Rule | File | Line |", "|----------|------|------|------|");
  for (const r of items.slice(0, maxRows)) {
    const extra = r.extra || {};
    secLines.push(`| ${SEV(semap[extra.severity] || "INFO")} | ${safe(r.check_id || "")} | ${safe(r.path || "-")} | ${r.start?.line || "-"} |`);
  }
  if (items.length > maxRows) secLines.push(`... and ${items.length - maxRows} more`);
}
addSemgrepDetail("Semgrep SAST", semSast);
addSemgrepDetail("Semgrep SCA", semSca);

// Grype vulns
const grypeItems = grypeArr.map(m => {
  const v = m.vulnerability || {};
  const a = m.artifact || {};
  const f = v.fix || {};
  let sev = (v.severity || "unknown").toUpperCase();
  if (sev === "NEGLIGIBLE" || sev === "UNKNOWN") sev = "INFO";
  return { sev, cve: v.id || "—", pkg: a.name || "—", ver: a.version || "—", fixed: (f.versions || []).join(", ") || "no fix" };
}).sort((a, b) => sevRank(b.sev) - sevRank(a.sev));

if (grypeItems.length) {
  secLines.push("\n### Grype — Vulnerable Dependencies");
  secLines.push("| Severity | CVE | Package | Version | Fixed In |", "|----------|-----|---------|---------|----------|");
  for (const f of grypeItems.slice(0, maxRows))
    secLines.push(`| ${SEV(f.sev)} | ${safe(f.cve)} | \`${safe(f.pkg)}\` | ${safe(f.ver)} | ${safe(f.fixed)} |`);
  if (grypeItems.length > maxRows) secLines.push(`... and ${grypeItems.length - maxRows} more`);
}

// Gitleaks
if (gArr.length) {
  secLines.push("\n### Gitleaks — Detected Secrets");
  secLines.push("| Rule | File | Line |", "|------|------|------|");
  for (const f of gArr.slice(0, maxRows))
    secLines.push(`| \`${safe(f.RuleID || "-")}\` | ${safe(f.File || "-")} | ${f.StartLine || "-"} |`);
  if (gArr.length > maxRows) secLines.push(`... and ${gArr.length - maxRows} more`);
}

const secHeader = [
  `# Security Report — ${safe(repo)}`,
  "",
  "| Field | Value |", "|-------|-------|",
  `| Repository | ${safe(repo)} |`,
  `| Branch | ${safe(branch)} |`,
  `| Commit | \`${commit}\` |`,
  `| Generated | ${now} |`,
  `| Run | [GitHub Actions](${runUrl}) |`,
  `| Report Type | security |`,
  "", "---",
].join("\n");

// Write security report
mkd(`${centralRepoDir}/reports/${repo}`);
fs.writeFileSync(`${centralRepoDir}/reports/${repo}/latest-security.md`, secHeader + "\n\n" + secLines.join("\n") + "\n");

// ────────────────────────────────────────────────
// SBOM REPORT
// ────────────────────────────────────────────────
let sbomLines = [];
const components = sbom?.components || [];

// By type
const byType = {};
for (const c of components) byType[c.type || "unknown"] = (byType[c.type || "unknown"] || 0) + 1;
const typeSummary = Object.entries(byType).sort((a, b) => b[1] - a[1]).map(([t, c]) => `  ${t}: ${c}`).join("\n");

sbomLines.push(
  `**${components.length} total components**`,
  `Vulnerable: ${grypeItems.length} · Clean: ${components.length - new Set(grypeItems.map(f => `${f.pkg}@${f.ver}`)).size}`,
  "",
  "By type:",
  typeSummary,
);

// Vuln table
if (grypeItems.length) {
  sbomLines.push("\n### 🟡 Vulnerable Dependencies");
  sbomLines.push("| Severity | Package | Version | CVE | Fixed In |", "|----------|---------|---------|-----|----------|");
  for (const f of grypeItems.slice(0, maxRows))
    sbomLines.push(`| ${SEV(f.sev)} | \`${safe(f.pkg)}\` | ${safe(f.ver)} | ${safe(f.cve)} | ${safe(f.fixed)} |`);
  if (grypeItems.length > maxRows) sbomLines.push(`... and ${grypeItems.length - maxRows} more`);
} else {
  sbomLines.push("\n✅ No vulnerable dependencies detected.");
}

// All components
const maxComp = 200;
const vulnKeys = new Set(grypeItems.map(f => `${f.pkg}@${f.ver}`));
sbomLines.push("\n### All Components");
sbomLines.push("| Component | Version | Type | Status |", "|-----------|---------|------|--------|");
for (const c of components.sort((a, b) => (a.name || "").localeCompare(b.name || "")).slice(0, maxComp)) {
  const key = `${c.name || ""}@${c.version || ""}`;
  const flag = vulnKeys.has(key) ? SEV("HIGH") : "✅";
  sbomLines.push(`| \`${safe(c.name || "-")}\` | ${safe(c.version || "-")} | ${safe(c.type || "-")} | ${flag} |`);
}
if (components.length > maxComp) sbomLines.push(`... and ${components.length - maxComp} more`);

const sbomHeader = [
  `# SBOM Report — ${safe(repo)}`,
  "",
  "| Field | Value |", "|-------|-------|",
  `| Repository | ${safe(repo)} |`,
  `| Branch | ${safe(branch)} |`,
  `| Commit | \`${commit}\` |`,
  `| Generated | ${now} |`,
  `| Run | [GitHub Actions](${runUrl}) |`,
  `| Report Type | sbom |`,
  "", "---",
].join("\n");

fs.writeFileSync(`${centralRepoDir}/reports/${repo}/latest-sbom.md`, sbomHeader + "\n\n" + sbomLines.join("\n") + "\n");

console.log(`Reports generated: reports/${repo}/latest-security.md, latest-sbom.md`);
