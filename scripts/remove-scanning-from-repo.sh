#!/usr/bin/env bash
# remove-scanning-from-repo.sh
#
# Removes all security scanning artifacts from a repository:
#   - Deletes the SECURITY_SCAN_TOKEN secret immediately
#   - Creates a pull request to remove .github/workflows/security-scan.yml
#   - Optionally purges this repo's findings from the central hub
#
# Usage:
#   GITHUB_TOKEN=<pat> ./scripts/remove-scanning-from-repo.sh <owner/repo> [--purge-hub]
#
# Configuration is read from .env at the project root (created by
# setup-central-repo.sh).  Explicit environment variables override .env.
#
# Requirements:
#   - git, curl, jq installed
#   - gh CLI (recommended, brew install gh) OR just curl/jq for secret deletion
#   - GITHUB_TOKEN: PAT with Contents:Write + Pull-requests:Write + Secrets:Write
#     on the target repository (Secrets:Write needed to remove the secret)
#
# Examples:
#   GITHUB_TOKEN=ghp_xxxx ./scripts/remove-scanning-from-repo.sh alice/my-app
#   GITHUB_TOKEN=ghp_xxxx ./scripts/remove-scanning-from-repo.sh alice/my-app --purge-hub

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Load .env (created by setup-central-repo.sh)
# ---------------------------------------------------------------------------
ENV_FILE="${REPO_ROOT}/.env"
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

GITHUB_API="https://api.github.com"
WORKFLOW_PATH=".github/workflows/security-scan.yml"
BRANCH="remove-security-scanning-$(date -u +%Y%m%d%H%M%S)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
die()  { echo "Error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

usage() {
  cat >&2 <<EOF

Usage: GITHUB_TOKEN=<pat> $0 <owner/repo> [--purge-hub]

  Removes the security scanning workflow and secret from a repository.

  Arguments:
    <owner/repo>   Target repository, e.g. alice/my-app
    --purge-hub    Also delete findings/{repo}/ from the central hub

  Environment:
    GITHUB_TOKEN   PAT with Contents:Write + Pull-requests:Write + Secrets:Write
    HUB_TOKEN      PAT for hub write access when using --purge-hub (falls back
                   to SECURITY_SCAN_TOKEN from .env, then GITHUB_TOKEN)

  Example:
    GITHUB_TOKEN=ghp_xxxx $0 alice/my-app --purge-hub

EOF
  exit 1
}

gh_api() {
  local token="$1" method="$2" path="$3" body="${4:-}"
  local args=(-sf -X "$method"
    -H "Authorization: Bearer ${token}"
    -H "Accept: application/vnd.github+json"
    -H "X-GitHub-Api-Version: 2022-11-28"
    "${GITHUB_API}${path}")
  [[ -n "$body" ]] && args+=(-d "$body")
  curl "${args[@]}"
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
[[ $# -lt 1 ]] && usage

for cmd in git curl jq; do
  command -v "$cmd" &>/dev/null || die "'$cmd' is not installed — please install it and retry."
done
[[ -n "${GITHUB_TOKEN:-}" ]] || die "GITHUB_TOKEN is not set."

TARGET_REPO=""
PURGE_HUB=false
for arg in "$@"; do
  case "$arg" in
    --purge-hub) PURGE_HUB=true ;;
    --help|-h)   usage ;;
    *)
      [[ -z "$TARGET_REPO" ]] || die "Unexpected argument: ${arg}"
      TARGET_REPO="$arg"
      ;;
  esac
done

[[ -n "$TARGET_REPO" ]]       || usage
[[ "$TARGET_REPO" == */* ]]   || die "repo must be in owner/repo format, e.g. alice/my-app"

OWNER_TARGET="${TARGET_REPO%%/*}"
REPO="${TARGET_REPO##*/}"
CENTRAL_OWNER="${OWNER:-$OWNER_TARGET}"
CENTRAL_HUB="${CENTRAL_HUB:-${CENTRAL_OWNER}/security-scans}"
OWNER="${OWNER:-$OWNER_TARGET}"
CLONE_URL="https://x-access-token:${GITHUB_TOKEN}@github.com/${TARGET_REPO}.git"

# Resolve hub token for --purge-hub
HUB_TOKEN="${HUB_TOKEN:-}"
if [[ -z "$HUB_TOKEN" ]]; then
  # Try SECURITY_SCAN_TOKEN from .env first
  HUB_TOKEN="${SECURITY_SCAN_TOKEN:-}"
fi
if [[ -z "$HUB_TOKEN" ]]; then
  HUB_TOKEN="$GITHUB_TOKEN"
fi

info "Target:      ${TARGET_REPO}"
info "Central hub: ${CENTRAL_HUB}"
$PURGE_HUB && info "Hub purge:   yes — findings/${REPO}/ will be deleted from ${CENTRAL_HUB}"

# Confirm before proceeding
echo
printf "This will remove scanning from %s. Continue? [y/N]: " "$TARGET_REPO"
read -r CONFIRM
[[ "${CONFIRM:-N}" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

# ---------------------------------------------------------------------------
# Step 1 – Delete SECURITY_SCAN_TOKEN secret
# ---------------------------------------------------------------------------
echo
info "Step 1/3 — Deleting SECURITY_SCAN_TOKEN secret..."

delete_secret() {
  # Prefer gh CLI
  if command -v gh &>/dev/null; then
    if GITHUB_TOKEN="$GITHUB_TOKEN" \
        gh secret delete SECURITY_SCAN_TOKEN --repo "$TARGET_REPO" 2>/dev/null; then
      info "SECURITY_SCAN_TOKEN deleted (via gh CLI)."
      return 0
    fi
    info "gh CLI failed — falling back to direct API..."
  fi
  # Fallback: REST API
  gh_api "$GITHUB_TOKEN" DELETE \
    "/repos/${TARGET_REPO}/actions/secrets/SECURITY_SCAN_TOKEN" \
    > /dev/null \
    && info "SECURITY_SCAN_TOKEN deleted (via API)." \
    || info "Warning: could not delete secret — check GITHUB_TOKEN has Secrets:Write."
}

SECRET_STATUS=$(curl -so /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "${GITHUB_API}/repos/${TARGET_REPO}/actions/secrets/SECURITY_SCAN_TOKEN")

if [[ "$SECRET_STATUS" == "404" ]]; then
  info "SECURITY_SCAN_TOKEN not present on ${TARGET_REPO} — skipping."
else
  delete_secret
fi

# ---------------------------------------------------------------------------
# Step 2 – Open a PR removing the workflow file
# ---------------------------------------------------------------------------
echo
info "Step 2/3 — Creating removal PR..."

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

info "Cloning ${TARGET_REPO}..."
git clone --quiet --depth=1 "$CLONE_URL" "${WORK_DIR}/repo"
cd "${WORK_DIR}/repo"

DEFAULT_BRANCH="$(git symbolic-ref --short HEAD)"

if [[ ! -f "$WORKFLOW_PATH" ]]; then
  info "Workflow file not found in ${TARGET_REPO} — skipping PR."
  PR_URL="(no PR — workflow was not present)"
  PR_NUMBER=""
else
  git checkout -b "${BRANCH}"

  git rm -f "$WORKFLOW_PATH"

  # If .github/workflows/ is now empty, remove the directory too
  if [[ -d ".github/workflows" ]] && [[ -z "$(ls -A .github/workflows)" ]]; then
    rmdir ".github/workflows"
    # If .github/ is now empty, remove it
    if [[ -d ".github" ]] && [[ -z "$(ls -A .github)" ]]; then
      rmdir ".github"
    fi
  fi

  git config user.name  "security-scan-setup"
  git config user.email "security-scan-setup@users.noreply.github.com"
  git add -A
  git commit -m "ci: remove automated security scanning workflow"

  info "Pushing branch..."
  git push --quiet origin "${BRANCH}"

  PR_BODY="## Remove automated security scanning

This PR removes the security scanning workflow added by \`add-scanning-to-repo.sh\`.

### What this PR does

- Deletes \`.github/workflows/security-scan.yml\`

### What was already done automatically

- \`SECURITY_SCAN_TOKEN\` secret deleted from this repository

### Optional follow-up

If you want to remove this repository's historical findings from the central hub
(\`${CENTRAL_HUB}\`), re-run the removal script with \`--purge-hub\`:

\`\`\`bash
GITHUB_TOKEN=<pat> ./scripts/remove-scanning-from-repo.sh ${TARGET_REPO} --purge-hub
\`\`\`

Or delete \`findings/${REPO}/\` from \`${CENTRAL_HUB}\` manually."

  info "Opening pull request..."
  API_RESPONSE=$(curl -sf \
    -H "Authorization: Bearer ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -X POST \
    "${GITHUB_API}/repos/${TARGET_REPO}/pulls" \
    -d "$(jq -n \
      --arg title "ci: remove automated security scanning" \
      --arg head  "${BRANCH}" \
      --arg base  "${DEFAULT_BRANCH}" \
      --arg body  "${PR_BODY}" \
      '{title:$title, head:$head, base:$base, body:$body}'
    )") || die "PR creation failed — check GITHUB_TOKEN has Pull-requests:Write on ${TARGET_REPO}"

  PR_URL=$(echo    "$API_RESPONSE" | jq -r '.html_url')
  PR_NUMBER=$(echo "$API_RESPONSE" | jq -r '.number')

  if [[ "$PR_URL" == "null" || -z "$PR_URL" ]]; then
    echo "API response:" >&2
    echo "$API_RESPONSE" | jq . >&2
    die "PR creation returned unexpected response — see above."
  fi
  info "PR created: ${PR_URL}"
fi

# ---------------------------------------------------------------------------
# Step 3 – Purge findings from the hub (optional)
# ---------------------------------------------------------------------------
FINDINGS_STATUS="skipped (run with --purge-hub to remove)"

if $PURGE_HUB; then
  echo
  info "Step 3/3 — Purging findings/${REPO}/ from ${CENTRAL_HUB}..."

  HUB_CLONE_URL="https://x-access-token:${HUB_TOKEN}@github.com/${CENTRAL_HUB}.git"

  git clone --quiet "${HUB_CLONE_URL}" "${WORK_DIR}/hub"
  cd "${WORK_DIR}/hub"

  HUB_DEFAULT=$(git symbolic-ref --short HEAD)

  if [[ ! -d "findings/${REPO}" ]]; then
    info "findings/${REPO}/ not found in ${CENTRAL_HUB} — nothing to delete."
    FINDINGS_STATUS="not found in hub"
  else
    git config user.name  "security-scan-setup"
    git config user.email "security-scan-setup@users.noreply.github.com"
    git rm -rf "findings/${REPO}/"
    git commit -m "chore: remove findings for ${TARGET_REPO}"
    git push --quiet origin "${HUB_DEFAULT}"
    info "findings/${REPO}/ removed from ${CENTRAL_HUB}."
    FINDINGS_STATUS="deleted from ${CENTRAL_HUB}"
  fi
else
  info "Step 3/3 — Hub purge skipped."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "══════════════════════════════════════════════════════════════"
echo " Removal complete: ${TARGET_REPO}"
echo "══════════════════════════════════════════════════════════════"
echo ""
echo "  SECURITY_SCAN_TOKEN secret : deleted"
echo "  Workflow removal PR        : ${PR_URL}"
echo "  Hub findings               : ${FINDINGS_STATUS}"
echo ""
[[ -n "${PR_NUMBER:-}" ]] && \
  echo "  Merge PR #${PR_NUMBER} to complete the removal." || true
echo ""
