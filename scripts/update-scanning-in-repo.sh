#!/usr/bin/env bash
# update-scanning-in-repo.sh
#
# Updates the security scanning workflow in a target repository to the
# latest version from this templates/ directory and opens a pull request.
#
# Usage:
#   GITHUB_TOKEN=<pat> ./scripts/update-scanning-in-repo.sh <owner/repo>
#
# Configuration is read from .env at the project root (created by
# setup-central-repo.sh).  Explicit environment variables override .env.
#
# Requirements:
#   - git, curl, jq installed
#   - GITHUB_TOKEN: PAT with Contents:Write + Pull-requests:Write on the target repo
#
# Examples:
#   GITHUB_TOKEN=ghp_xxxx ./scripts/update-scanning-in-repo.sh alice/my-app
#   CENTRAL_HUB=alice/custom-hub GITHUB_TOKEN=ghp_xxxx ./scripts/update-scanning-in-repo.sh alice/my-app

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

TEMPLATE="${REPO_ROOT}/templates/security-scan.yml"
WORKFLOW_PATH=".github/workflows/security-scan.yml"
BRANCH="update-security-scanning-$(date -u +%Y%m%d%H%M%S)"
GITHUB_API="https://api.github.com"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
die()  { echo "Error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

usage() {
  cat >&2 <<EOF

Usage: GITHUB_TOKEN=<pat> $0 <owner/repo>

  Updates .github/workflows/security-scan.yml to the latest template and
  opens a pull request with the diff.

  Arguments:
    <owner/repo>   Target repository, e.g. alice/my-app

  Environment:
    GITHUB_TOKEN   PAT with Contents:Write + Pull-requests:Write on target repo

  Example:
    GITHUB_TOKEN=ghp_xxxx $0 alice/my-app

EOF
  exit 1
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
[[ $# -lt 1 ]] && usage

for cmd in git curl jq; do
  command -v "$cmd" &>/dev/null || die "'$cmd' is not installed — please install it and retry."
done

TARGET_REPO="$1"
[[ "$TARGET_REPO" == */* ]] || die "repo must be in owner/repo format, e.g. alice/my-app"
[[ -n "${GITHUB_TOKEN:-}" ]]  || die "GITHUB_TOKEN is not set."
[[ -f "$TEMPLATE" ]]          || die "template not found at ${TEMPLATE}"

OWNER_TARGET="${TARGET_REPO%%/*}"
CENTRAL_OWNER="${OWNER:-$OWNER_TARGET}"
CENTRAL_HUB="${CENTRAL_HUB:-${CENTRAL_OWNER}/security-scans}"
OWNER="${OWNER:-$OWNER_TARGET}"
CLONE_URL="https://x-access-token:${GITHUB_TOKEN}@github.com/${TARGET_REPO}.git"

info "Target:      ${TARGET_REPO}"
info "Central hub: ${CENTRAL_HUB}"

# ---------------------------------------------------------------------------
# Clone target repo
# ---------------------------------------------------------------------------
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

info "Cloning ${TARGET_REPO}..."
git clone --quiet --depth=1 "$CLONE_URL" "${WORK_DIR}/repo"
cd "${WORK_DIR}/repo"

DEFAULT_BRANCH="$(git symbolic-ref --short HEAD)"
info "Default branch: ${DEFAULT_BRANCH}"

# ---------------------------------------------------------------------------
# Guard: workflow must already exist
# ---------------------------------------------------------------------------
if [[ ! -f "$WORKFLOW_PATH" ]]; then
  die "${WORKFLOW_PATH} not found in ${TARGET_REPO}.
  Run add-scanning-to-repo.sh first to install scanning."
fi

# ---------------------------------------------------------------------------
# Apply latest template and detect changes
# ---------------------------------------------------------------------------
info "Rendering latest template..."
sed "s|__OWNER__|${OWNER}|g" "$TEMPLATE" > "${WORKFLOW_PATH}.new"

if diff -q "$WORKFLOW_PATH" "${WORKFLOW_PATH}.new" > /dev/null 2>&1; then
  info "Workflow is already up to date — no changes needed."
  rm "${WORKFLOW_PATH}.new"
  exit 0
fi

DIFF_OUTPUT="$(diff "$WORKFLOW_PATH" "${WORKFLOW_PATH}.new" || true)"
LINES_ADDED=$(printf '%s\n' "$DIFF_OUTPUT" | grep -c '^>' || true)
LINES_REMOVED=$(printf '%s\n' "$DIFF_OUTPUT" | grep -c '^<' || true)

mv "${WORKFLOW_PATH}.new" "$WORKFLOW_PATH"
info "Changes detected: +${LINES_ADDED} / -${LINES_REMOVED} lines"

# ---------------------------------------------------------------------------
# Commit and push
# ---------------------------------------------------------------------------
git config user.name  "security-scan-setup"
git config user.email "security-scan-setup@users.noreply.github.com"
git checkout -b "${BRANCH}"
git add "$WORKFLOW_PATH"
git commit -m "ci: update security scanning workflow to latest template"

info "Pushing branch..."
git push --quiet origin "${BRANCH}"

# ---------------------------------------------------------------------------
# Open pull request
# ---------------------------------------------------------------------------
PR_BODY="## Update automated security scanning workflow

This PR updates \`.github/workflows/security-scan.yml\` to the latest
template from \`security-scanner-v1\`.

### What changed

| | Count |
|-|-------|
| Lines added   | ${LINES_ADDED} |
| Lines removed | ${LINES_REMOVED} |

<details><summary>Full diff</summary>

\`\`\`diff
${DIFF_OUTPUT}
\`\`\`

</details>

### Files changed

- \`.github/workflows/security-scan.yml\`"

info "Creating pull request..."
API_RESPONSE=$(curl -sf \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  -X POST \
  "${GITHUB_API}/repos/${TARGET_REPO}/pulls" \
  -d "$(jq -n \
    --arg title "ci: update security scanning workflow to latest template" \
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

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Done."
echo ""
echo "  Repository : ${TARGET_REPO}"
echo "  Changes    : +${LINES_ADDED} / -${LINES_REMOVED} lines"
echo "  PR #${PR_NUMBER}       : ${PR_URL}"
echo ""
echo "  Review and merge the PR to apply the update."
echo ""
