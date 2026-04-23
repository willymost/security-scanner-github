#!/usr/bin/env bash
# add-scanning-to-repo.sh
#
# Adds the security scanning workflow to a target repository, sets the
# SECURITY_SCAN_TOKEN secret, and opens a pull request.
#
# Usage:
#   GITHUB_TOKEN=<pat> ./scripts/add-scanning-to-repo.sh <owner/repo>
#
# Configuration is read from .env at the project root (created by
# setup-central-repo.sh).  Explicit environment variables override .env.
#
# Requirements:
#   - git, curl, jq installed
#   - GITHUB_TOKEN: PAT with Contents:Write, Pull-requests:Write, and Secrets:Write
#     on the target repository
#   - For setting secrets: gh CLI (recommended, brew install gh) OR python3+pynacl
#
# Examples:
#   GITHUB_TOKEN=ghp_xxxx ./scripts/add-scanning-to-repo.sh alice/my-app
#   SECURITY_SCAN_TOKEN=ghp_yyy GITHUB_TOKEN=ghp_xxxx ./scripts/add-scanning-to-repo.sh alice/my-app
#   CENTRAL_HUB=alice/custom-hub GITHUB_TOKEN=ghp_xxxx ./scripts/add-scanning-to-repo.sh alice/my-app

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
BRANCH="add-security-scanning-$(date -u +%Y%m%d%H%M%S)"
GITHUB_API="https://api.github.com"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
die()  { echo "Error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

usage() {
  cat >&2 <<EOF

Usage: GITHUB_TOKEN=<pat> $0 <owner/repo>

  Installs the security scanning workflow, sets SECURITY_SCAN_TOKEN, and
  opens a pull request.

  Arguments:
    <owner/repo>         Target repository, e.g. alice/my-app

  Environment:
    GITHUB_TOKEN         PAT with Contents:Write + Pull-requests:Write +
                         Secrets:Write on the target repo
    SECURITY_SCAN_TOKEN  Token to set as a secret (read from .env)
    CENTRAL_HUB          Hub repo (default: <owner>/security-scans)

  Example:
    GITHUB_TOKEN=ghp_xxxx $0 alice/my-app

EOF
  exit 1
}

gh_api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sf -X "$method"
    -H "Authorization: Bearer ${GITHUB_TOKEN}"
    -H "Accept: application/vnd.github+json"
    -H "X-GitHub-Api-Version: 2022-11-28"
    "${GITHUB_API}${path}")
  [[ -n "$body" ]] && args+=(-d "$body")
  curl "${args[@]}"
}

set_repo_secret() {
  local target="$1" secret_name="$2" secret_value="$3"

  # Prefer gh CLI — handles encryption natively, no crypto library needed.
  if command -v gh &>/dev/null; then
    if echo "$secret_value" | GITHUB_TOKEN="$GITHUB_TOKEN" \
        gh secret set "$secret_name" --repo "$target" 2>/dev/null; then
      info "${secret_name} set on ${target} (via gh CLI)."
      return 0
    fi
    info "gh CLI failed — falling back to direct API..."
  fi

  # Fallback: encrypt with pynacl and call the Secrets REST API directly.
  if ! python3 -c "import nacl" 2>/dev/null; then
    info "Installing pynacl for secret encryption..."
    python3 -m pip install --quiet pynacl \
      || { info "Warning: no gh CLI and pynacl unavailable — secret not set."; return 1; }
  fi

  local pub_key_resp key_value key_id encrypted
  pub_key_resp=$(gh_api GET "/repos/${target}/actions/public-key") \
    || { info "Warning: could not fetch public key for ${target} — secret not set."; return 1; }
  key_value=$(echo "$pub_key_resp" | jq -r '.key')
  key_id=$(echo    "$pub_key_resp" | jq -r '.key_id')
  encrypted=$(python3 - "$key_value" "$secret_value" <<'PYEOF'
import sys
from base64 import b64encode
from nacl import encoding, public as nacl_public
pk = nacl_public.PublicKey(sys.argv[1].encode(), encoding.Base64Encoder())
print(b64encode(nacl_public.SealedBox(pk).encrypt(sys.argv[2].encode())).decode())
PYEOF
  )
  gh_api PUT "/repos/${target}/actions/secrets/${secret_name}" \
    "$(jq -n --arg ev "$encrypted" --arg kid "$key_id" \
      '{encrypted_value:$ev,key_id:$kid}')" \
    > /dev/null \
    && info "${secret_name} set on ${target} (via API)." \
    || { info "Warning: failed to set ${secret_name} on ${target}."; return 1; }
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
REPO="${TARGET_REPO##*/}"
CENTRAL_OWNER="${OWNER:-$OWNER_TARGET}"
CENTRAL_HUB="${CENTRAL_HUB:-${CENTRAL_OWNER}/security-scans}"
OWNER="${OWNER:-$OWNER_TARGET}"
CLONE_URL="https://x-access-token:${GITHUB_TOKEN}@github.com/${TARGET_REPO}.git"

# Resolve SECURITY_SCAN_TOKEN: already loaded from .env (set -a) via the
# ENV_FILE block above; env var takes precedence.
SCAN_TOKEN="${SECURITY_SCAN_TOKEN:-}"
SCAN_TOKEN_SOURCE=""
if [[ -n "$SCAN_TOKEN" ]]; then
  SCAN_TOKEN_SOURCE=".env / environment variable"
fi

# ---------------------------------------------------------------------------
# Clone target repo
# ---------------------------------------------------------------------------
info "Target:      ${TARGET_REPO}"
info "Central hub: ${CENTRAL_HUB}"
[[ -n "$SCAN_TOKEN_SOURCE" ]] \
  && info "Scan token:  found via ${SCAN_TOKEN_SOURCE}" \
  || info "Scan token:  not found — will need to be added manually"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

info "Cloning ${TARGET_REPO}..."
git clone --quiet --depth=1 "$CLONE_URL" "${WORK_DIR}/repo"
cd "${WORK_DIR}/repo"

DEFAULT_BRANCH="$(git symbolic-ref --short HEAD)"
info "Default branch: ${DEFAULT_BRANCH}"

# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------
if [[ -f "$WORKFLOW_PATH" ]]; then
  die "${WORKFLOW_PATH} already exists in ${TARGET_REPO}. Use remove-scanning-from-repo.sh to remove it first."
fi

# ---------------------------------------------------------------------------
# Set SECURITY_SCAN_TOKEN secret before creating the PR
# ---------------------------------------------------------------------------
SECRET_STATUS=""
if [[ -n "$SCAN_TOKEN" ]]; then
  info "Setting SECURITY_SCAN_TOKEN on ${TARGET_REPO}..."
  if set_repo_secret "$TARGET_REPO" "SECURITY_SCAN_TOKEN" "$SCAN_TOKEN"; then
    info "SECURITY_SCAN_TOKEN set successfully."
    SECRET_STATUS="configured"
  else
    info "Warning: secret could not be set — check GITHUB_TOKEN has Secrets:Write."
    SECRET_STATUS="failed"
  fi
else
  SECRET_STATUS="missing"
fi

# ---------------------------------------------------------------------------
# Install workflow — inject the hub owner into the template placeholder
# ---------------------------------------------------------------------------
info "Creating branch '${BRANCH}'..."
git checkout -b "${BRANCH}"

mkdir -p "$(dirname "$WORKFLOW_PATH")"
sed "s|__OWNER__|${OWNER}|g" "$TEMPLATE" > "$WORKFLOW_PATH"

git config user.name  "security-scan-setup"
git config user.email "security-scan-setup@users.noreply.github.com"
git add "$WORKFLOW_PATH"
git commit -m "ci: add automated security scanning (Semgrep SAST/SCA + Grype)"

info "Pushing branch..."
git push --quiet origin "${BRANCH}"

# ---------------------------------------------------------------------------
# Build PR body — reflect secret status
# ---------------------------------------------------------------------------
if [[ "$SECRET_STATUS" == "configured" ]]; then
  SECRET_SECTION="### Secret configuration

The \`SECURITY_SCAN_TOKEN\` secret has been **automatically configured** on this
repository. No manual action needed."
elif [[ "$SECRET_STATUS" == "failed" ]]; then
  SECRET_SECTION="### Secret configuration

> **Action required:** \`SECURITY_SCAN_TOKEN\` could not be set automatically
> (token lacked Secrets:Write). Add it manually:
> Repo → Settings → Secrets and variables → Actions → New repository secret
> - Name: \`SECURITY_SCAN_TOKEN\`
> - Value: fine-grained PAT with Contents:Write on \`${CENTRAL_HUB}\`"
else
  SECRET_SECTION="### Secret configuration

> **Action required:** \`SECURITY_SCAN_TOKEN\` was not available during setup.
> Add it manually:
> Repo → Settings → Secrets and variables → Actions → New repository secret
> - Name: \`SECURITY_SCAN_TOKEN\`
> - Value: fine-grained PAT with Contents:Write on \`${CENTRAL_HUB}\`
>
> Or run \`./scripts/setup-central-repo.sh\` first to create and cache the token."
fi

PR_BODY="## Add automated security scanning

This PR adds a GitHub Actions workflow that runs three security scans on every
push, pull request, and weekly schedule.

| Tool | Type | What it finds |
|------|------|--------------|
| **Semgrep SAST** | Static analysis | Code vulnerabilities, injection, insecure patterns |
| **Semgrep SCA** | Supply chain | Vulnerable/reachable dependencies |
| **Grype + Syft** | Dependency scan | CVEs in dependencies; generates a CycloneDX SBOM |
| **Gitleaks** | Secret scan | Hardcoded secrets, API keys, credentials in code and git history |

### On pull requests

Posts a severity summary comment directly on the PR:

\`\`\`
| Tool           | Critical | High | Medium | Low |
|----------------|----------|------|--------|-----|
| Semgrep SAST   | 0        | 1    | 3      | 2   |
| Semgrep SCA    | 0        | 0    | 1      | 0   |
| Grype          | 0        | 2    | 1      | 4   |
| Gitleaks       | 0        | 1    | 0      | 0   |
\`\`\`

### On merge to \`${DEFAULT_BRANCH}\`

Pushes raw findings (SARIF + JSON) to the central hub (\`${CENTRAL_HUB}\`).

${SECRET_SECTION}

### Optional

Add \`SEMGREP_APP_TOKEN\` (from semgrep.dev) to enable Semgrep Pro rules and
CRITICAL-severity findings. Without it, the highest severity reported is HIGH.

### Files changed

- \`.github/workflows/security-scan.yml\`"

# ---------------------------------------------------------------------------
# Open pull request
# ---------------------------------------------------------------------------
info "Creating pull request..."

API_RESPONSE=$(curl -sf \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  -X POST \
  "${GITHUB_API}/repos/${TARGET_REPO}/pulls" \
  -d "$(jq -n \
    --arg title "ci: add automated security scanning (Semgrep SAST/SCA + Grype)" \
    --arg head  "${BRANCH}" \
    --arg base  "${DEFAULT_BRANCH}" \
    --arg body  "${PR_BODY}" \
    '{title: $title, head: $head, base: $base, body: $body}'
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
echo "  Repository          : ${TARGET_REPO}"
echo "  Hub                 : ${CENTRAL_HUB}"
echo "  SECURITY_SCAN_TOKEN : ${SECRET_STATUS}"
echo "  PR #${PR_NUMBER}            : ${PR_URL}"
echo ""
[[ "$SECRET_STATUS" == "configured" ]] \
  && echo "  Merge the PR and scans will start immediately." \
  || echo "  Add SECURITY_SCAN_TOKEN before merging (see PR body for instructions)."
echo ""
