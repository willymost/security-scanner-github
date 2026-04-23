#!/bin/bash
#
# manage-semgrep-tokens.sh
# Set SEMGREP_APP_TOKEN as a GitHub repository secret on a target repo.
#
# Usage:
#   GITHUB_TOKEN=<pat> ./scripts/manage-semgrep-tokens.sh <owner/repo> <semgrep-token>
#
# Examples:
#   GITHUB_TOKEN=ghp_xxxx ./scripts/manage-semgrep-tokens.sh alice/my-app abc123token
#   GITHUB_TOKEN=github_pat_xxx ./scripts/manage-semgrep-tokens.sh owner/your-repo $SEMGREP_APP_TOKEN
#
# Requires:
#   curl, jq
#   GITHUB_TOKEN: PAT with repo scope (secrets read/write)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Load .env (created by setup-central-repo.sh) for SECURITY_SCAN_TOKEN
ENV_FILE="${REPO_ROOT}/.env"
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

die() { echo "❌ $*" >&2; exit 1; }

# --- Argument parsing -------------------------------------------------------

if [[ $# -lt 2 ]]; then
    echo "Usage: GITHUB_TOKEN=<pat> $0 <owner/repo> <semgrep-token>"
    echo ""
    echo "  GITHUB_TOKEN   PAT with repo scope (secrets read/write)"
    echo "  owner/repo     Target repository (e.g. alice/my-app)"
    echo "  semgrep-token  The SEMGREP_APP_TOKEN value to store"
    echo ""
    echo "Examples:"
    echo "  GITHUB_TOKEN=ghp_xxxx $0 alice/my-app abc123token"
    echo "  GITHUB_TOKEN=ghp_xxxx $0 your-org/your-repo \"\$SEMGREP_APP_TOKEN\""
    exit 1
fi

TARGET_REPO="$1"
SEMGREP_TOKEN="$2"

# Validate owner/repo format
if [[ "$TARGET_REPO" != */* ]]; then
    die "Repository must be in owner/repo format (got: $TARGET_REPO)"
fi

OWNER="${TARGET_REPO%%/*}"
REPO="${TARGET_REPO#*/}"

# --- Token resolution -------------------------------------------------------
# Try explicit GITHUB_TOKEN env var, then fall back to SECURITY_SCAN_TOKEN from .env

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    if [[ -n "${SECURITY_SCAN_TOKEN:-}" ]]; then
        GITHUB_TOKEN="$SECURITY_SCAN_TOKEN"
    else
        die "GITHUB_TOKEN is not set and SECURITY_SCAN_TOKEN not found in .env."
    fi
fi

# --- Secret setting ----------------------------------------------------------

set_secret() {
    local secret_name="$1"
    local secret_value="$2"

    echo "Setting ${secret_name} on ${TARGET_REPO}..."

    # Method 1: gh CLI (handles libsodium encryption natively)
    if command -v gh &>/dev/null; then
        if gh secret set "$secret_name" --repo "$TARGET_REPO" --body "$secret_value" 2>/dev/null; then
            echo "  ✅ ${secret_name} set on ${TARGET_REPO} (via gh)"
            return 0
        fi
    fi

    # Method 2: pynacl + GitHub REST API
    if python3 -c "import nacl.public" 2>/dev/null; then
        _set_secret_pynacl "$secret_name" "$secret_value"
        return $?
    fi

    # No viable method
    die "Cannot set secrets: neither 'gh' CLI nor 'pynacl' (pip install pynacl) is available."
}

_set_secret_pynacl() {
    local secret_name="$1"
    local secret_value="$2"
    local API="https://api.github.com"

    local resp
    resp=$(curl -sf \
        -H "Accept: application/vnd.github.v3+json" \
        -H "Authorization: Bearer ${GITHUB_TOKEN}" \
        "${API}/repos/${OWNER}/${REPO}/actions/secrets/public-key") \
        || die "Failed to fetch public key for ${TARGET_REPO}"

    local key_id key_b64
    key_id=$(echo "$resp" | jq -r '.key_id')
    key_b64=$(echo "$resp" | jq -r '.key')
    [[ -n "$key_id" && "$key_id" != "null" ]] || die "Could not retrieve public key for ${TARGET_REPO}"

    local encrypted
    encrypted=$(python3 -c "
import base64, sys
from nacl.public import PublicKey, SealedBox
key = PublicKey(base64.b64decode(sys.argv[1]))
sealed = SealedBox(key).encrypt(sys.argv[2].encode())
print(base64.b64encode(sealed).decode())
" "$key_b64" "$secret_value")

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT \
        -H "Accept: application/vnd.github.v3+json" \
        -H "Authorization: Bearer ${GITHUB_TOKEN}" \
        -H "Content-Type: application/json" \
        "${API}/repos/${OWNER}/${REPO}/actions/secrets/${secret_name}" \
        -d "$(jq -n --arg kid "$key_id" --arg val "$encrypted" \
            '{encrypted_value: $val, key_id: $kid}')")

    case "$http_code" in
        201|204) echo "  ✅ ${secret_name} set on ${TARGET_REPO} (via API)" ;;
        *)       die "Failed to set ${secret_name} on ${TARGET_REPO} (HTTP ${http_code})" ;;
    esac
}

# --- Main -------------------------------------------------------------------

echo "🔧 Managing Semgrep tokens for ${TARGET_REPO}"

set_secret "SEMGREP_APP_TOKEN" "$SEMGREP_TOKEN"

echo "✅ Done"
