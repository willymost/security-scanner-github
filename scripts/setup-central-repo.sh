#!/usr/bin/env bash
# setup-central-repo.sh
#
# One-shot setup for the security-scans central hub.
# Creates the hub repo, pushes all hub files, configures permissions,
# provisions the SECURITY_SCAN_TOKEN used by source-repo workflows,
# and writes configuration to .env for all other scripts to use.
#
# Usage:
#   GITHUB_TOKEN=<pat> ./scripts/setup-central-repo.sh [source-repo ...]
#
# On first run you will be prompted for your GitHub username (or
# organisation).  The resolved identity and hub details are saved to
# .env at the project root so every other script picks them up
# automatically.
#
# Arguments:
#   source-repo    Repo names (not owner/repo — just the name) to receive
#                  SECURITY_SCAN_TOKEN right now. More can be added later with
#                  add-scanning-to-repo.sh.
#
# Optional environment variables:
#   OWNER                 GitHub username or org – will override the interactive
#                         prompt / .env if you supply it.
#   HUB_NAME              Central hub repo name (default: security-scans).
#   SECURITY_SCAN_TOKEN   Supply the push token non-interactively. If omitted the
#                         script will prompt you to create one in the GitHub UI and
#                         paste it.
#
# Requirements:
#   - git, curl, jq
#   - For setting secrets: gh CLI (recommended, brew install gh) OR python3+pynacl
#   - GITHUB_TOKEN   Classic PAT with 'repo' scope, OR fine-grained PAT with:
#                      Administration:Write  (create repo)
#                      Contents:Write        (push files)
#                      Secrets:Write         (set secrets on source repos)
#
# Note on PAT creation:
#   GitHub does not expose an API to create Personal Access Tokens — this is a
#   deliberate security boundary. The script will guide you through creating the
#   narrowly-scoped token in the browser and paste the value here for distribution.
#
# Examples:
#   GITHUB_TOKEN=ghp_xxx ./scripts/setup-central-repo.sh
#   GITHUB_TOKEN=ghp_xxx ./scripts/setup-central-repo.sh my-app my-api
#   OWNER=alice GITHUB_TOKEN=ghp_xxx ./scripts/setup-central-repo.sh my-app
#   SECURITY_SCAN_TOKEN=ghp_yyy GITHUB_TOKEN=ghp_xxx ./scripts/setup-central-repo.sh my-app

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"
CENTRAL_REPO_FILES="${REPO_ROOT}/central-repo"
GITHUB_API="https://api.github.com"
HUB_NAME="${HUB_NAME:-security-scans}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
die()     { echo; echo "Error: $*" >&2; exit 1; }
info()    { echo "  ==> $*"; }
section() { echo; echo "── $* ──────────────────────────────────────────────"; }

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
      || die "No gh CLI and pynacl unavailable. Install one: brew install gh  OR  pip install pynacl"
  fi

  local pub_key_resp key_value key_id encrypted
  pub_key_resp=$(gh_api GET "/repos/${target}/actions/public-key") \
    || die "Could not fetch public key for ${target}. Does GITHUB_TOKEN have Secrets:Write?"
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
    || info "Warning: failed to set ${secret_name} on ${target}. Add it manually."
}

update_env_file() {
  local owner="$1" hub_name="$2" central_hub="$3" scan_token="$4"
  # Preserve existing .env values as defaults, then overlay new ones.
  local existing_owner="" existing_hub_name="" existing_central_hub="" existing_token=""
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE" 2>/dev/null || true
    existing_owner="${OWNER:-}"
    existing_hub_name="${HUB_NAME:-}"
    existing_central_hub="${CENTRAL_HUB:-}"
    existing_token="${SECURITY_SCAN_TOKEN:-}"
  fi

  cat > "$ENV_FILE" <<EOF
# Security Scanner Configuration
# Generated by setup-central-repo.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Do NOT commit this file or share it publicly.

OWNER=${owner:-${existing_owner}}
HUB_NAME=${hub_name:-${existing_hub_name}}
CENTRAL_HUB=${central_hub:-${existing_central_hub}}

# The PAT that source-repo workflows use to push findings into the central hub.
SECURITY_SCAN_TOKEN=${scan_token:-${existing_token}}
EOF
  chmod 600 "$ENV_FILE"
  info "Wrote configuration to ${ENV_FILE}"
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
for cmd in git curl jq python3; do
  command -v "$cmd" &>/dev/null || die "'$cmd' is not installed. Install it and retry."
done
[[ -n "${GITHUB_TOKEN:-}" ]] || die "GITHUB_TOKEN is not set."
[[ -d "$CENTRAL_REPO_FILES" ]] || \
  die "central-repo/ not found at ${CENTRAL_REPO_FILES}. Run from the security-scanner-v1 root."

# ---------------------------------------------------------------------------
# Resolve / prompt for OWNER
# ---------------------------------------------------------------------------
section "Identifying your GitHub account"

# Load existing .env so we can reuse values on re-run
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
  info "Loaded existing configuration from ${ENV_FILE}"
fi

# If still unknown, prompt interactively
if [[ -z "${OWNER:-}" ]]; then
  section "Enter GitHub username"
  echo "  What is your GitHub username or organisation name?"
  echo "  (This is used as the owner for the central hub repo)."
  echo
  printf "  GitHub owner > "
  read -r OWNER
  if [[ -z "$OWNER" ]]; then
    # Fall back to API resolution if user enters nothing
    info "No input — resolving via GitHub API..."
    OWNER=$(gh_api GET /user | jq -r '.login') \
      || die "Could not resolve GitHub user — please re-run with OWNER=<name> or set GITHUB_TOKEN."
  fi
  # Basic validation: only allow alphanumeric, hyphens
  if [[ ! "$OWNER" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]]; then
    die "Invalid GitHub username: '${OWNER}'. Must be alphanumeric with optional hyphens."
  fi
  info "Using: ${OWNER}"
fi

# Collect source repo names from remaining arguments
SOURCE_REPOS=()
# Skip args that look like flags
for arg in "$@"; do
  [[ "$arg" == -* ]] && continue
  SOURCE_REPOS+=("$arg")
done

CENTRAL_HUB="${OWNER}/${HUB_NAME}"
CLONE_URL="https://x-access-token:${GITHUB_TOKEN}@github.com/${CENTRAL_HUB}.git"

# ---------------------------------------------------------------------------
# Step 0 – Persist config to .env (token filled in after Step 4)
# ---------------------------------------------------------------------------
update_env_file "$OWNER" "$HUB_NAME" "$CENTRAL_HUB" ""

# ---------------------------------------------------------------------------
# Step 1 – Create the hub repository
# ---------------------------------------------------------------------------
section "Step 1/4 — Create ${CENTRAL_HUB}"

HTTP_STATUS=$(curl -so /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  "${GITHUB_API}/repos/${CENTRAL_HUB}")

if [[ "$HTTP_STATUS" == "200" ]]; then
  info "${CENTRAL_HUB} already exists — skipping creation."
else
  info "Creating ${CENTRAL_HUB} (private)..."
  gh_api POST /user/repos "$(jq -n \
    --arg name "$HUB_NAME" \
    --arg desc "Central aggregation hub for automated security scan findings (Semgrep SAST/SCA + Grype)" \
    '{name:$name, description:$desc, private:true, auto_init:true}'
  )" > /dev/null \
    || die "Repo creation failed. Ensure GITHUB_TOKEN has Administration:Write (or classic 'repo' scope)."
  info "Repository created: https://github.com/${CENTRAL_HUB}"
fi

DEFAULT_BRANCH=$(gh_api GET "/repos/${CENTRAL_HUB}" | jq -r '.default_branch')
info "Default branch: ${DEFAULT_BRANCH}"

# ---------------------------------------------------------------------------
# Step 2 – Push hub files
# ---------------------------------------------------------------------------
section "Step 2/4 — Push hub files"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

info "Cloning ${CENTRAL_HUB}..."
git clone --quiet "$CLONE_URL" "${WORK_DIR}/repo"
cd "${WORK_DIR}/repo"

cp -r "${CENTRAL_REPO_FILES}/." .

git config user.name  "security-scan-setup"
git config user.email "security-scan-setup@users.noreply.github.com"
git add .

if git diff --cached --quiet; then
  info "Hub files already present — nothing new to commit."
else
  git commit -m "feat: initialize security-scans hub"
  git push --quiet origin "${DEFAULT_BRANCH}"
  info "Hub files pushed."
fi

# ---------------------------------------------------------------------------
# Step 3 – Enable workflow read/write permissions
# ---------------------------------------------------------------------------
section "Step 3/4 — Enable workflow permissions"

gh_api PUT "/repos/${CENTRAL_HUB}/actions/permissions/workflow" \
  '{"default_workflow_permissions":"write","can_approve_pull_request_reviews":false}' \
  > /dev/null \
  && info "Workflow permissions set to read/write." \
  || info "Warning: could not set workflow permissions via API. Do it manually:" \
     "${CENTRAL_HUB} → Settings → Actions → General → Workflow permissions → Read and write."

# ---------------------------------------------------------------------------
# Step 4 – Provision SECURITY_SCAN_TOKEN
# ---------------------------------------------------------------------------
section "Step 4/4 — SECURITY_SCAN_TOKEN"

SCAN_TOKEN="${SECURITY_SCAN_TOKEN:-}"

if [[ -n "$SCAN_TOKEN" ]]; then
  info "SECURITY_SCAN_TOKEN supplied via environment / .env."
else
  # GitHub does not provide an API to create PATs — guide the user through the UI.
  echo
  echo "  SECURITY_SCAN_TOKEN is a narrowly-scoped PAT that source-repo"
  echo "  workflows use to push findings into ${CENTRAL_HUB}."
  echo
  echo "  GitHub does not allow PATs to be created via API, so you need to"
  echo "  create one in your browser. Open this URL:"
  echo
  echo "    https://github.com/settings/personal-access-tokens/new"
  echo
  echo "  Fill it in as follows:"
  echo "    Token name:        security-scan-push"
  echo "    Expiration:        1 year  (set a calendar reminder to rotate it)"
  echo "    Resource owner:    ${OWNER}"
  echo "    Repository access: Only selected repositories → ${CENTRAL_HUB}"
  echo "    Permissions:"
  echo "      Contents  → Read and Write"
  echo "      Metadata  → Read  (auto-selected)"
  echo "      (leave everything else as No access)"
  echo
  echo "  Click 'Generate token', copy the value, then paste it below."
  echo
  printf "  Paste token (input hidden): "
  read -rs SCAN_TOKEN
  echo
  [[ -n "$SCAN_TOKEN" ]] || die "No token entered. Re-run to retry."
fi

# Validate the token can reach the hub
info "Validating token against ${CENTRAL_HUB}..."
TEST=$(curl -sf \
  -H "Authorization: Bearer ${SCAN_TOKEN}" \
  "${GITHUB_API}/repos/${CENTRAL_HUB}" 2>/dev/null | jq -r '.name' 2>/dev/null || echo "")
[[ "$TEST" == "$HUB_NAME" ]] \
  || die "Token cannot access ${CENTRAL_HUB}. Check permissions (Contents:Write on ${CENTRAL_HUB}) and try again."
info "Token validated."

# Persist the validated token to .env
update_env_file "$OWNER" "$HUB_NAME" "$CENTRAL_HUB" "$SCAN_TOKEN"

# Distribute to any source repos provided as arguments
if [[ ${#SOURCE_REPOS[@]} -gt 0 ]]; then
  for REPO_NAME in "${SOURCE_REPOS[@]}"; do
    info "Setting SECURITY_SCAN_TOKEN on ${OWNER}/${REPO_NAME}..."
    set_repo_secret "${OWNER}/${REPO_NAME}" "SECURITY_SCAN_TOKEN" "$SCAN_TOKEN"
  done
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo
echo "══════════════════════════════════════════════════════════════"
echo " Setup complete"
echo " Hub: https://github.com/${CENTRAL_HUB}"
echo " Configuration saved to: ${ENV_FILE}"
echo "══════════════════════════════════════════════════════════════"
echo
echo " To onboard a repository:"
echo
echo "   ./scripts/add-scanning-to-repo.sh my-app"
echo
echo " The .env file provides all config — no environment variables needed."
echo
