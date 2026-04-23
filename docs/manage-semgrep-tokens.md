# Managing Semgrep Tokens

Set `SEMGREP_APP_TOKEN` as a GitHub repository secret so scanning workflows can
use Semgrep Pro rules and access the Semgrep cloud.

---

## When you need this

The security scan workflow includes a `SEMGREP_APP_TOKEN` secret reference in the
`env` section of its jobs. Without it, Semgrep runs in OSS-only mode. To unlock:

- **Pro rule packs** (`--config p/default`, `--config p/owasp-top-ten`, etc.)
- **Semgrep Code (Pro)** — deep dataflow and taint analysis
- **Managed rules** from your Semgrep organization

you need a valid `SEMGREP_APP_TOKEN` stored as a **Actions secret** on each
repo you scan.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| `curl`, `jq`, `python3` | Standard CLI tools |
| `pynacl` (optional) | `pip install pynacl` — enables proper secret encryption. Without it the script falls back to base64-only (not recommended for production). |
| `GITHUB_TOKEN` | Classic PAT with `repo` scope, or fine-grained PAT with **Secrets:Write + Metadata:Read** on target repos |
| `SEMGREP_APP_TOKEN` | The token value from your Semgrep dashboard |

---

## Get your Semgrep token

1. Go to **[Semgrep Settings → Tokens](https://semgrep.dev/orgs/-/settings/tokens)**
2. Create a new token (or copy an existing one)
3. Copy the value — it starts with `dr_` or `d8s_`

---

## Run the script

```bash
GITHUB_TOKEN=ghp_xxxx \
  ./scripts/manage-semgrep-tokens.sh <owner/repo> <semgrep-token>
```

**Example:**
```bash
GITHUB_TOKEN=ghp_xxxx \
  ./scripts/manage-semgrep-tokens.sh your-org/your-repo dr_abc123token
```

**Multiple repos:**
```bash
GITHUB_TOKEN=ghp_xxxx ./scripts/manage-semgrep-tokens.sh your-org/my-app dr_abc123token
GITHUB_TOKEN=ghp_xxxx ./scripts/manage-semgrep-tokens.sh your-org/api dr_abc123token
GITHUB_TOKEN=ghp_xxxx ./scripts/manage-semgrep-tokens.sh your-org/infra dr_abc123token
```

You can also pass the token from an environment variable:
```bash
GITHUB_TOKEN=ghp_xxxx \
  ./scripts/manage-semgrep-tokens.sh your-org/my-app "$SEMGREP_APP_TOKEN"
```

---

## What the script does

| Step | Action |
|------|--------|
| 1 | Fetches the repo's public key from the GitHub Actions secrets API |
| 2 | Encrypts the token value with that key (via pynacl) |
| 3 | PUTs the encrypted secret as `SEMGREP_APP_TOKEN` on the target repo |

The script is **idempotent** — running it again on the same repo updates the
secret value rather than creating a duplicate.

---

## Verify

1. Go to **Repo → Settings → Secrets and variables → Actions**
2. Confirm `SEMGREP_APP_TOKEN` appears in the repository secrets list

Then trigger a scan and check that the Semgrep jobs reference the token in their
logs (look for `semgrep cloud login` or similar).

---

## Rotating tokens

When your Semgrep token expires or you want to rotate:

1. Generate a new token in the Semgrep dashboard
2. Re-run the script with the new value — it overwrites the existing secret

```bash
GITHUB_TOKEN=ghp_xxxx \
  ./scripts/manage-semgrep-tokens.sh your-org/my-app dr_newtoken456
```

No workflow changes needed — workflows reference the secret by name
(`${{ secrets.SEMGREP_APP_TOKEN }}`), so they pick up the new value immediately.
