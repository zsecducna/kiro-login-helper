# kiro-login-helper

Tools for signing into **Kiro (AWS CodeWhisperer)** and producing credentials —
either a [CLIProxyAPI](https://github.com/zsecducna/cli-cache-proxy-api)-compatible
Kiro auth JSON, or a `kiro.dev` **API key**.

The repo ships **three scripts**, each targeting a different sign-in path:

| Script | Sign-in path | Browser | Output | Batch |
|--------|--------------|---------|--------|-------|
| `kiro-login-helper.py` | Hosted SSO portal (M365/Entra external IdP, Google/GitHub social) **and** AWS IdC device flow | Manual (you open a URL) or CloakBrowser auto-open | `CLIProxyAPI_<user>.json` auth file | No (one account per run) |
| `kiro-web-login.py` | AWS IAM Identity Center via **Start URL** (native AWS username/password) | Automated headed CloakBrowser (Playwright) | `kiro.dev` **API key** JSON | Yes (`--all`) |
| `kiro-go-login.py` | Fully-automated **M365 / Entra ID SSO** (or interactive/manual, or IdC device flow) | Automated headed CloakBrowser (Playwright) for M365; manual for interactive | `kiro-go-account_<email>.json` account | Yes (`--all`) |

> A fourth script, `kiro-idc-m365-login.py` (IdC Start URL **federated to M365**),
> exists locally but is **experimental / unverified** and not covered here.

---

## Requirements

- **Python ≥ 3.7.** The core OAuth flow in `kiro-login-helper.py` is standard
  library only.
- The **automated** scripts (`kiro-web-login.py`, `kiro-go-login.py` M365 mode)
  additionally need **CloakBrowser** + Playwright:
  ```bash
  pip install cloakbrowser
  playwright install chromium
  ```
- TCP port **3128** on loopback must be free — it is the OAuth redirect target
  for the loopback-listener flows. Logins therefore run **one at a time**;
  `--all` iterates sequentially, releasing the port between accounts.
- A modern browser (for the manual `kiro-login-helper.py` path).

---

## Account file format

The automated scripts read a plain-text accounts file, **one account per line**,
pipe-delimited. Blank lines and lines that don't parse as an account (headers,
`━━━` separators, `Format:` / `Accounts:` banners) are ignored — you can paste a
noisy export straight in.

| Script | Line format |
|--------|-------------|
| `kiro-web-login.py` | `username\|password\|start_url` |
| `kiro-go-login.py` (M365) | `email\|password` or `email\|password\|mfa_secret` |

- The `\|` (pipe) is the field delimiter, so **passwords may not contain `\|`**.
- `mfa_secret` (kiro-go M365) is optional. If a TOTP secret is captured during a
  first-time MFA enrollment, the script **writes it back** into the same line,
  turning `email|password` into `email|password|mfa_secret` for reuse next run.
- `kiro-web-login.py` may need to set a new password on a forced reset; when it
  does, it **writes the generated password back** into the accounts file.

---

## `kiro-login-helper.py` — manual / interactive auth file

Interactive, step-by-step helper for the hosted SSO portal (M365/Entra external
IdP + Google/GitHub social) and AWS IdC. Writes a CLIProxyAPI-compatible Kiro
auth JSON. No CloakBrowser required — it prints a URL (or auto-opens one if
CloakBrowser is installed) and waits on the loopback listener.

```bash
# Hosted SSO portal (default) — asks you to pick portal vs IdC
python3 kiro-login-helper.py

# Go straight to AWS IAM Identity Center via start URL
python3 kiro-login-helper.py \
  --idc-start-url https://d-1234567890.awsapps.com/start \
  --region eu-central-1
```

**Portal flow:** the script opens (or prints) the sign-in URL in a fresh
profile, you sign in with your Microsoft 365 work/school account (or
Google/GitHub), and when the page says *"sign-in complete"* you return to the
terminal. **IdC flow:** a browser opens the AWS device-approval page — sign in,
confirm the shown user code, approve.

On success it writes `CLIProxyAPI_<username>.json` (mode `0600`) into the output
directory.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--username` | *(from token)* | Account label used in the filename. Defaults to the access-token JWT `preferred_username` (M365 email), or the start-URL directory id for IdC. |
| `--idc-start-url` | *(prompted)* | AWS IdC start URL. When set, runs the IdC device-authorization login instead of the hosted portal. |
| `--region` | *(prompted)* | AWS region: `us-east-1` or `eu-central-1`. Overridden by the region in the resolved profile ARN when present. |
| `--out-dir` | *(current dir)* | Directory to write the credential file into. |
| `--proxy` | *(`HTTPS_PROXY` env)* | Proxy URL for the OAuth / AWS calls. |
| `--timeout` | `600` | Seconds to wait for the browser sign-in. |

---

## `kiro-web-login.py` — automated IdC Start-URL login → API key

Drives the real `app.kiro.dev` sign-in UI end-to-end in a headed CloakBrowser
for the **AWS IAM Identity Center** path: Start URL → AWS username → password →
(forced reset if required) → generate a `kiro.dev` **API key**. A fresh
disposable browser profile is used per account and wiped on exit (no caching).

```bash
# Single account (default: first line of accounts_test.txt)
python3 kiro-web-login.py

# A specific accounts file, first account
python3 kiro-web-login.py accounts.txt

# Pick one account by 1-based index or by username
python3 kiro-web-login.py accounts.txt --index 3
python3 kiro-web-login.py accounts.txt --username alice@corp.example

# BATCH: log in EVERY account, a fresh browser each, sequentially
python3 kiro-web-login.py accounts.txt --all

# Fast production run (no per-step delay), headless
python3 kiro-web-login.py accounts.txt --all --step-delay 0 --headless

# Sign in only, skip API-key creation
python3 kiro-web-login.py accounts.txt --no-api-key
```

**Output:** for each account it writes an API-key JSON (mode `0600`) into the
API-key output directory (`./api-keys` by default), holding
`{username, key_name, api_key, created_unix}`. Default key name is `Kiro-Go`.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `accounts_file` | `accounts_test.txt` | Positional. Accounts file (`username\|password\|start_url`). |
| `--index N` | `1` | 1-based index of the account to log in. Mutually exclusive with `--username` / `--all`. |
| `--username U` | — | Log in the account whose username matches `U`. |
| `--all` | — | Log in every account in the file, one fresh browser each, in sequence. |
| `--step-delay S` | `1.0` | Seconds to pause around each UI step (for watching). Use `0` for production. |
| `--timeout T` | `300` | Max seconds for one login to reach a terminal state. |
| `--headless` | *(headed)* | Run the browser headless. Default is headed so you can watch. |
| `--api-key-name NAME` | `Kiro-Go` | Name for the API key created after sign-in. |
| `--no-api-key` | — | Skip API-key generation; only sign in. |
| `--api-key-out-dir DIR` | `./api-keys` | Directory for the generated API-key JSON files. |

---

## `kiro-go-login.py` — Kiro-Go account JSON (M365 automated / interactive / IdC)

Produces a **Kiro-Go account JSON** (`config.Account` camelCase shape:
`authMethod`, `accessToken`, `refreshToken`, `profileArn`, `clientId`,
`tokenEndpoint`, `issuerUrl`, `scopes`). Three modes:

1. **Fully-automated M365 / Entra ID SSO** — pass `--m365-accounts-file`. Drives
   a disposable headed CloakBrowser through email → Microsoft password → (MFA
   enrollment / TOTP if required) → success, then builds the account JSON. This
   is the mode with `--index / --username / --all` batch support.
2. **Interactive / manual** — no `--m365-accounts-file`. Prints (or auto-opens)
   the sign-in URL and waits on the loopback listener, like
   `kiro-login-helper.py`.
3. **AWS IdC device flow** — pass `--idc-start-url`.

```bash
# Automated M365, single account (first line)
python3 kiro-go-login.py --m365-accounts-file accounts_sso.txt

# Pick one M365 account by index or email
python3 kiro-go-login.py --m365-accounts-file accounts_sso.txt --index 2
python3 kiro-go-login.py --m365-accounts-file accounts_sso.txt --username bob@corp.example

# BATCH: every M365 account, fresh browser each, sequential
python3 kiro-go-login.py --m365-accounts-file accounts_sso.txt --all

# Fast production batch, headless, into an output dir
python3 kiro-go-login.py --m365-accounts-file accounts_sso.txt \
  --all --step-delay 0 --headless --out-dir ./output

# Interactive (manual) mode
python3 kiro-go-login.py

# AWS IdC device flow
python3 kiro-go-login.py --idc-start-url https://d-1234567890.awsapps.com/start --region us-east-1
```

**Output:** a standalone `kiro-go-account_<email>.json` per account in
`--out-dir` (current dir by default). With `--config path/to/config.json` the
account is **merged into** that Kiro-Go config instead, and the standalone file
is skipped unless `--keep-standalone` is also given.

**MFA:** on a first-time enrollment the captured TOTP secret is written back into
the accounts file (`email|password` → `email|password|mfa_secret`) so subsequent
runs authenticate non-interactively. Tenants that don't force MFA sail straight
through password → success.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--m365-accounts-file FILE` | — | Enables **automated M365 mode**. File of `email\|password[\|mfa_secret]` lines. |
| `--index N` | `1` | 1-based index into the M365 accounts file. Mutually exclusive with `--username` / `--all`. |
| `--username EMAIL` | — | Log in the M365 account with this email. |
| `--all` | — | Log in every M365 account, one fresh browser each, sequentially. |
| `--step-delay S` | `1.0` | Seconds to pause around each M365 browser step. Use `0` for production. |
| `--headless` | *(headed)* | Run the M365 browser headless. |
| `--email` | *(from token)* | Override the email recorded on the account. |
| `--region {us-east-1,eu-central-1}` | *(prompted)* | AWS auth region. |
| `--provider` | *(detected)* | Override the provider label (GitHub, Google, AzureAD). |
| `--idc-start-url URL` | — | Run the AWS IdC device-authorization login instead of the portal. |
| `--out-dir DIR` | *(current dir)* | Directory for the standalone account file. |
| `--config FILE` | — | Merge the account into this Kiro-Go `config.json` (created if missing). Skips the standalone file unless `--keep-standalone`. |
| `--keep-standalone` | — | Also write the standalone file when `--config` is used. |
| `--proxy` | *(`HTTPS_PROXY` env)* | Proxy URL for the OAuth / AWS calls. |
| `--timeout` | `600` | Seconds to wait for the browser sign-in. |

---

## Batch jobs (`--all`)

Both automated scripts accept `--all` to process an entire accounts file in one
invocation. Because every login binds the **same loopback port (3128)** and each
account gets its **own fresh, wiped browser profile**, accounts are handled
**strictly in sequence** — the port and profile are released before the next
account starts. There is no parallelism by design; a failed account is reported
and the run continues to the next.

```bash
# Web (IdC Start URL) → API keys for all accounts, unattended
python3 kiro-web-login.py accounts.txt --all --step-delay 0 --headless

# Go (M365 SSO) → account JSONs for all accounts, unattended
python3 kiro-go-login.py --m365-accounts-file accounts_sso.txt --all --step-delay 0 --headless --out-dir ./output
```

For an unattended production batch: set `--step-delay 0` (removes the
human-watching pauses) and `--headless` (no visible window). Keep the default
headed mode with a `1.0s` delay while you're validating an accounts file.

---

## How the hosted-portal / IdC OAuth flow works

```
1. Generate PKCE verifier/challenge + anti-CSRF state.
2. Build https://app.kiro.dev/signin?... and open/print it.
3. Bind a loopback listener on 127.0.0.1:3128 (and [::1]:3128).
4. Portal detects an external-IdP email and redirects to
   /signin/callback?login_option=external_idp&issuer_url&client_id&scopes
     -> OIDC-discover the issuer (allow-listed to *.microsoftonline.com[.us|.cn])
     -> run a 2nd auth-code + PKCE leg, 302-redirecting the browser to the IdP.
5. IdP redirects the code back to /oauth/callback?code&state (state-matched).
6. Exchange the code at the IdP token endpoint -> access / refresh / expires_in.
7. Resolve the CodeWhisperer profile ARN via ListAvailableProfiles
   (header TokenType: EXTERNAL_IDP).
8. Write the credential file.
```

**AWS IdC (`--idc-start-url`)** instead runs RegisterClient →
StartDeviceAuthorization → open `verificationUriComplete` → poll the token
endpoint → resolve profile ARN → write with `auth_method: "idc"`.

### `kiro-login-helper.py` output format

```json
{
  "access_token": "...",
  "auth_method": "external_idp",
  "client_id": "<azure-app-client-id>",
  "disabled": false,
  "expired": "2026-06-18T11:06:42Z",
  "issuer_url": "https://login.microsoftonline.com/<tenant>/v2.0",
  "profile_arn": "arn:aws:codewhisperer:us-east-1:...:profile/...",
  "refresh_token": "...",
  "region": "us-east-1",
  "scopes": "api://<id>/codewhisperer:conversations ... offline_access",
  "timestamp": 1781775636204,
  "token_endpoint": "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token",
  "type": "kiro"
}
```

The IdC path writes `auth_method: "idc"` and persists `client_id`,
`client_secret`, `region`, `start_url`, `username` for refresh. The social path
writes `auth_method: "social"` and omits the IdP-specific fields.

---

## Security notes

- All credential and API-key files are written with mode `0600`.
- Generated JSON credentials, API keys, and the accounts files are
  **git-ignored** (`CLIProxyAPI_*.json`, `kiro-*.json`, `*.auth.json`,
  `api-keys/`). Do not commit real accounts or tokens.
- Automated scripts use a **fresh, disposable** browser profile per account,
  wiped on exit, so no corporate session is cached between accounts.

---

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `cannot bind loopback 127.0.0.1:3128` / `Address already in use` | Port 3128 in use (a proxy like Squid, or a prior login not yet released). Free it or wait, then retry. |
| `external IdP host ... is not allow-listed` | Your tenant uses a non-Entra IdP. Add its host suffix to `ALLOWED_EXTERNAL_IDP_SUFFIXES` in the script. |
| `failed to resolve profile ARN` | The account is not provisioned for Kiro / CodeWhisperer, or the token lacks the right scopes / `--region` is wrong. |
| `SSO login timed out` | Sign-in not completed within `--timeout`. Re-run; raise `--timeout`. |
| `device code expired before authorization completed` | IdC device approval not finished in time. Re-run and approve promptly. |
| Browser shows the personal account picker | A cached session interfered. The automated scripts avoid this with fresh profiles; for manual mode use an incognito/guest window. |
| Playwright / CloakBrowser import error | `pip install cloakbrowser && playwright install chromium`. |
| M365 batch stops on one account | Failures are per-account; the run continues. Re-run that account with `--username <email>`. |
