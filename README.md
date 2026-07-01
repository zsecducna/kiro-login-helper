# kiro-login-helper

Interactive, step-by-step helper that walks you through the **Kiro (AWS
CodeWhisperer) browser SSO sign-in** and writes a
[CLIProxyAPI](https://github.com/zsecducna/cli-cache-proxy-api)-compatible Kiro auth
JSON file.

It targets the **enterprise / external IdP** path used by **Microsoft 365 /
Entra ID (Azure AD)** tenants, and also transparently handles the **social**
(Google / GitHub) path — both legs arrive on the same loopback listener.

This is a faithful Python re-implementation of the Go login flow in
`internal/auth/kiro/social.go` + `sdk/auth/kiro.go`.

---

## Requirements

- **Python ≥ 3.7** (standard library only — no third-party packages, no `pip install`).
- A web browser, ideally able to open a **guest / incognito** window.
- TCP port **3128** on loopback must be free (the OAuth redirect target).

---

## Usage

```bash
python3 kiro-login-helper.py
```

Then follow the two on-screen steps:

1. **Open the printed URL in a guest / incognito browser window.**
   Incognito avoids a cached personal session hijacking the corporate M365
   login.
   - Chrome / Edge: `Ctrl/Cmd+Shift+N`
   - Firefox: `Ctrl/Cmd+Shift+P`
2. **Sign in with your Microsoft 365 work/school account.**
   You are redirected automatically; when the page says *"sign-in complete"*,
   return to the terminal.

On success it writes `CLIProxyAPI_<username>.json` (file mode `0600`) into the
output directory and prints the saved path.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--username` | *(from token)* | Override the account label used in the filename. By default it is derived from the access-token JWT (`preferred_username` → the M365 email). |
| `--region` | `us-east-1` | AWS region for the CodeWhisperer endpoints. Overridden by the region in the resolved profile ARN when present. |
| `--out-dir` | *(current dir)* | Directory to write the credential file into. |
| `--proxy` | *(`HTTPS_PROXY` env)* | Proxy URL for the OAuth / AWS calls. |
| `--timeout` | `600` | Seconds to wait for the browser sign-in. |


---

## How it works

```
1. Generate PKCE verifier/challenge + anti-CSRF state.
2. Build https://app.kiro.dev/signin?... and print it.            [you open it]
3. Bind a loopback listener on 127.0.0.1:3128 (and [::1]:3128).
4. Portal detects an external-IdP email and redirects to
   /signin/callback?login_option=external_idp&issuer_url&client_id&scopes
     → OIDC-discover the issuer (allow-listed to *.microsoftonline.com[.us|.cn])
     → run a 2nd auth-code + PKCE leg, 302-redirecting the browser to the IdP.
5. IdP redirects the code back to /oauth/callback?code&state (state-matched).
6. Exchange the code at the IdP token endpoint → access / refresh / expires_in.
7. Resolve the CodeWhisperer profile ARN via ListAvailableProfiles
   (mandatory header: TokenType: EXTERNAL_IDP).
8. Write CLIProxyAPI_<username>.json.
```

### Output format

The written JSON matches what CLIProxyAPI persists for an external-IdP Kiro
credential (alphabetical keys, a `disabled` flag, a millisecond `timestamp`):

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

The social (Google / GitHub) path produces `"auth_method": "social"` and omits
the IdP-specific fields (`client_id`, `issuer_url`, `token_endpoint`, `scopes`).

---

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `cannot bind loopback 127.0.0.1:3128` | Port 3128 in use (a proxy like Squid often uses it). Free it, or stop the other process, then retry. |
| `external IdP host ... is not allow-listed` | Your tenant uses a non-Entra IdP. Add its host suffix to `ALLOWED_EXTERNAL_IDP_SUFFIXES` in the script. |
| `failed to resolve profile ARN` | The M365 account is not provisioned for Kiro / CodeWhisperer, or the token lacks the right scopes. |
| `SSO login timed out` | Sign-in not completed within `--timeout`. Re-run; raise `--timeout` if needed. |
| Browser shows the personal account picker | You did not use an incognito/guest window — a cached session interfered. Retry in incognito. |
```
