#!/usr/bin/env python3
# kiro-go-login.py
#
# Interactive Kiro browser SSO login helper that writes a credential in the
# *Kiro-Go* (https://github.com/Quorinex/Kiro-Go) account format instead of the
# CLIProxyAPI format. It drives the exact same hosted-portal PKCE sign-in as
# kiro-login-helper.py -- both the social (Google/GitHub via Cognito) leg and the
# enterprise external-IdP leg (Microsoft 365 / Entra ID / Azure AD) -- then maps
# the resolved tokens onto Kiro-Go's `config.Account` JSON shape (camelCase).
#
# Why a separate script:
#   * Kiro-Go reads `data/config.json` whose `accounts[]` entries are the Go
#     `config.Account` struct (camelCase keys: accessToken, refreshToken,
#     authMethod, region, profileArn, ...). CLIProxyAPI uses a different,
#     flattened snake_case schema, so the output file is not interchangeable.
#   * Kiro-Go's external-IdP (Azure AD) support lands via PR #131, which adds the
#     authMethod "external_idp" plus tokenEndpoint / issuerUrl / scopes refresh
#     material. This script emits exactly those keys so the credential can be
#     dropped straight into a Kiro-Go config.json (or merged with --config).
#
# Region handling (answers "does Kiro-Go detect the region?"):
#   Kiro-Go's data-plane region resolver (proxy/kiro_api.go: kiroRegionForProfile)
#   prefers the region embedded in the profileArn (arn:aws:codewhisperer:<region>),
#   then falls back to the account's `region` field, then to "us-east-1". So the
#   profileArn -- which we resolve eagerly via ListAvailableProfiles -- is what
#   actually drives the q.<region>.amazonaws.com endpoint. The default region here
#   (eu-central-1) is only the fallback used when the ARN carries no region.
#
# All OAuth/state-machine logic is reused from kiro-login-helper.py via importlib
# so there is a single source of truth for the (security-sensitive) login flow;
# this file only changes the default region and the final output assembly. Only
# the Python standard library is used.

import argparse
import copy
import importlib.util
import json
import os
import queue
import sys
import tempfile
import time
import uuid

# Kiro-Go's data-plane region resolver falls back to us-east-1, but per the
# request this helper defaults the *auth* region to eu-central-1. The eventual
# profileArn region (when present) still overrides this for data-plane calls.
DEFAULT_REGION = "eu-central-1"


# --- Reuse the shared login flow from kiro-login-helper.py --------------------

# load_helper imports the sibling kiro-login-helper.py as a module. The file name
# contains hyphens (not a valid identifier) so it cannot be imported with a plain
# `import`; importlib loads it by path. Importing it only defines functions and
# constants -- the interactive driver is guarded by `if __name__ == "__main__"`,
# so nothing runs as a side effect of the import.
def load_helper():
    here = os.path.dirname(os.path.abspath(__file__))
    helper_path = os.path.join(here, "kiro-login-helper.py")
    if not os.path.isfile(helper_path):
        raise SystemExit(
            "ERROR: required sibling file not found: %s\n"
            "       kiro-go-login.py reuses the login flow from kiro-login-helper.py;\n"
            "       keep both files in the same directory." % helper_path
        )
    spec = importlib.util.spec_from_file_location("kiro_login_helper", helper_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- Email extraction (for the Kiro-Go `email` field) -------------------------

# extract_email pulls the best human-readable email/identity from the access-token
# JWT, mirroring Kiro-Go's ExtractEmailFromJWT (prefers the real email claim, then
# the M365 sign-in name). Returns "" when nothing usable is present.
def extract_email(helper, access_token):
    claims = helper.decode_jwt_claims(access_token)
    for key in ("email", "preferred_username", "upn", "unique_name", "name"):
        val = (claims.get(key) or "").strip()
        if val:
            return val
    return ""


# --- Kiro-Go account assembly -------------------------------------------------

# build_kiro_go_account maps the resolved token bundle onto Kiro-Go's
# `config.Account` JSON (camelCase). Field choices mirror the account the Kiro-Go
# admin handler persists (proxy/handler.go) and PR #131's external-IdP additions:
#   * id / machineId            -> UUID v4 strings (auth.GenerateAccountID /
#                                  config.GenerateMachineId both emit UUID v4).
#   * authMethod                -> "social" or "external_idp" (exact literals).
#   * provider                  -> "Kiro SSO" (social) / "AzureAD" (external_idp),
#                                  matching the values Kiro-Go assigns.
#   * expiresAt                 -> Unix *seconds* (Go: time.Now().Unix()+expiresIn).
#   * enabled                   -> true so the pool dispatches it immediately.
#   * profileArn                -> resolved eagerly; carries the data-plane region.
#   * tokenEndpoint/issuerUrl/  -> external-IdP refresh material; only emitted for
#     scopes/clientId              authMethod=="external_idp".
def build_kiro_go_account(token, region, email, provider_override):
    auth_method = token["auth_method"]
    expires_at = 0
    if token.get("expires_in", 0) > 0:
        # Kiro-Go stores absolute expiry as a Unix-seconds timestamp.
        expires_at = int(time.time()) + int(token["expires_in"])

    account = {
        "id": str(uuid.uuid4()),
        "accessToken": token["access_token"],
        "refreshToken": token["refresh_token"],
        "authMethod": auth_method,
        "region": region,
        "expiresAt": expires_at,
        "enabled": True,
        "machineId": str(uuid.uuid4()),
    }
    if email:
        account["email"] = email
    # Provider label: explicit override wins, else the per-method default Kiro-Go uses.
    account["provider"] = provider_override or (
        "AzureAD" if auth_method == "external_idp" else "Kiro SSO"
    )
    if token.get("profile_arn"):
        account["profileArn"] = token["profile_arn"]
    # External-IdP (enterprise SSO) refresh material. Kiro-Go refreshes these
    # against the IdP token endpoint (refresh_token grant, public client) rather
    # than the AWS SSO OIDC endpoint, so all four fields must be persisted.
    if auth_method == "external_idp":
        if token.get("client_id"):
            account["clientId"] = token["client_id"]
        if token.get("token_endpoint"):
            account["tokenEndpoint"] = token["token_endpoint"]
        if token.get("issuer_url"):
            account["issuerUrl"] = token["issuer_url"]
        if token.get("scopes"):
            account["scopes"] = token["scopes"]
    return account


# --- Profile ARN resolution ---------------------------------------------------

# Canonical control region for ListAvailableProfiles. A CodeWhisperer/Q profile
# may be homed in a different region than the auth-region default (eu-central-1),
# and ListAvailableProfiles is a control-plane call -- resolving it here reliably
# returns the profile plus its real data-plane region inside the ARN.
PROFILE_RESOLUTION_REGION = "us-east-1"


# resolve_profile_arn resolves the runtime-mandatory profile ARN, trying the
# requested region first and then falling back to us-east-1. The eu-central-1
# auth default would otherwise hit q.eu-central-1.amazonaws.com and could return
# "no profiles available" for a profile homed elsewhere; the fallback makes
# resolution succeed regardless, and the returned ARN carries the true region.
def resolve_profile_arn(helper, access_token, region, external_idp, proxy_url):
    last_exc = None
    tried = []
    for candidate in (region, PROFILE_RESOLUTION_REGION):
        if candidate in tried:
            continue
        tried.append(candidate)
        try:
            return helper.list_available_profiles(access_token, candidate, external_idp, proxy_url)
        except Exception as exc:  # noqa: BLE001 - try the next region before giving up
            last_exc = exc
    raise last_exc


# --- config.json merge --------------------------------------------------------

# DEFAULT_KIRO_GO_CONFIG seeds a brand-new Kiro-Go config.json when --config
# points at a path that does not exist yet. Values mirror the defaults Kiro-Go
# itself writes on first launch (config/config.go: Load()).
DEFAULT_KIRO_GO_CONFIG = {
    "password": "changeme",
    "port": 8080,
    "host": "0.0.0.0",
    "requireApiKey": False,
    "accounts": [],
}


# merge_into_config inserts `account` into a Kiro-Go config.json `accounts[]`
# array, creating the file (with sane defaults) when absent. An existing account
# with the same non-empty email is replaced (re-login refreshes credentials);
# otherwise the account is appended. Returns ("replaced"|"appended", path).
def merge_into_config(config_path, account):
    config_path = os.path.abspath(config_path)
    # Deep-copy the default so the create-new-file path never mutates the
    # module-level template (a shallow copy would share its "accounts" list).
    data = copy.deepcopy(DEFAULT_KIRO_GO_CONFIG)
    if os.path.isfile(config_path):
        with open(config_path, "r", encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    "ERROR: %s is not valid JSON (%s); refusing to overwrite it."
                    % (config_path, exc)
                )
        if not isinstance(data, dict):
            raise SystemExit("ERROR: %s does not contain a JSON object." % config_path)

    accounts = data.get("accounts")
    if not isinstance(accounts, list):
        accounts = []
        data["accounts"] = accounts

    action = "appended"
    email = (account.get("email") or "").strip()
    if email:
        for existing in accounts:
            if isinstance(existing, dict) and (existing.get("email") or "").strip() == email:
                # Re-login: refresh only the credential/token fields we produce,
                # in place, so every operator-managed field already on the account
                # (proxyURL, weight, nickname, ban/usage/overage state, ...) is
                # preserved. The stable id/machineId are kept too so admin
                # references and per-account stats survive the re-login.
                preserved = {k: existing[k] for k in ("id", "machineId") if existing.get(k)}
                existing.update(account)
                existing.update(preserved)
                action = "replaced"
                break
    if action == "appended":
        accounts.append(account)

    parent = os.path.dirname(config_path) or "."
    os.makedirs(parent, exist_ok=True)
    # Atomic write: serialize to a sibling temp file (0600), then rename over the
    # target. An interrupt mid-write leaves the original config intact rather than
    # a truncated/empty file that would lose every account. The temp file is
    # created 0600 so refresh tokens are never briefly world-readable, and the
    # mode survives the rename even when the target pre-existed with looser perms.
    fd, tmp_path = tempfile.mkstemp(prefix=".config-", suffix=".json", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
        os.replace(tmp_path, config_path)
    except BaseException:
        # Never leave the half-written temp file behind on failure/interrupt.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return action, config_path


# --- Interactive driver -------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Interactive Kiro SSO login helper -> writes a Kiro-Go account JSON",
    )
    parser.add_argument("--email", default="", help="Override the email recorded on the account")
    parser.add_argument("--region", default=DEFAULT_REGION, help="AWS auth region (default: %(default)s)")
    parser.add_argument("--provider", default="", help="Override the provider label (e.g. GitHub, Google, AzureAD)")
    parser.add_argument(
        "--out-dir",
        default=os.getcwd(),
        help="Directory for the standalone account file (default: current directory)",
    )
    parser.add_argument(
        "--config",
        default="",
        help="Path to a Kiro-Go config.json to merge the account into (created if missing). "
        "When given, the standalone file is skipped unless --keep-standalone is set.",
    )
    parser.add_argument(
        "--keep-standalone",
        action="store_true",
        help="Also write the standalone account file even when --config is used",
    )
    parser.add_argument("--proxy", default="", help="Proxy URL for the OAuth/AWS calls (else HTTPS_PROXY env)")
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Seconds to wait for the browser sign-in (default: helper's 600s)",
    )
    args = parser.parse_args()

    helper = load_helper()
    proxy_url = args.proxy.strip() or None
    timeout = args.timeout if args.timeout is not None else helper.SOCIAL_LOGIN_TIMEOUT_SECONDS

    # Step 1: generate PKCE + state and build the hosted sign-in URL (reusing the
    # helper's constants so this stays byte-for-byte the same portal flow).
    verifier = helper.random_url_safe(96)
    state = helper.random_url_safe(32)
    challenge = helper.pkce_challenge(verifier)
    signin_url = helper.SOCIAL_SIGNIN_BASE_URL + "?" + helper.urllib.parse.urlencode(
        {
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": helper.SOCIAL_REDIRECT_URI,
            "redirect_from": helper.SOCIAL_REDIRECT_FROM,
        }
    )

    # Step 2: bind the loopback listener BEFORE printing the URL so the redirect
    # cannot race ahead of a ready listener.
    try:
        servers, flow_state = helper.start_listener(state, proxy_url)
    except RuntimeError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1

    # Step 3: print the step-by-step instructions. Reuse the helper's banner so
    # the Telegram bot link and styling stay identical across both entrypoints.
    helper.print_banner("Kiro-Go account · social + M365 / Entra ID SSO")
    print("STEP 1. Open the URL below in a *GUEST / INCOGNITO* browser window.")
    print("        (Incognito avoids a cached personal session hijacking the login.)")
    print()
    print("        Chrome/Edge:  Ctrl/Cmd+Shift+N      Firefox:  Ctrl/Cmd+Shift+P")
    print()
    print("  " + signin_url)
    print()
    print("STEP 2. Sign in (Google/GitHub, or your Microsoft 365 work/school account).")
    print('        When the page says "sign-in complete", return here.')
    print()
    print("Waiting for SSO authorization (timeout: %ds) ... " % timeout, flush=True)

    # Step 4: wait for the listener to capture the final result.
    try:
        result = flow_state.result_queue.get(timeout=timeout)
    except queue.Empty:
        for srv in servers:
            srv.shutdown()
        print("ERROR: SSO login timed out after %ds." % timeout, file=sys.stderr)
        return 1
    finally:
        for srv in servers:
            try:
                srv.shutdown()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass

    if isinstance(result, Exception):
        print("ERROR: %s" % result, file=sys.stderr)
        return 1

    # Step 5: exchange the captured authorization code for tokens.
    print("Authorization received. Exchanging code for tokens ...", flush=True)
    region = args.region.strip() or DEFAULT_REGION
    token = {"auth_method": result["kind"]}
    try:
        if result["kind"] == "external_idp":
            access, refresh, expires_in, _ = helper.exchange_external_idp_code(
                result["token_endpoint"],
                result["client_id"],
                result["code"],
                result["verifier"],
                result["redirect_uri"],
                result["scopes"],
                proxy_url,
            )
            token.update(
                access_token=access,
                refresh_token=refresh,
                expires_in=expires_in,
                profile_arn="",
                client_id=result["client_id"],
                token_endpoint=result["token_endpoint"],
                issuer_url=result["issuer_url"],
                scopes=result["scopes"],
            )
            external_idp = True
        else:
            access, refresh, expires_in, profile_arn = helper.exchange_social_code(
                result["code"], verifier, proxy_url
            )
            token.update(
                access_token=access,
                refresh_token=refresh,
                expires_in=expires_in,
                profile_arn=profile_arn,
            )
            external_idp = False
    except Exception as exc:  # noqa: BLE001 - surface any exchange failure
        print("ERROR: token exchange failed: %s" % exc, file=sys.stderr)
        return 1

    # Step 6: resolve the runtime-mandatory profile ARN if the exchange didn't
    # provide one (always the case for external IdP). Resolving it eagerly means
    # the saved account already carries the data-plane region in its ARN, so
    # Kiro-Go does not have to resolve it lazily on first use.
    if not token.get("profile_arn"):
        print("Resolving CodeWhisperer profile ARN ...", flush=True)
        try:
            token["profile_arn"] = resolve_profile_arn(
                helper, token["access_token"], region, external_idp, proxy_url
            )
        except Exception as exc:  # noqa: BLE001 - profile is mandatory; report clearly
            print("ERROR: failed to resolve profile ARN: %s" % exc, file=sys.stderr)
            print(
                "       (For M365: the account must be provisioned for Kiro/CodeWhisperer.)",
                file=sys.stderr,
            )
            return 1

    # If the ARN carries a region, prefer it: Kiro-Go derives the data-plane host
    # from the ARN region first, so the saved `region` field should agree with it.
    arn_region = helper.region_from_profile_arn(token["profile_arn"])
    if arn_region:
        region = arn_region

    # Step 7: assemble the Kiro-Go account and persist it.
    email = args.email.strip() or extract_email(helper, token["access_token"])
    provider_override = args.provider.strip()
    account = build_kiro_go_account(token, region, email, provider_override)

    written = []  # (label, path) pairs to report at the end
    if args.config.strip():
        try:
            action, cfg_path = merge_into_config(args.config.strip(), account)
        except SystemExit:
            raise
        except Exception as exc:  # noqa: BLE001 - surface any merge failure
            print("ERROR: failed to update %s: %s" % (args.config, exc), file=sys.stderr)
            return 1
        written.append(("config.json (%s)" % action, cfg_path))

    # Write the standalone single-account file unless a --config merge already
    # ran without --keep-standalone.
    if not args.config.strip() or args.keep_standalone:
        label = email or account["id"]
        safe = helper.sanitize_file_component(label) or ("kiro-%d" % int(time.time() * 1000))
        out_dir = os.path.abspath(args.out_dir)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "kiro-go-account_%s.json" % safe)
        # 0600: the file holds the refresh token; restrict it to the owner.
        fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(account, fh, indent=2)
            fh.write("\n")
        written.append(("standalone account", out_path))

    print()
    print(bar)
    print("  Kiro-Go credential created!")
    print("  Account : %s" % (email or "(no email claim)"))
    print("  Method  : %s" % account["authMethod"])
    print("  Provider: %s" % account["provider"])
    print("  Region  : %s" % region)
    print("  Profile : %s" % token["profile_arn"])
    for label, path in written:
        print("  Saved   : %s  [%s]" % (path, label))
    print(bar)
    print()
    if args.config.strip():
        print("Next: (re)start Kiro-Go pointed at this config, e.g.")
        print("  CONFIG_PATH='%s' ./kiro-go" % os.path.abspath(args.config.strip()))
    else:
        print("Next: add this account to your Kiro-Go data/config.json. Either")
        print("  - paste the object into the config.json \"accounts\": [ ... ] array, or")
        print("  - re-run with --config /path/to/Kiro-Go/data/config.json to merge it automatically.")
    if account["authMethod"] == "external_idp":
        print()
        print("Note: external_idp (Microsoft 365 / Entra ID) refresh needs Kiro-Go PR #131")
        print("      (tokenEndpoint/issuerUrl/scopes + the external_idp refresh branch).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
