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
# All OAuth/state-machine logic (including the optional CloakBrowser auto-open)
# is reused from kiro-login-helper.py via importlib so there is a single source
# of truth for the (security-sensitive) login flow; this file only changes the
# default region and the final output assembly.

import argparse
import base64
import copy
import hashlib
import hmac
import importlib.util
import json
import os
import queue
import re
import shutil
import struct
import sys
import tempfile
import time
import uuid

# CloakBrowser returns a Playwright *sync* BrowserContext for the automated M365
# driver below, so the Playwright sync error types are what a wait/timeout
# raises. Imported up front for precise except clauses; fall back to a bare
# Exception alias if Playwright is laid out oddly (mirrors kiro-web-login.py).
try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import Error as PlaywrightError
except Exception:  # noqa: BLE001 - keep the script importable even if types move
    class PlaywrightTimeoutError(Exception):
        pass

    class PlaywrightError(Exception):
        pass

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
    account["provider"] = provider_override or {
        "external_idp": "AzureAD",
        "idc": "IAM Identity Center",
    }.get(auth_method, "Kiro SSO")
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
    # AWS SSO OIDC (IAM Identity Center) refresh material. Kiro-Go refreshes these against
    # the oidc.<region>.amazonaws.com token endpoint (refresh_token grant), which needs the
    # registered clientId + clientSecret; startUrl records the tenant.
    if auth_method == "idc":
        if token.get("client_id"):
            account["clientId"] = token["client_id"]
        if token.get("client_secret"):
            account["clientSecret"] = token["client_secret"]
        if token.get("start_url"):
            account["startUrl"] = token["start_url"]
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


# --- Persistence + reporting (shared by every login method) -------------------

# persist_and_report writes the assembled Kiro-Go account (merging into --config and/or a
# standalone file per the flags) and prints the framed success summary. Returns a process
# exit code. Shared by the hosted-portal and IAM Identity Center paths.
def persist_and_report(args, helper, account, email, region, profile_arn):
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

    rule = "─" * 78
    print()
    print(rule)
    print("  Kiro-Go credential created!")
    print("  Account : %s" % (email or "(no email claim)"))
    print("  Method  : %s" % account["authMethod"])
    print("  Provider: %s" % account["provider"])
    print("  Region  : %s" % region)
    print("  Profile : %s" % profile_arn)
    for label, path in written:
        print("  Saved   : %s  [%s]" % (path, label))
    print(rule)
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


# run_idc_kiro_go drives the AWS IAM Identity Center device-authorization login (reusing the
# helper's OIDC flow) and persists the result as a Kiro-Go account. Returns an exit code.
def run_idc_kiro_go(args, helper, start_url, proxy_url, timeout):
    start_url = (start_url or "").strip()
    if not start_url:
        print("ERROR: an IAM Identity Center start URL is required for IdC login.", file=sys.stderr)
        return 1
    region = args.region or helper.prompt_idc_region(DEFAULT_REGION)
    if not helper.valid_aws_region(region):
        print("ERROR: invalid AWS region %r (expected e.g. us-east-1)." % region, file=sys.stderr)
        return 1

    helper.print_banner("Kiro-Go account · AWS IAM Identity Center SSO")
    try:
        creds = helper.idc_login(start_url, region, proxy_url, timeout)
    except Exception as exc:  # noqa: BLE001 - surface any registration/device/poll failure
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1

    token = {
        "auth_method": "idc",
        "access_token": creds["access_token"],
        "refresh_token": creds["refresh_token"],
        "expires_in": creds["expires_in"],
        "profile_arn": "",
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
        "start_url": start_url,
    }

    print("Resolving CodeWhisperer profile ARN ...", flush=True)
    try:
        # IDC tokens are normal AWS SSO tokens: resolve with external_idp=False (no header).
        token["profile_arn"] = resolve_profile_arn(
            helper, token["access_token"], region, False, proxy_url
        )
    except Exception as exc:  # noqa: BLE001 - profile is mandatory; report clearly
        print("ERROR: failed to resolve profile ARN: %s" % exc, file=sys.stderr)
        return 1

    arn_region = helper.region_from_profile_arn(token["profile_arn"])
    if arn_region:
        region = arn_region

    # The IDC access token is opaque (no email claim), so label the account by the
    # start-URL directory id unless the operator supplied --email.
    email = args.email.strip() or helper.directory_id_from_start_url(start_url)
    account = build_kiro_go_account(token, region, email, args.provider.strip())
    return persist_and_report(args, helper, account, email, region, token["profile_arn"])


# --- Automated M365 / Entra ID login -------------------------------------------
#
# Fully-automated variant of the "Your organization" enterprise leg: instead of
# a human clicking through the Kiro chooser + Microsoft login pages, a
# disposable CloakBrowser drives the whole thing -- email, password, and (when
# needed) TOTP-based MFA computed from a stored secret. On an account's first
# run (no MFA enrolled yet), Microsoft may force enrollment ("Let's keep your
# account secure"); this driver walks the "set up a different authentication
# app" path, captures the manual TOTP secret Microsoft displays, and persists
# it back into the accounts file (upgrading an `email|password` line to
# `email|password|mfa_secret`) so future runs can compute codes without
# re-enrolling. Once the browser leg lands the local OAuth listener's leg-2
# result, the rest of the flow (token exchange, profile ARN resolution, Kiro-Go
# JSON assembly) is the exact same code the interactive path uses.

LOCATOR_TIMEOUT_MS = 30_000

M365_SUCCESS = "success"
M365_SUCCESS_MFA_SETUP = "success_after_mfa_setup"
M365_MANUAL = "manual_action_required"
M365_TIMEOUT = "timeout"
M365_ERROR = "error"


# --- TOTP (RFC 6238), stdlib only ----------------------------------------------

# totp_code computes the current 6-digit time-based one-time password for a
# base32 secret, matching what Microsoft Authenticator (or any TOTP app) would
# show right now. No third-party dependency (pyotp) needed -- HMAC-SHA1 over a
# 30-second time-step counter is the entire RFC 6238 algorithm.
def totp_code(secret, period=30, digits=6):
    raw = secret.strip().upper().replace(" ", "")
    padded = raw + "=" * ((8 - len(raw) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // period)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


# --- M365 accounts file --------------------------------------------------------

# M365Account bundles the email/password/mfa_secret fields plus the source
# line index, mirroring kiro-web-login.py's Account so a newly-captured MFA
# secret can be written back to the exact line it came from. mfa_secret is ""
# until the first automated run enrolls MFA and captures it.
class M365Account:
    def __init__(self, email, password, mfa_secret, line_index):
        self.email = email
        self.password = password
        self.mfa_secret = mfa_secret
        self.line_index = line_index


# _EMAIL_RE matches a plain email as the first field. It deliberately forbids
# whitespace and requires a dotted domain, so decorative/header lines that
# happen to contain "|" and "@" ("Format: portal_url|...", "Contact: a@b desc")
# are rejected while real "user@host.tld|..." lines pass.
_EMAIL_RE = re.compile(r"^[^@\s|]+@[^@\s|]+\.[^@\s|]+$")


# parse_m365_accounts reads an `email|password[|mfa_secret]` file (mfa_secret is
# optional -- absent until this driver enrolls MFA and fills it in). It tolerates
# noise: blank lines, count headers ("Accounts: 10"), a "Format:" legend line
# (which itself contains "|"), and box-drawing separators ("━━━ TK 1 ━━━") are
# all skipped. A line counts as a credential only if it has a "|" and its first
# field is a syntactically valid email address.
def parse_m365_accounts(path):
    with open(path, "r", encoding="utf-8") as fh:
        all_lines = fh.read().split("\n")

    accounts = []
    for idx, line in enumerate(all_lines):
        stripped = line.strip()
        if not stripped or "|" not in stripped:
            continue
        # "|" is the field delimiter, so a password cannot itself contain "|"
        # (same invariant as kiro-web-login.py's accounts parser). Fields are
        # therefore email | password | [mfa_secret], mfa_secret optional.
        parts = stripped.split("|")
        email = parts[0].strip()
        if not _EMAIL_RE.match(email):
            continue
        password = parts[1] if len(parts) > 1 else ""
        mfa_secret = parts[2].strip() if len(parts) > 2 else ""
        accounts.append(M365Account(email, password, mfa_secret, idx))
    return accounts, all_lines


# update_m365_secret rewrites the accounts file in place, upgrading the source
# line for `account` to `email|password|mfa_secret` (adding the third field if
# the line didn't have one yet). Atomic write (temp file + rename, 0600): this
# file holds live passwords and TOTP seeds.
def update_m365_secret(path, account, secret, all_lines):
    all_lines[account.line_index] = "%s|%s|%s" % (account.email, account.password, secret)
    account.mfa_secret = secret

    data = "\n".join(all_lines)
    parent = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".m365-accounts-", suffix=".txt", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --- Browser step helpers -------------------------------------------------------

def step(msg, delay):
    print("  -> %s" % msg, flush=True)
    if delay > 0:
        time.sleep(delay)


# click_by_text clicks the first visible button/link whose trimmed text matches
# one of `texts` (case-insensitive, substring) -- both the AWS Cloudscape and
# Microsoft identity pages use plain text buttons with no stable id/class.
def click_by_text(page, texts, timeout_ms=LOCATOR_TIMEOUT_MS):
    lowered = [t.lower() for t in texts]
    deadline = time.time() + timeout_ms / 1000.0
    while time.time() < deadline:
        for el in page.query_selector_all("button, a, [role=button]"):
            try:
                if not el.is_visible():
                    continue
                label = (el.inner_text() or "").strip().lower()
            except PlaywrightError:
                continue
            if any(t in label for t in lowered):
                el.click()
                return True
        page.wait_for_timeout(250)
    return False


def fill_input(page, selector, value, timeout_ms=LOCATOR_TIMEOUT_MS):
    page.wait_for_selector(selector, timeout=timeout_ms, state="visible")
    page.locator(selector).first.fill(value)


# _click_selector clicks the first visible element matched by a CSS selector.
# Returns True on click, False if no visible match exists right now (no wait).
def _click_selector(page, selector):
    try:
        for el in page.query_selector_all(selector):
            if el.is_visible():
                el.click()
                return True
    except PlaywrightError:
        pass
    return False


# _click_ests_primary clicks Microsoft's ESTS primary button. Every step of the
# login.microsoftonline.com flow renders it as `<input type=submit id=idSIButton9>`
# ("Next" on the username page, "Sign in" on the password page, "Yes" on
# "Stay signed in?") -- crucially an <input>, not a <button>, so click_by_text
# (which scans button/a/[role=button]) never matches it, and its text would
# collide with the "Sign in with another account" link anyway. Selecting the
# stable id is the correct, unambiguous action. Returns True on click.
def _click_ests_primary(page):
    return _click_selector(page, "#idSIButton9")


def _visible(page, selector):
    try:
        el = page.query_selector(selector)
        return bool(el and el.is_visible())
    except PlaywrightError:
        return False


# _click_next advances a "Next"/continue step, trying the ESTS primary button
# (#idSIButton9, an <input> that click_by_text can't see) first, then the plain
# text button used on the non-ESTS mysignins.microsoft.com enrollment screens.
def _click_next(page, timeout_ms=8000):
    if _click_ests_primary(page):
        return True
    return click_by_text(page, ["Next"], timeout_ms=timeout_ms)


def _body_text(page):
    try:
        return (page.inner_text("body") or "").lower()
    except PlaywrightError:
        return ""


def _any(haystack, needles):
    return any(n in haystack for n in needles)


# _fill_sole_code_input fills the single visible text/tel/number input on the
# page (Microsoft's "Enter the code" screens render exactly one). Returns False
# if no such input is found.
def _fill_sole_code_input(page, code):
    selector = "input[type=tel], input[type=text], input[type=number]"
    try:
        page.wait_for_selector(selector, timeout=LOCATOR_TIMEOUT_MS, state="visible")
    except PlaywrightTimeoutError:
        return False
    inputs = [i for i in page.query_selector_all(selector) if i.is_visible()]
    if not inputs:
        return False
    inputs[0].fill(code)
    return True


# _read_secret_key finds Microsoft's manual TOTP secret on the "Can't scan the
# QR code?" page. It renders as a bare run of base32 characters right after a
# "Secret key:" label with no stable id (build-hashed React classes), so leaf
# text nodes are scanned for that shape instead. Base32 is case-insensitive and
# Microsoft may space it into groups, so spaces are stripped and either case is
# accepted; totp_code() normalizes to uppercase before decoding.
def _read_secret_key(page):
    try:
        texts = page.eval_on_selector_all(
            "body *",
            "els => els.filter(e => e.children.length === 0).map(e => (e.innerText || '').trim())",
        )
    except PlaywrightError:
        return ""
    for t in texts:
        candidate = (t or "").replace(" ", "")
        if re.fullmatch(r"[A-Za-z2-7]{16,32}", candidate):
            return candidate
    return ""


# _handle_mfa_enrollment walks Microsoft's forced MFA-enrollment nudge
# ("Let's keep your account secure") via the manual/other-authenticator-app
# path, submits a TOTP code computed from the freshly revealed secret, and
# returns that secret so the caller can persist it. Raises RuntimeError with a
# descriptive message if any expected step doesn't appear.
def _handle_mfa_enrollment(page, delay):
    step("MFA enrollment requested -- setting up an authenticator app", delay)
    # "Let's keep your account secure" is an ESTS page (its Next is #idSIButton9);
    # the rest are mysignins.microsoft.com pages with plain <button>s.
    if not _click_next(page):
        raise RuntimeError("could not click Next on the MFA enrollment prompt")

    # "Install Microsoft Authenticator" screen -> switch to the manual path.
    if not click_by_text(page, ["Set up a different authentication app"], timeout_ms=8000):
        raise RuntimeError('could not find "Set up a different authentication app"')
    step('chose "Set up a different authentication app"', delay)

    # "Set up your account in app" -> Next -> renders the QR code.
    if not _click_next(page):
        raise RuntimeError("could not click Next past the app-setup intro")

    # "Scan the QR code" -> "Can't scan the QR code?" reveals the manual secret.
    if not click_by_text(page, ["Can't scan the QR code?", "Can't scan"], timeout_ms=8000):
        raise RuntimeError('could not find "Can\'t scan the QR code?"')
    step("revealed manual setup secret key", delay)

    secret = _read_secret_key(page)
    if not secret:
        raise RuntimeError("secret key text not found on the manual setup page")

    if not _click_next(page):
        raise RuntimeError("could not click Next past the secret-key page")

    # "Enter the code" -> the TOTP computed from the secret just captured.
    step("entering TOTP code from the new secret", delay)
    if not _fill_sole_code_input(page, totp_code(secret)):
        raise RuntimeError('could not find the "Enter the code" input')
    if not _click_next(page):
        raise RuntimeError("could not submit the verification code")

    # "Authenticator app added" -> Done. Settle before the caller re-inspects
    # page state so a stale "enter the code" match can't double-submit.
    click_by_text(page, ["Done"], timeout_ms=8000)
    page.wait_for_timeout(1000)
    return secret


# run_m365_login drives the browser through the enterprise-IdP leg for one
# account inside a fresh CloakBrowser page: kiro.dev chooser -> "Your
# organization" -> email -> Microsoft password -> (MFA setup or TOTP code, if
# challenged) -> resolves once the local OAuth listener captures the leg-2
# result. Returns (outcome, detail, new_mfa_secret_or_None, queued_result).
# queued_result is the dict handed to the listener's result_queue (needed by
# the caller to finish the token exchange) -- it must be returned here since
# result_queue.get_nowait() dequeues (and would otherwise discard) it.
def run_m365_login(page, account, signin_url, flow_state, delay, timeout):
    deadline = time.time() + timeout

    step("open %s" % signin_url, delay)
    page.goto(signin_url, wait_until="domcontentloaded", timeout=LOCATOR_TIMEOUT_MS)
    click_by_text(page, ["Decline", "Accept all cookies", "Accept"], timeout_ms=4000)

    step('click "Your organization"', delay)
    if not click_by_text(page, ["Your organization"]):
        return M365_ERROR, 'could not find the "Your organization" button', None, None

    step("enter email: %s" % account.email, delay)
    fill_input(page, "#idp-email-input, input[name=email]", account.email)
    step("click Continue", delay)
    if not click_by_text(page, ["Continue"]):
        return M365_ERROR, "could not find the email Continue button", None, None

    step("waiting for Microsoft sign-in", delay)

    # Poll-driven state machine for the Microsoft (login.microsoftonline.com)
    # side. The exact page sequence varies by tenant/account state -- username
    # page may be skipped via login_hint, MFA may be enrolled-once vs. prompted,
    # a "Stay signed in?" (KMSI) page may or may not appear -- so we react to
    # whichever page is showing rather than assuming a fixed order. All ESTS
    # pages submit via the same primary button (#idSIButton9); its text ("Next"
    # / "Sign in" / "Yes") and DOM order collide with links, so it must be
    # clicked by id, not text.
    new_secret = None
    handled_enrollment = False
    password_submitted = False
    # TOTP is only valid once per 30s window, and a wrong/rejected code leaves
    # the same "enter the code" page up. Track which windows we have already
    # submitted so the loop waits for a fresh code instead of hammering the same
    # one every iteration, and cap distinct attempts so a bad secret / clock
    # skew fails fast instead of spinning until the overall timeout.
    code_windows_tried = set()
    MAX_CODE_ATTEMPTS = 3
    while time.time() < deadline:
        # The listener may already have captured leg-2 -- a session with no MFA
        # challenge goes straight from password to the localhost redirect. Check
        # first, non-blocking, every iteration.
        try:
            result = flow_state.result_queue.get_nowait()
        except queue.Empty:
            result = None
        if result is not None:
            if isinstance(result, Exception):
                return M365_ERROR, str(result), new_secret, None
            outcome = M365_SUCCESS_MFA_SETUP if handled_enrollment else M365_SUCCESS
            return outcome, "signed in", new_secret, result

        body = _body_text(page)
        if os.environ.get("KIRO_M365_DEBUG"):
            print("    [debug] url=%s body[:120]=%r" % (page.url, body[:120]), flush=True)

        # Microsoft rejected the credentials -- fail fast rather than spin until
        # timeout on a page that will never advance.
        if _any(body, ["your account or password is incorrect",
                       "that microsoft account doesn't exist",
                       "we couldn't find an account", "this username may be incorrect"]):
            return M365_ERROR, "Microsoft rejected the email/password", new_secret, None

        # Username page (login_hint usually skips it, but handle it when shown):
        # a visible email field with no password field yet.
        if _visible(page, "input[name=loginfmt]") and not _visible(page, "input[name=passwd]"):
            step("enter username", delay)
            fill_input(page, "input[name=loginfmt]", account.email)
            _click_ests_primary(page)
            page.wait_for_timeout(800)
            continue

        # Password page.
        if _visible(page, "input[name=passwd]") and not password_submitted:
            step("enter password", delay)
            fill_input(page, "input[name=passwd]", account.password)
            _click_ests_primary(page)
            password_submitted = True
            page.wait_for_timeout(800)
            continue

        # Forced MFA enrollment nudge.
        if not handled_enrollment and _any(body, ["keep your account secure", "more information required"]):
            try:
                new_secret = _handle_mfa_enrollment(page, delay)
            except RuntimeError as exc:
                return M365_ERROR, str(exc), new_secret, None
            handled_enrollment = True
            continue

        # MFA code prompt (already-enrolled account): an ESTS one-time-code page
        # (input[name=otc]) or the generic "enter the code" screen.
        if _visible(page, "input[name=otc]") or _any(body, ["enter the code", "enter code",
                                                            "enter your code", "verification code"]):
            secret = new_secret or account.mfa_secret
            if not secret:
                return M365_MANUAL, "MFA code requested but no mfa_secret is stored for this account", new_secret, None
            window = int(time.time() // 30)
            if window in code_windows_tried:
                # Already submitted this window's code and the prompt is still
                # up; wait for the next 30s window rather than resubmit the same
                # (rejected) code.
                page.wait_for_timeout(1000)
                continue
            if len(code_windows_tried) >= MAX_CODE_ATTEMPTS:
                return M365_ERROR, "MFA code rejected across %d codes (bad secret or clock skew?)" % MAX_CODE_ATTEMPTS, new_secret, None
            code_windows_tried.add(window)
            step("entering TOTP code from the stored secret", delay)
            code = totp_code(secret)
            # Prefer the ESTS one-time-code field by name; fall back to the sole
            # visible code input on non-ESTS (mysignins) code screens.
            if _visible(page, "input[name=otc]"):
                page.locator("input[name=otc]").first.fill(code)
            elif not _fill_sole_code_input(page, code):
                return M365_ERROR, "found code prompt but no input field", new_secret, None
            if not _click_ests_primary(page):
                click_by_text(page, ["Verify", "Next"], timeout_ms=5000)
            page.wait_for_timeout(1200)
            continue

        # "Stay signed in?" (KMSI). Click No (#idBtn_Back) -- the profile is
        # disposable, so there's no benefit to persisting the session.
        if _any(body, ["stay signed in"]):
            if not _click_selector(page, "#idBtn_Back"):
                _click_ests_primary(page)
            page.wait_for_timeout(800)
            continue

        page.wait_for_timeout(500)

    return M365_TIMEOUT, "no terminal state reached before timeout", new_secret, None


# drive_m365_account launches a brand-new CloakBrowser with an empty temporary
# profile, drives run_m365_login, persists any newly-captured MFA secret, and
# -- on success -- finishes the login exactly like the interactive path
# (token exchange, profile ARN resolution, Kiro-Go JSON assembly). Returns an
# exit code.
def drive_m365_account(args, helper, account, accounts_path, all_lines, proxy_url, delay, timeout, headless):
    from cloakbrowser import launch_persistent_context

    region = args.region or DEFAULT_REGION

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

    try:
        servers, flow_state = helper.start_listener(state, proxy_url)
    except RuntimeError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1

    profile_dir = tempfile.mkdtemp(prefix="kiro-go-m365-")
    ctx = None
    try:
        ctx = launch_persistent_context(profile_dir, headless=headless)
        # A persistent context may open with a first blank page; reuse it to
        # avoid leaving an extra tab around.
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        outcome, detail, new_secret, queued_result = run_m365_login(
            page, account, signin_url, flow_state, delay, timeout
        )
    except Exception as exc:  # noqa: BLE001 - report any driver/launch failure
        outcome, detail, new_secret, queued_result = M365_ERROR, str(exc), None, None
    finally:
        if ctx is not None:
            try:
                ctx.close()
            except Exception:  # noqa: BLE001 - best-effort browser shutdown
                pass
        # Wipe the disposable profile so no cookies/cache/localStorage survive.
        shutil.rmtree(profile_dir, ignore_errors=True)
        # shutdown() stops the serve loop but leaves the listening socket bound;
        # server_close() releases the port so the next account (--all) can rebind
        # 127.0.0.1:3128 instead of hitting "Address already in use".
        for srv in servers:
            try:
                srv.shutdown()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
            try:
                srv.server_close()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass

    if new_secret:
        try:
            update_m365_secret(accounts_path, account, new_secret, all_lines)
            print("  -> accounts file updated with MFA secret for %s" % account.email, flush=True)
        except Exception as exc:  # noqa: BLE001 - login already progressed; report, don't discard it
            print("  !! WARNING: could not persist MFA secret: %s" % exc, file=sys.stderr)
            print("  !! MFA secret for %s: %s" % (account.email, new_secret), file=sys.stderr)

    print("  == %s: %s" % (outcome, detail))
    if outcome not in (M365_SUCCESS, M365_SUCCESS_MFA_SETUP) or queued_result is None:
        return 1

    return finish_external_idp_result(args, helper, queued_result, None, proxy_url, region)


# run_m365_batch resolves which account(s) from --m365-accounts-file to log in
# (--index / --username / --all, default: the first account), then drives each
# one through drive_m365_account with a fresh disposable CloakBrowser. Returns
# an exit code: 0 only if every selected account signed in successfully.
def run_m365_batch(args, helper, proxy_url):
    accounts_path = args.m365_accounts_file.strip()
    if not os.path.isfile(accounts_path):
        print("ERROR: M365 accounts file not found: %s" % accounts_path, file=sys.stderr)
        return 2

    accounts, all_lines = parse_m365_accounts(accounts_path)
    if not accounts:
        print("ERROR: no `email|password[|mfa_secret]` lines found in %s" % accounts_path, file=sys.stderr)
        return 2

    if args.all:
        targets = accounts
    elif args.username is not None:
        targets = [a for a in accounts if a.email == args.username]
        if not targets:
            print("ERROR: no account with email %r in %s" % (args.username, accounts_path), file=sys.stderr)
            return 2
    else:
        idx = args.index if args.index is not None else 1
        if idx < 1 or idx > len(accounts):
            print("ERROR: --index %d out of range (1..%d)" % (idx, len(accounts)), file=sys.stderr)
            return 2
        targets = [accounts[idx - 1]]

    timeout = args.timeout if args.timeout is not None else helper.SOCIAL_LOGIN_TIMEOUT_SECONDS
    helper.print_banner("Kiro-Go account · automated M365 / Entra ID SSO")
    print("kiro-go M365 login  |  %d account(s)  |  step-delay=%.1fs  |  %s" % (
        len(targets), args.step_delay, "headless" if args.headless else "headed"))

    results = []
    for i, account in enumerate(targets, 1):
        print("\n[%d/%d] %s" % (i, len(targets), account.email))
        code = drive_m365_account(
            args, helper, account, accounts_path, all_lines, proxy_url, args.step_delay, timeout, args.headless
        )
        results.append((account.email, code))

    print("\n" + "-" * 70)
    ok = sum(1 for _, code in results if code == 0)
    for email, code in results:
        print("  %-34s %s" % (email, "ok" if code == 0 else "FAILED"))
    print("-" * 70)
    print("  %d/%d signed in" % (ok, len(results)))
    return 0 if ok == len(results) else 1


# finish_external_idp_result exchanges the captured authorization code for
# tokens, resolves the runtime-mandatory profile ARN, and assembles + persists
# the Kiro-Go account JSON. Shared by the interactive driver (result["kind"]
# may be "social" or "external_idp", hence the outer `verifier` for the social
# leg) and the automated M365 driver (always "external_idp", so `verifier` is
# unused there and callers pass None). Returns an exit code.
def finish_external_idp_result(args, helper, result, verifier, proxy_url, region):
    print("Authorization received. Exchanging code for tokens ...", flush=True)
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

    # Resolve the runtime-mandatory profile ARN if the exchange didn't provide
    # one (always the case for external IdP). Resolving it eagerly means the
    # saved account already carries the data-plane region in its ARN, so
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

    # If the ARN carries a region, prefer it: Kiro-Go derives the data-plane
    # host from the ARN region first, so the saved `region` field should agree.
    arn_region = helper.region_from_profile_arn(token["profile_arn"])
    if arn_region:
        region = arn_region

    email = args.email.strip() or extract_email(helper, token["access_token"])
    account = build_kiro_go_account(token, region, email, args.provider.strip())
    return persist_and_report(args, helper, account, email, region, token["profile_arn"])


# --- Interactive driver -------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Interactive Kiro SSO login helper -> writes a Kiro-Go account JSON",
    )
    parser.add_argument("--email", default="", help="Override the email recorded on the account")
    parser.add_argument(
        "--region",
        default=None,
        choices=("us-east-1", "eu-central-1"),
        help="AWS auth region; omit to be prompted interactively",
    )
    parser.add_argument("--provider", default="", help="Override the provider label (e.g. GitHub, Google, AzureAD)")
    parser.add_argument(
        "--idc-start-url",
        default="",
        help="AWS IAM Identity Center start URL (e.g. https://d-1234567890.awsapps.com/start). "
        "When set, runs the IdC device-authorization login instead of the hosted SSO portal.",
    )
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
    parser.add_argument(
        "--m365-accounts-file",
        default="",
        help="Path to an `email|password[|mfa_secret]` file. When set, runs the fully-automated "
        "headed-browser M365/Entra ID SSO login instead of the interactive/manual flow.",
    )
    m365_selector = parser.add_mutually_exclusive_group()
    m365_selector.add_argument("--index", type=int, default=None,
                                help="1-based index of the --m365-accounts-file account to log in (default: 1)")
    m365_selector.add_argument("--username", default=None,
                                help="Log in the --m365-accounts-file account with this email")
    m365_selector.add_argument("--all", action="store_true",
                                help="Log in every account in --m365-accounts-file, one fresh browser each")
    parser.add_argument("--step-delay", type=float, default=1.0,
                        help="Seconds to pause around each M365 browser step for visibility (default: 1.0). "
                             "Use 0 for a fast production run.")
    parser.add_argument("--headless", action="store_true",
                        help="Run the M365 browser headless (default: headed, so you can watch)")
    args = parser.parse_args()

    helper = load_helper()
    proxy_url = args.proxy.strip() or None

    if args.m365_accounts_file.strip():
        return run_m365_batch(args, helper, proxy_url)
    timeout = args.timeout if args.timeout is not None else helper.SOCIAL_LOGIN_TIMEOUT_SECONDS

    # Method selection: an explicit --idc-start-url forces the IAM Identity Center device
    # flow; otherwise ask interactively (defaulting to the hosted SSO portal) so existing
    # non-interactive use is unchanged.
    idc_start_url = args.idc_start_url.strip()
    if idc_start_url:
        method = "idc"
    else:
        method, idc_start_url = helper.prompt_login_method()
    if method == "idc":
        return run_idc_kiro_go(args, helper, idc_start_url, proxy_url, timeout)

    region = args.region or helper.prompt_region(DEFAULT_REGION)

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

    # Step 3: open the sign-in URL. Reuse the helper's banner and CloakBrowser
    # launcher so styling and the disposable-profile behavior stay identical
    # across both entrypoints.
    helper.print_banner("Kiro-Go account · social + M365 / Entra ID SSO")
    # cloak_cleanup is acquired before the try so the finally below reliably closes
    # the browser and wipes its profile even if a print() or Step 4's wait raises.
    cloak_cleanup = helper.open_in_cloakbrowser(signin_url)
    try:
        if cloak_cleanup:
            print("STEP 1. A fresh browser window has been opened for you.")
            print("        (New profile, no prior data; it is wiped once sign-in finishes.)")
        else:
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
        result = flow_state.result_queue.get(timeout=timeout)
    except queue.Empty:
        for srv in servers:
            srv.shutdown()
        print("ERROR: SSO login timed out after %ds." % timeout, file=sys.stderr)
        return 1
    finally:
        # shutdown() stops the serve loop; server_close() releases the bound
        # socket so a later run can rebind 127.0.0.1:3128.
        for srv in servers:
            try:
                srv.shutdown()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
            try:
                srv.server_close()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
        if cloak_cleanup:
            cloak_cleanup()

    if isinstance(result, Exception):
        print("ERROR: %s" % result, file=sys.stderr)
        return 1

    # Steps 5-7 (token exchange, profile ARN resolution, account assembly +
    # persistence) are shared with the automated M365 driver.
    return finish_external_idp_result(args, helper, result, verifier, proxy_url, region)


if __name__ == "__main__":
    sys.exit(main())
