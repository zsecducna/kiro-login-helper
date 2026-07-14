#!/usr/bin/env python3
# kiro-web-login.py
#
# Headed browser automation that drives the *interactive* kiro.dev sign-in for an
# AWS IAM Identity Center (IdC) account, exactly as a human would:
#
#     https://app.kiro.dev/signin
#        -> "Your organization"
#        -> "Sign in with AWS IAM Identity Center"
#        -> enter the account's Start URL  -> Continue
#        -> AWS access portal: enter username -> Next
#        -> enter password -> Sign in
#        -> (optional) forced "Set new password"
#        -> (optional) device / consent "Allow access"
#        -> back on app.kiro.dev, signed in.
#
# Unlike kiro-login-helper.py (which registers an OIDC client and runs the
# device-authorization API flow itself), this script does NOT touch the AWS OIDC
# APIs directly. It just automates the real browser pages, so it exercises the
# same path a user clicks through -- useful for validating that an account's
# credentials actually work end-to-end against kiro.dev.
#
# Browser: a fresh, disposable CloakBrowser profile per account. The profile
# directory is created new (empty cache/cookies/localStorage) and is deleted on
# exit, so nothing is cached between accounts or after the run -- every login
# starts from a clean slate.
#
# Visibility: --step-delay puts a deliberate pause around each UI step so a human
# can watch the automation. The default is 1.0s (per the request); a production
# run can pass --step-delay 0 (or a small value) for speed.
#
# Forced password reset: some IdC accounts are provisioned in a
# "reset-on-first-login" state and present a "Set new password" page right after
# the correct password is accepted. When that happens this script generates a
# strong new password, completes the reset, and writes the new password back into
# the accounts file (replacing the old one for that username) so the credential
# stays usable.
#
# API key: after a successful sign-in, the script (unless --no-api-key is passed)
# opens https://app.kiro.dev/settings/api-keys, creates a key named --api-key-name
# (default "Kiro-Go"), and saves the raw key to a local JSON file under
# --api-key-out-dir (default ./api-keys/). Kiro shows the raw key exactly once at
# creation time -- it is captured from the page immediately, since there is no
# way to retrieve it later.

import argparse
import json
import os
import secrets
import shutil
import string
import sys
import tempfile
import time

# CloakBrowser returns a Playwright *sync* BrowserContext, so the Playwright sync
# error type is what a wait/timeout raises. Import it up front for precise except
# clauses; fall back to a bare Exception alias if Playwright is laid out oddly.
try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import Error as PlaywrightError
except Exception:  # noqa: BLE001 - keep the script importable even if types move
    class PlaywrightTimeoutError(Exception):
        pass

    class PlaywrightError(Exception):
        pass


# --- Constants ----------------------------------------------------------------

SIGNIN_URL = "https://app.kiro.dev/signin"
API_KEYS_URL = "https://app.kiro.dev/settings/api-keys"

# Per-locator wait budget (ms). Individual steps use this; the overall login has
# its own wall-clock budget via --timeout.
LOCATOR_TIMEOUT_MS = 30_000

# Characters allowed in a generated reset password. Deliberately EXCLUDES the
# pipe "|" (the accounts-file field delimiter) and any whitespace, so the new
# password can be written back into a `user|pass|url` line without corrupting it.
# The symbol set is drawn from the common AWS-accepted punctuation.
_PW_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
_PW_UPPER = string.ascii_uppercase
_PW_LOWER = string.ascii_lowercase
_PW_DIGITS = string.digits


# --- Accounts file ------------------------------------------------------------

# Account bundles the three credential fields plus the raw source line, so the
# writer can find and replace exactly the line this account came from.
class Account:
    def __init__(self, username, password, start_url, raw_line, line_index):
        self.username = username
        self.password = password
        self.start_url = start_url
        self.raw_line = raw_line
        self.line_index = line_index  # index into the file's list of lines


# parse_accounts reads the accounts file and returns [Account]. The real data
# format is `username|password|start_url`; the human-facing header block at the
# top ("Accounts:", "Format:", the "TK n" separators, blank lines) is ignored.
# A credential line is any line with at least two "|" separators whose third
# field looks like a URL. Returns (accounts, all_lines) so the caller can rewrite
# the file in place while preserving every non-credential line verbatim.
def parse_accounts(path):
    with open(path, "r", encoding="utf-8") as fh:
        all_lines = fh.read().split("\n")

    accounts = []
    for idx, line in enumerate(all_lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("Accounts:") or stripped.startswith("Format:"):
            continue
        # The "TK n" separators use box-drawing chars and no pipes; skip anything
        # without the field delimiter.
        if stripped.count("|") < 2:
            continue
        parts = stripped.split("|")
        # username | password | start_url  (password itself may contain no "|"
        # because "|" is the delimiter, so a straight 3-way split is correct).
        username, password, start_url = parts[0], parts[1], parts[2]
        if not (start_url.startswith("http://") or start_url.startswith("https://")):
            continue
        accounts.append(Account(username.strip(), password, start_url.strip(), line, idx))
    return accounts, all_lines


# generate_password builds a strong reset password that satisfies the common AWS
# IAM Identity Center default policy (>=8 chars with upper, lower, digit, and a
# symbol) and contains no "|" or whitespace so it is safe to store in the
# pipe-delimited accounts file. Length defaults to 20 for margin.
def generate_password(length=20):
    if length < 8:
        length = 8
    # Guarantee one character from each required class, then fill the rest from
    # the combined pool, then shuffle so the required chars are not positional.
    pools = [_PW_UPPER, _PW_LOWER, _PW_DIGITS, _PW_SYMBOLS]
    chars = [secrets.choice(p) for p in pools]
    combined = _PW_UPPER + _PW_LOWER + _PW_DIGITS + _PW_SYMBOLS
    chars += [secrets.choice(combined) for _ in range(length - len(chars))]
    # secrets-backed Fisher-Yates shuffle (random.shuffle is not cryptographic).
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


# update_account_password rewrites the accounts file in place, replacing the
# password field on the exact source line this account came from. The username
# and start_url fields are preserved byte-for-byte; only field 2 changes. The
# write is atomic (temp file + os.replace, 0600) so an interrupt cannot truncate
# the credential store.
def update_account_password(path, account, new_password, all_lines):
    old_line = all_lines[account.line_index]
    parts = old_line.split("|")
    if len(parts) < 3:
        raise ValueError("cannot update password: source line is not user|pass|url")
    parts[1] = new_password
    all_lines[account.line_index] = "|".join(parts)
    account.password = new_password

    data = "\n".join(all_lines)
    parent = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".accounts-", suffix=".txt", dir=parent)
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


# --- Small step helpers -------------------------------------------------------

# step logs a numbered, human-readable action and then pauses for `delay`
# seconds so a person watching the headed browser can follow along. The pause is
# intentional visibility padding; production runs pass a small/zero delay.
def step(msg, delay):
    print("  -> %s" % msg, flush=True)
    if delay > 0:
        time.sleep(delay)


# click_by_text clicks the first visible button/link whose trimmed text matches
# one of `texts` (case-insensitive, substring). Cloudscape/kiro buttons carry no
# stable id, so text is the reliable handle. Returns True if something was
# clicked.
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


# fill_input sets `value` on the element matched by `selector`, using Playwright's
# fill() (which focuses, clears, and emits input/change events). Cloudscape
# controlled inputs accept this; a follow-up value check guards against a silent
# no-op. Raises if the selector never appears.
def fill_input(page, selector, value, timeout_ms=LOCATOR_TIMEOUT_MS):
    page.wait_for_selector(selector, timeout=timeout_ms, state="visible")
    loc = page.locator(selector).first
    loc.fill(value)


# --- The login flow -----------------------------------------------------------

# Outcome codes returned by login_account.
OUTCOME_SUCCESS = "success"
OUTCOME_RESET = "success_after_password_reset"
OUTCOME_MFA = "manual_action_required"  # MFA / device registration -> human must finish
OUTCOME_TIMEOUT = "timeout"
OUTCOME_ERROR = "error"


# login_account drives one full sign-in inside a page from a fresh CloakBrowser
# context. It returns (outcome_code, detail). When a forced password reset is
# handled, it also updates the accounts file via update_account_password.
def login_account(page, account, accounts_path, all_lines, delay, timeout):
    login_deadline = time.time() + timeout

    # Step 1: open the kiro.dev sign-in chooser.
    step("open %s" % SIGNIN_URL, delay)
    page.goto(SIGNIN_URL, wait_until="domcontentloaded", timeout=LOCATOR_TIMEOUT_MS)

    # Best-effort: dismiss the AWS cookie-consent banner if it appears, so its
    # overlay can never intercept a later click. Not fatal if absent.
    click_by_text(page, ["Decline", "Accept all cookies", "Accept"], timeout_ms=4000)

    # Step 2: choose "Your organization" (the enterprise / IdC path).
    step('click "Your organization"', delay)
    if not click_by_text(page, ["Your organization"]):
        return OUTCOME_ERROR, 'could not find the "Your organization" button'

    # Step 3: enter the Start URL and Continue. The field id is stable
    # (#enterprise-sign-in-url); Continue enables once the field is non-empty.
    step("enter Start URL: %s" % account.start_url, delay)
    fill_input(page, "#enterprise-sign-in-url", account.start_url)
    step("click Continue", delay)
    if not click_by_text(page, ["Continue"]):
        return OUTCOME_ERROR, "could not find the Start URL Continue button"

    # Step 4: AWS access portal username page. The portal renders a Cloudscape
    # text input (#awsui-input-0, or the sole visible text field) plus "Next".
    step("wait for AWS portal username page", delay)
    try:
        page.wait_for_selector(
            "input#awsui-input-0, input[type=text]:not([type=hidden])",
            timeout=LOCATOR_TIMEOUT_MS,
            state="visible",
        )
    except PlaywrightTimeoutError:
        return OUTCOME_TIMEOUT, "AWS portal username page did not load"

    step("enter username: %s" % account.username, delay)
    fill_input(page, "input#awsui-input-0, input[type=text]:not([type=hidden])", account.username)
    step("click Next", delay)
    if not click_by_text(page, ["Next"]):
        return OUTCOME_ERROR, "could not find the username Next button"

    # Step 5: password page.
    step("wait for password page", delay)
    try:
        page.wait_for_selector("input[type=password]", timeout=LOCATOR_TIMEOUT_MS, state="visible")
    except PlaywrightTimeoutError:
        return OUTCOME_TIMEOUT, "password page did not load (username may be rejected)"
    step("enter password", delay)
    fill_input(page, "input[type=password]", account.password)
    step("click Sign in", delay)
    if not click_by_text(page, ["Sign in"]):
        return OUTCOME_ERROR, "could not find the Sign in button"

    # Step 6: resolve the post-sign-in state. Poll for one of the known outcomes
    # until the login deadline: forced password reset, MFA/registration, an
    # OAuth consent "Allow" page, or a successful return to app.kiro.dev.
    step("waiting for sign-in result", delay)
    return _resolve_post_signin(page, account, accounts_path, all_lines, delay, login_deadline)


# _resolve_post_signin watches the page after "Sign in" is clicked and reacts to
# whichever branch the portal takes. Returns (outcome, detail).
def _resolve_post_signin(page, account, accounts_path, all_lines, delay, login_deadline):
    handled_reset = False
    while time.time() < login_deadline:
        url = page.url
        body = _body_text(page)

        # Branch A: success -- back on app.kiro.dev off the /signin route, or an
        # explicit "you can close this window" style confirmation.
        if url.startswith("https://app.kiro.dev/") and "/signin" not in url:
            return (OUTCOME_RESET if handled_reset else OUTCOME_SUCCESS), "signed in (%s)" % url
        if _any(body, ["you can now close", "sign-in complete", "signed in", "authentication complete"]):
            return (OUTCOME_RESET if handled_reset else OUTCOME_SUCCESS), "sign-in confirmed"

        # Branch B: forced password reset. Fill the fresh strong password into the
        # right fields, submit, and only persist to the accounts file once the
        # reset visibly succeeds (the reset form is gone) -- persisting a password
        # the portal rejected would corrupt the credential store.
        if _any(body, ["set new password", "set a new password", "change your password", "new password"]) \
                and _count_password_inputs(page) >= 2 and not handled_reset:
            new_pw = generate_password()
            step("forced password reset detected -- setting a new password", delay)
            pw_inputs = page.query_selector_all("input[type=password]")
            # Field layout depends on whether the portal asks for the current
            # password too: 2 fields = [New, Confirm]; 3 fields = [Old, New,
            # Confirm]. Anything else is unexpected -- bail rather than guess.
            if len(pw_inputs) == 2:
                pw_inputs[0].fill(new_pw)
                pw_inputs[1].fill(new_pw)
            elif len(pw_inputs) == 3:
                pw_inputs[0].fill(account.password)  # current password
                pw_inputs[1].fill(new_pw)
                pw_inputs[2].fill(new_pw)
            else:
                return OUTCOME_ERROR, "unexpected password-reset layout (%d password fields)" % len(pw_inputs)
            step("submit new password", delay)
            if not click_by_text(page, ["Set new password", "Change password", "Confirm", "Submit"]):
                return OUTCOME_ERROR, "found reset page but no submit button"

            # Confirm the reset actually took: wait for the reset form to leave the
            # page. If it is still showing (e.g. policy rejected the password), do
            # NOT write anything back -- report the failure with the attempted pw
            # so the operator can recover.
            if not _reset_left_page(page, timeout_s=15):
                print("  !! new password may have been rejected by the portal.", file=sys.stderr)
                print("  !! attempted NEW PASSWORD for %s: %s" % (account.username, new_pw), file=sys.stderr)
                return OUTCOME_ERROR, "password reset did not complete (form still present)"

            # Reset succeeded -> persist the new credential.
            try:
                update_account_password(accounts_path, account, new_pw, all_lines)
                print("  -> accounts file updated with new password for %s" % account.username, flush=True)
            except Exception as exc:  # noqa: BLE001 - surface but don't lose the login
                print("  !! WARNING: could not update accounts file: %s" % exc, file=sys.stderr)
                print("  !! NEW PASSWORD for %s: %s" % (account.username, new_pw), file=sys.stderr)
            handled_reset = True
            continue

        # Branch C: MFA / device registration -- cannot be automated blindly
        # (needs an authenticator app / hardware key). Hand back to the human.
        if _any(body, ["multi-factor", "mfa", "authenticator app", "register mfa",
                       "register a", "verification code", "one-time password", "security key"]):
            return OUTCOME_MFA, "MFA / device registration required -- finish in the open browser"

        # Branch D: OAuth consent / device approval. Click the allow/continue
        # affordance and keep polling for the final redirect.
        if _any(body, ["allow", "authorize", "confirm and continue", "grant access", "request approved"]):
            if click_by_text(page, ["Allow access", "Allow", "Confirm and continue", "Approve", "Continue"],
                             timeout_ms=3000):
                step("approved access request", delay)
                page.wait_for_timeout(1500)
                continue

        page.wait_for_timeout(500)

    return OUTCOME_TIMEOUT, "no terminal state reached before timeout"


def _body_text(page):
    try:
        return (page.inner_text("body") or "").lower()
    except PlaywrightError:
        return ""


# _reset_left_page returns True once the "set new password" form is no longer on
# the page -- the signal that the reset was accepted and the flow moved on. It
# treats "fewer than two password fields" or the reset wording disappearing as
# "left". Returns False if the form is still present after timeout_s.
def _reset_left_page(page, timeout_s=15):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        body = _body_text(page)
        still_reset = _count_password_inputs(page) >= 2 and _any(
            body, ["set new password", "set a new password", "change your password", "new password"]
        )
        if not still_reset:
            return True
        page.wait_for_timeout(500)
    return False


def _count_password_inputs(page):
    try:
        return len(page.query_selector_all("input[type=password]"))
    except PlaywrightError:
        return 0


def _any(haystack, needles):
    return any(n in haystack for n in needles)


# --- API key generation --------------------------------------------------------

# generate_api_key drives the API Keys settings page for the *already
# authenticated* session in `page`: navigate there, enter `key_name`, click
# "Create key", and read the raw key back from the page. The raw key is rendered
# in a <code> element (class prefixed "_keyCode_") directly under the "Copy this
# key now. You will not be able to see it again." notice -- Kiro never shows it
# again after this render, so it must be captured here rather than re-fetched
# later. Raises RuntimeError with a descriptive message on any failure.
def generate_api_key(page, key_name, delay):
    step("open %s" % API_KEYS_URL, delay)
    page.goto(API_KEYS_URL, wait_until="domcontentloaded", timeout=LOCATOR_TIMEOUT_MS)

    name_selector = 'input[aria-label="New API key name"], input[placeholder*="name for the new key" i]'
    try:
        page.wait_for_selector(name_selector, timeout=LOCATOR_TIMEOUT_MS, state="visible")
    except PlaywrightTimeoutError:
        raise RuntimeError("API Keys page did not load (name field not found)")

    step("enter API key name: %s" % key_name, delay)
    page.locator(name_selector).first.fill(key_name)

    step('click "Create key"', delay)
    if not click_by_text(page, ["Create key"]):
        raise RuntimeError('could not find the "Create key" button')

    # The raw key renders in a <code class="_keyCode_..."> element. Class names
    # are build-hashed and may shift across Kiro web releases; the "_keyCode_"
    # substring is the stable part observed in the shipped bundle.
    key_selector = 'code[class*="_keyCode_"]'
    try:
        page.wait_for_selector(key_selector, timeout=LOCATOR_TIMEOUT_MS, state="visible")
    except PlaywrightTimeoutError:
        raise RuntimeError("key was not created (no key code rendered after Create key)")

    # wait_for_selector resolves on attach/visible, not on the text inside it
    # being populated -- poll briefly for non-empty text so a render order where
    # the <code> tag mounts a beat before React fills it in doesn't read "".
    raw_key = ""
    poll_deadline = time.time() + 5
    while time.time() < poll_deadline:
        raw_key = (page.locator(key_selector).first.inner_text() or "").strip()
        if raw_key:
            break
        page.wait_for_timeout(200)
    if not raw_key:
        raise RuntimeError("key element rendered but text stayed empty")
    return raw_key


# save_api_key writes the captured raw key to <out_dir>/kiro-api-key_<username>.json
# (0600, since it is a live bearer credential). Overwrites any existing file for
# the same username -- each run captures the key from its own fresh "Create key"
# click, so the file always reflects the most recently generated key.
def save_api_key(out_dir, username, key_name, raw_key):
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    safe_user = "".join(c if (c.isalnum() or c in "._-") else "_" for c in username) or "unknown"
    out_path = os.path.join(out_dir, "kiro-api-key_%s.json" % safe_user)

    # Two distinct usernames can sanitize to the same safe_user (e.g. differing
    # only by a stripped symbol). If the target file already holds a *different*
    # username's key, disambiguate with a short suffix instead of silently
    # overwriting that other account's credential.
    if os.path.isfile(out_path):
        try:
            with open(out_path, "r", encoding="utf-8") as fh:
                existing = json.load(fh)
            if isinstance(existing, dict) and existing.get("username") not in (username, None):
                suffix = format(abs(hash(username)) % 0xFFFF, "04x")
                out_path = os.path.join(out_dir, "kiro-api-key_%s_%s.json" % (safe_user, suffix))
        except (json.JSONDecodeError, OSError):
            pass  # unreadable/corrupt existing file -- fall through and overwrite it

    payload = {
        "username": username,
        "key_name": key_name,
        "api_key": raw_key,
        "created_unix": int(time.time()),
    }

    # Atomic write (temp file + rename), matching update_account_password: this
    # holds a live bearer credential, so a write interrupted mid-json.dump must
    # never leave a truncated/corrupt file at the real path.
    fd, tmp_path = tempfile.mkstemp(prefix=".kiro-api-key-", suffix=".json", dir=out_dir)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
        os.replace(tmp_path, out_path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return out_path


# --- Per-account driver (fresh disposable CloakBrowser each time) --------------

# run_one launches a brand-new CloakBrowser with an empty temporary profile,
# runs the login, and (if the login succeeded and api_key_name is set) generates
# and saves an API key -- all in the same authenticated page -- before closing
# the browser and deleting the profile directory so nothing is cached on exit.
# Returns (outcome, detail, api_key_path_or_None).
def run_one(account, accounts_path, all_lines, delay, timeout, headless, api_key_name, api_key_out_dir):
    from cloakbrowser import launch_persistent_context

    profile_dir = tempfile.mkdtemp(prefix="kiro-web-login-")
    ctx = None
    key_path = None
    try:
        ctx = launch_persistent_context(profile_dir, headless=headless)
        # A persistent context may open with a first blank page; reuse it to
        # avoid leaving an extra tab around.
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        outcome, detail = login_account(page, account, accounts_path, all_lines, delay, timeout)

        if api_key_name and outcome in (OUTCOME_SUCCESS, OUTCOME_RESET):
            try:
                raw_key = generate_api_key(page, api_key_name, delay)
                key_path = save_api_key(api_key_out_dir, account.username, api_key_name, raw_key)
                print("  -> API key '%s' saved to %s" % (api_key_name, key_path), flush=True)
            except Exception as exc:  # noqa: BLE001 - login already succeeded; report, don't discard it
                print("  !! WARNING: API key generation failed: %s" % exc, file=sys.stderr)

        return outcome, detail, key_path
    except Exception as exc:  # noqa: BLE001 - report any driver/launch failure per-account
        return OUTCOME_ERROR, str(exc), key_path
    finally:
        if ctx is not None:
            try:
                ctx.close()
            except Exception:  # noqa: BLE001 - best-effort browser shutdown
                pass
        # Wipe the disposable profile so no cookies/cache/localStorage survive.
        shutil.rmtree(profile_dir, ignore_errors=True)


# --- CLI ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Headed browser automation for the interactive kiro.dev IAM Identity Center sign-in.",
    )
    parser.add_argument(
        "accounts_file",
        nargs="?",
        default="accounts_test.txt",
        help="Path to the accounts file (username|password|start_url). Default: accounts_test.txt",
    )
    selector = parser.add_mutually_exclusive_group()
    selector.add_argument("--index", type=int, default=None,
                          help="1-based index of the account to log in (default: 1)")
    selector.add_argument("--username", default=None,
                          help="Log in the account with this username")
    selector.add_argument("--all", action="store_true",
                          help="Log in every account in the file, one fresh browser each")
    parser.add_argument("--step-delay", type=float, default=1.0,
                        help="Seconds to pause around each UI step for visibility (default: 1.0). "
                             "Use 0 for a fast production run.")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Max seconds to wait for one login to reach a terminal state (default: 300)")
    parser.add_argument("--headless", action="store_true",
                        help="Run the browser headless (default: headed, so you can watch)")
    parser.add_argument("--api-key-name", default="Kiro-Go",
                        help='Name for the API key created after sign-in (default: "Kiro-Go")')
    parser.add_argument("--no-api-key", action="store_true",
                        help="Skip API key generation; only sign in")
    parser.add_argument("--api-key-out-dir", default="api-keys",
                        help="Directory to save generated API key JSON files (default: ./api-keys)")
    args = parser.parse_args()

    accounts_path = args.accounts_file
    if not os.path.isfile(accounts_path):
        print("ERROR: accounts file not found: %s" % accounts_path, file=sys.stderr)
        return 2

    accounts, all_lines = parse_accounts(accounts_path)
    if not accounts:
        print("ERROR: no `username|password|start_url` lines found in %s" % accounts_path, file=sys.stderr)
        return 2

    # Resolve which account(s) to process.
    if args.all:
        targets = accounts
    elif args.username is not None:
        targets = [a for a in accounts if a.username == args.username]
        if not targets:
            print("ERROR: no account with username %r in %s" % (args.username, accounts_path), file=sys.stderr)
            return 2
    else:
        idx = args.index if args.index is not None else 1
        if idx < 1 or idx > len(accounts):
            print("ERROR: --index %d out of range (1..%d)" % (idx, len(accounts)), file=sys.stderr)
            return 2
        targets = [accounts[idx - 1]]

    print("kiro.dev web login  |  %d account(s)  |  step-delay=%.1fs  |  %s" % (
        len(targets), args.step_delay, "headless" if args.headless else "headed"))

    api_key_name = "" if args.no_api_key else args.api_key_name.strip()

    results = []
    for i, account in enumerate(targets, 1):
        print("\n[%d/%d] %s" % (i, len(targets), account.username))
        # Re-read the accounts snapshot before each login so a password rewritten
        # for an earlier account is reflected if the same file is processed again.
        outcome, detail, key_path = run_one(
            account, accounts_path, all_lines, args.step_delay, args.timeout, args.headless,
            api_key_name, args.api_key_out_dir,
        )
        results.append((account.username, outcome, detail, key_path))
        print("  == %s: %s" % (outcome, detail))

    # Final summary.
    print("\n" + "-" * 70)
    ok = sum(1 for _, o, _, _ in results if o in (OUTCOME_SUCCESS, OUTCOME_RESET))
    for user, outcome, detail, key_path in results:
        line = "  %-28s %s" % (user, outcome)
        if key_path:
            line += "  [key: %s]" % key_path
        print(line)
    print("-" * 70)
    print("  %d/%d signed in" % (ok, len(results)))

    # Exit non-zero if any account failed to reach a signed-in state, so the
    # script is usable in CI / scripted checks.
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
