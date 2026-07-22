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
#        -> EITHER the AWS access portal (native username/password), OR a
#           federated SSO handoff (Microsoft 365 / Entra ID, or another IdP)
#        -> (optional) forced "Set new password"  (AWS-native only)
#        -> (optional) MFA / device / consent "Allow access"
#        -> back on app.kiro.dev, signed in.
#
# Unlike kiro-login-helper.py (which registers an OIDC client and runs the
# device-authorization API flow itself), this script does NOT touch the AWS OIDC
# APIs directly. It just automates the real browser pages, so it exercises the
# same path a user clicks through -- useful for validating that an account's
# credentials actually work end-to-end against kiro.dev.
#
# SSO detection: after the Start URL is submitted, the AWS access portal decides
# whether the instance authenticates natively (an AWS-hosted Cloudscape
# username/password page) or is federated to an external identity provider. This
# script watches the post-Start-URL navigation and detects that handoff by host:
# a jump to *.microsoftonline.com is driven automatically (email -> password ->
# optional MFA, reusing kiro-go-login.py's M365 state machine); any other
# external IdP host is detected and reported as "manual completion required" so
# the operator can finish it in the visible browser.
#
# Proxy: pass --proxy to route the whole browser session through an HTTP(S) or
# SOCKS proxy. Both the standard URL form (http://user:pass@host:port) and the
# colon-delimited provider forms (user:pass:host:port and host:port:user:pass)
# are accepted; see normalize_proxy().
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
# Forced password reset: some AWS-native IdC accounts are provisioned in a
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
import importlib.util
import json
import os
import secrets
import shutil
import string
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# --- Concurrency plumbing -----------------------------------------------------
#
# Each account is logged in inside its own disposable CloakBrowser (fresh temp
# profile, deleted on exit -- effectively an incognito session), so the accounts
# are independent and safe to run in parallel worker threads. Two shared
# resources need guarding across workers:
#   _WRITE_LOCK  serializes read-modify-write of the accounts file (password
#                reset / MFA-secret persistence) so concurrent write-backs can't
#                interleave or corrupt the shared line list.
#   _PRINT_LOCK  keeps interleaved worker log lines from splitting mid-line.
# _TL.label carries the current worker's account name so log lines can be tagged.
_WRITE_LOCK = threading.Lock()
_PRINT_LOCK = threading.Lock()
_TL = threading.local()


def _tag():
    label = getattr(_TL, "label", "")
    return ("[%s] " % label) if label else ""


# _emit prints a worker-tagged line atomically (so parallel output stays legible).
def _emit(msg, err=False):
    with _PRINT_LOCK:
        print("%s%s" % (_tag(), msg), file=(sys.stderr if err else sys.stdout), flush=True)

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


# --- Sibling module loading ---------------------------------------------------

# load_sibling imports a sibling .py by path (their hyphenated names can't be
# imported normally). Import only defines functions/constants -- their drivers
# are guarded by `if __name__ == "__main__"`. Returns None on any failure so a
# missing/broken sibling degrades gracefully (AWS-native logins keep working; an
# SSO handoff is reported as manual instead of crashing).
def load_sibling(filename, modname):
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, filename)
    if not os.path.isfile(path):
        return None
    try:
        spec = importlib.util.spec_from_file_location(modname, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:  # noqa: BLE001 - optional dependency; absence is not fatal
        return None


# --- Proxy normalization ------------------------------------------------------

# _looks_like_host returns True if `s` reads like a hostname/IP rather than a
# username or password -- it either contains a dot (IPv4 / FQDN) or is a bare
# label that is not purely numeric (a numeric-only token is a port, not a host).
def _looks_like_host(s):
    if "." in s:
        return True
    return bool(s) and not s.isdigit()


# normalize_proxy converts the several proxy spellings an operator might paste
# into the single form CloakBrowser/Playwright want: scheme://[user:pass@]host:port.
#
# Accepted inputs:
#   - full URL:            http://user:pass@host:port  (or https/socks5)
#   - full URL no creds:   http://host:port
#   - colon, creds first:  user:pass:host:port
#   - colon, host first:   host:port:user:pass
#   - bare endpoint:       host:port
# A leading scheme is preserved; when absent, http:// is assumed. Returns None
# for a falsy input (no proxy). Raises ValueError on a shape it can't decode so
# a typo fails loudly rather than silently disabling the proxy.
def normalize_proxy(raw):
    if not raw:
        return None
    raw = raw.strip()

    # Split off an explicit scheme so the credential/host parsing below only ever
    # deals with the authority portion.
    scheme = "http"
    rest = raw
    if "://" in raw:
        scheme, rest = raw.split("://", 1)
        scheme = scheme.lower()

    # Already in user:pass@host:port form -- trust it, just re-attach the scheme.
    if "@" in rest:
        return "%s://%s" % (scheme, rest)

    parts = rest.split(":")
    if len(parts) == 2:
        # host:port, no credentials.
        host, port = parts
        return "%s://%s:%s" % (scheme, host, port)

    if len(parts) == 4:
        # Decide which layout by locating the numeric port next to a host token.
        if parts[3].isdigit() and _looks_like_host(parts[2]):
            user, password, host, port = parts  # user:pass:host:port
        elif parts[1].isdigit() and _looks_like_host(parts[0]):
            host, port, user, password = parts  # host:port:user:pass
        else:
            # Ambiguous but 4 fields -- default to the provider-common
            # user:pass:host:port ordering rather than refusing outright.
            user, password, host, port = parts
        return "%s://%s:%s@%s:%s" % (scheme, user, password, host, port)

    raise ValueError(
        "unrecognized proxy format %r (want scheme://user:pass@host:port, "
        "user:pass:host:port, host:port:user:pass, or host:port)" % raw
    )


# --- Accounts file ------------------------------------------------------------

# Account bundles the credential fields plus enough source location to rewrite
# the exact line(s) this account came from. mfa_secret is an optional TOTP seed
# used when a federated M365 instance asks for a verification code; it is empty
# for plain AWS-native accounts.
#
# Two source layouts are supported and recorded in `fmt`:
#   - "pipe":  a single `username|password|start_url[|mfa_secret]` line; the whole
#              record lives at line_index.
#   - "order": a multi-line order dump where a shared "Login portal:" gives the
#              Start URL and each account block carries `username:`/`password:`
#              (optionally `mfa_secret:`) lines; pw_line_index / mfa_line_index
#              point at those fields for in-place rewrites.
class Account:
    def __init__(self, username, password, start_url, raw_line, line_index, mfa_secret="",
                 fmt="pipe", pw_line_index=None, mfa_line_index=None, region="",
                 mfa_label="mfa_secret:"):
        self.username = username
        self.password = password
        self.start_url = start_url
        self.raw_line = raw_line
        self.line_index = line_index  # pipe: index of the single record line
        self.mfa_secret = mfa_secret
        self.fmt = fmt
        self.pw_line_index = pw_line_index    # order: index of the `password:` line
        self.mfa_line_index = mfa_line_index  # order: index of the existing MFA line, or None
        self.mfa_label = mfa_label            # order: that line's actual label (mfa_secret:/mfa:/totp:)
        self.region = region                  # order: informational only


# parse_accounts reads the accounts file and returns [Account]. The real data
# format is `username|password|start_url[|mfa_secret]`; the human-facing header
# block at the top ("Accounts:", "Format:", the "TK n" separators, blank lines)
# is ignored. A credential line is any line with at least two "|" separators
# whose third field looks like a URL. Returns (accounts, all_lines) so the caller
# can rewrite the file in place while preserving every non-credential line
# verbatim.
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
        # username | password | start_url [| mfa_secret]. A straight split is
        # correct because "|" is the delimiter and none of the fields contain it.
        username, password, start_url = parts[0], parts[1], parts[2]
        if not (start_url.startswith("http://") or start_url.startswith("https://")):
            continue
        mfa_secret = parts[3].strip() if len(parts) > 3 else ""
        accounts.append(Account(username.strip(), password, start_url.strip(), line, idx, mfa_secret,
                                fmt="pipe"))
    return accounts, all_lines


# _split_value returns the text after the first ":" in `line` (the value of a
# `label: value` order-file field), stripped. Used to read Login portal / Region
# / username / password / mfa_secret fields.
def _split_value(line):
    return line.split(":", 1)[1].strip() if ":" in line else ""


# parse_order_file reads an "order" dump: a header carrying a shared Start URL
# ("Login portal:") and optional Region, followed by per-account blocks (usually
# fenced by "---") that each hold `username:` and `password:` lines, optionally an
# `mfa_secret:` line. Every account in the file shares the header's Start URL.
# Returns (accounts, all_lines). A block is only emitted once it has both a
# username and a password and the header supplied a valid http(s) Start URL.
def parse_order_file(path):
    with open(path, "r", encoding="utf-8") as fh:
        all_lines = fh.read().split("\n")

    start_url = ""
    region = ""
    accounts = []

    # Per-block accumulators; a new "username:" line (or a "---" fence) flushes
    # the previous block.
    cur = {"user": None, "pass": None, "pass_idx": None, "mfa": "", "mfa_idx": None,
           "mfa_label": "mfa_secret:"}

    def flush():
        if cur["user"] and cur["pass"] is not None and start_url:
            accounts.append(Account(
                cur["user"], cur["pass"], start_url, None, None, cur["mfa"],
                fmt="order", pw_line_index=cur["pass_idx"], mfa_line_index=cur["mfa_idx"],
                region=region, mfa_label=cur["mfa_label"],
            ))
        cur.update({"user": None, "pass": None, "pass_idx": None, "mfa": "", "mfa_idx": None,
                    "mfa_label": "mfa_secret:"})

    for idx, line in enumerate(all_lines):
        low = line.strip().lower()
        if low.startswith("login portal:") or low.startswith("start url:") or low.startswith("login url:"):
            start_url = _split_value(line)
        elif low.startswith("region:"):
            region = _split_value(line)
        elif low.startswith("username:") or low.startswith("email:"):
            flush()  # a username line begins a new account block
            cur["user"] = _split_value(line)
        elif low.startswith("password:"):
            cur["pass"] = _split_value(line)
            cur["pass_idx"] = idx
        elif low.startswith("mfa_secret:") or low.startswith("mfa:") or low.startswith("totp:"):
            cur["mfa"] = _split_value(line)
            cur["mfa_idx"] = idx
            cur["mfa_label"] = line.strip().split(":", 1)[0].strip() + ":"
        elif line.strip() == "---":
            flush()  # explicit block fence
    flush()  # trailing block with no closing fence

    # Only keep accounts whose shared Start URL is a real http(s) URL.
    if not (start_url.startswith("http://") or start_url.startswith("https://")):
        return [], all_lines
    return accounts, all_lines


# parse_header_pipe_file reads the header-plus-pipe layout: a header carrying a
# shared Start URL ("Start URL:" or "Login portal:") and optional Region,
# followed (after an optional "---" fence) by `email|password[|mfa_secret]`
# credential lines that all share that Start URL. Distinct from parse_order_file,
# whose credentials are `username:`/`password:` label lines rather than pipes.
# Returns (accounts, all_lines).
def parse_header_pipe_file(path):
    with open(path, "r", encoding="utf-8") as fh:
        all_lines = fh.read().split("\n")

    start_url = ""
    region = ""
    accounts = []
    for idx, line in enumerate(all_lines):
        s = line.strip()
        low = s.lower()
        if low.startswith("start url:") or low.startswith("login portal:") or low.startswith("login url:"):
            start_url = _split_value(line)
            continue
        if low.startswith("region:"):
            region = _split_value(line)
            continue
        if not s or s == "---" or "|" not in s:
            continue
        parts = s.split("|")
        email = parts[0].strip()
        # A credential line's first field is the email/username; require an "@" so
        # header noise or stray pipes are not mistaken for accounts.
        if "@" not in email:
            continue
        password = parts[1] if len(parts) > 1 else ""
        mfa_secret = parts[2].strip() if len(parts) > 2 else ""
        accounts.append(Account(email, password, start_url, line, idx, mfa_secret,
                                fmt="header_pipe", region=region))

    if not (start_url.startswith("http://") or start_url.startswith("https://")):
        return [], all_lines
    return accounts, all_lines


# parse_accounts_auto sniffs the file and dispatches to the right parser:
#   - order dump      -> "Order ID:" / "Account list:" markers, or `username:` /
#                        `password:` label credential lines,
#   - header + pipe   -> a "Start URL:" / "Login portal:" header followed by
#                        `email|password` credential lines,
#   - bare pipe       -> `username|password|start_url` lines with no header.
# Returns (accounts, all_lines, fmt) so the caller can report the layout read.
def parse_accounts_auto(path):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    low = text.lower()
    stripped = [ln.strip() for ln in low.split("\n")]
    has_header = any(ln.startswith(("start url:", "login portal:", "login url:")) for ln in stripped)
    has_label_creds = any(ln.startswith(("username:", "password:")) for ln in stripped)

    if "order id:" in low or "account list:" in low or has_label_creds:
        accounts, all_lines = parse_order_file(path)
        return accounts, all_lines, "order"
    if has_header:
        accounts, all_lines = parse_header_pipe_file(path)
        return accounts, all_lines, "header-pipe"
    accounts, all_lines = parse_accounts(path)
    return accounts, all_lines, "pipe"


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


# _rewrite_accounts_file writes `all_lines` back to `path` atomically (temp file
# + os.replace, 0600) so an interrupt can never truncate the credential store.
# Shared by the password-reset and MFA-secret writers.
def _rewrite_accounts_file(path, all_lines):
    # Callers (update_account_password / update_account_mfa_secret) hold
    # _WRITE_LOCK, so concurrent workers never rewrite the file at the same time.
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


# _replace_field_value rewrites the value of a `label: value` line at `idx`,
# preserving the original indentation and label text (only the value changes).
def _replace_field_value(all_lines, idx, label, value):
    old = all_lines[idx]
    lower = old.lower()
    pos = lower.find(label.lower())
    if pos < 0:
        raise ValueError("expected %r on line %d but found %r" % (label, idx, old))
    label_end = pos + len(label)
    all_lines[idx] = old[:label_end] + " " + value


# update_account_password rewrites the accounts file in place, replacing only the
# password field on the exact source line(s) this account came from. Pipe records
# keep username/start_url byte-for-byte (only field 2 changes); order records
# rewrite the value of their `password:` line.
def update_account_password(path, account, new_password, all_lines):
    with _WRITE_LOCK:
        if account.fmt == "order":
            if account.pw_line_index is None:
                raise ValueError("cannot update password: no password line recorded for this order account")
            _replace_field_value(all_lines, account.pw_line_index, "password:", new_password)
        elif account.fmt == "header_pipe":
            # `email|password[|mfa_secret]` -- only field 2 changes.
            old_line = all_lines[account.line_index]
            parts = old_line.split("|")
            if len(parts) < 2:
                raise ValueError("cannot update password: source line is not email|password")
            parts[1] = new_password
            all_lines[account.line_index] = "|".join(parts)
        else:
            old_line = all_lines[account.line_index]
            parts = old_line.split("|")
            if len(parts) < 3:
                raise ValueError("cannot update password: source line is not user|pass|url")
            parts[1] = new_password
            all_lines[account.line_index] = "|".join(parts)
        account.password = new_password
        _rewrite_accounts_file(path, all_lines)


# _shift_order_line_indices bumps the recorded line indices of every "order"
# account whose password/mfa line sits at or after `insert_at` by `delta`. Called
# after inserting a line so subsequent accounts' write-backs stay correct.
def _shift_order_line_indices(accounts, insert_at, delta):
    for a in accounts:
        if a.fmt != "order":
            continue
        if a.pw_line_index is not None and a.pw_line_index >= insert_at:
            a.pw_line_index += delta
        if a.mfa_line_index is not None and a.mfa_line_index >= insert_at:
            a.mfa_line_index += delta


# update_account_mfa_secret persists a captured TOTP seed. For a pipe record it
# rewrites the source line to a 4-field `user|pass|url|mfa_secret` (appending the
# field if absent). For an order record it replaces an existing `mfa_secret:`
# line, or inserts one right after the `password:` line and shifts the other
# order accounts' recorded indices to match. `all_accounts` is the full parsed
# list, needed only for that index shift. Atomic write via _rewrite_accounts_file.
def update_account_mfa_secret(path, account, secret, all_lines, all_accounts):
    with _WRITE_LOCK:
        if account.fmt == "order":
            if account.mfa_line_index is not None:
                _replace_field_value(all_lines, account.mfa_line_index, account.mfa_label, secret)
            else:
                if account.pw_line_index is None:
                    raise ValueError("cannot update mfa secret: no password line recorded for this order account")
                pw_line = all_lines[account.pw_line_index]
                indent = pw_line[:len(pw_line) - len(pw_line.lstrip())]
                insert_at = account.pw_line_index + 1
                all_lines.insert(insert_at, "%smfa_secret: %s" % (indent, secret))
                _shift_order_line_indices(all_accounts, insert_at, 1)
                account.mfa_line_index = insert_at
        elif account.fmt == "header_pipe":
            # `email|password[|mfa_secret]` -- the TOTP seed is the 3rd field.
            old_line = all_lines[account.line_index]
            parts = old_line.split("|")
            if len(parts) < 2:
                raise ValueError("cannot update mfa secret: source line is not email|password")
            while len(parts) < 3:
                parts.append("")
            parts[2] = secret
            all_lines[account.line_index] = "|".join(parts)
        else:
            old_line = all_lines[account.line_index]
            parts = old_line.split("|")
            if len(parts) < 3:
                raise ValueError("cannot update mfa secret: source line is not user|pass|url")
            while len(parts) < 4:
                parts.append("")
            parts[3] = secret
            all_lines[account.line_index] = "|".join(parts)
        account.mfa_secret = secret
        _rewrite_accounts_file(path, all_lines)


# --- Small step helpers -------------------------------------------------------

# step logs a numbered, human-readable action and then pauses for `delay`
# seconds so a person watching the headed browser can follow along. The pause is
# intentional visibility padding; production runs pass a small/zero delay.
def step(msg, delay):
    _emit("  -> %s" % msg)
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


# --- Host classification (SSO detection) --------------------------------------

# These predicates classify the *current* page by host so the post-Start-URL
# state machine can tell an AWS-native portal page from a federated IdP handoff.

def _host_is_kiro(url):
    return url.startswith("https://app.kiro.dev/") or url.startswith("https://kiro.dev/")


def _host_is_microsoft(url):
    return ("microsoftonline.com" in url or "login.microsoft.com" in url
            or "login.live.com" in url)


def _host_is_aws(url):
    return (".signin.aws" in url or ".app.aws" in url or "portal.amazonaws.com" in url
            or ".awsapps.com" in url or "signin.aws.amazon.com" in url)


# _is_external_idp returns True when the page is on some third-party host that is
# neither kiro, AWS, nor Microsoft, and not a transient blank/about page -- i.e.
# an SSO IdP this script does not know how to automate (Okta, Ping, Google, ...).
def _is_external_idp(url):
    if not url or url.startswith("about:") or url.startswith("data:"):
        return False
    if _host_is_kiro(url) or _host_is_aws(url) or _host_is_microsoft(url):
        return False
    return url.startswith("http://") or url.startswith("https://")


def _hostname(url):
    try:
        return urlparse(url).hostname or url
    except ValueError:
        return url


# --- The login flow -----------------------------------------------------------

# Outcome codes returned by login_account.
OUTCOME_SUCCESS = "success"
OUTCOME_RESET = "success_after_password_reset"
OUTCOME_MFA_SETUP = "success_after_mfa_setup"
OUTCOME_MFA = "manual_action_required"  # MFA / device / unknown IdP -> human must finish
OUTCOME_TIMEOUT = "timeout"
OUTCOME_ERROR = "error"


# login_account drives one full sign-in inside a page from a fresh CloakBrowser
# context. `kg` is the loaded kiro-go-login module (its M365 primitives) or None.
# Returns (outcome_code, detail, new_mfa_secret_or_None). When a forced password
# reset is handled it also updates the accounts file via update_account_password;
# a captured MFA secret is returned for the caller to persist.
def login_account(page, account, kg, accounts_path, all_lines, delay, timeout):
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
        return OUTCOME_ERROR, 'could not find the "Your organization" button', None

    # Step 3: enter the Start URL and Continue. The field id is stable
    # (#enterprise-sign-in-url); Continue enables once the field is non-empty.
    # Some variants show an email-first page -- click through to the IAM Identity
    # Center option if the Start URL field is not immediately present.
    if not _wait_selector(page, "#enterprise-sign-in-url", 6000):
        click_by_text(page, ["Sign in via IAM Identity Center instead",
                             "IAM Identity Center"], timeout_ms=6000)
    try:
        page.wait_for_selector("#enterprise-sign-in-url", timeout=LOCATOR_TIMEOUT_MS, state="visible")
    except PlaywrightTimeoutError:
        return OUTCOME_ERROR, "Start URL field never appeared", None

    step("enter Start URL: %s" % account.start_url, delay)
    fill_input(page, "#enterprise-sign-in-url", account.start_url)
    step("click Continue", delay)
    if not click_by_text(page, ["Continue"]):
        return OUTCOME_ERROR, "could not find the Start URL Continue button", None

    # Step 4: resolve everything after the Start URL with a host-gated state
    # machine. It detects whether the portal stays AWS-native or hands off to an
    # external SSO IdP, and drives whichever it sees to completion.
    step("waiting for sign-in result (detecting AWS-native vs SSO)", delay)
    return _resolve_login(page, account, kg, accounts_path, all_lines, delay, login_deadline)


# _wait_selector is a boolean wait -- True if `selector` becomes visible within
# timeout_ms, False on timeout (used to branch on optional page variants).
def _wait_selector(page, selector, timeout_ms):
    try:
        page.wait_for_selector(selector, timeout=timeout_ms, state="visible")
        return True
    except PlaywrightTimeoutError:
        return False


# _resolve_login is the post-Start-URL state machine. It polls the page until the
# login reaches a terminal state, reacting to whichever branch the portal takes:
#   - success (back on app.kiro.dev),
#   - an OAuth consent "Allow access" page,
#   - the AWS-native username -> password -> (forced reset) sequence,
#   - a Microsoft 365 / Entra ID SSO handoff (driven via the kg helpers),
#   - any other external IdP (detected and returned for manual completion).
# Returns (outcome, detail, new_mfa_secret_or_None).
def _resolve_login(page, account, kg, accounts_path, all_lines, delay, login_deadline):
    handled_reset = False
    handled_enrollment = False
    sso_reported = False
    aws_email_submitted = False
    aws_password_submitted = False
    ms_login_seen = False
    ms_email_submitted = False
    ms_password_submitted = False
    new_secret = None
    code_windows_tried = set()
    MAX_CODE_ATTEMPTS = 3

    while time.time() < login_deadline:
        url = page.url
        body = _body_text(page)

        # Branch A: success -- back on app.kiro.dev off the /signin route, or an
        # explicit "you can close this window" style confirmation. The outcome
        # records whichever mid-flow enrollment/reset happened, most-specific first.
        if _host_is_kiro(url) and "/signin" not in url:
            return _success_outcome(handled_reset, handled_enrollment), "signed in (%s)" % url, new_secret
        # Text confirmation, but NOT while still on a Microsoft page: the KMSI
        # "Stay signed in?" interstitial contains the substring "signed in", so a
        # bare "signed in" needle would false-positive there before the redirect
        # back to kiro. Gate on non-Microsoft and use unambiguous phrases only.
        if not _host_is_microsoft(url) and _any(body, ["you can now close", "sign-in complete",
                                                       "authentication complete"]):
            return _success_outcome(handled_reset, handled_enrollment), "sign-in confirmed", new_secret

        # Branch B: OAuth consent / device approval (can appear on any host).
        # Click the allow/continue affordance and keep polling for the redirect.
        if _any(body, ["access your data", "allow kiro", "authorize access", "authorize kiro",
                       "confirm and continue", "grant access", "request approved"]):
            if click_by_text(page, ["Allow access", "Allow", "Confirm and continue", "Approve", "Continue"],
                             timeout_ms=3000):
                step("approved access request", delay)
                page.wait_for_timeout(1500)
                continue

        # Branch C: Microsoft 365 / Entra ID SSO. Detected purely by host -- the
        # Start URL federated out to *.microsoftonline.com. Drive email ->
        # password -> optional MFA using kiro-go-login.py's tested primitives.
        if _host_is_microsoft(url):
            if not sso_reported:
                step("SSO detected after Start URL: Microsoft / Entra ID (%s)" % _hostname(url), delay)
                sso_reported = True
            if kg is None:
                return OUTCOME_MFA, "Microsoft SSO detected but kiro-go-login.py helpers are unavailable", new_secret
            outcome = _drive_microsoft(
                page, account, kg, delay,
                state={
                    "ms_login_seen": ms_login_seen,
                    "ms_email_submitted": ms_email_submitted,
                    "ms_password_submitted": ms_password_submitted,
                    "handled_enrollment": handled_enrollment,
                    "code_windows_tried": code_windows_tried,
                    "new_secret": new_secret,
                    "max_code_attempts": MAX_CODE_ATTEMPTS,
                },
            )
            # _drive_microsoft returns the carried-forward flags plus either a
            # None terminal (keep polling) or an (outcome, detail) tuple.
            ms_login_seen = outcome["ms_login_seen"]
            ms_email_submitted = outcome["ms_email_submitted"]
            ms_password_submitted = outcome["ms_password_submitted"]
            handled_enrollment = outcome["handled_enrollment"]
            new_secret = outcome["new_secret"]
            if outcome["terminal"] is not None:
                code, detail = outcome["terminal"]
                return code, detail, new_secret
            continue

        # Branch D: AWS-native access portal (username -> password -> reset).
        if _host_is_aws(url):
            # Forced password reset takes priority: it is the only AWS page with
            # two or more password fields plus the reset wording.
            if _any(body, ["set new password", "set a new password", "change your password", "new password"]) \
                    and _count_password_inputs(page) >= 2 and not handled_reset:
                result, detail = _handle_password_reset(page, account, accounts_path, all_lines, delay)
                if result == "ok":
                    handled_reset = True
                    continue
                return OUTCOME_ERROR, detail, new_secret

            # AWS-native password page (single password field).
            if _visible(page, "input[type=password]") and not aws_password_submitted:
                step("enter AWS portal password", delay)
                fill_input(page, "input[type=password]", account.password)
                click_by_text(page, ["Sign in"], timeout_ms=5000)
                aws_password_submitted = True
                page.wait_for_timeout(1000)
                continue

            # AWS portal username/email page. For a native instance this is the
            # local username; for a federated one this email is what triggers the
            # redirect to the external IdP.
            if not aws_email_submitted and _visible(page, "input#awsui-input-0, input[type=text]:not([type=hidden])"):
                step("enter username at AWS portal: %s" % account.username, delay)
                fill_input(page, "input#awsui-input-0, input[type=text]:not([type=hidden])", account.username)
                click_by_text(page, ["Next"], timeout_ms=5000)
                aws_email_submitted = True
                page.wait_for_timeout(1000)
                continue

            page.wait_for_timeout(500)
            continue

        # Branch E: some other external IdP (Okta, Ping, Google, ...). Detected
        # by host; this script cannot automate it blindly, so hand back to the
        # human watching the visible browser.
        if _is_external_idp(url):
            if not sso_reported:
                step("SSO detected after Start URL: external IdP %s -- cannot automate" % _hostname(url), delay)
                sso_reported = True
            return OUTCOME_MFA, "external SSO IdP (%s) requires manual completion in the open browser" % _hostname(url), new_secret

        page.wait_for_timeout(500)

    return OUTCOME_TIMEOUT, "no terminal state reached before timeout", new_secret


# _success_outcome picks the most specific success code for whatever mid-flow
# handling occurred (a captured MFA enrollment or a forced password reset).
def _success_outcome(handled_reset, handled_enrollment):
    if handled_enrollment:
        return OUTCOME_MFA_SETUP
    if handled_reset:
        return OUTCOME_RESET
    return OUTCOME_SUCCESS


# _drive_microsoft advances the Microsoft sign-in by exactly one reactive step
# per call, using kiro-go-login.py's (`kg`) selectors and helpers. It reads and
# writes progress through the `state` dict and returns a result dict carrying the
# updated state plus a `terminal` value: None to keep polling, or an
# (outcome, detail) tuple when the Microsoft leg reaches a dead end.
# _await_ms_ready waits for a Microsoft/ESTS page to actually finish loading
# before a field is touched: network settles, then the target input becomes
# visible, enabled, and editable. ESTS renders the input tag early and hydrates
# it a beat later, so filling before this returns can silently drop the value.
# Best-effort -- returns True if it observed the field ready, False on timeout.
def _await_ms_ready(page, selector, timeout_ms=15000):
    try:
        page.wait_for_load_state("networkidle", timeout=timeout_ms)
    except (PlaywrightTimeoutError, PlaywrightError):
        pass
    try:
        page.wait_for_selector(selector, state="visible", timeout=timeout_ms)
        loc = page.locator(selector).first
        deadline = time.time() + timeout_ms / 1000.0
        while time.time() < deadline:
            if loc.is_editable() and loc.is_enabled():
                return True
            page.wait_for_timeout(200)
    except (PlaywrightTimeoutError, PlaywrightError):
        pass
    return False


# _keystroke_type types `value` into `loc` as real per-character keystrokes.
# Microsoft ESTS binds its inputs through Knockout, whose view-model only updates
# on the keydown/input/keyup events that real typing emits -- a raw fill() sets
# the DOM value but leaves the view-model empty, so the server still sees a blank
# field. press_sequentially (newer Playwright) or type() (older) both emit those
# events; pick whichever the installed version exposes.
def _keystroke_type(loc, value):
    fn = getattr(loc, "press_sequentially", None) or loc.type
    fn(value, delay=25)


# _fill_verify clears `selector`, types `value` as real keystrokes, and confirms
# the value persisted, retrying up to `tries` times. ESTS can wipe an early entry
# during hydration and needs keystroke events to bind, so this reads input_value()
# back and retries until it sticks. Returns True once the field holds `value`.
def _fill_verify(page, selector, value, tries=4):
    loc = page.locator(selector).first
    last = None
    for _ in range(tries):
        try:
            loc.click()
            loc.fill("")  # clear any placeholder-clobbered/prior content
            _keystroke_type(loc, value)
            last = loc.input_value()
        except (PlaywrightTimeoutError, PlaywrightError):
            last = None
        if last == value:
            return True
        page.wait_for_timeout(400)
    return last == value


# _submit_and_confirm re-asserts `value` in `selector` immediately before
# clicking the ESTS primary button (a late branding/script repaint can wipe an
# earlier fill in the window before submit), then checks whether Microsoft
# flagged an error. Returns True if submitted with no error needle visible,
# False if the page shows one of `error_needles`. The caller retries on False.
def _submit_and_confirm(page, kg, selector, value, error_needles):
    try:
        loc = page.locator(selector).first
        if loc.input_value() != value:
            loc.click()
            loc.fill("")
            _keystroke_type(loc, value)
    except (PlaywrightTimeoutError, PlaywrightError):
        pass
    kg._click_ests_primary(page)
    page.wait_for_timeout(1200)
    body = kg._body_text(page)
    return not kg._any(body, error_needles)


def _drive_microsoft(page, account, kg, delay, state):
    ms_login_seen = state["ms_login_seen"]
    ms_email_submitted = state["ms_email_submitted"]
    ms_password_submitted = state["ms_password_submitted"]
    handled_enrollment = state["handled_enrollment"]
    code_windows_tried = state["code_windows_tried"]
    new_secret = state["new_secret"]
    max_code_attempts = state["max_code_attempts"]

    def result(terminal):
        return {
            "terminal": terminal,
            "ms_login_seen": ms_login_seen,
            "ms_email_submitted": ms_email_submitted,
            "ms_password_submitted": ms_password_submitted,
            "handled_enrollment": handled_enrollment,
            "new_secret": new_secret,
        }

    body = kg._body_text(page)

    # Hard rejections -- surface immediately rather than spinning to timeout.
    if kg._any(body, ["your account or password is incorrect",
                      "that microsoft account doesn't exist",
                      "we couldn't find an account", "this username may be incorrect"]):
        return result((OUTCOME_ERROR, "Microsoft rejected the email/password"))

    # Email step. Microsoft always asks for the email FIRST. On this tenant both
    # the loginfmt (email) and passwd inputs render visible on the same page, so
    # passwd visibility can NOT be used to tell the steps apart -- drive strictly
    # off ms_email_submitted so the email always goes in before the password.
    if not ms_email_submitted and kg._visible(page, "input[name=loginfmt]"):
        ms_login_seen = True
        if "sign in" not in body:
            page.wait_for_timeout(500)  # form not painted yet -- let it settle
            return result(None)
        step("wait for M365 sign-in (email) form to finish loading", delay)
        _await_ms_ready(page, "input[name=loginfmt]")
        step("enter M365 username: %s" % account.username, delay)
        if not _fill_verify(page, "input[name=loginfmt]", account.username):
            return result(None)  # still hydrating -- retry on the next poll
        # Some tenants render a combined email+password page (both boxes + one
        # submit). If a password box is already shown, fill it now so a single
        # submit carries both; a two-step flow simply re-asks on the next page.
        if kg._visible(page, "input[name=passwd]"):
            _fill_verify(page, "input[name=passwd]", account.password)
        if not _submit_and_confirm(page, kg, "input[name=loginfmt]", account.username,
                                   ["enter a valid email", "valid email address",
                                    "couldn't find an account", "this username may be incorrect"]):
            return result(None)  # rejected / clobbered -- refill on the next poll
        ms_email_submitted = True
        page.wait_for_timeout(1000)
        return result(None)

    # Password step. Only after the email was accepted, and only if a password
    # box is actually shown (a combined page may already have consumed it).
    if not ms_password_submitted and kg._visible(page, "input[name=passwd]"):
        step("wait for M365 password form to finish loading", delay)
        _await_ms_ready(page, "input[name=passwd]")
        step("enter M365 password", delay)
        if not _fill_verify(page, "input[name=passwd]", account.password):
            return result(None)  # still hydrating -- retry on the next poll
        if not _submit_and_confirm(page, kg, "input[name=passwd]", account.password,
                                   ["your account or password is incorrect", "password is incorrect"]):
            return result((OUTCOME_ERROR, "Microsoft rejected the password"))
        ms_password_submitted = True
        page.wait_for_timeout(1000)
        return result(None)

    # Forced MFA enrollment ("keep your account secure" / "more information
    # required") -- capture the TOTP secret so the account is usable next run.
    if not handled_enrollment and kg._any(body, ["keep your account secure", "more information required"]):
        try:
            new_secret = kg._handle_mfa_enrollment(page, delay)
        except RuntimeError as exc:
            return result((OUTCOME_ERROR, str(exc)))
        handled_enrollment = True
        return result(None)

    # MFA verification code prompt.
    if kg._visible(page, "input[name=otc]") or kg._any(body, ["enter the code", "enter code",
                                                              "enter your code", "verification code"]):
        secret = new_secret or account.mfa_secret
        if not secret:
            return result((OUTCOME_MFA, "MFA code requested but no mfa_secret is stored for this account"))
        window = int(time.time() // 30)
        if window in code_windows_tried:
            page.wait_for_timeout(1000)
            return result(None)
        if len(code_windows_tried) >= max_code_attempts:
            return result((OUTCOME_ERROR,
                           "MFA code rejected across %d codes (bad secret or clock skew?)" % max_code_attempts))
        code_windows_tried.add(window)
        step("entering TOTP code from the stored secret", delay)
        code = kg.totp_code(secret)
        if kg._visible(page, "input[name=otc]"):
            page.locator("input[name=otc]").first.fill(code)
        elif not kg._fill_sole_code_input(page, code):
            return result((OUTCOME_ERROR, "found code prompt but no input field"))
        if not kg._click_ests_primary(page):
            kg.click_by_text(page, ["Verify", "Next"], timeout_ms=5000)
        page.wait_for_timeout(1200)
        return result(None)

    # "Stay signed in?" interstitial -- click No (#idBtn_Back) to move on.
    if kg._any(body, ["stay signed in"]):
        if not kg._click_selector(page, "#idBtn_Back"):
            kg._click_ests_primary(page)
        page.wait_for_timeout(800)
        return result(None)

    page.wait_for_timeout(500)
    return result(None)


# _handle_password_reset fills a fresh strong password into the AWS-native "Set
# new password" form, submits it, and (only once the reset visibly succeeds)
# persists it to the accounts file. Returns ("ok", "") on success or
# ("error", detail) on failure -- never writes a password the portal rejected.
def _handle_password_reset(page, account, accounts_path, all_lines, delay):
    new_pw = generate_password()
    step("forced password reset detected -- setting a new password", delay)
    pw_inputs = page.query_selector_all("input[type=password]")
    # Field layout depends on whether the portal asks for the current password
    # too: 2 fields = [New, Confirm]; 3 fields = [Old, New, Confirm]. Anything
    # else is unexpected -- bail rather than guess.
    if len(pw_inputs) == 2:
        pw_inputs[0].fill(new_pw)
        pw_inputs[1].fill(new_pw)
    elif len(pw_inputs) == 3:
        pw_inputs[0].fill(account.password)  # current password
        pw_inputs[1].fill(new_pw)
        pw_inputs[2].fill(new_pw)
    else:
        return "error", "unexpected password-reset layout (%d password fields)" % len(pw_inputs)
    step("submit new password", delay)
    if not click_by_text(page, ["Set new password", "Change password", "Confirm", "Submit"]):
        return "error", "found reset page but no submit button"

    # Confirm the reset actually took: wait for the reset form to leave the page.
    # If it is still showing (e.g. policy rejected the password), do NOT write
    # anything back -- report the failure with the attempted pw so the operator
    # can recover.
    if not _reset_left_page(page, timeout_s=15):
        _emit("  !! new password may have been rejected by the portal.", err=True)
        _emit("  !! attempted NEW PASSWORD for %s: %s" % (account.username, new_pw), err=True)
        return "error", "password reset did not complete (form still present)"

    # Reset succeeded -> persist the new credential.
    try:
        update_account_password(accounts_path, account, new_pw, all_lines)
        _emit("  -> accounts file updated with new password for %s" % account.username)
    except Exception as exc:  # noqa: BLE001 - surface but don't lose the login
        _emit("  !! WARNING: could not update accounts file: %s" % exc, err=True)
        _emit("  !! NEW PASSWORD for %s: %s" % (account.username, new_pw), err=True)
    return "ok", ""


def _body_text(page):
    try:
        return (page.inner_text("body") or "").lower()
    except PlaywrightError:
        return ""


# _visible returns True if `selector` currently matches a visible element -- a
# non-throwing existence check used to branch the state machine.
def _visible(page, selector):
    try:
        loc = page.locator(selector).first
        return loc.is_visible()
    except PlaywrightError:
        return False


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

# run_one launches a brand-new CloakBrowser with an empty temporary profile
# (optionally through `proxy`), runs the login, and (if the login succeeded and
# api_key_name is set) generates and saves an API key -- all in the same
# authenticated page -- before closing the browser and deleting the profile
# directory so nothing is cached on exit. Any MFA secret captured during a
# federated enrollment is persisted back to the accounts file.
# Returns (outcome, detail, api_key_path_or_None).
def run_one(account, all_accounts, kg, accounts_path, all_lines, delay, timeout, headless,
            api_key_name, api_key_out_dir, proxy):
    from cloakbrowser import launch_persistent_context

    # Tag every log line from this worker with the account name so parallel
    # output is attributable.
    _TL.label = account.username

    profile_dir = tempfile.mkdtemp(prefix="kiro-web-login-")
    ctx = None
    key_path = None
    outcome, detail, new_secret = OUTCOME_ERROR, "browser not started", None
    try:
        ctx = launch_persistent_context(profile_dir, headless=headless, proxy=proxy)
        # A persistent context may open with a first blank page; reuse it to
        # avoid leaving an extra tab around.
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        outcome, detail, new_secret = login_account(
            page, account, kg, accounts_path, all_lines, delay, timeout)

        if api_key_name and outcome in (OUTCOME_SUCCESS, OUTCOME_RESET, OUTCOME_MFA_SETUP):
            try:
                raw_key = generate_api_key(page, api_key_name, delay)
                key_path = save_api_key(api_key_out_dir, account.username, api_key_name, raw_key)
                _emit("  -> API key '%s' saved to %s" % (api_key_name, key_path))
            except Exception as exc:  # noqa: BLE001 - login already succeeded; report, don't discard it
                _emit("  !! WARNING: API key generation failed: %s" % exc, err=True)
    except Exception as exc:  # noqa: BLE001 - report any driver/launch failure per-account
        outcome, detail = OUTCOME_ERROR, str(exc)
    finally:
        if ctx is not None:
            try:
                ctx.close()
            except Exception:  # noqa: BLE001 - best-effort browser shutdown
                pass
        # Wipe the disposable profile so no cookies/cache/localStorage survive.
        shutil.rmtree(profile_dir, ignore_errors=True)

    # Persist a freshly captured MFA secret (outside the browser lifetime so a
    # browser-close error can't lose it).
    if new_secret:
        try:
            update_account_mfa_secret(accounts_path, account, new_secret, all_lines, all_accounts)
            _emit("  -> accounts file updated with MFA secret for %s" % account.username)
        except Exception as exc:  # noqa: BLE001 - surface but don't lose it
            _emit("  !! WARNING: could not persist MFA secret: %s" % exc, err=True)
            _emit("  !! MFA secret for %s: %s" % (account.username, new_secret), err=True)

    return outcome, detail, key_path


# --- CLI ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Headed browser automation for the interactive kiro.dev IAM Identity Center sign-in.",
    )
    parser.add_argument(
        "accounts_file",
        nargs="?",
        default="accounts_test.txt",
        help="Path to the accounts file (username|password|start_url[|mfa_secret]). "
             "Default: accounts_test.txt",
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
    parser.add_argument("--workers", type=int, default=1,
                        help="Log in this many accounts concurrently, each in its own disposable "
                             "(incognito) CloakBrowser (default: 1). e.g. --workers 5")
    parser.add_argument("--proxy", default=None,
                        help="Route the browser through a proxy. Accepts scheme://user:pass@host:port, "
                             "user:pass:host:port, host:port:user:pass, or host:port.")
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

    # Normalize the proxy once, up front, so a malformed value fails before any
    # browser is launched.
    try:
        proxy = normalize_proxy(args.proxy)
    except ValueError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2

    accounts, all_lines, file_fmt = parse_accounts_auto(accounts_path)
    if not accounts:
        print("ERROR: no accounts found in %s (want either `username|password|start_url` lines "
              "or an order dump with `Login portal:` + username/password blocks)" % accounts_path,
              file=sys.stderr)
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

    # Load the M365/Entra sign-in primitives from the sibling script. Optional:
    # if it can't be loaded, AWS-native logins still work and a Microsoft SSO
    # handoff is reported as manual instead of driven.
    kg = load_sibling("kiro-go-login.py", "kiro_go_login")
    sso_note = "M365 SSO auto-drive: on" if kg is not None else "M365 SSO auto-drive: OFF (kiro-go-login.py unavailable)"

    # Clamp workers to a sensible range: at least 1, never more than the number
    # of accounts to process.
    workers = max(1, min(args.workers, len(targets)))

    region = next((a.region for a in targets if a.region), "")
    print("kiro.dev web login  |  %d account(s)  |  format=%s%s  |  workers=%d  |  step-delay=%.1fs  |  %s  |  proxy=%s  |  %s" % (
        len(targets), file_fmt, ("/%s" % region if region else ""), workers, args.step_delay,
        "headless" if args.headless else "headed", "on" if proxy else "off", sso_note))

    api_key_name = "" if args.no_api_key else args.api_key_name.strip()
    api_key_out_dir_abs = os.path.abspath(args.api_key_out_dir)

    # process one account and return its indexed result tuple (index preserves the
    # file order for the final summary regardless of completion order).
    def process(i, account):
        _emit_header(i, len(targets), account)
        outcome, detail, key_path = run_one(
            account, accounts, kg, accounts_path, all_lines, args.step_delay, args.timeout,
            args.headless, api_key_name, args.api_key_out_dir, proxy,
        )
        _emit("  == %s: %s" % (outcome, detail))
        return (i, account.username, outcome, detail, key_path)

    started = time.time()
    indexed = []
    if workers == 1:
        for i, account in enumerate(targets, 1):
            indexed.append(process(i, account))
    else:
        # One thread per worker; each spins up its own CloakBrowser, so the pool
        # size caps how many browsers run at once.
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(process, i, account) for i, account in enumerate(targets, 1)]
            for fut in as_completed(futures):
                indexed.append(fut.result())

    indexed.sort(key=lambda r: r[0])
    results = [(user, outcome, detail, key_path) for _, user, outcome, detail, key_path in indexed]

    elapsed = time.time() - started
    _print_summary(results, elapsed, api_key_name, api_key_out_dir_abs)

    # Exit non-zero if any account failed to reach a signed-in state, so the
    # script is usable in CI / scripted checks.
    ok = sum(1 for _, o, _, _ in results if o in (OUTCOME_SUCCESS, OUTCOME_RESET, OUTCOME_MFA_SETUP))
    return 0 if ok == len(results) else 1


# _emit_header prints the per-account banner (locked, so parallel workers don't
# split it across each other's lines).
def _emit_header(i, n, account):
    with _PRINT_LOCK:
        print("\n[%d/%d] %s  (%s)" % (i, n, account.username, account.start_url), flush=True)


# _print_summary renders the end-of-run report: a per-account result line (with
# the saved key path when there is one), an outcome-count breakdown, total
# elapsed time, and where the API keys were written.
def _print_summary(results, elapsed, api_key_name, api_key_out_dir_abs):
    success_codes = (OUTCOME_SUCCESS, OUTCOME_RESET, OUTCOME_MFA_SETUP)
    ok = sum(1 for _, o, _, _ in results if o in success_codes)
    keys_saved = [kp for _, _, _, kp in results if kp]

    print("\n" + "=" * 72)
    print("  RESULTS")
    print("-" * 72)
    for user, outcome, detail, key_path in results:
        line = "  %-32s %s" % (user, outcome)
        if key_path:
            line += "  [key: %s]" % os.path.basename(key_path)
        print(line)

    # Outcome breakdown -- count each terminal state so a batch run is legible
    # at a glance (e.g. how many needed manual MFA vs. errored).
    counts = {}
    for _, outcome, _, _ in results:
        counts[outcome] = counts.get(outcome, 0) + 1

    print("-" * 72)
    print("  STATS")
    print("    signed in         : %d / %d" % (ok, len(results)))
    for outcome in sorted(counts):
        print("    %-18s: %d" % (outcome, counts[outcome]))
    print("    API keys saved    : %d" % len(keys_saved))
    print("    elapsed           : %.1fs" % elapsed)

    print("-" * 72)
    print("  API KEYS")
    if api_key_name:
        print("    output directory  : %s" % api_key_out_dir_abs)
        if keys_saved:
            for kp in keys_saved:
                print("      - %s" % kp)
        else:
            print("      (no keys saved -- no account reached a signed-in state)")
    else:
        print("    (API key generation disabled via --no-api-key)")
    print("=" * 72)


if __name__ == "__main__":
    sys.exit(main())
