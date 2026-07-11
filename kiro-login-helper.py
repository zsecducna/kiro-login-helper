#!/usr/bin/env python3
# kiro-login-helper.py
#
# Interactive, step-by-step helper that walks a user through the Kiro (AWS
# CodeWhisperer) browser SSO sign-in and writes a CLIProxyAPI-compatible Kiro
# auth JSON file. It targets the *enterprise / external IdP* path used by
# Microsoft 365 / Entra ID (Azure AD) tenants, and also transparently handles
# the social (Google/GitHub) path because both arrive on the same loopback
# listener.
#
# This is a faithful Python re-implementation of the Go login flow that lives in
# internal/auth/kiro/social.go + sdk/auth/kiro.go. The flow is:
#
#   1. Generate a PKCE verifier/challenge + anti-CSRF state.
#   2. Build the Kiro hosted sign-in URL (https://app.kiro.dev/signin?...) and
#      print it. The USER opens it in a *guest / incognito* browser window so it
#      authenticates against their corporate M365 identity cleanly (no cached
#      personal session interfering).
#   3. Bind a transient loopback HTTP listener on 127.0.0.1:3128 (and [::1]:3128)
#      to capture the redirect(s).
#   4. The portal detects the email belongs to an external IdP and redirects to
#      /signin/callback with the IdP descriptor (issuer_url, client_id, scopes).
#      We OIDC-discover the issuer, run a SECOND authorization-code+PKCE leg
#      against the IdP, and 302-redirect the same browser tab on to the IdP login.
#   5. The IdP redirects the authorization code back to /oauth/callback.
#   6. We exchange the code at the IdP token endpoint for access/refresh tokens.
#   7. We resolve the CodeWhisperer profile ARN via ListAvailableProfiles
#      (sending the mandatory TokenType: EXTERNAL_IDP header).
#   8. We write the final JSON as CLIProxyAPI_<username>.json.
#
# Only the Python standard library is used for the core OAuth flow so the script
# runs anywhere a recent python3 is installed -- no pip install required. The one
# optional exception is CloakBrowser (auto-opens the sign-in URL in a fresh,
# disposable browser profile); when it is not installed the script falls back to
# printing the URL for the user to open manually.

import argparse
import base64
import hashlib
import http.server
import io
import json
import os
import queue
import re
import secrets
import shutil
import socket
import socketserver
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# --- Constants mirrored from internal/auth/kiro/constants.go ------------------

# The Kiro hosted sign-in page the user opens in their browser.
SOCIAL_SIGNIN_BASE_URL = "https://app.kiro.dev/signin"
# The loopback redirect URI the portal validates and redirects back to. Fixed by
# the portal, so we must bind a listener on this exact host:port.
SOCIAL_REDIRECT_URI = "http://localhost:3128"
SOCIAL_REDIRECT_PORT = 3128
# Client tag the portal expects on the sign-in URL (mirrors the Kiro IDE).
SOCIAL_REDIRECT_FROM = "KiroIDE"
# Distinct loopback path the enterprise (external IdP) leg redirects the code to,
# so the listener can tell the social and enterprise legs apart.
OAUTH_CALLBACK_PATH = "/oauth/callback"
# Cognito-backed social token-exchange endpoint (Google/GitHub path).
SOCIAL_AUTH_BASE = "https://prod.us-east-1.auth.desktop.kiro.dev"
SOCIAL_TOKEN_URL = SOCIAL_AUTH_BASE + "/oauth/token"
# Default AWS region for the Amazon Q (CodeWhisperer) endpoints when none is supplied.
DEFAULT_REGION = "us-east-1"
# Regions offered by the interactive --region prompt (both are known-good
# CodeWhisperer control-plane hosts for this login flow).
REGION_CHOICES = ("us-east-1", "eu-central-1")
# Kiro IDE version embedded in the User-Agent (CodeWhisperer rejects non-Kiro UAs).
KIRO_IDE_VERSION = "0.10.32"
# X-Amz-Target for the ListAvailableProfiles call used to resolve the profile ARN.
LIST_PROFILES_TARGET = "AmazonCodeWhispererService.ListAvailableProfiles"
# How long to wait for the user to finish the browser sign-in.
SOCIAL_LOGIN_TIMEOUT_SECONDS = 10 * 60

# Allow-list of IdP issuer/endpoint host suffixes the enterprise leg may talk to.
# The issuer arrives in an attacker-influenceable portal callback, so it is
# constrained to known Microsoft Entra / Azure AD hosts. The leading dot anchors
# each suffix to a real subdomain boundary so "evil-microsoftonline.com" cannot
# match. Extend this list to onboard additional enterprise IdPs.
ALLOWED_EXTERNAL_IDP_SUFFIXES = (
    ".microsoftonline.com",
    ".microsoftonline.us",
    ".microsoftonline.cn",
)

# --- AWS SSO OIDC device-authorization login (Builder ID / IAM Identity Center) ---
#
# The IdC leg is a wholly separate flow from the hosted portal above: instead of the
# loopback-listener PKCE dance, it registers a public OIDC client, starts an RFC 8628
# device authorization for the tenant's start URL, has the user approve it in a browser,
# then polls the token endpoint until approval. Mirrors internal/auth/kiro/kiro.go +
# constants.go so the emitted credential refreshes identically to a native IDC login.

# clientName registered with AWS SSO OIDC (mirrors OAuthClientName).
OIDC_CLIENT_NAME = "kiro-oauth-client"
# issuerUrl sent at client registration (the Kiro IAM Identity Center instance). This is
# fixed by the reference Go client; the *user's* tenant is selected by the device-auth
# start URL, not by this value.
OIDC_ISSUER_URL = "https://identitycenter.amazonaws.com/ssoins-722374e8c3c8e6c6"
# AWS Builder ID portal start URL, used as the default when no IDC start URL is supplied.
BUILDER_ID_START_URL = "https://view.awsapps.com/start"
# CodeWhisperer scopes requested during client registration (mirrors OAuthScopes).
OIDC_SCOPES = (
    "codewhisperer:completions",
    "codewhisperer:analysis",
    "codewhisperer:conversations",
)
# RFC 8628 device-code grant type and the OAuth2 refresh grant type.
DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
REFRESH_GRANT_TYPE = "refresh_token"
# Minimum seconds between device-token polls (AWS default; a slow_down response raises it).
OIDC_MIN_POLL_INTERVAL = 5


# --- PKCE helpers -------------------------------------------------------------

# random_url_safe returns n cryptographically random bytes as unpadded base64url,
# matching the Go randomURLSafe helper.
def random_url_safe(n):
    return base64.urlsafe_b64encode(secrets.token_bytes(n)).rstrip(b"=").decode("ascii")


# pkce_challenge returns the S256 challenge (base64url, no padding) for a verifier.
def pkce_challenge(verifier):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# --- Endpoint validation (SSRF / open-redirect guard) -------------------------

# validate_external_idp_endpoint verifies a URL is https, has a named (non-IP)
# host, and that host ends with an allow-listed enterprise IdP suffix. Applied to
# the issuer before discovery and to BOTH discovered endpoints (authorize + token).
def validate_external_idp_endpoint(raw_url):
    parsed = urllib.parse.urlparse((raw_url or "").strip())
    if parsed.scheme.lower() != "https":
        raise ValueError("external IdP URL must be https: %r" % raw_url)
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("external IdP URL has no host: %r" % raw_url)
    # Reject IP-literal hosts outright; only named, allow-listed IdP hosts pass.
    try:
        socket.inet_pton(socket.AF_INET, host)
        is_ip = True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            is_ip = True
        except OSError:
            is_ip = False
    if is_ip:
        raise ValueError("external IdP host must not be an IP literal: %r" % host)
    for suffix in ALLOWED_EXTERNAL_IDP_SUFFIXES:
        if host.endswith(suffix):
            return
    raise ValueError("external IdP host %r is not allow-listed" % host)


# --- HTTP plumbing ------------------------------------------------------------

# _opener builds a urllib opener. When follow_redirects is False, any 3xx raises
# (mirrors the Go discovery client that refuses to follow redirects so a
# discovery host cannot bounce the fetch to an internal target).
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect not allowed", headers, fp)


def _opener(proxy_url, follow_redirects=True):
    handlers = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    else:
        # Honor HTTP(S)_PROXY env vars by default (urllib does this automatically
        # only when no ProxyHandler is installed).
        handlers.append(urllib.request.ProxyHandler())
    if not follow_redirects:
        handlers.append(_NoRedirect())
    return urllib.request.build_opener(*handlers)


# http_get_json fetches url and returns the parsed JSON body. Used for OIDC
# discovery (redirects disabled, body never echoed into errors).
def http_get_json(url, proxy_url, follow_redirects=True, timeout=30):
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    with _opener(proxy_url, follow_redirects).open(req, timeout=timeout) as resp:
        body = resp.read(1 << 20)
    return json.loads(body.decode("utf-8"))


# http_post_form posts a form-encoded body (the OAuth2 token endpoints) and
# returns (status, parsed_json_or_none, raw_text).
def http_post_form(url, form, proxy_url, timeout=30):
    data = urllib.parse.urlencode(form).encode("ascii")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    return _do_request(req, proxy_url, timeout)


# http_post_json posts a JSON body (the Cognito social token endpoint) and
# returns (status, parsed_json_or_none, raw_text).
def http_post_json(url, payload, headers, proxy_url, timeout=30):
    data = json.dumps(payload).encode("utf-8")
    base_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    base_headers.update(headers or {})
    req = urllib.request.Request(url, data=data, method="POST", headers=base_headers)
    return _do_request(req, proxy_url, timeout)


# _do_request executes a prepared request and normalizes both success and HTTP
# error responses into (status, parsed_json_or_none, raw_text).
def _do_request(req, proxy_url, timeout):
    try:
        with _opener(proxy_url).open(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    text = raw.decode("utf-8", "replace")
    parsed = None
    if text.strip():
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
    return status, parsed, text


# --- OIDC discovery + token exchange (enterprise / external IdP leg) -----------

# oidc_discover fetches the OpenID configuration for issuer_url and returns
# (authorization_endpoint, token_endpoint). The issuer and BOTH endpoints are
# validated against the IdP host allow-list; redirects are not followed.
def oidc_discover(issuer_url, proxy_url):
    validate_external_idp_endpoint(issuer_url)
    doc_url = issuer_url.strip().rstrip("/") + "/.well-known/openid-configuration"
    doc = http_get_json(doc_url, proxy_url, follow_redirects=False)
    auth_endpoint = (doc.get("authorization_endpoint") or "").strip()
    token_endpoint = (doc.get("token_endpoint") or "").strip()
    if not auth_endpoint or not token_endpoint:
        raise ValueError("OIDC discovery document missing authorization_endpoint or token_endpoint")
    validate_external_idp_endpoint(auth_endpoint)
    validate_external_idp_endpoint(token_endpoint)
    return auth_endpoint, token_endpoint


# external_idp_authorize_url builds the IdP authorization-code+PKCE URL the
# browser is 302-redirected to for the enterprise leg.
def external_idp_authorize_url(auth_endpoint, client_id, redirect_uri, scopes, challenge, state, login_hint):
    q = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "response_mode": "query",
        "state": state,
    }
    if (login_hint or "").strip():
        q["login_hint"] = login_hint
    return auth_endpoint + "?" + urllib.parse.urlencode(q)


# exchange_external_idp_code swaps the IdP authorization code (+ PKCE verifier)
# for IdP tokens at the discovered token endpoint (public-client auth code grant).
def exchange_external_idp_code(token_endpoint, client_id, code, verifier, redirect_uri, scopes, proxy_url):
    form = {
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code": code.strip(),
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    }
    if (scopes or "").strip():
        form["scope"] = scopes
    status, parsed, text = http_post_form(token_endpoint, form, proxy_url)
    parsed = parsed or {}
    access = parsed.get("access_token", "")
    if not (200 <= status < 300) or not access:
        err = parsed.get("error", "")
        desc = parsed.get("error_description", "")
        if err:
            raise RuntimeError("external IdP token exchange failed (status %d): %s: %s" % (status, err, desc))
        raise RuntimeError("external IdP token exchange failed (status %d): %s" % (status, text))
    # token_data: (access, refresh, expires_in, profile_arn). The IdP issues no
    # profile ARN; it is resolved separately via ListAvailableProfiles.
    return access, parsed.get("refresh_token", ""), int(parsed.get("expires_in", 0) or 0), ""


# --- Social (Cognito) token exchange (Google/GitHub leg) ----------------------

# exchange_social_code swaps a Cognito authorization code (+ PKCE verifier) for
# Kiro tokens at the social token endpoint (camelCase response, returns profileArn).
def exchange_social_code(code, verifier, proxy_url):
    payload = {"code": code.strip(), "code_verifier": verifier, "redirect_uri": SOCIAL_REDIRECT_URI}
    status, parsed, text = http_post_json(SOCIAL_TOKEN_URL, payload, None, proxy_url)
    parsed = parsed or {}
    access = parsed.get("accessToken", "")
    if not (200 <= status < 300) or not access:
        raise RuntimeError("social token exchange failed (status %d): %s" % (status, text))
    return (
        access,
        parsed.get("refreshToken", ""),
        int(parsed.get("expiresIn", 0) or 0),
        parsed.get("profileArn", "") or "",
    )


# --- AWS SSO OIDC device-authorization flow (IAM Identity Center leg) ----------

# The three OIDC endpoints are region-scoped: the client/register, device_authorization,
# and token calls must all target oidc.<region>.amazonaws.com for the region that hosts
# the Identity Center instance the start URL belongs to.
def oidc_register_url(region):
    return "https://oidc.%s.amazonaws.com/client/register" % region


def oidc_device_auth_url(region):
    return "https://oidc.%s.amazonaws.com/device_authorization" % region


def oidc_token_url(region):
    return "https://oidc.%s.amazonaws.com/token" % region


# register_oidc_client registers a public OAuth client and returns (client_id,
# client_secret). Both are persisted so the credential can be refreshed later against
# the AWS SSO OIDC token endpoint (refresh_token grant needs the client credentials).
def register_oidc_client(region, proxy_url):
    payload = {
        "clientName": OIDC_CLIENT_NAME,
        "clientType": "public",
        "scopes": list(OIDC_SCOPES),
        "grantTypes": [DEVICE_CODE_GRANT_TYPE, REFRESH_GRANT_TYPE],
        "issuerUrl": OIDC_ISSUER_URL,
    }
    status, parsed, text = http_post_json(oidc_register_url(region), payload, None, proxy_url)
    parsed = parsed or {}
    client_id = parsed.get("clientId", "") or ""
    client_secret = parsed.get("clientSecret", "") or ""
    if not (200 <= status < 300) or not client_id or not client_secret:
        raise RuntimeError("OIDC client registration failed (status %d): %s" % (status, text))
    return client_id, client_secret


# start_device_authorization requests a device+user code pair for the start URL. It
# returns the raw response dict (deviceCode, userCode, verificationUri,
# verificationUriComplete, expiresIn, interval).
def start_device_authorization(client_id, client_secret, start_url, region, proxy_url):
    payload = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "startUrl": (start_url or "").strip() or BUILDER_ID_START_URL,
    }
    status, parsed, text = http_post_json(oidc_device_auth_url(region), payload, None, proxy_url)
    parsed = parsed or {}
    if not (200 <= status < 300) or not parsed.get("deviceCode"):
        raise RuntimeError("device authorization failed (status %d): %s" % (status, text))
    return parsed


# poll_for_idc_token polls the token endpoint until the user approves, the device code
# expires, or the overall timeout elapses. Returns (access, refresh, expires_in). It
# honors the server-provided interval (respecting slow_down back-off) and never polls
# faster than OIDC_MIN_POLL_INTERVAL.
def poll_for_idc_token(client_id, client_secret, device_code, region, interval, expires_in, timeout, proxy_url):
    interval = max(int(interval or 0), OIDC_MIN_POLL_INTERVAL)
    # The device code has its own lifetime; never wait past it or the caller's timeout.
    window = timeout if not expires_in else min(timeout, expires_in)
    deadline = time.time() + window
    while True:
        time.sleep(interval)
        if time.time() > deadline:
            raise RuntimeError("device code expired before authorization completed")
        payload = {
            "clientId": client_id,
            "clientSecret": client_secret,
            "deviceCode": device_code,
            "grantType": DEVICE_CODE_GRANT_TYPE,
        }
        try:
            status, parsed, text = http_post_json(oidc_token_url(region), payload, None, proxy_url)
        except (urllib.error.URLError, OSError):
            # A transient network hiccup during one poll of a multi-minute wait must not
            # abort the whole login: keep polling until the deadline instead.
            continue
        parsed = parsed or {}
        err = (parsed.get("error", "") or "").strip()
        # authorization_pending: user hasn't approved yet. slow_down: also back off.
        if err in ("authorization_pending", "slow_down"):
            if err == "slow_down":
                interval += 5
            continue
        if not (200 <= status < 300):
            # A bare 400 with no error code is treated as still-pending (mirrors the Go
            # client); anything else is a hard failure surfaced to the user.
            if not err and status == 400:
                continue
            raise RuntimeError("token poll failed (status %d): %s" % (status, text))
        access = parsed.get("accessToken", "") or ""
        if not access:
            raise RuntimeError("empty access token in token response")
        return access, parsed.get("refreshToken", "") or "", int(parsed.get("expiresIn", 0) or 0)


# directory_id_from_start_url extracts the IAM Identity Center directory identifier from a
# start URL. AWS issues start URLs of the form https://<directory-id>.awsapps.com/start
# (or a friendly alias); the leading host label is that identifier. Returns "" when absent.
def directory_id_from_start_url(start_url):
    s = (start_url or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "https://" + s
    host = (urllib.parse.urlparse(s).hostname or "").strip()
    if not host:
        return ""
    return host.split(".")[0]


# idc_login runs the full device-authorization flow: register client, start device auth,
# open the verification URL (CloakBrowser when available, else printed), then poll for the
# token. Returns a dict with client_id, client_secret, access_token, refresh_token,
# expires_in. The verification URL is opened in a fresh disposable profile that is wiped
# once the flow finishes.
def idc_login(start_url, region, proxy_url, timeout):
    print("Registering OIDC client with AWS SSO OIDC (%s) ..." % region, flush=True)
    client_id, client_secret = register_oidc_client(region, proxy_url)
    print("Requesting device authorization ...", flush=True)
    dev = start_device_authorization(client_id, client_secret, start_url, region, proxy_url)
    verify_url = (dev.get("verificationUriComplete") or dev.get("verificationUri") or "").strip()
    user_code = (dev.get("userCode", "") or "").strip()

    cloak_cleanup = open_in_cloakbrowser(verify_url) if verify_url else None
    try:
        print()
        if cloak_cleanup:
            print("STEP 1. A fresh browser window has been opened to approve the sign-in.")
            print("        (New profile, no prior data; it is wiped once sign-in finishes.)")
        else:
            print("STEP 1. Open this URL in a browser and approve the sign-in:")
            print()
            print("  " + verify_url)
        if user_code:
            print()
            print("        Confirm the code shown in the browser matches: %s" % user_code)
        print()
        print("STEP 2. Sign in with your IAM Identity Center account and approve access.")
        print()
        print("Waiting for device authorization (timeout: %ds) ... " % timeout, flush=True)
        access, refresh, expires_in = poll_for_idc_token(
            client_id,
            client_secret,
            dev.get("deviceCode", ""),
            region,
            int(dev.get("interval", 0) or 0),
            int(dev.get("expiresIn", 0) or 0),
            timeout,
            proxy_url,
        )
    finally:
        if cloak_cleanup:
            cloak_cleanup()

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": expires_in,
    }


# --- Profile ARN resolution (ListAvailableProfiles) ---------------------------

# build_machine_id mirrors Go BuildMachineID: hex SHA-256 of the pipe-joined parts.
def build_machine_id(*parts):
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


# build_user_agent / build_x_amz_user_agent mirror the Kiro IDE UA strings so
# CodeWhisperer accepts the request.
def build_user_agent(machine_id):
    return (
        "aws-sdk-js/1.0.0 ua/2.1 os/windows#10.0.26200 lang/js md/nodejs#22.21.1 "
        "api/codewhispererruntime#1.0.0 m/N,E KiroIDE-%s-%s" % (KIRO_IDE_VERSION, machine_id)
    )


def build_x_amz_user_agent(machine_id):
    return "aws-sdk-js/1.0.0 KiroIDE-%s-%s" % (KIRO_IDE_VERSION, machine_id)


# list_available_profiles resolves the runtime-mandatory profile ARN for a
# credential. For external IdP tokens it MUST send TokenType: EXTERNAL_IDP or
# CodeWhisperer silently returns an empty profile list.
def codewhisperer_host(region):
    # Amazon Q runtime host for every region. "q.<region>.amazonaws.com" is the
    # current (rebranded) endpoint; the legacy "codewhisperer.<region>" host is
    # retired and not used for any region.
    return "q.%s.amazonaws.com" % region


def list_available_profiles(access_token, region, external_idp, proxy_url):
    if not access_token.strip():
        raise ValueError("access token is empty")
    machine_id = build_machine_id(access_token)
    url = "https://%s/" % codewhisperer_host(region)
    headers = {
        "Content-Type": "application/x-amz-json-1.0",
        "Accept": "application/x-amz-json-1.0",
        "Authorization": "Bearer " + access_token,
        "X-Amz-Target": LIST_PROFILES_TARGET,
        "amz-sdk-invocation-id": build_machine_id(access_token, region, "list-profiles"),
        "amz-sdk-request": "attempt=1; max=1",
        "x-amzn-kiro-agent-mode": "vibe",
        "x-amzn-codewhisperer-optout": "true",
        "User-Agent": build_user_agent(machine_id),
        "x-amz-user-agent": build_x_amz_user_agent(machine_id),
    }
    if external_idp:
        headers["TokenType"] = "EXTERNAL_IDP"
    req = urllib.request.Request(url, data=b"{}", method="POST", headers=headers)
    status, parsed, text = _do_request(req, proxy_url, timeout=30)
    if not (200 <= status < 300):
        raise RuntimeError("list-profiles failed (status %d): %s" % (status, text))
    for prof in (parsed or {}).get("profiles", []) or []:
        arn = (prof.get("arn") or "").strip()
        if arn:
            return arn
    raise RuntimeError("no profiles available")


# region_from_profile_arn extracts the region from an ARN shaped like
# "arn:aws:codewhisperer:{region}:..." (index 3). Returns "" when absent.
def region_from_profile_arn(profile_arn):
    parts = (profile_arn or "").strip().split(":")
    if len(parts) >= 4:
        return parts[3].strip()
    return ""


# --- Username / filename helpers ----------------------------------------------

# decode_jwt_claims best-effort decodes the JWT payload (segment 1) of a token.
def decode_jwt_claims(token):
    parts = (token or "").strip().split(".")
    if len(parts) < 2:
        return {}
    seg = parts[1]
    # base64url decode, tolerating missing padding.
    padded = seg + "=" * (-len(seg) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except (ValueError, TypeError):
        return {}
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return {}


# derive_username pulls a human identity from the access-token JWT, preferring
# the M365 sign-in name. Returns "" when nothing usable is found.
def derive_username(access_token):
    claims = decode_jwt_claims(access_token)
    for key in ("preferred_username", "email", "upn", "unique_name", "name", "oid", "sub"):
        val = (claims.get(key) or "").strip()
        if val:
            return val
    return ""


# sanitize_file_component mirrors Go sanitizeFileComponent: keep alphanumerics
# plus '.', '_', '-'; collapse every other run into a single '-'; trim dashes.
def sanitize_file_component(s):
    s = (s or "").strip()
    if not s:
        return ""
    out = io.StringIO()
    prev_dash = False
    for ch in s:
        safe = ch.isalnum() and ch.isascii() or ch in "._-"
        if safe:
            out.write(ch)
            prev_dash = False
        elif not prev_dash:
            out.write("-")
            prev_dash = True
    return out.getvalue().strip("-")


# --- Loopback callback listener (replicates StartKiroLoginListener) -----------

# FlowState carries the shared, thread-safe state across the two HTTP server
# instances (IPv4 + IPv6) and the request handler threads.
class FlowState:
    def __init__(self, portal_state, proxy_url):
        self.portal_state = portal_state
        self.proxy_url = proxy_url
        self.lock = threading.Lock()
        self.leg2 = None  # set once when the enterprise descriptor arrives
        self.result_queue = queue.Queue(maxsize=1)
        self._delivered = False

    # deliver pushes the first (and only) result; later calls are ignored.
    def deliver(self, result):
        with self.lock:
            if self._delivered:
                return
            self._delivered = True
        self.result_queue.put(result)


# CallbackHandler implements the redirect state machine: enterprise leg-1
# descriptor -> 302 to IdP; enterprise leg-2 code at /oauth/callback; social code.
class CallbackHandler(http.server.BaseHTTPRequestHandler):
    # Silence the default per-request stderr logging.
    def log_message(self, fmt, *args):
        pass

    # _html writes a minimal browser-facing page after the final redirect.
    def _html(self, ok):
        msg = (
            "Kiro sign-in complete. You can close this tab and return to the terminal."
            if ok
            else "Kiro sign-in failed. Return to the terminal and try again."
        )
        body = (
            '<!doctype html><html><head><meta charset="utf-8"><title>Kiro Sign-In</title></head>'
            '<body style="font-family:sans-serif;padding:2rem"><p>%s</p></body></html>' % msg
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # _empty sends a 204 used to ignore stray/duplicate hits without consuming
    # the one-shot result.
    def _empty(self, code=204):
        self.send_response(code)
        self.end_headers()

    def do_GET(self):
        state = self.server.flow_state
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        q = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}

        # --- Enterprise leg-1: external IdP descriptor (no code) ---
        # Gate on path != /oauth/callback so a forged /oauth/callback?issuer_url=...
        # cannot reset an in-flight leg-2.
        is_descriptor = (q.get("login_option", "").strip().lower() == "external_idp") or bool(
            q.get("issuer_url", "").strip()
        )
        if path != OAUTH_CALLBACK_PATH and is_descriptor:
            with state.lock:
                already = state.leg2 is not None
            if already:
                return self._empty()
            issuer_url = q.get("issuer_url", "").strip()
            client_id = q.get("client_id", "").strip()
            scopes = q.get("scopes", "").strip()
            login_hint = q.get("login_hint", "").strip()
            if not client_id:
                self._html(False)
                state.deliver(RuntimeError("invalid external IdP descriptor (missing client_id)"))
                return
            try:
                # OIDCDiscover validates issuer + both discovered endpoints.
                auth_endpoint, token_endpoint = oidc_discover(issuer_url, state.proxy_url)
            except Exception as exc:  # noqa: BLE001 - surface any discovery failure to the user
                self._html(False)
                state.deliver(exc)
                return
            verifier = random_url_safe(96)
            state2 = random_url_safe(32)
            redirect_uri = SOCIAL_REDIRECT_URI + OAUTH_CALLBACK_PATH
            with state.lock:
                # Re-check under the lock to resolve a race between concurrent
                # descriptors: only the first sets leg2 and redirects.
                if state.leg2 is not None:
                    return self._empty()
                state.leg2 = {
                    "state": state2,
                    "verifier": verifier,
                    "token_endpoint": token_endpoint,
                    "issuer_url": issuer_url,
                    "client_id": client_id,
                    "scopes": scopes,
                    "redirect_uri": redirect_uri,
                }
            auth_url = external_idp_authorize_url(
                auth_endpoint, client_id, redirect_uri, scopes, pkce_challenge(verifier), state2, login_hint
            )
            # Redirect the SAME browser tab on to the IdP login page.
            self.send_response(302)
            self.send_header("Location", auth_url)
            self.end_headers()
            return

        # --- Enterprise leg-2: IdP authorization code at /oauth/callback ---
        if path == OAUTH_CALLBACK_PATH:
            with state.lock:
                ctx2 = state.leg2
            code = q.get("code", "").strip()
            cb_state = q.get("state", "").strip()
            err = q.get("error", "").strip()
            # Ignore callbacks that don't match the in-flight leg-2 state.
            if ctx2 is None or not cb_state or cb_state != ctx2["state"]:
                return self._empty()
            if err:
                desc = q.get("error_description", "").strip()
                self._html(False)
                state.deliver(RuntimeError("external IdP authorization error: %s %s" % (err, desc)))
                return
            if not code:
                return self._empty()
            self._html(True)
            state.deliver({"kind": "external_idp", "code": code, **ctx2})
            return

        # --- Social leg-1: Cognito authorization code ---
        code = q.get("code", "").strip()
        err = q.get("error", "").strip()
        cb_state = q.get("state", "").strip()
        if not code and not err:
            return self._empty()
        if not state.portal_state or cb_state != state.portal_state:
            return self._empty()
        if err:
            desc = q.get("error_description", "").strip()
            self._html(False)
            state.deliver(RuntimeError("SSO authorization error: %s %s" % (err, desc)))
            return
        self._html(True)
        state.deliver({"kind": "social", "code": code})


# ThreadingHTTPServer subclasses that share a FlowState. Two families are bound
# because a browser resolving "localhost" may use IPv4 or IPv6.
class _V4Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _V6Server(_V4Server):
    address_family = socket.AF_INET6


# start_listener binds the loopback listener(s) and returns (servers, flow_state).
# The IPv4 bind is mandatory; the IPv6 bind is best-effort.
def start_listener(portal_state, proxy_url):
    flow_state = FlowState(portal_state, proxy_url)
    servers = []
    try:
        v4 = _V4Server(("127.0.0.1", SOCIAL_REDIRECT_PORT), CallbackHandler)
    except OSError as exc:
        raise RuntimeError(
            "cannot bind loopback 127.0.0.1:%d for the SSO callback (is the port in use?): %s"
            % (SOCIAL_REDIRECT_PORT, exc)
        )
    v4.flow_state = flow_state
    servers.append(v4)
    try:
        v6 = _V6Server(("::1", SOCIAL_REDIRECT_PORT), CallbackHandler)
        v6.flow_state = flow_state
        servers.append(v6)
    except OSError:
        # IPv6 loopback unavailable; IPv4 alone is sufficient on most systems.
        pass
    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    return servers, flow_state


# --- CloakBrowser launch (fresh, disposable profile) ---------------------------

# open_in_cloakbrowser opens `url` in a CloakBrowser window backed by a brand-new
# temporary profile directory: a real profile (not incognito, so the M365 portal
# never sees an empty/ephemeral-context signal) that starts with zero data because
# the directory was just created. Returns a cleanup() callable that closes the
# browser and deletes the profile directory -- the caller must invoke it once the
# login flow finishes (success, failure, or timeout) so no browsing data survives.
# Returns None when the optional `cloakbrowser` package is not installed, or the
# launch fails for any reason, so the caller can fall back to a manual URL.
def open_in_cloakbrowser(url):
    try:
        from cloakbrowser import launch_persistent_context
    except ImportError:
        return None
    profile_dir = tempfile.mkdtemp(prefix="kiro-login-cloakbrowser-")
    ctx = None
    try:
        ctx = launch_persistent_context(profile_dir, headless=False)
        ctx.new_page().goto(url)
    except Exception:  # noqa: BLE001 - any launch/navigation failure falls back to a manual open
        if ctx is not None:  # launch succeeded but goto() failed -- don't orphan the process
            try:
                ctx.close()
            except Exception:  # noqa: BLE001 - best-effort browser shutdown
                pass
        shutil.rmtree(profile_dir, ignore_errors=True)
        return None

    def cleanup():
        try:
            ctx.close()
        except Exception:  # noqa: BLE001 - best-effort browser shutdown
            pass
        shutil.rmtree(profile_dir, ignore_errors=True)

    return cleanup


# --- Final auth JSON assembly -------------------------------------------------

# build_auth_json assembles the CLIProxyAPI-compatible Kiro credential dict. It
# mirrors the flattened metadata map persisted by buildKiroAuth + the file store
# (note: alphabetical keys, a "disabled" flag, a millisecond "timestamp", and no
# "email" key when the email claim is absent -- exactly like the sample file).
def build_auth_json(token, region):
    expired = ""
    if token["expires_in"] > 0:
        expires_at = int(time.time()) + token["expires_in"]
        expired = datetime.fromtimestamp(expires_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    obj = {
        "access_token": token["access_token"],
        "auth_method": token["auth_method"],
        "disabled": False,
        "refresh_token": token["refresh_token"],
        "region": region,
        "timestamp": int(time.time() * 1000),
        "type": "kiro",
    }
    if expired:
        obj["expired"] = expired
    if token.get("profile_arn"):
        obj["profile_arn"] = token["profile_arn"]
    # External IdP (enterprise) refresh material.
    if token.get("client_id"):
        obj["client_id"] = token["client_id"]
    if token.get("token_endpoint"):
        obj["token_endpoint"] = token["token_endpoint"]
    if token.get("issuer_url"):
        obj["issuer_url"] = token["issuer_url"]
    if token.get("scopes"):
        obj["scopes"] = token["scopes"]
    # AWS SSO OIDC (IAM Identity Center) refresh material. The refresh_token grant needs
    # the client_secret alongside client_id; start_url/username record the tenant and the
    # operator-supplied account label (the IDC access token is opaque and carries no name).
    if token.get("client_secret"):
        obj["client_secret"] = token["client_secret"]
    if token.get("start_url"):
        obj["start_url"] = token["start_url"]
    if token.get("username"):
        obj["username"] = token["username"]
    return obj


# --- Interactive driver -------------------------------------------------------

# Telegram contact surfaced on the banner so users always know where to reach
# the author / bot for support, updates, and new credential drops.
TELEGRAM_HANDLE = "@codezdev_bot"
TELEGRAM_URL = "https://t.me/codezdev_bot"


def print_banner(subtitle=""):
    """Print a framed ASCII banner with the tool name and Telegram bot link.

    Colour is emitted only when writing to a real terminal (and NO_COLOR is
    unset) so piped/redirected output stays clean. Every glyph used -- box
    drawing plus the ANSI-Shadow block letters -- is single terminal column
    wide, so plain len()-based padding keeps the right border aligned.
    """
    use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    def c(code, text):
        # Wrap text in an SGR colour code, or pass it through untouched when
        # colour is disabled. Length math elsewhere uses the *plain* text so
        # these escape sequences never disturb the border alignment.
        return "\033[%sm%s\033[0m" % (code, text) if use_color else text

    # ANSI-Shadow block letters, one list per glyph. Each list's rows share a
    # fixed width (K/R=8, I=3, O=9) so zip+join yields evenly aligned rows.
    K = ["██╗  ██╗", "██║ ██╔╝", "█████╔╝ ", "██╔═██╗ ", "██║  ██╗", "╚═╝  ╚═╝"]
    I = ["██╗", "██║", "██║", "██║", "██║", "╚═╝"]
    R = ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"]
    O = [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "]
    logo = ["".join(parts) for parts in zip(K, I, R, O)]

    width = 76  # inner width; +2 border chars == the 78-col rule used below

    def row(plain, colored=None, indent=None):
        # Render one bordered line. `plain` drives the padding math; `colored`
        # (defaulting to `plain`) is what actually prints. `indent` is the left
        # gap -- when omitted the content is centred.
        colored = plain if colored is None else colored
        if len(plain) > width:
            plain, colored = plain[:width], plain[:width]
        if indent is None:
            indent = (width - len(plain)) // 2
        right = max(0, width - len(plain) - indent)
        bar = c("38;5;44", "│")
        return bar + " " * indent + colored + " " * right + bar

    top = c("38;5;44", "┌" + "─" * width + "┐")
    bottom = c("38;5;44", "└" + "─" * width + "┘")

    print(top)
    print(row(""))
    for line in logo:
        print(row(line, c("1;38;5;44", line)))
    print(row(""))
    print(row("K I R O   L O G I N   H E L P E R",
              c("1;38;5;231", "K I R O   L O G I N   H E L P E R")))
    if subtitle:
        print(row(subtitle, c("38;5;245", subtitle)))
    print(row(""))
    tg_label, tg_val = "Telegram   ", TELEGRAM_HANDLE
    print(row(tg_label + tg_val,
              c("38;5;245", tg_label) + c("1;38;5;45", tg_val), indent=6))
    link_label, link_val = "Chat / bot ", TELEGRAM_URL
    print(row(link_label + link_val,
              c("38;5;245", link_label) + c("4;38;5;51", link_val), indent=6))
    print(row(""))
    print(bottom)
    print()


# prompt_region asks the operator to pick the AWS region for the
# CodeWhisperer control-plane calls. Always run interactively (unless
# overridden by --region) so a wrong region is never silently assumed.
def prompt_region(default_region):
    print("Select AWS region:")
    for i, opt in enumerate(REGION_CHOICES, 1):
        marker = " (default)" if opt == default_region else ""
        print("  %d) %s%s" % (i, opt, marker))
    default_index = REGION_CHOICES.index(default_region) + 1 if default_region in REGION_CHOICES else 1
    while True:
        choice = input("Region [%d]: " % default_index).strip()
        if not choice:
            return default_region
        if choice.isdigit() and 1 <= int(choice) <= len(REGION_CHOICES):
            return REGION_CHOICES[int(choice) - 1]
        if choice in REGION_CHOICES:
            return choice
        print("Invalid choice. Enter 1 or 2.")


# AWS region syntax (e.g. us-east-1, eu-central-1, ap-southeast-2). The region is
# interpolated into the OIDC endpoint hostname, so it is format-validated before use to
# stop a paste-typo from rerouting the client secret and tokens to an unintended host.
_AWS_REGION_RE = re.compile(r"^[a-z]{2}-[a-z]+-\d+$")


def valid_aws_region(region):
    return bool(_AWS_REGION_RE.match((region or "").strip()))


# prompt_idc_region asks for the AWS region hosting the IAM Identity Center instance.
# Unlike the portal flow, IDC instances can live in any region, so any syntactically valid
# region string is accepted (not just the two CodeWhisperer control-plane choices).
def prompt_idc_region(default_region):
    if not sys.stdin.isatty():
        return default_region
    while True:
        choice = input("AWS region for IAM Identity Center [%s]: " % default_region).strip()
        if not choice:
            return default_region
        if valid_aws_region(choice):
            return choice
        print("Invalid AWS region (expected e.g. us-east-1). Try again.")


# prompt_login_method lets the operator choose between the hosted SSO portal (the default
# social / external-IdP flow) and the AWS IAM Identity Center device flow. Returns
# (method, start_url) where method is "portal" or "idc". Non-interactive stdin defaults to
# the portal so existing scripted use is unchanged.
def prompt_login_method():
    if not sys.stdin.isatty():
        return "portal", ""
    print("Select Kiro login method:")
    print("  1) Hosted SSO portal — Microsoft 365 / Google / GitHub (default)")
    print("  2) AWS IAM Identity Center (start URL)")
    choice = input("Method [1]: ").strip().lower()
    if choice in ("2", "idc"):
        start_url = input("IDC Start URL (e.g. https://d-1234567890.awsapps.com/start): ").strip()
        return "idc", start_url
    return "portal", ""


# write_credential serializes the token bundle to CLIProxyAPI_<label>.json (mode 0600)
# in out_dir and returns the written path. Shared by every login method.
def write_credential(token, region, label, out_dir):
    safe = sanitize_file_component(label) or ("kiro-%d" % int(time.time() * 1000))
    obj = build_auth_json(token, region)
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "CLIProxyAPI_%s.json" % safe)
    # 0600: the file holds the refresh token (and OIDC client secret for IDC); owner-only.
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return out_path


# print_success prints the framed post-login summary shared by every login method.
def print_success(username, token, out_path):
    rule = "─" * 78
    print()
    print(rule)
    print("  Kiro authentication successful!")
    print("  Account : %s" % username)
    print("  Method  : %s" % token["auth_method"])
    print("  Profile : %s" % token["profile_arn"])
    print("  Saved   : %s" % out_path)
    print(rule)
    print()
    print("Next: copy this file into your CLIProxyAPI auths directory, e.g.")
    print("  cp '%s' ~/.cli-cache-proxy/auths/" % out_path)


# resolve_idc_profile_arn resolves the profile ARN for an IDC token, trying the login
# region first and then us-east-1 (a profile may be homed in a different region than the
# Identity Center instance). The IDC token is a normal AWS SSO token, so no EXTERNAL_IDP
# header is sent (external_idp=False).
def resolve_idc_profile_arn(access_token, region, proxy_url):
    last_exc = None
    tried = []
    for candidate in (region, DEFAULT_REGION):
        if not candidate or candidate in tried:
            continue
        tried.append(candidate)
        try:
            return list_available_profiles(access_token, candidate, False, proxy_url)
        except Exception as exc:  # noqa: BLE001 - try the fallback region before giving up
            last_exc = exc
    raise last_exc


# run_idc_login drives the AWS IAM Identity Center device-authorization login end to end
# and writes the CLIProxyAPI credential file. Returns a process exit code.
def run_idc_login(args, start_url, proxy_url):
    start_url = (start_url or "").strip()
    if not start_url:
        print("ERROR: an IAM Identity Center start URL is required for IdC login.", file=sys.stderr)
        return 1
    region = args.region or prompt_idc_region(DEFAULT_REGION)
    if not valid_aws_region(region):
        print("ERROR: invalid AWS region %r (expected e.g. us-east-1)." % region, file=sys.stderr)
        return 1
    # The IDC access token is opaque (no JWT identity), so the account label must come from
    # the operator or, failing that, the directory id in the start URL.
    label = args.username.strip() or directory_id_from_start_url(start_url)
    if not label:
        label = "kiro-%d" % int(time.time() * 1000)

    print_banner("AWS IAM Identity Center · device-authorization login")
    try:
        creds = idc_login(start_url, region, proxy_url, args.timeout)
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
        "username": label,
    }

    print("Resolving CodeWhisperer profile ARN ...", flush=True)
    try:
        token["profile_arn"] = resolve_idc_profile_arn(token["access_token"], region, proxy_url)
    except Exception as exc:  # noqa: BLE001 - profile is mandatory; report clearly
        print("ERROR: failed to resolve profile ARN: %s" % exc, file=sys.stderr)
        print(
            "       (The IAM Identity Center account must be provisioned for Kiro/CodeWhisperer.)",
            file=sys.stderr,
        )
        return 1

    # Prefer the region embedded in the ARN so the saved credential and runtime agree.
    arn_region = region_from_profile_arn(token["profile_arn"])
    if arn_region:
        region = arn_region

    out_path = write_credential(token, region, label, args.out_dir)
    print_success(label, token, out_path)
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Interactive Kiro M365/SSO login helper -> writes CLIProxyAPI_<username>.json",
    )
    parser.add_argument("--username", default="", help="Override the account label used in the filename")
    parser.add_argument(
        "--idc-start-url",
        default="",
        help="AWS IAM Identity Center start URL (e.g. https://d-1234567890.awsapps.com/start). "
        "When set, runs the IdC device-authorization login instead of the hosted SSO portal.",
    )
    parser.add_argument(
        "--region",
        default=None,
        choices=REGION_CHOICES,
        help="AWS region; omit to be prompted interactively",
    )
    parser.add_argument(
        "--out-dir",
        default=os.getcwd(),
        help="Directory to write the credential file into (default: current directory)",
    )
    parser.add_argument("--proxy", default="", help="Proxy URL for the OAuth/AWS calls (else HTTPS_PROXY env)")
    parser.add_argument(
        "--timeout",
        type=int,
        default=SOCIAL_LOGIN_TIMEOUT_SECONDS,
        help="Seconds to wait for the browser sign-in (default: %(default)s)",
    )
    args = parser.parse_args()
    proxy_url = args.proxy.strip() or None

    # Method selection: an explicit --idc-start-url forces the IAM Identity Center device
    # flow; otherwise ask interactively (defaulting to the hosted SSO portal). The portal
    # remains the default so existing non-interactive use is unchanged.
    idc_start_url = args.idc_start_url.strip()
    if idc_start_url:
        method = "idc"
    else:
        method, idc_start_url = prompt_login_method()
    if method == "idc":
        return run_idc_login(args, idc_start_url, proxy_url)

    region = args.region or prompt_region(DEFAULT_REGION)

    # Step 1: generate PKCE + state and build the hosted sign-in URL.
    verifier = random_url_safe(96)
    state = random_url_safe(32)
    challenge = pkce_challenge(verifier)
    signin_url = SOCIAL_SIGNIN_BASE_URL + "?" + urllib.parse.urlencode(
        {
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": SOCIAL_REDIRECT_URI,
            "redirect_from": SOCIAL_REDIRECT_FROM,
        }
    )

    # Step 2: bind the loopback listener BEFORE printing the URL so the redirect
    # cannot race ahead of a ready listener.
    try:
        servers, flow_state = start_listener(state, proxy_url)
    except RuntimeError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1

    # Step 3: open the sign-in URL. Prefer a fresh CloakBrowser window (a real,
    # just-created profile -- so the portal doesn't flag it as incognito -- wiped
    # once the login flow finishes); fall back to a manual URL otherwise.
    print_banner("Microsoft 365 · Entra ID (Azure AD) · SSO login helper")
    # cloak_cleanup is acquired before the try so the finally below reliably closes
    # the browser and wipes its profile even if a print() or Step 4's wait raises.
    cloak_cleanup = open_in_cloakbrowser(signin_url)
    try:
        if cloak_cleanup:
            print("STEP 1. A fresh browser window has been opened for you.")
            print("        (New profile, no prior data; it is wiped once sign-in finishes.)")
        else:
            print("STEP 1. Open the URL below in a *GUEST / INCOGNITO* browser window.")
            print("        (Incognito avoids a cached personal session hijacking the M365 login.)")
            print()
            print("        Chrome/Edge:  Ctrl/Cmd+Shift+N      Firefox:  Ctrl/Cmd+Shift+P")
            print()
            print("  " + signin_url)
        print()
        print("STEP 2. Sign in with your Microsoft 365 work/school account.")
        print("        You will be redirected automatically; when the page says")
        print('        "sign-in complete", return here.')
        print()
        print("Waiting for SSO authorization (timeout: %ds) ... " % args.timeout, flush=True)

        # Step 4: wait for the listener to capture the final result.
        result = flow_state.result_queue.get(timeout=args.timeout)
    except queue.Empty:
        for srv in servers:
            srv.shutdown()
        print("ERROR: SSO login timed out after %ds." % args.timeout, file=sys.stderr)
        return 1
    finally:
        for srv in servers:
            try:
                srv.shutdown()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
        if cloak_cleanup:
            cloak_cleanup()

    if isinstance(result, Exception):
        print("ERROR: %s" % result, file=sys.stderr)
        return 1

    # Step 5: exchange the captured authorization code for tokens.
    print("Authorization received. Exchanging code for tokens ...", flush=True)
    token = {"auth_method": result["kind"]}
    try:
        if result["kind"] == "external_idp":
            access, refresh, expires_in, _ = exchange_external_idp_code(
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
            access, refresh, expires_in, profile_arn = exchange_social_code(
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
    # provide one (always the case for external IdP).
    if not token.get("profile_arn"):
        print("Resolving CodeWhisperer profile ARN ...", flush=True)
        try:
            token["profile_arn"] = list_available_profiles(
                token["access_token"], region, external_idp, proxy_url
            )
        except Exception as exc:  # noqa: BLE001 - profile is mandatory; report clearly
            print("ERROR: failed to resolve profile ARN: %s" % exc, file=sys.stderr)
            print(
                "       (For M365: the account must be provisioned for Kiro/CodeWhisperer.)",
                file=sys.stderr,
            )
            return 1

    # If the ARN carries a region different from the requested one, prefer it so
    # the saved credential and the runtime endpoint agree.
    arn_region = region_from_profile_arn(token["profile_arn"])
    if arn_region:
        region = arn_region

    # Step 7: derive the username (M365 sign-in name) and write the file.
    username = args.username.strip() or derive_username(token["access_token"])
    if not username:
        # Last resort so a file is always produced.
        username = "kiro-%d" % int(time.time() * 1000)

    out_path = write_credential(token, region, username, args.out_dir)
    print_success(username, token, out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
