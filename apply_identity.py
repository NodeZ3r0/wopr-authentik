#!/usr/bin/env python3
"""Central Authentik identity changes for WOPR-055 (and the Authentik parts of WOPR-056/057).

Talks to the central Authentik API (default http://127.0.0.1:9091/api/v3, authentik
2025.12). The API token is AUTHENTIK_API_TOKEN from /opt/wopr/control-plane/.env, read
with `sudo -n` when the file is not readable. It stays in memory and is never printed
or logged.

Modes
  (default) --dry-run   read-only: GET requests only, prints the exact planned changes
  --apply PHASE         applies ONE phase; every change is logged to state/<utc>-<phase>.json
  --rollback LOG        undoes a logged apply, newest change first (add --dry-run to preview)

Phases, in run order. Each is idempotent (a second run plans nothing) and reversible.
  trust          D0  one account per email; new sign-ups verify their email
  antibot  WOPR-059  sign-up abuse defense: throwaway-email block, 3 sign-ups per client IP
                     per 24h, reputation gate on the login flows (only once auth.wopr.systems
                     pins X-Forwarded-For), Turnstile captcha on sign-up (only when its keys
                     are in Infisical and LoveJoos sends its relay proof)
  groups         D8  wopr-verified + yourspace-members, delete 'WOPR Admins-dup2',
                     LoveJoos service account + least-privilege API token (root-only file)
  yourspace-app  D7  public OAuth2 client 'yourspace' (PKCE S256 enforced) for beacon sign-in
  bink               user pk 23 -> username bink / name BINK, yourspace attribute,
                     yourspace-members + wopr-verified (paid), NOT lovejoos-users
  lovejoos-gate  D2  existing LoveJoos users -> lovejoos-users, then gate app 'lovejoos'.
                     Apply ONLY after the LoveJoos release (WOPR-056) is live.

Examples
  ./apply_identity.py                                   # dry-run, all phases
  ./apply_identity.py --phase groups                    # dry-run, one phase
  ./apply_identity.py --apply trust
  ./apply_identity.py --dry-run --phase antibot
  ./apply_identity.py --apply antibot --lovejoos-relay-ready   # also the captcha, if keys
  ./apply_identity.py --apply lovejoos-gate --lovejoos-release-deployed \\
      --lovejoos-emails lj-central-users.txt
  ./apply_identity.py --rollback state/20261005T120000.000000Z-trust.json --dry-run
  ./apply_identity.py --check-schema                    # live API shapes, read-only
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.1.0"
SUPPORTED_AUTHENTIK = "2025.12."

API_DEFAULT = "http://127.0.0.1:9091/api/v3"
ENV_FILE_DEFAULT = "/opt/wopr/control-plane/.env"
TOKEN_ENV_KEY = "AUTHENTIK_API_TOKEN"
STATE_DIR_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "state")

PHASES = ("trust", "antibot", "groups", "yourspace-app", "bink", "lovejoos-gate")
PHASE_TITLES = {
    "trust": "D0 - one account per email, verified sign-ups",
    "antibot": "WOPR-059 - sign-up abuse defense (throwaway email, per-IP cap, reputation, captcha)",
    "groups": "D8 - wopr-verified, yourspace-members, superuser cleanup, LoveJoos service account",
    "yourspace-app": "D7 - central OAuth2 client 'yourspace' for beacon sign-in",
    "bink": "BINK - pk 23 becomes bink / BINK, YourSpace member, verified (paid)",
    "lovejoos-gate": "D2 - LoveJoos only for members of lovejoos-users",
}

# --- trust (D0) -------------------------------------------------------------
POLICY_EMAIL_GUARD = "wopr-email-guard"
POLICY_SIGNUP_CLOSED = "wopr-signup-closed"
SELF_REG_FLOW = "self-registration"
SELF_REG_WRITE = "self-registration-write"
# New sign-ups live under this path, so the email guard can tell an abandoned
# (never confirmed) sign-up from every other inactive account.
SELF_REG_PATH = "users/self-registration"
# The confirmation link lasts 24h (EMAIL_STAGE_ATTRS); an hour of grace after that.
ABANDONED_AFTER_HOURS = 25
EMAIL_GUARD_NOTE = ("the email guard frees an address only from an abandoned, never-confirmed "
                    "sign-up on that path")
EMAIL_STAGE = "self-registration-email-verification"
EMAIL_TEMPLATE = "email/account_confirmation.html"
EMAIL_STAGE_ATTRS = {
    "use_global_settings": True,
    "template": EMAIL_TEMPLATE,
    "subject": "Confirm your WOPR account",
    "activate_user_on_success": True,
    "token_expiry": "hours=24",
}
# Prompt stages that must carry the guard (the D0 list). Others that write `email` and
# are used by a flow get it too; the first-boot admin setup stage is skipped on purpose.
REQUIRED_EMAIL_STAGES = ("self-registration-prompt", "onboarding-profile-prompt",
                         "default-user-settings")
SKIP_EMAIL_STAGES = {
    "stage-default-oobe-password": "first-boot admin setup (flow initial-setup); only runs "
                                   "while akadmin has no usable password",
}

EMAIL_GUARD_EXPR = '''\
# wopr-email-guard (WOPR-055 / D0) - managed by fixwave/authentik/apply_identity.py
# Validation policy on every prompt stage that writes "email":
#  1. one account per email address (case-insensitive);
#  2. a signed-in user may not change an existing email here unless authentik's own
#     email-change setting allows it (same rule as default-user-settings-authorization);
#  3. an abandoned sign-up does not hold its address forever. The confirmation link
#     cannot be re-sent, so an account that came from self-registration (path
#     users/self-registration), was never confirmed (inactive, never signed in) and is
#     older than its link (24h) plus an hour is deleted when the address is used again.
#     Nothing else is ever deleted here.
from datetime import datetime, timedelta, timezone
from authentik.core.models import USER_ATTRIBUTE_CHANGE_EMAIL, User

SELF_REG_PATH = "users/self-registration"
ABANDONED_AFTER = timedelta(hours=25)

prompt_data = request.context.get("prompt_data") or {}
if "email" not in prompt_data:
    return True
email = str(prompt_data.get("email") or "").strip()
if not email:
    return True
user = request.user
user_pk = getattr(user, "pk", None) if getattr(user, "is_authenticated", False) else None
def holders():
    qs = User.objects.filter(email__iexact=email)
    return qs.exclude(pk=user_pk) if user_pk is not None else qs

def unconfirmed(u):
    return (getattr(u, "path", "") == SELF_REG_PATH and not getattr(u, "is_active", True)
            and getattr(u, "last_login", None) is None)

cutoff = datetime.now(timezone.utc) - ABANDONED_AFTER
for old in list(holders()):
    joined = getattr(old, "date_joined", None)
    if unconfirmed(old) and joined is not None and joined < cutoff:
        ak_logger.info("wopr-email-guard: deleting an abandoned sign-up to free its address",
                       user=getattr(old, "username", ""), joined=str(joined))
        old.delete()
others = holders()
if others.exists():
    if all(unconfirmed(u) for u in others):
        ak_message("This address has a sign-up waiting to be confirmed. Use the link we "
                   "emailed (it works for 24 hours), or try again after that.")
    else:
        ak_message("This email address is already used by another account.")
    return False
current = str(getattr(user, "email", "") or "").strip() if user_pk is not None else ""
if current and current.lower() != email.lower():
    http_request = request.http_request
    default = getattr(getattr(http_request, "tenant", None), "default_user_change_email", False)
    allowed = user.group_attributes(http_request).get(USER_ATTRIBUTE_CHANGE_EMAIL, default)
    if not allowed:
        ak_message("Your email address can't be changed here.")
        return False
return True
'''

SIGNUP_CLOSED_EXPR = '''\
# wopr-signup-closed (WOPR-055 / D0, --signup close) - managed by fixwave/authentik/apply_identity.py
ak_message("Sign-up is closed. A WOPR account is created when you order a service.")
return False
'''

# --- antibot (WOPR-059) -----------------------------------------------------
# The disposable-email list is vendored byte for byte (the same file in every WOPR app,
# contract ABUSE-DEFENSE) and embedded in the policy. authentik keeps policies in its
# database, so the list travels with it (backups, restores, rollback of this script) and
# needs no file mounted into the authentik containers.
ABUSE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "abuse")
DISPOSABLE_FILE = os.path.join(ABUSE_DIR, "disposable_domains.txt")
DISPOSABLE_COMMIT_FILE = os.path.join(ABUSE_DIR, "SOURCE_COMMIT")
DISPOSABLE_SHA256 = "a1390dd93de132a45d6ffd598375310531da5358805659df4113f0584f663ef4"
DISPOSABLE_COMMIT = "1aac72a07cd89792016dd5d2056bc418d85b8f14"
DISPOSABLE_DOMAIN_RE = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")
POLICY_DISPOSABLE = "wopr-disposable-email"
POLICY_SIGNUP_IP = "wopr-signup-ip-limit"
POLICY_RELAY = "wopr-signup-relay"
POLICY_REPUTATION = "wopr-reputation"
POLICY_REPUTATION_GATE = "wopr-reputation-gate"
SIGNUP_PROMPT = "self-registration-prompt"
SIGNUP_IP_LIMIT = 3
SIGNUP_IP_WINDOW_HOURS = 24
RELAY_HEADER = "X-WOPR-Signup-Relay"
# authentik's built-in reputation: -1 per failed login or unknown username, +1 per
# successful login, kept per (username, client IP), clamped to the tenant limits (-5..5)
# and expiring after reputation.expiry (a day). check_username stays off: anyone who
# knows a username could otherwise lock its owner out.
REPUTATION_ATTRS = {"check_ip": True, "check_username": False, "threshold": -5}
PASSWORD_COMPONENT = "ak-stage-password-form"
CAPTCHA_STAGE = "wopr-turnstile"
TURNSTILE_KEYS = ("TURNSTILE_SITE_KEY", "TURNSTILE_SECRET_KEY")
# error_on_invalid_score must be True: authentik 2025.12 only checks the provider's
# "success" flag when it is (stages/captcha/stage.py, verify_captcha_token).
TURNSTILE_ATTRS = {"js_url": "https://challenges.cloudflare.com/turnstile/v0/api.js",
                   "api_url": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                   "interactive": True, "error_on_invalid_score": True}
CADDY_SITE_DEFAULT = "/etc/caddy-rig/sites-enabled/auth.wopr.systems.caddy"
CADDY_XFF_PIN = re.compile(r"header_up\s+X-Forwarded-For\s+(\{client_ip\}|"
                           r"\{http\.request\.header\.CF-Connecting-IP\})", re.I)
INFISICAL_ENV_DEFAULT = "/opt/grc/.infisical"
XFF_FIX = ("add 'header_up X-Forwarded-For {client_ip}' to every reverse_proxy block of that "
           "site and reload the wopr-caddy-rig container")

DISPOSABLE_EXPR_TEMPLATE = '''\
# wopr-disposable-email (WOPR-059) - managed by fixwave/authentik/apply_identity.py
# Validation policy on every prompt stage that writes "email", next to wopr-email-guard.
# Refuses a NEW address whose domain, or any parent domain, is a throwaway-inbox domain.
# The list below is the disposable-email-domains project's, commit @COMMIT@
# (@COUNT@ domains, sha256 @SHA256@),
# the same vendored file every WOPR app uses (fixwave/authentik/abuse/disposable_domains.txt).
# An address the signed-in user already has is never refused here, so nobody is locked
# out of the onboarding or settings form over an old address.
# The list lives inside this policy because authentik keeps policies in its database: no
# file in the authentik containers is needed. The check itself is after the list.
prompt_data = request.context.get("prompt_data") or {}
email = str(prompt_data.get("email") or "").strip().lower()
if "@" not in email:
    return True
user = request.user
if getattr(user, "is_authenticated", False):
    if str(getattr(user, "email", "") or "").strip().lower() == email:
        return True
domain = email.rsplit("@", 1)[1].strip().rstrip(".")
try:
    domain = domain.encode("idna").decode("ascii")
except UnicodeError:
    pass
DOMAINS = """
@DOMAINS@"""
blocked = frozenset(DOMAINS.split())
labels = [x for x in domain.split(".") if x]
if any(".".join(labels[i:]) in blocked for i in range(len(labels))):
    ak_message("Please use a permanent email address; throwaway inboxes can't be used here.")
    return False
return True
'''

RELAY_EXPR = '''\
# wopr-signup-relay (WOPR-059) - managed by fixwave/authentik/apply_identity.py
# True only when the request carries LoveJoos's relay proof: header X-WOPR-Signup-Relay
# equal to the key of API token 'lovejoos-api' of service account 'lovejoos-service'
# (account active, token not expired). LoveJoos's server sends it when it drives the
# self-registration flow for a person, straight to authentik on the docker network, never
# through the public URL. A browser cannot know the key, so it cannot claim what the proof
# unlocks: no captcha (LoveJoos runs its own proof-of-work) and no central per-IP cap
# (LoveJoos applies the same 3 sign-ups per IP per 24h itself).
# Used by wopr-signup-ip-limit (ak_call_policy) and, negated, on the captcha stage.
from hmac import compare_digest
from authentik.core.models import Token, TokenIntents

http = getattr(request, "http_request", None)
sent = str(http.headers.get("X-WOPR-Signup-Relay") or "").strip() if http is not None else ""
if not sent:
    return False
token = (Token.filter_not_expired(identifier="lovejoos-api", intent=TokenIntents.INTENT_API)
         .select_related("user").first())
if token is None:
    return False
owner = token.user
if owner.username != "lovejoos-service" or not owner.is_active:
    return False
return compare_digest(str(token.key).encode(), sent.encode())
'''

SIGNUP_IP_EXPR = '''\
# wopr-signup-ip-limit (WOPR-059) - managed by fixwave/authentik/apply_identity.py
# Validation policy on the self-registration prompt: at most 3 new accounts per client IP
# (IPv6: per /64 network) in any 24 hours, counted from authentik's own records: the event
# user_write with created=true, which authentik writes with the request's client IP each
# time a flow creates an account. Checked when the form is submitted, right before the
# account is written (a check when the flow starts could be passed by opening many
# sign-up pages first). The client IP is ak_client_ip, the first X-Forwarded-For entry,
# so auth.wopr.systems must pin that header to the real client
# (Caddy: header_up X-Forwarded-For {client_ip}). Not capped:
#  - a request with LoveJoos's relay proof (policy wopr-signup-relay): LoveJoos applies the
#    same rule itself and forwards the person's IP, so those sign-ups still count here
#    against that IP;
#  - a client IP that is not a public address: callers inside the Rig (a server driving
#    this flow without forwarding an IP must not use up everyone's allowance).
from datetime import timedelta
from ipaddress import ip_address, ip_network
from django.utils.timezone import now
from authentik.events.models import Event, EventAction

LIMIT = 3
WINDOW = timedelta(hours=24)

def network_of(addr):
    addr = getattr(addr, "ipv4_mapped", None) or addr
    return ip_network(f"{addr}/{64 if addr.version == 6 else 32}", strict=False)

client = getattr(ak_client_ip, "ipv4_mapped", None) or ak_client_ip
if not client.is_global:
    return True
if ak_call_policy("wopr-signup-relay").passing:
    return True
mine = network_of(client)
made = 0
for raw in (Event.objects.filter(action=EventAction.USER_WRITE, context__created=True,
                                 created__gte=now() - WINDOW)
            .exclude(client_ip=None).values_list("client_ip", flat=True)):
    try:
        if network_of(ip_address(raw)) == mine:
            made += 1
    except ValueError:
        continue
if made >= LIMIT:
    ak_message("Too many new accounts were made from your network in the last 24 hours. "
               "Please try again tomorrow.")
    return False
return True
'''

REPUTATION_GATE_EXPR = '''\
# wopr-reputation-gate (WOPR-059) - managed by fixwave/authentik/apply_identity.py
# Bound to every central login flow with a password stage (checked when the flow starts;
# after 5 wrong passwords the password stage ends the flow, so a guesser has to start
# again and meets this check) and to the self-registration prompt. Refuses a client IP
# with a bad reputation according to authentik's built-in reputation policy
# 'wopr-reputation': -1 per failed login or unknown username from that IP, +1 per
# successful login; bad = a total of -5 or lower; scores expire after a day. Someone
# refused can still reset their password (that flow is not gated), which signs them in
# and lifts the score.
# Not checked: client IPs that are not public addresses, i.e. callers inside the Rig
# (LoveJoos's /login drives the login flow from its server without forwarding the
# person's IP; one person's typos there must not lock every LoveJoos member out). That is
# only safe while auth.wopr.systems pins X-Forwarded-For to the real client, which
# apply_identity.py checks before it binds this policy.
client = getattr(ak_client_ip, "ipv4_mapped", None) or ak_client_ip
if not client.is_global:
    return True
if ak_call_policy("wopr-reputation").passing:
    ak_message("Too many failed sign-ins came from your network. Reset your password to get "
               "back in, or try again tomorrow.")
    return False
return True
'''

# --- groups (D8) ------------------------------------------------------------
GROUP_VERIFIED = "wopr-verified"
GROUP_YOURSPACE = "yourspace-members"
GROUP_LOVEJOOS = "lovejoos-users"
GROUP_DUP_SUPER = "WOPR Admins-dup2"
GROUP_DUP_SUPER_PK = "8b0c316d-229f-4849-8de8-9b0cf7c1a21f"
VERIFIED_ATTRS = {"wopr": {
    "meaning": "Verified - paid member",
    "writer": "control-plane paid-status sync job is the ONLY writer; admins may override "
              "for comped accounts (recorded by the control plane)",
    "card": "WOPR-055 / WOPR-057",
}}
YOURSPACE_ATTRS = {"wopr": {
    "meaning": "has a YourSpace server; may sign in to YourSpace with this account",
    "writer": "control-plane provisioning (D1)",
    "card": "WOPR-055",
}}
LJ_SA_USERNAME = "lovejoos-service"
LJ_ROLE = "lovejoos-service"
LJ_TOKEN_ID = "lovejoos-api"
LJ_TOKEN_FILE_DEFAULT = "/etc/lovejoos/authentik-sa.token"
LJ_GLOBAL_PERMS = ("authentik_core.view_user",)
LJ_GROUP_PERMS = ("authentik_core.add_user_to_group", "authentik_core.remove_user_from_group",
                  "authentik_core.view_group")
LJ_SA_ATTRS = {
    "goauthentik.io/user/token-expires": False,
    "wopr": {"purpose": "LoveJoos API -> central authentik: read users, add/remove members "
                        "of lovejoos-users. Nothing else.", "card": "WOPR-055"},
}
SA_PATH = "goauthentik.io/service-accounts"
# Permissions that let a role put users into groups (any group, wopr-verified included).
GROUP_WRITE_CODENAMES = {"add_user_to_group", "remove_user_from_group", "change_group",
                         "delete_group", "add_group"}
USER_WRITE_CODENAMES = {"add_user", "change_user"}

# --- lovejoos-gate (D2) -----------------------------------------------------
LOVEJOOS_APP = "lovejoos"

# --- yourspace-app (D7) -----------------------------------------------------
YS_APP_SLUG = "yourspace"
YS_APP_NAME = "YourSpace"
YS_PROVIDER_NAME = "YourSpace beacon sign-in (public, PKCE)"
YS_CLIENT_ID = "yourspace"
YS_REDIRECT_REGEX = r"^https://[a-z0-9-]+\.yourspace\.you/login/oidc/callback$"
YS_AUTH_FLOW = "default-provider-authorization-implicit-consent"
YS_INVALIDATION_FLOW = "default-provider-invalidation-flow"
YS_SIGNING_KEY_NAME = "authentik Self-signed Certificate"
OPENID_MAPPING_MANAGED = "goauthentik.io/providers/oauth2/scope-openid"
YS_ISSUER = "https://auth.wopr.systems/application/o/yourspace/"
POLICY_PKCE = "wopr-require-pkce-s256"
PKCE_EXPR = '''\
# wopr-require-pkce-s256 (WOPR-055 / D7) - managed by fixwave/authentik/apply_identity.py
# Bound to application 'yourspace' (policy engine mode "all", next to the
# yourspace-members group binding). authentik 2025.12 lets a public client sign in
# without PKCE, so this refuses any authorization request for this app that is not
# response_type=code with an S256 code_challenge. The token endpoint then insists on
# the matching code_verifier (authentik checks it whenever the code carries a challenge).
ctx = request.context
if "oauth_code_challenge" not in ctx:
    # Not an authorization request (token endpoint, app library, ...): nothing to check.
    return True
if ctx.get("oauth_response_type") != "code":
    ak_message("This sign-in is refused: only the authorization code flow is allowed.")
    return False
if not ctx.get("oauth_code_challenge") or ctx.get("oauth_code_challenge_method") != "S256":
    ak_message("This sign-in is refused: PKCE (S256) is required.")
    return False
return True
'''

# --- bink -------------------------------------------------------------------
BINK_PK = 23
BINK_EMAIL = "sbinkerd1@gmail.com"
BINK_USERNAME = "bink"
BINK_NAME = "BINK"
BINK_YOURSPACE = {"handle": "bink", "domain": "bink.yourspace.you"}
BARTER_APP = "barter-exchange"


# ============================================================================
# helpers
# ============================================================================
def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log_stamp() -> str:
    """Sortable UTC stamp for log file names (microseconds keep quick applies in order)."""
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


def mask_email(email: str | None) -> str:
    if not email or "@" not in email:
        return email or ""
    local, domain = email.split("@", 1)
    return local[:2] + "***@" + domain


def find(items, **kw):
    for item in items:
        if all(item.get(k) == v for k, v in kw.items()):
            return item
    return None


class Ref:
    """Placeholder for an id that only exists once an earlier change has run."""

    __slots__ = ("key", "label")

    def __init__(self, key: str, label: str):
        self.key = key
        self.label = label

    def __repr__(self) -> str:
        return f"<new {self.label}>"

    def __eq__(self, other):
        return isinstance(other, Ref) and other.key == self.key

    def __hash__(self):
        return hash(("Ref", self.key))


def external_ref(kind: str, name: str, phase: str) -> Ref:
    return Ref(f"external:{kind}:{name}", f"{kind} {name} (created by phase {phase})")


class InfisicalRef:
    """A secret read from Infisical only at the moment a change is applied. It is printed
    and logged as a placeholder, never as its value."""

    __slots__ = ("key", "source")

    def __init__(self, key: str, source):
        self.key = key
        self.source = source

    def __repr__(self) -> str:
        return f"<{self.key} from Infisical, not shown>"

    def __eq__(self, other):
        return isinstance(other, InfisicalRef) and other.key == self.key

    def __hash__(self):
        return hash(("InfisicalRef", self.key))


def walk_refs(obj):
    if isinstance(obj, Ref):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from walk_refs(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from walk_refs(v)


class MissingRef(Exception):
    pass


def resolve(obj, refs: dict, reveal: bool = False):
    """Fill in Refs. An InfisicalRef becomes its value only with reveal=True (the API call
    itself); whatever is printed or logged keeps the placeholder."""
    if isinstance(obj, Ref):
        if obj.key not in refs:
            raise MissingRef(repr(obj))
        return refs[obj.key]
    if isinstance(obj, InfisicalRef):
        return obj.source.value(obj.key) if reveal else repr(obj)
    if isinstance(obj, dict):
        return {k: resolve(v, refs, reveal) for k, v in obj.items()}
    if isinstance(obj, list):
        return [resolve(v, refs, reveal) for v in obj]
    if isinstance(obj, tuple):
        return "".join(str(resolve(v, refs, reveal)) for v in obj)
    return obj


def show(obj):
    """JSON-ish rendering where Refs print as <new ...>."""
    def conv(o):
        if isinstance(o, (Ref, InfisicalRef)):
            return repr(o)
        if isinstance(o, dict):
            return {k: conv(v) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            return [conv(v) for v in o]
        return o
    return json.dumps(conv(obj), sort_keys=False, ensure_ascii=False)


def show_path(path) -> str:
    if isinstance(path, tuple):
        return "".join(repr(p) if isinstance(p, Ref) else str(p) for p in path)
    return str(path)


# ============================================================================
# API client
# ============================================================================
class ApiError(Exception):
    def __init__(self, method: str, path: str, status: int, body: str):
        super().__init__(f"{method} {path} -> HTTP {status}: {body[:600]}")
        self.status = status


class Api:
    """Minimal authentik API client. Any non-GET call is refused unless write_enabled."""

    def __init__(self, base: str, token: str, write_enabled: bool = False, timeout: int = 60):
        self.base = base.rstrip("/")
        self.__token = token
        self.write_enabled = write_enabled
        self.timeout = timeout
        self.calls: list[tuple[str, str]] = []

    def _request(self, method, path, params=None, body=None):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"Authorization": "Bearer " + self.__token, "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        self.calls.append((method, path))
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read() or b""
            raise ApiError(method, path, exc.code, raw.decode("utf-8", "replace")) from None
        return status, (json.loads(raw.decode()) if raw else None)

    def get(self, path, **params):
        return self._request("GET", path, params or None)[1]

    def get_or_none(self, path, **params):
        try:
            return self.get(path, **params)
        except ApiError as exc:
            if exc.status == 404:
                return None
            raise

    def all(self, path, **params):
        out, page = [], 1
        while True:
            data = self.get(path, page=page, page_size=100, **params)
            out.extend(data["results"])
            if not (data.get("pagination") or {}).get("next"):
                return out
            page += 1

    def write(self, method, path, body=None):
        if method == "GET":
            raise ValueError("use get() for reads")
        if not self.write_enabled:
            raise RuntimeError(f"refusing {method} {path}: read-only (dry-run) mode")
        return self._request(method, path, None, body)


def parse_env_value(text: str, key: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if not line.startswith(key + "="):
            continue
        value = line.split("=", 1)[1].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        return value
    return ""


def read_api_token(env_file: str) -> str:
    """AUTHENTIK_API_TOKEN from env_file; uses `sudo -n` if the file is root-only."""
    try:
        with open(env_file, encoding="utf-8") as fh:
            token = parse_env_value(fh.read(), TOKEN_ENV_KEY)
    except PermissionError:
        proc = subprocess.run(["sudo", "-n", "sed", "-n", f"s/^{TOKEN_ENV_KEY}=//p", env_file],
                              capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise SystemExit(f"cannot read {env_file} with sudo -n (exit {proc.returncode})")
        first = proc.stdout.splitlines()[0] if proc.stdout.strip() else ""
        token = parse_env_value(f"{TOKEN_ENV_KEY}={first}", TOKEN_ENV_KEY)
    if not token:
        raise SystemExit(f"{TOKEN_ENV_KEY} not found in {env_file}")
    return token


class RootFiles:
    """Root-owned files (the LoveJoos token). Uses sudo -n unless already root."""

    def exists(self, path: str) -> bool:
        try:
            os.stat(path)
            return True
        except FileNotFoundError:
            return False
        except PermissionError:
            proc = subprocess.run(["sudo", "-n", "test", "-s", path], check=False,
                                  capture_output=True)
            return proc.returncode == 0

    def write_secret(self, path: str, content: str) -> None:
        if os.geteuid() == 0:
            tmp = path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, content.encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            os.chown(tmp, 0, 0)
            os.replace(tmp, path)
            return
        proc = subprocess.run(["sudo", "-n", "install", "-m", "0600", "-o", "root", "-g", "root",
                               "/dev/stdin", path], input=content, text=True,
                              capture_output=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"could not write {path} (sudo install exit {proc.returncode}): "
                               f"{proc.stderr.strip()[:300]}")

    def remove(self, path: str) -> None:
        if os.geteuid() == 0:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            return
        proc = subprocess.run(["sudo", "-n", "rm", "-f", "--", path], capture_output=True,
                              text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"could not remove {path}: {proc.stderr.strip()[:300]}")

    def read_text(self, path: str) -> str | None:
        """A root-only config file, read only; None when it is missing or unreadable."""
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.read()
        except FileNotFoundError:
            return None
        except PermissionError:
            proc = subprocess.run(["sudo", "-n", "cat", "--", path], capture_output=True,
                                  text=True, check=False)
            return proc.stdout if proc.returncode == 0 else None


class InfisicalUnavailable(Exception):
    pass


class Infisical:
    """Read-only Infisical client: the Rig's machine identity (CID, CSEC, WID, INFENV, API in
    /opt/grc/.infisical, the documented way to read Infisical on the Rig). It only answers
    whether a secret exists at path /, and gives its value when a change is applied. The
    identity, the access token and the values stay in memory; they are never printed."""

    KEYS = ("CID", "CSEC", "WID", "INFENV", "API")

    def __init__(self, env_file: str, timeout: int = 20):
        self.env_file = env_file
        self.timeout = timeout
        self.__cfg: dict | None = None
        self.__token: str | None = None
        self.__values: dict[str, str | None] = {}

    def describe(self) -> str:
        return f"identity {self.env_file}, path /"

    def _config(self) -> dict:
        if self.__cfg is None:
            try:
                with open(self.env_file, encoding="utf-8") as fh:
                    text = fh.read()
            except FileNotFoundError:
                raise InfisicalUnavailable(f"{self.env_file} not found") from None
            except PermissionError:
                proc = subprocess.run(["sudo", "-n", "grep", "-E", "^(CID|CSEC|WID|INFENV|API)=",
                                       self.env_file], capture_output=True, text=True,
                                      check=False)
                if proc.returncode != 0:
                    raise InfisicalUnavailable(f"cannot read {self.env_file} with sudo -n "
                                               f"(exit {proc.returncode})") from None
                text = proc.stdout
            cfg = {k: parse_env_value(text, k) for k in self.KEYS}
            missing = [k for k, v in cfg.items() if not v]
            if missing:
                raise InfisicalUnavailable(f"{self.env_file} lacks {', '.join(missing)}")
            self.__cfg = cfg
        return self.__cfg

    def _call(self, method: str, path: str, params=None, body=None, auth=True):
        """(status, json). Error bodies are never read or shown."""
        cfg = self._config()
        url = cfg["API"].rstrip("/") + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if auth:
            headers["Authorization"] = "Bearer " + self._login()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw.decode()) if raw else None)
        except urllib.error.HTTPError as exc:
            return exc.code, None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise InfisicalUnavailable(f"{cfg['API']} did not answer ({type(exc).__name__})") from None

    def _login(self) -> str:
        if self.__token is None:
            cfg = self._config()
            status, data = self._call("POST", "/api/v1/auth/universal-auth/login",
                                      body={"clientId": cfg["CID"], "clientSecret": cfg["CSEC"]},
                                      auth=False)
            token = (data or {}).get("accessToken") if status == 200 else None
            if not token:
                raise InfisicalUnavailable(f"universal-auth login refused (HTTP {status})")
            self.__token = token
        return self.__token

    def _fetch(self, key: str) -> str | None:
        if key not in self.__values:
            cfg = self._config()
            status, data = self._call("GET", f"/api/v3/secrets/raw/{urllib.parse.quote(key)}",
                                      {"workspaceId": cfg["WID"], "environment": cfg["INFENV"],
                                       "secretPath": "/"})
            if status == 404:
                self.__values[key] = None
            elif status == 200:
                value = ((data or {}).get("secret") or {}).get("secretValue")
                self.__values[key] = value or None
            else:
                raise InfisicalUnavailable(f"reading a secret answered HTTP {status}")
        return self.__values[key]

    def missing(self, keys) -> list[str]:
        """The names in `keys` that Infisical does not have (or has empty)."""
        return [k for k in keys if self._fetch(k) is None]

    def value(self, key: str) -> str:
        value = self._fetch(key)
        if value is None:
            raise InfisicalUnavailable(f"{key} is not in Infisical")
        return value


# ============================================================================
# live state (GET only)
# ============================================================================
class Snapshot:
    def __init__(self, api: Api, opts):
        self.api = api
        g, a = api.get, api.all
        self.version = (g("/admin/version/") or {}).get("version_current", "")
        self.settings = g("/admin/settings/")
        self.flows = a("/flows/instances/")
        self.flow_bindings = a("/flows/bindings/")
        self.prompt_stages = a("/stages/prompt/stages/")
        self.prompts = a("/stages/prompt/prompts/")
        self.email_stages = a("/stages/email/")
        self.email_templates = g("/stages/email/templates/") or []
        self.user_write_stages = a("/stages/user_write/")
        self.ident_stages = a("/stages/identification/")
        self.expr_policies = a("/policies/expression/")
        self.reputation_policies = a("/policies/reputation/")
        self.reputation_scores = ((g("/policies/reputation/scores/", page_size=1) or {})
                                  .get("pagination") or {}).get("count", 0)
        self.password_stages = a("/stages/password/")
        self.captcha_stages = a("/stages/captcha/")
        self.policy_bindings = a("/policies/bindings/")
        self.groups = a("/core/groups/", include_users="false")
        self.users = a("/core/users/", include_groups="false")
        self.oauth_sources = a("/sources/oauth/")
        self.source_connections = a("/sources/user_connections/oauth/")
        self.scope_mappings = a("/propertymappings/provider/scope/")
        self.keypairs = a("/crypto/certificatekeypairs/")
        self.apps = {slug: api.get_or_none(f"/core/applications/{slug}/")
                     for slug in (LOVEJOOS_APP, YS_APP_SLUG, BARTER_APP)}
        self.ys_providers = a("/providers/oauth2/", client_id=YS_CLIENT_ID)
        self.email_sent = g("/events/events/", action="email_sent", ordering="-created",
                            page_size=5)
        # groups / LoveJoos service account
        self.dup_group = self.group_by_pk(GROUP_DUP_SUPER_PK) or self.group(GROUP_DUP_SUPER)
        self.dup_used_by = (g(f"/core/groups/{self.dup_group['pk']}/used_by/")
                            if self.dup_group else [])
        self.lj_role = (a("/rbac/roles/", name=LJ_ROLE) or [None])[0]
        self.lj_role_global, self.lj_role_object = [], []
        if self.lj_role:
            self.lj_role_global = a("/rbac/permissions/", role=self.lj_role["pk"])
            self.lj_role_object = a("/rbac/permissions/roles/", uuid=self.lj_role["pk"])
        self.lj_tokens = a("/core/tokens/", identifier=LJ_TOKEN_ID)
        sa = find(self.users, username=LJ_SA_USERNAME)
        self.lj_sa_roles = a("/rbac/roles/", users=sa["pk"]) if sa else []
        verified = self.group(GROUP_VERIFIED)
        params = {"model": "authentik_core.group"}
        if verified:
            params["object_pk"] = verified["pk"]
        self.group_perm_roles = a("/rbac/permissions/assigned_by_roles/", **params)
        self.user_perm_roles = a("/rbac/permissions/assigned_by_roles/",
                                 model="authentik_core.user")
        # LoveJoos sign-ins recorded by authentik
        self.lj_authorize_events = []
        if self.apps.get(LOVEJOOS_APP):
            self.lj_authorize_events = self._authorize_events(self.apps[LOVEJOOS_APP]["pk"])
        # BINK's Barterra footprint (Barterra's OIDC subject is the username)
        self.bink_barter_events, self.bink_barter_tokens = [], []
        bink = self.user_by_pk(BINK_PK)
        barter = self.apps.get(BARTER_APP)
        if bink and barter:
            self.bink_barter_events = [
                e for e in self._authorize_events(barter["pk"], username=bink["username"])
                if (e.get("user") or {}).get("pk") == BINK_PK]
            if barter.get("provider"):
                for kind in ("refresh_tokens", "access_tokens"):
                    self.bink_barter_tokens += [
                        t for t in a(f"/oauth2/{kind}/", user=BINK_PK, provider=barter["provider"])
                        if (t.get("user") or {}).get("pk") == BINK_PK
                        and (t.get("provider") or {}).get("pk") == barter["provider"]]
        self.oldest_event = ((g("/events/events/", ordering="created", page_size=1) or {})
                             .get("results") or [{}])[0].get("created")

    def _authorize_events(self, app_pk: str, **extra):
        events = self.api.all("/events/events/", action="authorize_application",
                              context_authorized_app=app_pk.replace("-", ""), **extra)
        if not events:
            events = self.api.all("/events/events/", action="authorize_application",
                                  context_authorized_app=app_pk, **extra)
        return events

    def group(self, name):
        return find(self.groups, name=name)

    def group_by_pk(self, pk):
        return find(self.groups, pk=pk)

    def user_by_pk(self, pk):
        return find(self.users, pk=pk)

    def flow(self, slug):
        return find(self.flows, slug=slug)

    def flows_of_stage(self, stage_pk) -> list[str]:
        slugs = {f["pk"]: f["slug"] for f in self.flows}
        return sorted({slugs.get(b["target"], b["target"]) for b in self.flow_bindings
                       if b["stage"] == stage_pk})

    def prompt_keys(self, stage) -> list[str]:
        by_pk = {p["pk"]: p for p in self.prompts}
        return [by_pk[f]["field_key"] for f in stage.get("fields", []) if f in by_pk]


# ============================================================================
# plans
# ============================================================================
class Op:
    def __init__(self, key, desc, method, path, body=None, capture=None, inverse=None,
                 before=None, show_body=None, show_inverse=None):
        self.key = key
        self.desc = desc
        self.method = method
        self.path = path if isinstance(path, tuple) else (path,)
        self.body = body
        self.capture = capture or {}
        self.inverse = inverse
        self.before = before
        self.show_body = show_body
        self.show_inverse = show_inverse


def inv(method, path, body=None):
    return {"method": method, "path": path if isinstance(path, tuple) else (path,), "body": body}


class Plan:
    def __init__(self, phase: str):
        self.phase = phase
        self.checks: list[tuple[str, str]] = []
        self.ops: list[Op] = []
        self.texts: dict[str, str] = {}
        self.displays: dict[str, str] = {}

    def ok(self, msg):
        self.checks.append(("OK", msg))

    def info(self, msg):
        self.checks.append(("INFO", msg))

    def warn(self, msg):
        self.checks.append(("WARN", msg))

    def block(self, msg):
        self.checks.append(("BLOCK", msg))

    def add(self, op: Op) -> Op:
        self.ops.append(op)
        return op

    def text(self, name: str, value: str, display: str | None = None):
        self.texts[name] = value
        if display is not None:
            self.displays[name] = display

    def blockers(self) -> list[str]:
        out = [m for lvl, m in self.checks if lvl == "BLOCK"]
        produced = set()
        for op in self.ops:
            for ref in walk_refs([op.path, op.body]):
                if ref.key not in produced:
                    out.append(f"change '{op.desc}' needs {ref.label}, which does not exist "
                               "yet (run that phase first)")
            produced.update(op.capture.keys())
        return list(dict.fromkeys(out))


def ensure_expression_policy(p: Plan, s: Snapshot, name: str, expression: str, why: str,
                             display: str | None = None):
    """Returns the policy pk or a Ref to the policy created by this plan. `display` is what
    the dry-run prints instead of a very long expression."""
    # authentik's serializer trims the expression on save (CharField trim_whitespace), so
    # an untrimmed one never compares equal and the phase never converges (seen live
    # 2026-10-05: trust applied all 10 changes, then planned the guard again).
    expression = expression.strip()
    p.text(f"EXPRESSION {name}", expression, display)
    pol = find(s.expr_policies, name=name)
    if pol is None:
        ref = Ref(f"policy.{name}", f"policy {name}")
        p.add(Op(f"policy.{name}", f"create expression policy '{name}' ({why})", "POST",
                 "/policies/expression/",
                 {"name": name, "execution_logging": False, "expression": expression},
                 capture={ref.key: "pk"}, inverse=inv("DELETE", ("/policies/expression/", ref, "/"))))
        return ref
    if (pol.get("expression") or "").strip() != expression:
        p.add(Op(f"policy.{name}.expr", f"update the expression of policy '{name}' to this "
                 "script's version", "PATCH", ("/policies/expression/", pol["pk"], "/"),
                 {"expression": expression}, before={"expression": pol.get("expression")},
                 inverse=inv("PATCH", ("/policies/expression/", pol["pk"], "/"),
                             {"expression": pol.get("expression")}),
                 show_inverse=(None if display is None else {"expression": (
                     f"<the previous expression, {len(pol.get('expression') or '')} characters>")})))
    else:
        p.ok(f"expression policy '{name}' exists and is current (pk {pol['pk']})")
    return pol["pk"]


def binding_exists(s: Snapshot, target, policy=None, group=None):
    for b in s.policy_bindings:
        if b["target"] != target:
            continue
        if policy is not None and b.get("policy") == policy:
            return b
        if group is not None and b.get("group") == group:
            return b
    return None


def add_binding(p: Plan, key: str, desc: str, target, policy=None, group=None, order=0,
                negate=False, failure_result=False):
    ref = Ref(f"binding.{key}", f"binding {key}")
    body = {"target": target, "policy": policy, "group": group, "user": None, "order": order,
            "enabled": True, "negate": negate, "timeout": 30, "failure_result": failure_result}
    p.add(Op(f"binding.{key}", desc, "POST", "/policies/bindings/", body,
             capture={ref.key: "pk"}, inverse=inv("DELETE", ("/policies/bindings/", ref, "/"))))


# ---------------------------------------------------------------------------
def plan_trust(s: Snapshot, o) -> Plan:
    p = Plan("trust")

    # Self-service email change (D0: "turn it off if it is on").
    if s.settings.get("default_user_change_email"):
        p.add(Op("settings.change_email", "turn off self-service email change", "PATCH",
                 "/admin/settings/", {"default_user_change_email": False},
                 before={"default_user_change_email": True},
                 inverse=inv("PATCH", "/admin/settings/", {"default_user_change_email": True})))
    else:
        p.ok("system setting default_user_change_email is already False: users cannot change "
             "their own email in the settings flow (policy default-user-settings-authorization)")

    # Can central authentik send mail? (read-only evidence; nothing is sent)
    sent = (s.email_sent or {}).get("results") or []
    total = ((s.email_sent or {}).get("pagination") or {}).get("count", len(sent))
    recovery = [e["name"] for e in s.email_stages if e.get("use_global_settings")]
    if sent:
        latest = sent[0]
        p.info(f"central mail: {total} 'email_sent' event(s) on record, latest "
               f"{latest.get('created')} (subject '{(latest.get('context') or {}).get('subject')}', "
               f"from '{(latest.get('context') or {}).get('from_email')}'). authentik logs "
               "email_sent only after the SMTP server accepted the message. Email stage(s) on the "
               f"global SMTP settings: {', '.join(recovery) or 'none'}. => mail works: "
               "verify new sign-ups by email (not re-tested now: that would send mail)")
    else:
        p.warn("central mail: no 'email_sent' event on record - no proof that central authentik "
               "can send mail")
    if o.signup == "verify" and not sent:
        p.block("--signup verify needs working central mail; send a test email first "
                "(`ak test_email <addr>` in the authentik worker) or use --signup close")

    # 1. one account per email: validation policy on every prompt stage that writes email
    guard = ensure_expression_policy(p, s, POLICY_EMAIL_GUARD, EMAIL_GUARD_EXPR,
                                     "one account per email; no email change during onboarding")
    covered = set()
    for st in sorted(s.prompt_stages, key=lambda x: x["name"]):
        if "email" not in s.prompt_keys(st):
            continue
        flows = s.flows_of_stage(st["pk"])
        if st["name"] in SKIP_EMAIL_STAGES:
            p.info(f"prompt stage '{st['name']}' writes email but is skipped: "
                   f"{SKIP_EMAIL_STAGES[st['name']]}")
            continue
        if not flows:
            p.info(f"prompt stage '{st['name']}' writes email but no flow uses it: skipped")
            continue
        covered.add(st["name"])
        current = list(st.get("validation_policies") or [])
        if guard in current:
            p.ok(f"prompt stage '{st['name']}' ({', '.join(flows)}) already has {POLICY_EMAIL_GUARD}")
            continue
        p.add(Op(f"stage.{st['name']}.guard",
                 f"add {POLICY_EMAIL_GUARD} to prompt stage '{st['name']}' (flows: {', '.join(flows)})",
                 "PATCH", ("/stages/prompt/stages/", st["pk"], "/"),
                 {"validation_policies": current + [guard]},
                 before={"validation_policies": current},
                 inverse=inv("PATCH", ("/stages/prompt/stages/", st["pk"], "/"),
                             {"validation_policies": current})))
    for name in REQUIRED_EMAIL_STAGES:
        if name not in covered:
            p.block(f"prompt stage '{name}' (named in D0) was not found writing email in a flow")

    # 2. verified sign-ups (or sign-up closed)
    flow = s.flow(SELF_REG_FLOW)
    if flow is None:
        p.block(f"flow '{SELF_REG_FLOW}' not found")
        return p
    binds = sorted([b for b in s.flow_bindings if b["target"] == flow["pk"]],
                   key=lambda b: b["order"])
    write = find(s.user_write_stages, name=SELF_REG_WRITE)
    deny_policy = find(s.expr_policies, name=POLICY_SIGNUP_CLOSED)
    deny_binding = (binding_exists(s, flow["pk"], policy=deny_policy["pk"])
                    if deny_policy else None)
    if o.signup == "verify":
        if deny_binding:
            p.warn("sign-up is currently CLOSED by this script (--signup close was applied); "
                   "roll that apply back to reopen it")
        if write is None or not any(b["stage"] == write["pk"] for b in binds):
            p.block(f"user write stage '{SELF_REG_WRITE}' is not bound to '{SELF_REG_FLOW}'")
            return p
        if EMAIL_TEMPLATE not in {t.get("name") for t in s.email_templates}:
            p.block(f"email template {EMAIL_TEMPLATE} not available")
        est = find(s.email_stages, name=EMAIL_STAGE)
        if est is None:
            est_ref = Ref("stage.email", f"email stage {EMAIL_STAGE}")
            p.add(Op("stage.email", f"create email stage '{EMAIL_STAGE}' (confirmation link, "
                     "global SMTP settings, activates the account when clicked)", "POST",
                     "/stages/email/", {"name": EMAIL_STAGE, **EMAIL_STAGE_ATTRS},
                     capture={est_ref.key: "pk"},
                     inverse=inv("DELETE", ("/stages/email/", est_ref, "/"))))
        else:
            est_ref = est["pk"]
            diff = {k: v for k, v in EMAIL_STAGE_ATTRS.items() if est.get(k) != v}
            if diff:
                p.add(Op("stage.email.attrs", f"bring email stage '{EMAIL_STAGE}' back to the "
                         "intended settings", "PATCH", ("/stages/email/", est["pk"], "/"), diff,
                         before={k: est.get(k) for k in diff},
                         inverse=inv("PATCH", ("/stages/email/", est["pk"], "/"),
                                     {k: est.get(k) for k in diff})))
            else:
                p.ok(f"email stage '{EMAIL_STAGE}' exists (pk {est['pk']})")
        write_b = next(b for b in binds if b["stage"] == write["pk"])
        later = [b for b in binds if b["order"] > write_b["order"]]
        bound = [b for b in binds if b["stage"] == est_ref]
        if bound:
            eb = bound[0]
            if eb["order"] <= write_b["order"]:
                p.block(f"'{EMAIL_STAGE}' is bound at order {eb['order']}, before the user write "
                        f"stage ({write_b['order']}); fix by hand")
            else:
                p.ok(f"'{EMAIL_STAGE}' is bound to '{SELF_REG_FLOW}' at order {eb['order']}")
        else:
            nxt = later[0]["order"] if later else write_b["order"] + 20
            if nxt - write_b["order"] < 2:
                p.block(f"no free order between the user write stage ({write_b['order']}) and "
                        f"the next stage ({nxt})")
            else:
                order = write_b["order"] + (nxt - write_b["order"]) // 2
                ref = Ref("fsb.email", "flow binding of the email stage")
                p.add(Op("fsb.email", f"bind '{EMAIL_STAGE}' to flow '{SELF_REG_FLOW}' at order "
                         f"{order} (after '{SELF_REG_WRITE}' at {write_b['order']}, before "
                         f"'{later[0]['stage_obj']['name'] if later else 'end'}')", "POST",
                         "/flows/bindings/",
                         {"target": flow["pk"], "stage": est_ref, "order": order,
                          "evaluate_on_plan": False, "re_evaluate_policies": True,
                          "policy_engine_mode": "any", "invalid_response_action": "retry"},
                         capture={ref.key: "pk"},
                         inverse=inv("DELETE", ("/flows/bindings/", ref, "/"))))
        if not write.get("create_users_as_inactive"):
            p.add(Op("stage.write.inactive", f"'{SELF_REG_WRITE}': create new users inactive "
                     "(the confirmation link activates them). Runs after the email stage is "
                     "bound, so no sign-up is ever left inactive without a link", "PATCH",
                     ("/stages/user_write/", write["pk"], "/"), {"create_users_as_inactive": True},
                     before={"create_users_as_inactive": False},
                     inverse=inv("PATCH", ("/stages/user_write/", write["pk"], "/"),
                                 {"create_users_as_inactive": False})))
        else:
            p.ok(f"'{SELF_REG_WRITE}' already creates users inactive")
        if (write.get("user_path_template") or "") != SELF_REG_PATH:
            was = write.get("user_path_template") or ""
            p.add(Op("stage.write.path", f"'{SELF_REG_WRITE}': put new sign-ups under path "
                     f"'{SELF_REG_PATH}' ({EMAIL_GUARD_NOTE})", "PATCH",
                     ("/stages/user_write/", write["pk"], "/"), {"user_path_template": SELF_REG_PATH},
                     before={"user_path_template": was},
                     inverse=inv("PATCH", ("/stages/user_write/", write["pk"], "/"),
                                 {"user_path_template": was})))
        else:
            p.ok(f"'{SELF_REG_WRITE}' already puts new sign-ups under '{SELF_REG_PATH}'")
    else:  # close
        deny = ensure_expression_policy(p, s, POLICY_SIGNUP_CLOSED, SIGNUP_CLOSED_EXPR,
                                        "refuses the self-registration flow")
        if deny_binding:
            p.ok(f"flow '{SELF_REG_FLOW}' is already closed by {POLICY_SIGNUP_CLOSED}")
        else:
            add_binding(p, "signup_closed", f"bind {POLICY_SIGNUP_CLOSED} to flow "
                        f"'{SELF_REG_FLOW}' (direct links to the sign-up page are refused)",
                        flow["pk"], policy=deny, order=0)
        for st in s.ident_stages:
            if st.get("enrollment_flow") == flow["pk"]:
                # The serializer refuses a PATCH that carries neither user_fields nor sources,
                # so both go along unchanged.
                keep = {"user_fields": st.get("user_fields") or [], "sources": st.get("sources") or []}
                p.add(Op(f"ident.{st['name']}.enroll", f"identification stage '{st['name']}': "
                         "remove the sign-up link", "PATCH",
                         ("/stages/identification/", st["pk"], "/"),
                         {"enrollment_flow": None, **keep}, before={"enrollment_flow": flow["pk"]},
                         inverse=inv("PATCH", ("/stages/identification/", st["pk"], "/"),
                                     {"enrollment_flow": flow["pk"], **keep})))

    # 3. sources that link a sign-in to an existing account by email/username
    links = {}
    for c in s.source_connections:
        slug = (c.get("source_obj") or {}).get("slug") or c.get("source")
        links[slug] = links.get(slug, 0) + 1
    for src in sorted(s.oauth_sources, key=lambda x: x["slug"]):
        mode = src.get("user_matching_mode")
        if mode not in ("email_link", "username_link"):
            continue
        target = mode.replace("_link", "_deny")
        what = mode.split("_")[0]
        msg = (f"source '{src['name']}' ({src['slug']}) uses {mode}: a sign-in from that source "
               f"whose {what} matches an existing central account is LINKED to it, so whoever "
               f"controls an account there with BINK's {what} becomes BINK here")
        if o.keep_source_email_link:
            p.warn(msg + f" - kept (--keep-source-email-link); fix: user_matching_mode={target}")
            continue
        # OAuthSourceSerializer.validate() reads attrs["provider_type"] and, for generic types,
        # needs the three endpoint URLs in the same request; resend the current values so a
        # PATCH changes nothing else (no well-known/JWKS URL is sent, so nothing is fetched).
        keep_keys = ("provider_type", "authorization_url", "access_token_url", "profile_url")
        if any(k not in src for k in keep_keys):
            p.block(f"source '{src['slug']}': cannot read {', '.join(keep_keys)} to build a safe "
                    "PATCH; change user_matching_mode by hand")
            continue
        keep = {k: src.get(k) for k in keep_keys}
        p.add(Op(f"source.{src['slug']}", f"{msg}. Change to {target}: existing links "
                 f"({links.get(src['slug'], 0)}) keep working; new sign-ins that match an "
                 "existing account are refused (link it from the account's settings instead)",
                 "PATCH", ("/sources/oauth/", src["slug"], "/"),
                 {"user_matching_mode": target, **keep}, before={"user_matching_mode": mode},
                 inverse=inv("PATCH", ("/sources/oauth/", src["slug"], "/"),
                             {"user_matching_mode": mode, **keep})))

    # 4. existing duplicates would be stuck at the guard
    seen = {}
    for u in s.users:
        e = (u.get("email") or "").strip().lower()
        if e:
            seen.setdefault(e, []).append(u["username"])
    dups = {e: v for e, v in seen.items() if len(v) > 1}
    if dups:
        p.warn("accounts already sharing an email (they will be stopped by the guard until an "
               "admin fixes them): " + "; ".join(f"{mask_email(e)}: {', '.join(v)}"
                                                  for e, v in dups.items()))
    else:
        p.ok(f"no two of the {len(s.users)} accounts share an email today")
    p.info("API-created accounts (control plane D1, LoveJoos) do not pass through flows: their "
           "creators must check the email is unused first (see contract IDENTITY-GROUPS)")
    return p


# ---------------------------------------------------------------------------
def load_disposable(path: str | None = None, commit_path: str | None = None):
    """The vendored list as (text, domains, source commit). ValueError when the file is not
    the pinned one or holds anything but plain lowercase domain names (the text goes into a
    policy expression, so nothing else may get in)."""
    path = path or DISPOSABLE_FILE
    commit_path = commit_path or DISPOSABLE_COMMIT_FILE
    with open(path, "rb") as fh:
        raw = fh.read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != DISPOSABLE_SHA256:
        raise ValueError(f"{path} has sha256 {digest[:16]}..., not the pinned "
                         f"{DISPOSABLE_SHA256[:16]}... (vendor the list byte for byte and change "
                         "DISPOSABLE_SHA256 on purpose)")
    with open(commit_path, encoding="utf-8") as fh:
        commit = fh.read().strip()
    if commit != DISPOSABLE_COMMIT:
        raise ValueError(f"{commit_path} names commit {commit[:12]}, not {DISPOSABLE_COMMIT[:12]}")
    text = raw.decode("ascii")
    if not text.endswith("\n"):
        raise ValueError(f"{path} does not end with a newline")
    domains = text[:-1].split("\n")
    bad = [d for d in domains if not DISPOSABLE_DOMAIN_RE.fullmatch(d)]
    if bad:
        raise ValueError(f"{path}: {len(bad)} line(s) are not plain lowercase domain names, "
                         f"e.g. {bad[0][:40]!r}")
    return text, domains, commit


def disposable_expression(text: str, count: int, commit: str) -> tuple[str, str]:
    """(the policy expression, the same with the domain list left out for printing)."""
    head = (DISPOSABLE_EXPR_TEMPLATE.replace("@COMMIT@", commit).replace("@COUNT@", str(count))
            .replace("@SHA256@", DISPOSABLE_SHA256))
    expr = head.replace("@DOMAINS@", text, 1)
    shown = head.replace("@DOMAINS@", f"<{count} domains from abuse/disposable_domains.txt "
                         f"(sha256 {DISPOSABLE_SHA256[:16]}...), not printed>\n", 1)
    return expr, shown


def is_disposable(email: str, blocked) -> bool:
    """The policy's own test, for reporting existing accounts (see DISPOSABLE_EXPR_TEMPLATE)."""
    email = (email or "").strip().lower()
    if "@" not in email:
        return False
    labels = [x for x in email.rsplit("@", 1)[1].strip().rstrip(".").split(".") if x]
    return any(".".join(labels[i:]) in blocked for i in range(len(labels)))


def caddy_xff_pinned(text: str | None) -> tuple[bool, str]:
    """Does every reverse_proxy block of the auth site pin X-Forwarded-For to the real client?
    authentik 2025.12 takes the FIRST X-Forwarded-For entry as the client IP (ak_client_ip,
    events, reputation), and Caddy keeps a client-supplied one when the hop in front of it
    (cloudflared on 127.0.0.1) is a trusted proxy."""
    if text is None:
        return False, "could not be read"
    lines = [ln.split("#", 1)[0].strip() for ln in text.splitlines()]
    blocks = pinned = 0
    for i, line in enumerate(lines):
        if not re.match(r"reverse_proxy\b", line):
            continue
        blocks += 1
        depth = line.count("{") - line.count("}")
        found = False
        j = i + 1
        while depth > 0 and j < len(lines):
            if CADDY_XFF_PIN.fullmatch(lines[j]):
                found = True
            depth += lines[j].count("{") - lines[j].count("}")
            j += 1
        pinned += found
    if not blocks:
        return False, "has no reverse_proxy block"
    return pinned == blocks, (f"{pinned} of {blocks} reverse_proxy block(s) pin X-Forwarded-For "
                              "to the real client")


def email_prompt_stages(p: Plan, s: Snapshot) -> dict:
    """The prompt stages wopr-email-guard covers: they write `email` in a flow (the first-boot
    admin setup stage is skipped on purpose, as in phase trust)."""
    out = {}
    for st in sorted(s.prompt_stages, key=lambda x: x["name"]):
        if "email" not in s.prompt_keys(st) or st["name"] in SKIP_EMAIL_STAGES:
            continue
        if s.flows_of_stage(st["pk"]):
            out[st["name"]] = st
    for name in REQUIRED_EMAIL_STAGES:
        if name not in out:
            p.block(f"prompt stage '{name}' (named in D0) was not found writing email in a flow")
    return out


def login_flows(s: Snapshot) -> list:
    """Authentication flows with a password stage: what a password guesser can use."""
    out = []
    for f in sorted(s.flows, key=lambda x: x["slug"]):
        if f.get("designation") != "authentication":
            continue
        comps = {(b.get("stage_obj") or {}).get("component") for b in s.flow_bindings
                 if b["target"] == f["pk"]}
        if PASSWORD_COMPONENT in comps:
            out.append(f)
    return out


def ensure_reputation_policy(p: Plan, s: Snapshot):
    pol = find(s.reputation_policies, name=POLICY_REPUTATION)
    if pol is None:
        ref = Ref(f"policy.{POLICY_REPUTATION}", f"policy {POLICY_REPUTATION}")
        p.add(Op(f"policy.{POLICY_REPUTATION}", f"create reputation policy '{POLICY_REPUTATION}' "
                 "(authentik's built-in check: true when the client IP's score, summed over every "
                 f"username tried from it, is {REPUTATION_ATTRS['threshold']} or lower)", "POST",
                 "/policies/reputation/",
                 {"name": POLICY_REPUTATION, "execution_logging": False, **REPUTATION_ATTRS},
                 capture={ref.key: "pk"},
                 inverse=inv("DELETE", ("/policies/reputation/", ref, "/"))))
        return ref
    diff = {k: v for k, v in REPUTATION_ATTRS.items() if pol.get(k) != v}
    if diff:
        before = {k: pol.get(k) for k in diff}
        p.add(Op(f"policy.{POLICY_REPUTATION}.fix", f"reputation policy '{POLICY_REPUTATION}': "
                 f"{', '.join(diff)} back to the intended value", "PATCH",
                 ("/policies/reputation/", pol["pk"], "/"), diff, before=before,
                 inverse=inv("PATCH", ("/policies/reputation/", pol["pk"], "/"), before)))
    else:
        p.ok(f"reputation policy '{POLICY_REPUTATION}' exists as intended (pk {pol['pk']})")
    return pol["pk"]


def plan_login_gates(p: Plan, s: Snapshot, gate):
    for f in login_flows(s):
        slug, mode = f["slug"], f.get("policy_engine_mode")
        binds = [b for b in s.policy_bindings if b["target"] == f["pk"]]
        if any(b.get("policy") == gate for b in binds):
            p.ok(f"login flow '{slug}' already has {POLICY_REPUTATION_GATE} (mode {mode})")
            continue
        others = [b for b in binds if b.get("policy") != gate]
        if others and mode != "all":
            p.warn(f"login flow '{slug}' has {len(others)} other flow binding(s) in policy engine "
                   f"mode '{mode}': the gate would only be one of several alternatives there, so "
                   f"it is NOT bound (bind {POLICY_REPUTATION_GATE} by hand after reviewing them)")
            continue
        if mode != "all":
            p.add(Op(f"flow.{slug}.mode", f"login flow '{slug}': policy engine mode {mode} -> all "
                     "(it has no flow bindings yet, so nothing changes now; a binding added later "
                     "can never open the gate)", "PATCH", ("/flows/instances/", slug, "/"),
                     {"policy_engine_mode": "all"}, before={"policy_engine_mode": mode},
                     inverse=inv("PATCH", ("/flows/instances/", slug, "/"),
                                 {"policy_engine_mode": mode})))
        add_binding(p, f"repgate.{slug}", f"bind {POLICY_REPUTATION_GATE} to login flow '{slug}' "
                    "(checked when the flow starts; if the check itself fails with an error the "
                    "login goes ahead, so a fault cannot lock everyone out)", f["pk"],
                    policy=gate, order=0, failure_result=True)


def plan_captcha(p: Plan, s: Snapshot, o, relay):
    """Cloudflare Turnstile between the sign-up prompt and the user write stage, only when
    both keys are in Infisical and LoveJoos sends its relay proof (it skips the captcha)."""
    stage = find(s.captcha_stages, name=CAPTCHA_STAGE)
    try:
        missing = o.infisical.missing(TURNSTILE_KEYS)
    except InfisicalUnavailable as exc:
        p.info(f"captcha off: Infisical could not be read ({exc}); no captcha is planned")
        return
    if missing:
        p.info(f"captcha off: no Turnstile keys in Infisical ({', '.join(missing)} not found; "
               f"{o.infisical.describe()}), so nothing is planned for the captcha")
        if stage:
            p.warn(f"captcha stage '{CAPTCHA_STAGE}' exists although its keys are gone from "
                   "Infisical; it keeps the keys it was given (not changed here)")
        return
    if not o.lovejoos_relay_ready:
        p.warn("captcha held back: the Turnstile keys are in Infisical, but LoveJoos /register runs "
               f"this same flow from its server and must first send header {RELAY_HEADER} "
               "(contract ABUSE-DEFENSE-CENTRAL), or every LoveJoos sign-up would stop at the "
               "captcha. Re-run with --lovejoos-relay-ready once it does")
        return
    flow = s.flow(SELF_REG_FLOW)
    prompt = find(s.prompt_stages, name=SIGNUP_PROMPT)
    write = find(s.user_write_stages, name=SELF_REG_WRITE)
    binds = sorted([b for b in s.flow_bindings if flow and b["target"] == flow["pk"]],
                   key=lambda b: b["order"])
    prompt_b = next((b for b in binds if prompt and b["stage"] == prompt["pk"]), None)
    write_b = next((b for b in binds if write and b["stage"] == write["pk"]), None)
    if prompt_b is None or write_b is None:
        p.block(f"captcha: flow '{SELF_REG_FLOW}' needs '{SIGNUP_PROMPT}' and '{SELF_REG_WRITE}' "
                "bound to place the captcha between them")
        return
    if stage is None:
        stage_pk = Ref("stage.captcha", f"captcha stage {CAPTCHA_STAGE}")
        p.add(Op("stage.captcha", f"create captcha stage '{CAPTCHA_STAGE}' (Cloudflare Turnstile; "
                 "site and secret key read from Infisical when applied, never shown or logged)",
                 "POST", "/stages/captcha/",
                 {"name": CAPTCHA_STAGE, "public_key": InfisicalRef(TURNSTILE_KEYS[0], o.infisical),
                  "private_key": InfisicalRef(TURNSTILE_KEYS[1], o.infisical), **TURNSTILE_ATTRS},
                 capture={stage_pk.key: "pk"},
                 inverse=inv("DELETE", ("/stages/captcha/", stage_pk, "/"))))
    else:
        stage_pk = stage["pk"]
        if stage.get("public_key") != o.infisical.value(TURNSTILE_KEYS[0]):
            p.block(f"captcha stage '{CAPTCHA_STAGE}' has another site key than "
                    f"{TURNSTILE_KEYS[0]} in Infisical (keys rotated?). Its secret key cannot be "
                    "read back to compare: roll back the antibot apply that made the stage (or "
                    "delete it) and apply again")
        diff = {k: v for k, v in TURNSTILE_ATTRS.items() if stage.get(k) != v}
        if diff:
            before = {k: stage.get(k) for k in diff}
            p.add(Op("stage.captcha.fix", f"captcha stage '{CAPTCHA_STAGE}': {', '.join(diff)} "
                     "back to the intended value", "PATCH", ("/stages/captcha/", stage["pk"], "/"),
                     diff, before=before,
                     inverse=inv("PATCH", ("/stages/captcha/", stage["pk"], "/"), before)))
        else:
            p.ok(f"captcha stage '{CAPTCHA_STAGE}' exists (pk {stage['pk']}, site key matches "
                 "Infisical)")
    bound = next((b for b in binds if b["stage"] == stage_pk), None)
    if bound is not None:
        fsb = bound["pk"]
        if not prompt_b["order"] < bound["order"] < write_b["order"]:
            p.block(f"'{CAPTCHA_STAGE}' is bound at order {bound['order']}, not between "
                    f"'{SIGNUP_PROMPT}' ({prompt_b['order']}) and '{SELF_REG_WRITE}' "
                    f"({write_b['order']}); fix by hand")
        else:
            p.ok(f"'{CAPTCHA_STAGE}' is bound to '{SELF_REG_FLOW}' at order {bound['order']}")
    else:
        if write_b["order"] - prompt_b["order"] < 2:
            p.block(f"no free order between '{SIGNUP_PROMPT}' ({prompt_b['order']}) and "
                    f"'{SELF_REG_WRITE}' ({write_b['order']}) for the captcha")
            return
        order = prompt_b["order"] + (write_b["order"] - prompt_b["order"]) // 2
        fsb = Ref("fsb.captcha", "flow binding of the captcha stage")
        p.add(Op("fsb.captcha", f"bind '{CAPTCHA_STAGE}' to flow '{SELF_REG_FLOW}' at order {order} "
                 f"(after '{SIGNUP_PROMPT}' at {prompt_b['order']}, before '{SELF_REG_WRITE}' at "
                 f"{write_b['order']}): no account is written without a solved captcha", "POST",
                 "/flows/bindings/",
                 {"target": flow["pk"], "stage": stage_pk, "order": order,
                  "evaluate_on_plan": False, "re_evaluate_policies": True,
                  "policy_engine_mode": "any", "invalid_response_action": "retry"},
                 capture={fsb.key: "pk"}, inverse=inv("DELETE", ("/flows/bindings/", fsb, "/"))))
    if bound is not None and any(b.get("policy") == relay and b.get("negate")
                                 for b in s.policy_bindings if b["target"] == bound["pk"]):
        p.ok(f"the captcha is skipped only with LoveJoos's relay proof ({POLICY_RELAY}, negated)")
    else:
        add_binding(p, "captcha_relay_skip", f"bind {POLICY_RELAY} NEGATED to the captcha's flow "
                    "binding: the captcha is skipped only for a request with LoveJoos's relay proof "
                    "(LoveJoos runs its own proof-of-work); if that check fails with an error the "
                    "captcha is shown", fsb, policy=relay, order=0, negate=True,
                    failure_result=True)


def plan_antibot(s: Snapshot, o) -> Plan:
    p = Plan("antibot")

    # Can authentik trust the client IP it sees?
    site = o.caddy_site
    pinned, detail = caddy_xff_pinned(o.files.read_text(site))
    if pinned:
        p.ok(f"{site}: {detail}, so ak_client_ip (the first X-Forwarded-For entry) is the real "
             "client (Caddy's client_ip, from Cloudflare's CF-Connecting-IP)")
    else:
        p.warn(f"{site}: {detail}. authentik takes the FIRST X-Forwarded-For entry as the client "
               "IP and Caddy passes on one the client sent, so anyone can choose the IP authentik "
               "sees: the per-IP sign-up cap can be dodged until this is fixed, and the "
               "reputation gate is held back (anyone could lock another IP out of signing in). "
               f"Fix: {XFF_FIX}, then run this phase again")

    # What protects the login today (read-only report)
    pw = "; ".join(f"password stage '{x['name']}' ends a flow after "
                   f"{x.get('failed_attempts_before_cancel')} wrong passwords"
                   for x in s.password_stages) or "no password stage found"
    reps = ", ".join(f"'{x['name']}'" for x in s.reputation_policies) or "none"
    p.info(f"login protection found: {pw}; authentik keeps a reputation score per username and "
           f"client IP ({s.reputation_scores} on record); reputation policies: {reps}")

    # 1. the policies, each created before anything refers to it
    relay = ensure_expression_policy(
        p, s, POLICY_RELAY, RELAY_EXPR, f"true only for LoveJoos's server: header {RELAY_HEADER} "
        f"= the key of its API token '{LJ_TOKEN_ID}'")
    ip_limit = ensure_expression_policy(
        p, s, POLICY_SIGNUP_IP, SIGNUP_IP_EXPR, f"at most {SIGNUP_IP_LIMIT} sign-ups per client IP "
        f"per {SIGNUP_IP_WINDOW_HOURS}h, from authentik's user_write events")
    disposable = None
    try:
        text, domains, commit = load_disposable()
    except (OSError, ValueError) as exc:
        p.block(f"disposable-email list: {exc}")
    else:
        expr, shown = disposable_expression(text, len(domains), commit)
        p.info(f"disposable-email list: {len(domains)} domains (disposable-email-domains commit "
               f"{commit[:12]}, sha256 {DISPOSABLE_SHA256[:16]}..., pinned), embedded in the "
               f"policy: {len(expr)} characters")
        disposable = ensure_expression_policy(
            p, s, POLICY_DISPOSABLE, expr, "refuses a new address on a throwaway-inbox domain or "
            "a subdomain of one", display=shown)
        blocked = frozenset(domains)
        users = [u for u in s.users if is_disposable(u.get("email"), blocked)]
        if users:
            p.info(f"{len(users)} existing account(s) already use a throwaway domain (they keep "
                   "it; they cannot switch to another one): "
                   + ", ".join(mask_email(u.get("email")) for u in users))
        else:
            p.ok(f"none of the {len(s.users)} accounts uses a throwaway domain today")
    gate = None
    gate_pol = find(s.expr_policies, name=POLICY_REPUTATION_GATE)
    if pinned:
        ensure_reputation_policy(p, s)
        gate = ensure_expression_policy(
            p, s, POLICY_REPUTATION_GATE, REPUTATION_GATE_EXPR, "refuses a client IP with a bad "
            f"login reputation (built-in policy '{POLICY_REPUTATION}')")
        plan_login_gates(p, s, gate)
    else:
        p.info(f"reputation gate held back: nothing is bound until {site} pins X-Forwarded-For "
               "(see the warning above)")
        if gate_pol and any(b.get("policy") == gate_pol["pk"] for b in s.policy_bindings):
            p.warn(f"{POLICY_REPUTATION_GATE} is bound although X-Forwarded-For is not pinned: "
                   "anyone can now lock another IP out of signing in. Pin it again, or roll back "
                   "the antibot apply that bound it (not changed here)")

    # 2. validation policies on the prompt stages, one PATCH per stage
    names = {POLICY_DISPOSABLE: disposable, POLICY_SIGNUP_IP: ip_limit,
             POLICY_REPUTATION_GATE: gate}
    stages = email_prompt_stages(p, s)
    want: dict[str, list[str]] = {}
    if disposable is not None:
        for name in stages:
            want.setdefault(name, []).append(POLICY_DISPOSABLE)
    flow = s.flow(SELF_REG_FLOW)
    signup = find(s.prompt_stages, name=SIGNUP_PROMPT)
    if flow is None or signup is None or SELF_REG_FLOW not in s.flows_of_stage(signup["pk"]):
        p.block(f"prompt stage '{SIGNUP_PROMPT}' of flow '{SELF_REG_FLOW}' not found")
    else:
        stages.setdefault(SIGNUP_PROMPT, signup)
        want.setdefault(SIGNUP_PROMPT, []).append(POLICY_SIGNUP_IP)
        if gate is not None:
            want[SIGNUP_PROMPT].append(POLICY_REPUTATION_GATE)
        guard = find(s.expr_policies, name=POLICY_EMAIL_GUARD)
        if not guard or guard["pk"] not in (signup.get("validation_policies") or []):
            p.info(f"phase trust is not applied yet ('{SIGNUP_PROMPT}' has no {POLICY_EMAIL_GUARD});"
                   " these policies work without it and leave it alone when it comes")
    for name in sorted(want):
        st = stages[name]
        current = list(st.get("validation_policies") or [])
        add = [n for n in want[name] if names[n] not in current]
        if not add:
            p.ok(f"prompt stage '{name}' already has {', '.join(want[name])}")
            continue
        flows = ", ".join(s.flows_of_stage(st["pk"]))
        p.add(Op(f"stage.{name}.antibot", f"add {', '.join(add)} to prompt stage '{name}' (flows: "
                 f"{flows}) as validation policies, keeping the ones it has", "PATCH",
                 ("/stages/prompt/stages/", st["pk"], "/"),
                 {"validation_policies": current + [names[n] for n in add]},
                 before={"validation_policies": current},
                 inverse=inv("PATCH", ("/stages/prompt/stages/", st["pk"], "/"),
                             {"validation_policies": current})))

    # 3. captcha, only with keys
    plan_captcha(p, s, o, relay)
    return p


# ---------------------------------------------------------------------------
def roles_with_codenames(entries, codenames, object_pk=None):
    """Role names holding any of `codenames` (authentik_core) globally or on objects."""
    out = []
    for r in entries:
        perms = [f"{m['codename']} (global)" for m in r.get("model_permissions") or []
                 if m.get("app_label") == "authentik_core" and m["codename"] in codenames]
        objs: dict[str, int] = {}
        for m in r.get("object_permissions") or []:
            if (m.get("app_label") == "authentik_core" and m["codename"] in codenames
                    and (object_pk is None or str(m.get("object_pk")) == str(object_pk))):
                objs[m["codename"]] = objs.get(m["codename"], 0) + 1
        perms += [f"{c} (on {n} object(s))" for c, n in objs.items()]
        if perms:
            out.append(f"{r['name']}: {', '.join(sorted(set(perms)))}")
    return out


def plan_groups(s: Snapshot, o) -> Plan:
    p = Plan("groups")
    for name, attrs in ((GROUP_VERIFIED, VERIFIED_ATTRS), (GROUP_YOURSPACE, YOURSPACE_ATTRS)):
        grp = s.group(name)
        if grp is None:
            ref = Ref(f"group.{name}", f"group {name}")
            p.add(Op(f"group.{name}", f"create group '{name}' (not superuser, no parents, no "
                     "members, no bindings)", "POST", "/core/groups/",
                     {"name": name, "is_superuser": False, "parents": [], "users": [],
                      "roles": [], "attributes": attrs},
                     capture={ref.key: "pk"}, inverse=inv("DELETE", ("/core/groups/", ref, "/"))))
            continue
        changes, before = {}, {}
        if grp.get("is_superuser"):
            changes["is_superuser"], before["is_superuser"] = False, True
        if (grp.get("attributes") or {}).get("wopr") != attrs["wopr"]:
            changes["attributes"] = {**(grp.get("attributes") or {}), **attrs}
            before["attributes"] = grp.get("attributes") or {}
        if changes:
            p.add(Op(f"group.{name}.fix", f"group '{name}': {', '.join(changes)} back to the "
                     "intended value", "PATCH", ("/core/groups/", grp["pk"], "/"), changes,
                     before=before, inverse=inv("PATCH", ("/core/groups/", grp["pk"], "/"), before)))
        else:
            p.ok(f"group '{name}' exists (pk {grp['pk']}, {len(grp.get('users') or [])} members)")
        children = [g["name"] for g in s.groups if grp["pk"] in (g.get("parents") or [])]
        if children:
            p.warn(f"groups under '{name}' (their members count as {name}): {', '.join(children)}")
        bound = [b["pk"] for b in s.policy_bindings if b.get("group") == grp["pk"]]
        if name == GROUP_VERIFIED and bound:
            p.warn(f"'{name}' is used in {len(bound)} policy binding(s); D8 says it has none")
        writers = [st["name"] for st in s.user_write_stages
                   if st.get("create_users_group") == grp["pk"]]
        if name == GROUP_VERIFIED and writers:
            p.block(f"user write stage(s) {', '.join(writers)} put new users into '{name}'; "
                    "only the control-plane sync may write it")

    # who can write wopr-verified besides superusers (read-only report)
    verified = s.group(GROUP_VERIFIED)
    gw = roles_with_codenames(s.group_perm_roles, GROUP_WRITE_CODENAMES,
                              verified["pk"] if verified else None)
    uw = roles_with_codenames(s.user_perm_roles, USER_WRITE_CODENAMES)
    p.info("roles that can change membership of wopr-verified (directly or by writing users, "
           "whose 'groups' field authentik 2025.12 does not check): "
           + ("; ".join(gw + uw) if gw or uw else "none") + ". Superusers (group 'WOPR Admins', "
           "and the akadmin token the control plane uses) can always write it")

    # WOPR Admins-dup2: superuser group with no members
    dup = s.dup_group
    if dup is None:
        p.ok(f"group '{GROUP_DUP_SUPER}' is already gone")
    else:
        reasons = []
        if dup.get("users"):
            reasons.append(f"{len(dup['users'])} member(s)")
        kids = [g["name"] for g in s.groups if dup["pk"] in (g.get("parents") or [])]
        if kids:
            reasons.append(f"child groups {', '.join(kids)}")
        if dup.get("roles"):
            reasons.append(f"{len(dup['roles'])} role(s)")
        nb = [b["pk"] for b in s.policy_bindings if b.get("group") == dup["pk"]]
        if nb:
            reasons.append(f"{len(nb)} policy binding(s)")
        uws = [st["name"] for st in s.user_write_stages if st.get("create_users_group") == dup["pk"]]
        if uws:
            reasons.append(f"user write stage(s) {', '.join(uws)}")
        if s.dup_used_by:
            reasons.append(f"used by {len(s.dup_used_by)} object(s)")
        if not dup.get("is_superuser"):
            p.info(f"'{GROUP_DUP_SUPER}' is no longer a superuser group")
        if reasons:
            p.block(f"'{GROUP_DUP_SUPER}' is not safe to delete: {'; '.join(reasons)}")
        else:
            snap = {k: dup.get(k) for k in ("pk", "num_pk", "name", "is_superuser", "parents",
                                            "users", "roles", "attributes")}
            p.add(Op("group.dup2.delete", f"delete superuser group '{GROUP_DUP_SUPER}' (0 members, "
                     "no roles, no child groups, no bindings, used by nothing; anyone added to "
                     "it would become a full admin)", "DELETE", ("/core/groups/", dup["pk"], "/"),
                     before=snap,
                     inverse=inv("POST", "/core/groups/",
                                 {"name": dup["name"], "is_superuser": dup.get("is_superuser"),
                                  "parents": dup.get("parents") or [], "users": [], "roles": [],
                                  "attributes": dup.get("attributes") or {}})))

    # LoveJoos service account + least-privilege token
    lj = s.group(GROUP_LOVEJOOS)
    if lj is None:
        p.block(f"group '{GROUP_LOVEJOOS}' not found: the LoveJoos role's object permissions "
                "need it (authentik grants a permission GLOBALLY when its object is missing)")
        return p
    role = s.lj_role
    role_ref = role["pk"] if role else Ref("role.lj", f"role {LJ_ROLE}")
    if role is None:
        p.add(Op("role.lj", f"create role '{LJ_ROLE}'", "POST", "/rbac/roles/", {"name": LJ_ROLE},
                 capture={role_ref.key: "pk"}, inverse=inv("DELETE", ("/rbac/roles/", role_ref, "/"))))
    have_global = {f"{x['app_label']}.{x['codename']}" for x in s.lj_role_global}
    want_global = set(LJ_GLOBAL_PERMS)
    have_obj = {(f"{x['app_label']}.{x['codename']}", f"{x['app_label']}.{x['model']}",
                 str(x['object_pk'])) for x in s.lj_role_object}
    want_obj = {(perm, "authentik_core.group", lj["pk"]) for perm in LJ_GROUP_PERMS}
    assign = ("/rbac/permissions/assigned_by_roles/", role_ref, "/assign/")
    unassign = ("/rbac/permissions/assigned_by_roles/", role_ref, "/unassign/")
    if want_global - have_global:
        body = {"permissions": sorted(want_global - have_global)}
        p.add(Op("role.lj.global", f"role '{LJ_ROLE}': global permission(s) "
                 f"{', '.join(body['permissions'])} (find users by email; needed to add a user "
                 "to a group)", "POST", assign, body, inverse=inv("PATCH", unassign, body)))
    if have_global - want_global:
        body = {"permissions": sorted(have_global - want_global)}
        p.add(Op("role.lj.global.extra", f"role '{LJ_ROLE}': remove extra global permission(s) "
                 f"{', '.join(body['permissions'])}", "PATCH", unassign, body,
                 inverse=inv("POST", assign, body)))
    if want_obj - have_obj:
        body = {"permissions": sorted(x[0] for x in want_obj - have_obj),
                "model": "authentik_core.group", "object_pk": lj["pk"]}
        p.add(Op("role.lj.object", f"role '{LJ_ROLE}': {', '.join(body['permissions'])} on group "
                 f"'{GROUP_LOVEJOOS}' ONLY", "POST", assign, body, inverse=inv("PATCH", unassign, body)))
    extra_obj = have_obj - want_obj
    for (perm, model, obj_pk) in sorted(extra_obj):
        body = {"permissions": [perm], "model": model, "object_pk": obj_pk}
        p.add(Op(f"role.lj.object.extra.{perm}.{obj_pk}", f"role '{LJ_ROLE}': remove extra "
                 f"{perm} on {model} {obj_pk}", "PATCH", unassign, body,
                 inverse=inv("POST", assign, body)))
    if role and not (want_global - have_global or have_global - want_global
                     or want_obj - have_obj or extra_obj):
        p.ok(f"role '{LJ_ROLE}' has exactly: {', '.join(sorted(want_global))} (global) + "
             f"{', '.join(sorted(LJ_GROUP_PERMS))} on '{GROUP_LOVEJOOS}'")

    sa = find(s.users, username=LJ_SA_USERNAME)
    sa_ref = sa["pk"] if sa else Ref("user.lj", f"user {LJ_SA_USERNAME}")
    if sa is None:
        p.add(Op("user.lj", f"create service account '{LJ_SA_USERNAME}' (no password, no groups, "
                 f"only role '{LJ_ROLE}')", "POST", "/core/users/",
                 {"username": LJ_SA_USERNAME, "name": "LoveJoos API (service account)",
                  "type": "service_account", "path": SA_PATH, "is_active": True,
                  "groups": [], "roles": [role_ref], "attributes": LJ_SA_ATTRS},
                 capture={sa_ref.key: "pk"}, inverse=inv("DELETE", ("/core/users/", sa_ref, "/"))))
    else:
        if sa.get("type") != "service_account":
            p.block(f"user '{LJ_SA_USERNAME}' exists but is type {sa.get('type')}, not a service "
                    "account")
        changes, before = {}, {}
        cur_roles = list(sa.get("roles") or [])
        if role_ref not in cur_roles:
            changes["roles"], before["roles"] = cur_roles + [role_ref], cur_roles
        # authentik adds the account's own managed role (ak-managed-role--user-<pk>) when it
        # creates a token for itself; anything else is reported, not removed.
        own = f"ak-managed-role--user-{sa['pk']}"
        extra = [r["name"] for r in s.lj_sa_roles
                 if r["pk"] != (role["pk"] if role else None) and r["name"] != own]
        if extra:
            p.warn(f"service account '{LJ_SA_USERNAME}' also holds role(s) {', '.join(extra)}; "
                   "review them (not changed here)")
        if sa.get("groups"):
            changes["groups"], before["groups"] = [], list(sa["groups"])
        if not sa.get("is_active"):
            changes["is_active"], before["is_active"] = True, False
        if changes:
            p.add(Op("user.lj.fix", f"service account '{LJ_SA_USERNAME}': set {', '.join(changes)}",
                     "PATCH", ("/core/users/", sa["pk"], "/"), changes, before=before,
                     inverse=inv("PATCH", ("/core/users/", sa["pk"], "/"), before)))
        else:
            p.ok(f"service account '{LJ_SA_USERNAME}' exists (pk {sa['pk']}), only role {LJ_ROLE}")

    tok = s.lj_tokens[0] if s.lj_tokens else None
    write_file = tok is None
    if tok is None:
        p.add(Op("token.lj", f"create API token '{LJ_TOKEN_ID}' for '{LJ_SA_USERNAME}' (intent "
                 "api, non-expiring: the tenant default for expiring API tokens is 30 minutes)",
                 "POST", "/core/tokens/",
                 {"identifier": LJ_TOKEN_ID, "intent": "api", "user": sa_ref, "expiring": False,
                  "description": "LoveJoos API -> central authentik (WOPR-055): read users; "
                                 "add/remove members of lovejoos-users only"},
                 capture={"token.lj": "identifier"},
                 inverse=inv("DELETE", ("/core/tokens/", LJ_TOKEN_ID, "/"))))
    else:
        if sa is None or (tok.get("user") != sa["pk"]):
            p.block(f"token '{LJ_TOKEN_ID}' exists but belongs to user {tok.get('user')}")
        if tok.get("intent") != "api":
            p.block(f"token '{LJ_TOKEN_ID}' has intent {tok.get('intent')}, not api")
        if tok.get("expiring"):
            # TokenSerializer.validate() fills a missing "user" with the CALLER (akadmin) and
            # would move the token to it; always send the owner and intent explicitly.
            owner = {"user": tok.get("user"), "intent": "api"}
            p.add(Op("token.lj.expiring", f"token '{LJ_TOKEN_ID}': make it non-expiring", "PATCH",
                     ("/core/tokens/", LJ_TOKEN_ID, "/"), {"expiring": False, **owner},
                     before={"expiring": True},
                     inverse=inv("PATCH", ("/core/tokens/", LJ_TOKEN_ID, "/"),
                                 {"expiring": True, **owner})))
        if o.files.exists(o.token_file):
            p.ok(f"token '{LJ_TOKEN_ID}' exists and {o.token_file} exists (content not read)")
        else:
            write_file = True
    if write_file:
        p.add(Op("token.lj.file", f"write the key of token '{LJ_TOKEN_ID}' (read with GET "
                 f"/core/tokens/{LJ_TOKEN_ID}/view_key/) to {o.token_file}, root:root 0600. "
                 "Never printed or logged", "TOKEN_FILE", (o.token_file,),
                 {"token_identifier": LJ_TOKEN_ID},
                 inverse=inv("REMOVE_FILE", (o.token_file,))))
    p.info(f"LoveJoos keeps its current admin token until its release switches "
           f"AUTHENTIK_API_TOKEN in /etc/lovejoos/lovejoos.env to the key in {o.token_file}. "
           "This token CANNOT create or edit users (authentik 2025.12 lets user create/edit set "
           "any group, superuser groups and wopr-verified included), so LoveJoos /register must "
           "create the central account through a sign-up flow, then add it to lovejoos-users")
    return p


# ---------------------------------------------------------------------------
def read_email_list(path: str) -> list[str]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip().lower()
            if line:
                out.append(line)
    return list(dict.fromkeys(out))


def plan_lovejoos_gate(s: Snapshot, o) -> Plan:
    p = Plan("lovejoos-gate")
    app = s.apps.get(LOVEJOOS_APP)
    lj = s.group(GROUP_LOVEJOOS)
    if app is None or lj is None:
        p.block(f"app '{LOVEJOOS_APP}' or group '{GROUP_LOVEJOOS}' not found")
        return p
    if not o.lovejoos_release_deployed:
        p.block("apply only AFTER the LoveJoos release (WOPR-056: groups-claim check, both-sides "
                "default, /register adds lovejoos-users) is live; then pass "
                "--lovejoos-release-deployed")
    users = {u["pk"]: u for u in s.users}
    cands: dict[int, list[str]] = {}
    if o.lovejoos_emails:
        by_email = {}
        for u in s.users:
            e = (u.get("email") or "").strip().lower()
            if e:
                by_email.setdefault(e, []).append(u)
        missing = []
        for e in read_email_list(o.lovejoos_emails):
            hits = by_email.get(e, [])
            if len(hits) == 1:
                cands.setdefault(hits[0]["pk"], []).append("in the LoveJoos export")
            elif not hits:
                missing.append(mask_email(e))
            else:
                p.warn(f"{mask_email(e)} matches {len(hits)} central accounts; skipped")
        if missing:
            p.info(f"{len(missing)} LoveJoos email(s) have no central account (nothing to add): "
                   + ", ".join(missing))
    elif not o.no_lovejoos_export:
        p.block("give --lovejoos-emails FILE (one email per line: LoveJoos users with a central "
                "login, exported from the LoveJoos DB at deploy time) or --no-lovejoos-export")
    for e in s.lj_authorize_events:
        pk = (e.get("user") or {}).get("pk")
        if pk in users:
            cands.setdefault(pk, []).append("signed in to LoveJoos through authentik")
    for u in s.users:
        if u.get("path") == "lovejoos":
            cands.setdefault(u["pk"], []).append("created by LoveJoos /register (path lovejoos)")
    if BINK_PK in cands:
        p.warn(f"pk {BINK_PK} looks like a LoveJoos user ({'; '.join(sorted(set(cands[BINK_PK])))})"
               " but the owner decided BINK stays out of lovejoos-users until he opts in: skipped")
        cands.pop(BINK_PK)
    members = set(lj.get("users") or [])
    for pk in sorted(cands):
        u = users[pk]
        why = "; ".join(sorted(set(cands[pk])))
        if u.get("type") not in ("internal", "external"):
            p.info(f"skip {u['username']} (pk {pk}): {u.get('type')}")
            continue
        if pk in members:
            p.ok(f"{u['username']} (pk {pk}) is already in {GROUP_LOVEJOOS} ({why})")
            continue
        p.add(Op(f"member.{pk}", f"add existing LoveJoos user {u['username']} (pk {pk}) to "
                 f"{GROUP_LOVEJOOS} ({why})", "POST", ("/core/groups/", lj["pk"], "/add_user/"),
                 {"pk": pk}, inverse=inv("POST", ("/core/groups/", lj["pk"], "/remove_user/"),
                                         {"pk": pk})))
    if not cands:
        p.warn("no existing LoveJoos user found: nobody keeps access when the gate closes")
    binds = [b for b in s.policy_bindings if b["target"] == app["pk"]]
    ours = [b for b in binds if b.get("group") == lj["pk"]]
    others = [b for b in binds if b not in ours]
    if others:
        p.warn(f"app '{LOVEJOOS_APP}' has {len(others)} other binding(s); with policy engine "
               "mode 'all' they can only narrow access further")
    if ours:
        p.ok(f"group '{GROUP_LOVEJOOS}' is already bound to app '{LOVEJOOS_APP}'")
    else:
        add_binding(p, "lovejoos_gate", f"bind group '{GROUP_LOVEJOOS}' to app '{LOVEJOOS_APP}' "
                    "(only members can sign in to LoveJoos through authentik)", app["pk"],
                    group=lj["pk"], order=0)
    if app.get("policy_engine_mode") != "all":
        p.add(Op("app.lovejoos.mode", f"app '{LOVEJOOS_APP}': policy engine mode "
                 f"{app.get('policy_engine_mode')} -> all (a binding added later can never "
                 "open the gate)", "PATCH", ("/core/applications/", LOVEJOOS_APP, "/"),
                 {"policy_engine_mode": "all"},
                 before={"policy_engine_mode": app.get("policy_engine_mode")},
                 inverse=inv("PATCH", ("/core/applications/", LOVEJOOS_APP, "/"),
                             {"policy_engine_mode": app.get("policy_engine_mode")})))
    return p


# ---------------------------------------------------------------------------
def plan_yourspace_app(s: Snapshot, o) -> Plan:
    p = Plan("yourspace-app")
    ysg = s.group(GROUP_YOURSPACE)
    ysg_pk = ysg["pk"] if ysg else external_ref("group", GROUP_YOURSPACE, "groups")
    auth_flow, inv_flow = s.flow(YS_AUTH_FLOW), s.flow(YS_INVALIDATION_FLOW)
    openid = find(s.scope_mappings, managed=OPENID_MAPPING_MANAGED)
    key = find(s.keypairs, name=YS_SIGNING_KEY_NAME)
    for what, val in ((f"flow {YS_AUTH_FLOW}", auth_flow), (f"flow {YS_INVALIDATION_FLOW}", inv_flow),
                      ("openid scope mapping", openid), (f"key pair '{YS_SIGNING_KEY_NAME}'", key)):
        if val is None:
            p.block(f"{what} not found")
    if key is not None and not key.get("private_key_available"):
        p.block(f"key pair '{YS_SIGNING_KEY_NAME}' has no private key; it cannot sign ID tokens")
    if p.blockers():
        return p
    p.info(f"ID tokens signed RS256 with '{YS_SIGNING_KEY_NAME}' (expires "
           f"{key.get('cert_expiry')}); issuer {YS_ISSUER}, discovery "
           f"{YS_ISSUER}.well-known/openid-configuration")
    desired = {
        "name": YS_PROVIDER_NAME,
        "authorization_flow": auth_flow["pk"],
        "invalidation_flow": inv_flow["pk"],
        "client_type": "public",
        "client_id": YS_CLIENT_ID,
        "property_mappings": [openid["pk"]],
        "sub_mode": "hashed_user_id",
        "issuer_mode": "per_provider",
        "include_claims_in_id_token": True,
        "signing_key": key["pk"],
        "redirect_uris": [{"matching_mode": "regex", "url": YS_REDIRECT_REGEX}],
        "access_code_validity": "minutes=1",
        "access_token_validity": "minutes=5",
    }
    prov = s.ys_providers[0] if s.ys_providers else None
    if prov is None:
        prov_ref = Ref("provider.ys", f"OAuth2 provider '{YS_PROVIDER_NAME}'")
        p.add(Op("provider.ys", f"create public OAuth2 provider client_id '{YS_CLIENT_ID}': "
                 "no secret on beacons, sub = hashed user id (= X-Authentik-UID), scope openid "
                 f"only, one anchored redirect regex. Not attached to an app yet, so unusable",
                 "POST", "/providers/oauth2/", desired, capture={prov_ref.key: "pk"},
                 inverse=inv("DELETE", ("/providers/oauth2/", prov_ref, "/"))))
    else:
        prov_ref = prov["pk"]
        diff = {}
        for k, v in desired.items():
            cur = prov.get(k)
            if k == "property_mappings":
                same = sorted(cur or []) == sorted(v)
            elif k == "redirect_uris":
                same = [{"matching_mode": r.get("matching_mode"), "url": r.get("url")}
                        for r in cur or []] == v
            else:
                same = cur == v
            if not same:
                diff[k] = v
        if diff:
            before = {k: prov.get(k) for k in diff}
            p.add(Op("provider.ys.fix", f"provider '{YS_CLIENT_ID}': set {', '.join(diff)} to the "
                     "intended value", "PATCH", ("/providers/oauth2/", prov["pk"], "/"), diff,
                     before=before, inverse=inv("PATCH", ("/providers/oauth2/", prov["pk"], "/"),
                                                before)))
        else:
            p.ok(f"OAuth2 provider '{YS_CLIENT_ID}' exists as intended (pk {prov['pk']})")
    pkce = ensure_expression_policy(p, s, POLICY_PKCE, PKCE_EXPR,
                                    "authentik 2025.12 does not force PKCE on public clients")
    app = s.apps.get(YS_APP_SLUG)
    if app is None:
        app_ref = Ref("app.ys", f"application {YS_APP_SLUG}")
        p.add(Op("app.ys", f"create application '{YS_APP_SLUG}' WITHOUT a provider (unusable "
                 "until the gate below is in place), policy engine mode 'all'", "POST",
                 "/core/applications/",
                 {"name": YS_APP_NAME, "slug": YS_APP_SLUG, "provider": None,
                  "policy_engine_mode": "all", "open_in_new_tab": False,
                  "meta_launch_url": "https://yourspace.you/",
                  "meta_description": "Sign in to your YourSpace page with your WOPR account",
                  "meta_publisher": "WOPR"},
                 capture={app_ref.key: "pk"},
                 inverse=inv("DELETE", ("/core/applications/", YS_APP_SLUG, "/"))))
        app_pk, has_group, has_pkce, mode, cur_provider = app_ref, False, False, "all", None
    else:
        app_pk = app["pk"]
        binds = [b for b in s.policy_bindings if b["target"] == app_pk]
        has_group = any(b.get("group") == ysg_pk for b in binds)
        has_pkce = any(b.get("policy") == pkce for b in binds)
        others = [b for b in binds if b.get("group") != ysg_pk and b.get("policy") != pkce]
        if others:
            p.warn(f"app '{YS_APP_SLUG}' has {len(others)} other binding(s) (mode 'all': they "
                   "only narrow access)")
        mode, cur_provider = app.get("policy_engine_mode"), app.get("provider")
        if cur_provider not in (None, prov_ref):
            p.block(f"app '{YS_APP_SLUG}' uses another provider ({cur_provider})")
    if mode != "all":
        p.add(Op("app.ys.mode", f"app '{YS_APP_SLUG}': policy engine mode {mode} -> all (member "
                 "AND PKCE)", "PATCH", ("/core/applications/", YS_APP_SLUG, "/"),
                 {"policy_engine_mode": "all"}, before={"policy_engine_mode": mode},
                 inverse=inv("PATCH", ("/core/applications/", YS_APP_SLUG, "/"),
                             {"policy_engine_mode": mode})))
    if not has_group:
        add_binding(p, "ys_members", f"bind group '{GROUP_YOURSPACE}' to app '{YS_APP_SLUG}'",
                    app_pk, group=ysg_pk, order=0)
    else:
        p.ok(f"group '{GROUP_YOURSPACE}' is bound to app '{YS_APP_SLUG}'")
    if not has_pkce:
        add_binding(p, "ys_pkce", f"bind {POLICY_PKCE} to app '{YS_APP_SLUG}'", app_pk,
                    policy=pkce, order=10)
    else:
        p.ok(f"{POLICY_PKCE} is bound to app '{YS_APP_SLUG}'")
    if cur_provider is None:
        p.add(Op("app.ys.provider", f"attach provider '{YS_CLIENT_ID}' to app '{YS_APP_SLUG}' "
                 "(last step: sign-in works only from here on, already gated)", "PATCH",
                 ("/core/applications/", YS_APP_SLUG, "/"), {"provider": prov_ref},
                 before={"provider": None},
                 inverse=inv("PATCH", ("/core/applications/", YS_APP_SLUG, "/"), {"provider": None})))
    return p


# ---------------------------------------------------------------------------
def plan_bink(s: Snapshot, o) -> Plan:
    p = Plan("bink")
    u = s.user_by_pk(BINK_PK)
    if u is None:
        p.block(f"user pk {BINK_PK} not found")
        return p
    if (u.get("email") or "").strip().lower() != BINK_EMAIL:
        p.block(f"user pk {BINK_PK} has email {mask_email(u.get('email'))}, not "
                f"{mask_email(BINK_EMAIL)}: refusing to rename the wrong account")
        return p
    p.ok(f"pk {BINK_PK} is '{u['username']}' / '{u.get('name')}', email {mask_email(BINK_EMAIL)}, "
         f"type {u.get('type')}, uid {u.get('uid')} (the control plane stores this uid as "
         "users.authentik_user_id, D1)")
    taken = [x["username"] for x in s.users
             if x["pk"] != BINK_PK and x["username"].lower() == BINK_USERNAME]
    if taken:
        p.block(f"username '{BINK_USERNAME}' is taken by another account")
    handle = [x["username"] for x in s.users if x["pk"] != BINK_PK
              and ((x.get("attributes") or {}).get("yourspace") or {}).get("handle") == "bink"]
    if handle:
        p.block(f"another account already holds yourspace handle 'bink': {', '.join(handle)}")
    rename = u["username"] != BINK_USERNAME
    if rename:
        footprint = len(s.bink_barter_events) + len(s.bink_barter_tokens)
        if footprint and not o.allow_barterra_orphan:
            p.block(f"pk {BINK_PK} has signed in to Barterra ({footprint} event/token record(s)); "
                    "Barterra keys accounts on the username, so the rename would orphan that "
                    "link. Fix the Barterra side first or pass --allow-barterra-orphan")
        elif footprint:
            p.warn("renaming although Barterra has a link keyed on the old username "
                   "(--allow-barterra-orphan)")
        else:
            p.ok(f"no Barterra sign-in or token for pk {BINK_PK} (events since {s.oldest_event}), "
                 "so the rename orphans nothing (Barterra keys on the username)")
    attrs = copy.deepcopy(u.get("attributes") or {})
    attrs["yourspace"] = dict(BINK_YOURSPACE)
    # The login onboarding prompt (default-authentication-flow, order 110) asks for a name
    # (empty field) while attributes.profile_complete is not "true"; mark it complete so the
    # name BINK set here sticks.
    attrs["profile_complete"] = "true"
    changes, before = {}, {}
    if rename:
        changes["username"], before["username"] = BINK_USERNAME, u["username"]
    if u.get("name") != BINK_NAME:
        changes["name"], before["name"] = BINK_NAME, u.get("name")
    if attrs != (u.get("attributes") or {}):
        changes["attributes"], before["attributes"] = attrs, u.get("attributes") or {}
    if changes:
        shown = dict(changes)
        if "attributes" in shown:
            shown["attributes"] = {k: (v if k in ("yourspace", "profile_complete") else "<kept as is>")
                                   for k, v in attrs.items()}
        shown_inv = dict(before)
        if "attributes" in shown_inv:
            shown_inv["attributes"] = (f"<previous attributes: keys "
                                       f"{sorted((u.get('attributes') or {}).keys())}>")
        p.add(Op("user.bink", f"pk {BINK_PK}: {', '.join(changes)} (username bink, name BINK, "
                 "attribute yourspace={handle: bink, domain: bink.yourspace.you}, "
                 "profile_complete=true so the login onboarding does not ask for a new name)",
                 "PATCH", ("/core/users/", BINK_PK, "/"), changes, before=before,
                 inverse=inv("PATCH", ("/core/users/", BINK_PK, "/"), before),
                 show_body=shown, show_inverse=shown_inv))
    else:
        p.ok(f"pk {BINK_PK} already is bink / BINK with the yourspace attribute")
    # wopr-verified is NOT written here: the control-plane paid-status sync is its only
    # writer (contract IDENTITY-GROUPS / VERIFIED-BADGE). It finds BINK by his paid
    # subscription's email; a comped BINK needs a grant in its overrides file instead.
    verified = s.group(GROUP_VERIFIED)
    if verified and BINK_PK in (verified.get("users") or []):
        p.ok(f"pk {BINK_PK} is in {GROUP_VERIFIED} (kept there by the control-plane sync)")
    else:
        p.info(f"pk {BINK_PK} is not in {GROUP_VERIFIED} yet; the control-plane paid-status "
               "sync adds him from his paid subscription (this phase never writes that group)")
    for name, why in ((GROUP_YOURSPACE, "he has a YourSpace server"),):
        grp = s.group(name)
        gref = grp["pk"] if grp else external_ref("group", name, "groups")
        if grp and BINK_PK in (grp.get("users") or []):
            p.ok(f"pk {BINK_PK} is already in {name}")
            continue
        p.add(Op(f"bink.{name}", f"add pk {BINK_PK} to {name} ({why})", "POST",
                 ("/core/groups/", gref, "/add_user/"), {"pk": BINK_PK},
                 inverse=inv("POST", ("/core/groups/", gref, "/remove_user/"), {"pk": BINK_PK})))
    lj = s.group(GROUP_LOVEJOOS)
    if lj and BINK_PK in (lj.get("users") or []):
        p.warn(f"pk {BINK_PK} IS in {GROUP_LOVEJOOS}; the owner wants LoveJoos off until he opts "
               "in (not changed here: the control-plane toggle owns that membership)")
    else:
        p.ok(f"pk {BINK_PK} is not in {GROUP_LOVEJOOS} and this phase does not add him")
    return p


PLANNERS = {
    "trust": plan_trust,
    "antibot": plan_antibot,
    "groups": plan_groups,
    "yourspace-app": plan_yourspace_app,
    "bink": plan_bink,
    "lovejoos-gate": plan_lovejoos_gate,
}


# ============================================================================
# output, apply, rollback
# ============================================================================
def print_plan(p: Plan, out=None):
    out = out or sys.stdout
    w = lambda s="": print(s, file=out)  # noqa: E731
    w(f"\n== Phase {p.phase}: {PHASE_TITLES[p.phase]} ==")
    for level, msg in p.checks:
        w(f"  [{level}] {msg}")
    long_texts = {v: k for k, v in p.texts.items()}

    def disp(body):
        if isinstance(body, dict):
            return {k: (f"<{long_texts[v]}, printed below>" if isinstance(v, str) and v in long_texts
                        else v) for k, v in body.items()}
        return body

    if not p.ops:
        w("  Planned changes: none")
    else:
        w(f"  Planned changes ({len(p.ops)}):")
        for i, op in enumerate(p.ops, 1):
            w(f"  {i:2d}. {op.method} {show_path(op.path)}")
            w(f"      what: {op.desc}")
            body = op.show_body if op.show_body is not None else op.body
            if body is not None:
                w(f"      body: {show(disp(body))}")
            if op.inverse:
                ib = op.show_inverse if op.show_inverse is not None else op.inverse.get("body")
                w(f"      undo: {op.inverse['method']} {show_path(op.inverse['path'])}"
                  + (f" {show(disp(ib))}" if ib is not None else ""))
        used = {v for op in p.ops for v in (op.body or {}).values() if isinstance(v, str)}
        for name, text in p.texts.items():
            if text in used:
                shown = p.displays.get(name)
                w(f"  {name} (exact text"
                  + ("" if shown is None else ", except the part marked 'not printed'") + "):")
                for line in (text if shown is None else shown).rstrip("\n").split("\n"):
                    w(f"      | {line}")
    blockers = p.blockers()
    if blockers:
        w(f"  APPLY WOULD BE REFUSED ({len(blockers)}):")
        for b in blockers:
            w(f"    - {b}")


def write_log(path: str, log: dict):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(log, fh, indent=1, sort_keys=False)
    os.replace(tmp, path)


def token_file_write(api: Api, files: RootFiles, identifier: str, path: str) -> dict:
    data = api.get(f"/core/tokens/{identifier}/view_key/")
    key = (data or {}).get("key") or ""
    if not key:
        raise RuntimeError(f"token {identifier} returned no key")
    files.write_secret(path, key + "\n")
    length = len(key)
    del key, data
    return {"written": path, "owner": "root:root", "mode": "0600", "key_length": length}


def apply_plan(api: Api, p: Plan, state_dir: str, files: RootFiles) -> str:
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    stamp = log_stamp()
    log_path = os.path.join(state_dir, f"{stamp}-{p.phase}.json")
    log = {"tool": "apply_identity.py", "version": VERSION, "phase": p.phase, "api": api.base,
           "started": now_utc(), "status": "running", "ops": []}
    write_log(log_path, log)
    refs: dict = {}
    print(f"\nApplying phase {p.phase}: {len(p.ops)} change(s); log {log_path}")
    try:
        for i, op in enumerate(p.ops, 1):
            # An InfisicalRef is read only for the call itself; the log keeps the placeholder.
            path, body = resolve(op.path, refs), resolve(op.body, refs, reveal=True)
            entry = {"n": i, "key": op.key, "desc": op.desc, "method": op.method, "path": path,
                     "body": resolve(op.body, refs), "before": op.before}
            if op.method == "TOKEN_FILE":
                result = token_file_write(api, files, body["token_identifier"], path)
            else:
                status, data = api.write(op.method, path, body)
                result = {"status": status}
                for ref_key, field in op.capture.items():
                    refs[ref_key] = data[field]
                    result.setdefault("captured", {})[ref_key] = data[field]
            entry["result"] = result
            if op.inverse:
                entry["inverse"] = {"method": op.inverse["method"],
                                    "path": resolve(op.inverse["path"], refs),
                                    "body": resolve(op.inverse.get("body"), refs)}
            entry["done_at"] = now_utc()
            log["ops"].append(entry)
            write_log(log_path, log)
            print(f"  ok {i:2d}. {op.method} {path} - {op.desc}")
        log["status"] = "ok"
    except Exception as exc:
        log["status"] = "failed"
        log["error"] = str(exc)[:1000]
        print(f"  FAILED: {str(exc)[:600]}")
        print(f"  The changes made before the failure are in {log_path}; undo them with "
              f"--rollback {log_path}")
        raise
    finally:
        log["finished"] = now_utc()
        write_log(log_path, log)
    return log_path


def same_value(current, logged) -> bool:
    """Rollback drift check. Lists of ids compare as sets: authentik does not promise the
    order of many-to-many fields such as validation_policies."""
    if (isinstance(current, list) and isinstance(logged, list)
            and all(isinstance(x, (str, int)) for x in current + logged)):
        return sorted(map(str, current)) == sorted(map(str, logged))
    return current == logged


def rollback(api: Api, log_path: str, dry: bool, force: bool, files: RootFiles,
             state_dir: str) -> int:
    with open(log_path, encoding="utf-8") as fh:
        log = json.load(fh)
    entries = [e for e in log.get("ops", []) if e.get("inverse")]
    print(f"Rollback of phase {log.get('phase')} applied {log.get('started')} "
          f"({len(entries)} change(s) to undo, newest first){' - DRY-RUN' if dry else ''}")
    rb = {"tool": "apply_identity.py", "version": VERSION, "rollback_of": log_path,
          "started": now_utc(), "ops": []}
    rc = 0

    def brief(body):
        if isinstance(body, dict) and isinstance(body.get("attributes"), dict):
            body = {**body, "attributes": f"<{len(body['attributes'])} attribute key(s)>"}
        return json.dumps(body)

    for e in reversed(entries):
        inv_ = e["inverse"]
        method, path, body = inv_["method"], inv_["path"], inv_.get("body")
        line = f"  undo {e['n']:2d}: {method} {path}" + (f" {brief(body)}" if body is not None else "")
        print(line + f"   ({e['desc'][:90]})")
        if dry:
            continue
        outcome = "done"
        try:
            if method == "REMOVE_FILE":
                files.remove(path)
            elif method == "PATCH" and not path.endswith("/unassign/") and not force:
                cur = api.get_or_none(path)
                if cur is None:
                    outcome = "skipped: object is gone"
                else:
                    drift = [k for k, v in (e.get("body") or {}).items()
                             if not same_value(cur.get(k), v)]
                    if drift:
                        outcome = f"SKIPPED: changed since the apply ({', '.join(drift)}); --force"
                        rc = 4
                    else:
                        api.write(method, path, body)
            elif method == "DELETE" and path.startswith("/core/groups/") and not force:
                cur = api.get_or_none(path)
                if cur is None:
                    outcome = "skipped: already gone"
                elif cur.get("users"):
                    outcome = f"SKIPPED: group now has {len(cur['users'])} member(s); --force"
                    rc = 4
                else:
                    api.write(method, path, body)
            elif method == "POST" and path == "/core/groups/" and not force:
                if api.all("/core/groups/", name=(body or {}).get("name")):
                    outcome = "skipped: a group with that name exists"
                else:
                    api.write(method, path, body)
            else:
                try:
                    api.write(method, path, body)
                except ApiError as exc:
                    if method == "DELETE" and exc.status == 404:
                        outcome = "skipped: already gone"
                    else:
                        raise
        except Exception as exc:  # keep going, report at the end
            outcome = f"FAILED: {str(exc)[:300]}"
            rc = 5
        print(f"      -> {outcome}")
        rb["ops"].append({"n": e["n"], "method": method, "path": path, "outcome": outcome,
                          "at": now_utc()})
    if not dry:
        os.makedirs(state_dir, mode=0o700, exist_ok=True)
        stamp = log_stamp()
        out = os.path.join(state_dir, f"{stamp}-rollback-{log.get('phase')}.json")
        rb["finished"] = now_utc()
        write_log(out, rb)
        print(f"Rollback log: {out}")
    return rc


# ============================================================================
# live schema check (GET /schema/ only)
# ============================================================================
# (method, path template as in the OpenAPI document, request body fields this script sends)
SCHEMA_USES = [
    ("get", "/admin/version/", ()), ("get", "/admin/settings/", ()),
    ("patch", "/admin/settings/", ("default_user_change_email",)),
    ("get", "/flows/instances/", ()), ("get", "/flows/bindings/", ()),
    ("post", "/flows/bindings/", ("target", "stage", "order", "evaluate_on_plan",
                                  "re_evaluate_policies", "policy_engine_mode",
                                  "invalid_response_action")),
    ("delete", "/flows/bindings/{fsb_uuid}/", ()),
    ("get", "/stages/prompt/stages/", ()), ("get", "/stages/prompt/prompts/", ()),
    ("patch", "/stages/prompt/stages/{stage_uuid}/", ("validation_policies",)),
    ("get", "/stages/email/", ()), ("get", "/stages/email/templates/", ()),
    ("post", "/stages/email/", ("name", "use_global_settings", "template", "subject",
                                "activate_user_on_success", "token_expiry")),
    ("patch", "/stages/email/{stage_uuid}/", ("template",)),
    ("delete", "/stages/email/{stage_uuid}/", ()),
    ("get", "/stages/user_write/", ()),
    ("patch", "/stages/user_write/{stage_uuid}/", ("create_users_as_inactive", "user_path_template")),
    ("get", "/stages/identification/", ()),
    ("patch", "/stages/identification/{stage_uuid}/", ("enrollment_flow", "user_fields", "sources")),
    ("get", "/policies/expression/", ()),
    ("post", "/policies/expression/", ("name", "execution_logging", "expression")),
    ("patch", "/policies/expression/{policy_uuid}/", ("expression",)),
    ("delete", "/policies/expression/{policy_uuid}/", ()),
    ("get", "/policies/bindings/", ()),
    ("post", "/policies/bindings/", ("target", "policy", "group", "user", "order", "enabled",
                                     "negate", "timeout", "failure_result")),
    ("delete", "/policies/bindings/{policy_binding_uuid}/", ()),
    ("get", "/core/groups/", ()),
    ("post", "/core/groups/", ("name", "is_superuser", "parents", "users", "roles", "attributes")),
    ("get", "/core/groups/{group_uuid}/", ()),
    ("patch", "/core/groups/{group_uuid}/", ("is_superuser", "attributes")),
    ("delete", "/core/groups/{group_uuid}/", ()),
    ("post", "/core/groups/{group_uuid}/add_user/", ("pk",)),
    ("post", "/core/groups/{group_uuid}/remove_user/", ("pk",)),
    ("get", "/core/groups/{group_uuid}/used_by/", ()),
    ("get", "/core/users/", ()),
    ("post", "/core/users/", ("username", "name", "type", "path", "is_active", "groups", "roles",
                              "attributes")),
    ("patch", "/core/users/{id}/", ("username", "name", "attributes", "roles", "groups",
                                    "is_active")),
    ("delete", "/core/users/{id}/", ()),
    ("get", "/sources/oauth/", ()), ("get", "/sources/user_connections/oauth/", ()),
    ("get", "/sources/oauth/{slug}/", ()),
    ("patch", "/sources/oauth/{slug}/", ("user_matching_mode", "provider_type", "authorization_url",
                                         "access_token_url", "profile_url")),
    ("get", "/propertymappings/provider/scope/", ()), ("get", "/crypto/certificatekeypairs/", ()),
    ("post", "/core/applications/", ("name", "slug", "provider", "policy_engine_mode",
                                     "open_in_new_tab", "meta_launch_url", "meta_description",
                                     "meta_publisher")),
    ("get", "/core/applications/{slug}/", ()),
    ("patch", "/core/applications/{slug}/", ("policy_engine_mode", "provider")),
    ("delete", "/core/applications/{slug}/", ()),
    ("get", "/providers/oauth2/", ()),
    ("post", "/providers/oauth2/", ("name", "authorization_flow", "invalidation_flow",
                                    "client_type", "client_id", "property_mappings", "sub_mode",
                                    "issuer_mode", "include_claims_in_id_token", "signing_key",
                                    "redirect_uris", "access_code_validity",
                                    "access_token_validity")),
    ("patch", "/providers/oauth2/{id}/", ("redirect_uris", "sub_mode")),
    ("delete", "/providers/oauth2/{id}/", ()),
    ("get", "/rbac/roles/", ()), ("post", "/rbac/roles/", ("name",)),
    ("delete", "/rbac/roles/{uuid}/", ()),
    ("get", "/rbac/permissions/", ()), ("get", "/rbac/permissions/roles/", ()),
    ("get", "/rbac/permissions/assigned_by_roles/", ()),
    ("post", "/rbac/permissions/assigned_by_roles/{uuid}/assign/", ("permissions", "model",
                                                                   "object_pk")),
    ("patch", "/rbac/permissions/assigned_by_roles/{uuid}/unassign/", ("permissions", "model",
                                                                      "object_pk")),
    ("get", "/core/tokens/", ()),
    ("post", "/core/tokens/", ("identifier", "intent", "user", "expiring", "description")),
    ("patch", "/core/tokens/{identifier}/", ("expiring", "user", "intent")),
    ("delete", "/core/tokens/{identifier}/", ()),
    ("get", "/core/tokens/{identifier}/view_key/", ()),
    ("get", "/events/events/", ()), ("get", "/oauth2/refresh_tokens/", ()),
    ("get", "/oauth2/access_tokens/", ()),
    # antibot (WOPR-059)
    ("get", "/policies/reputation/", ()), ("get", "/policies/reputation/scores/", ()),
    ("post", "/policies/reputation/", ("name", "execution_logging", "check_ip", "check_username",
                                       "threshold")),
    ("patch", "/policies/reputation/{policy_uuid}/", ("check_ip", "check_username", "threshold")),
    ("delete", "/policies/reputation/{policy_uuid}/", ()),
    ("get", "/stages/password/", ()), ("get", "/stages/captcha/", ()),
    ("post", "/stages/captcha/", ("name", "public_key", "private_key", "js_url", "api_url",
                                  "interactive", "error_on_invalid_score")),
    ("patch", "/stages/captcha/{stage_uuid}/", ("js_url", "api_url", "interactive",
                                                "error_on_invalid_score")),
    ("delete", "/stages/captcha/{stage_uuid}/", ()),
    ("patch", "/flows/instances/{slug}/", ("policy_engine_mode",)),
]
SCHEMA_ENUMS = {
    "SubModeEnum": ("hashed_user_id",), "ClientTypeEnum": ("public",),
    "MatchingModeEnum": ("regex",), "UserMatchingModeEnum": ("email_deny", "username_deny"),
    "IntentEnum": ("api",), "UserTypeEnum": ("service_account",),
    "ModelEnum": ("authentik_core.group", "authentik_core.user"),
    "PolicyEngineMode": ("all", "any"), "IssuerModeEnum": ("per_provider",),
    "InvalidResponseActionEnum": ("retry",),
}


def check_schema(api: Api) -> int:
    schema = api.get("/schema/", format="json")
    print(f"live schema: {schema.get('info', {}).get('title')} "
          f"{schema.get('info', {}).get('version')}, {len(schema.get('paths', {}))} paths")
    comps = schema.get("components", {}).get("schemas", {})
    bad = 0
    for method, path, fields in SCHEMA_USES:
        op = (schema.get("paths", {}).get(path) or {}).get(method)
        if op is None:
            print(f"  MISSING  {method.upper()} {path}")
            bad += 1
            continue
        if not fields:
            print(f"  ok       {method.upper()} {path}")
            continue
        ref = (((op.get("requestBody") or {}).get("content") or {}).get("application/json")
               or {}).get("schema", {}).get("$ref", "")
        props = (comps.get(ref.rsplit("/", 1)[-1]) or {}).get("properties", {})
        missing = [f for f in fields if f not in props]
        if missing:
            bad += 1
        print(f"  {'ok' if not missing else 'MISSING':8} {method.upper()} {path} "
              f"[{ref.rsplit('/', 1)[-1]}: {', '.join(fields)}]"
              + (f"  missing: {', '.join(missing)}" if missing else ""))
    for enum, values in SCHEMA_ENUMS.items():
        have = set((comps.get(enum) or {}).get("enum") or [])
        missing = [v for v in values if v not in have]
        bad += bool(missing)
        print(f"  {'ok' if not missing else 'MISSING':8} enum {enum} has {', '.join(values)}"
              + (f"  missing: {', '.join(missing)}" if missing else ""))
    print(f"schema check: {len(SCHEMA_USES)} operations + {len(SCHEMA_ENUMS)} enums, "
          f"{bad} problem(s); API calls: {len(api.calls)} GET")
    return 0 if bad == 0 else 6


# ============================================================================
# main
# ============================================================================
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="apply_identity.py", formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__.split("\n\n", 1)[1] if __doc__ else "")
    ap.add_argument("--dry-run", action="store_true",
                    help="read-only plan (the default); with --rollback: preview the undo")
    ap.add_argument("--apply", choices=PHASES, metavar="PHASE",
                    help="apply ONE phase: " + ", ".join(PHASES))
    ap.add_argument("--rollback", metavar="LOG", help="undo a logged apply (state/*.json)")
    ap.add_argument("--check-schema", action="store_true",
                    help="read-only: check every endpoint, request field and enum this script "
                         "uses against the live /api/v3/schema/")
    ap.add_argument("--phase", action="append", choices=PHASES,
                    help="dry-run only these phases (repeatable)")
    ap.add_argument("--api", default=API_DEFAULT)
    ap.add_argument("--env-file", default=ENV_FILE_DEFAULT)
    ap.add_argument("--state-dir", default=STATE_DIR_DEFAULT)
    ap.add_argument("--signup", choices=("verify", "close"), default="verify",
                    help="trust: verify new sign-ups by email (default; central mail works) or "
                         "close self sign-up")
    ap.add_argument("--keep-source-email-link", action="store_true",
                    help="trust: leave OAuth sources on email_link/username_link")
    ap.add_argument("--token-file", default=LJ_TOKEN_FILE_DEFAULT,
                    help="groups: root-only file for the LoveJoos token")
    ap.add_argument("--lovejoos-emails", metavar="FILE",
                    help="lovejoos-gate: emails of LoveJoos users with a central login")
    ap.add_argument("--no-lovejoos-export", action="store_true",
                    help="lovejoos-gate: proceed without the LoveJoos export (authentik evidence only)")
    ap.add_argument("--lovejoos-release-deployed", action="store_true",
                    help="lovejoos-gate: confirm the LoveJoos release (WOPR-056) is live")
    ap.add_argument("--allow-barterra-orphan", action="store_true",
                    help="bink: rename even if Barterra has a link keyed on the old username")
    ap.add_argument("--caddy-site", default=CADDY_SITE_DEFAULT,
                    help="antibot: the auth.wopr.systems Caddy site, read only: does it pin "
                         "X-Forwarded-For to the real client?")
    ap.add_argument("--infisical-env", default=INFISICAL_ENV_DEFAULT,
                    help="antibot: Infisical machine identity (CID, CSEC, WID, INFENV, API); only "
                         "the Turnstile keys are read, never printed")
    ap.add_argument("--lovejoos-relay-ready", action="store_true",
                    help=f"antibot: confirm LoveJoos sends {RELAY_HEADER} on its sign-up flow "
                         "requests (a captcha is planned only then, and only with Turnstile keys)")
    ap.add_argument("--allow-version", action="store_true",
                    help="run against an authentik version other than 2025.12.x")
    ap.add_argument("--force", action="store_true",
                    help="rollback: undo even objects that changed since the apply")
    return ap


def main(argv=None, api=None, files=None, infisical=None) -> int:
    args = build_parser().parse_args(argv)
    if args.apply and args.dry_run:
        print("--apply and --dry-run exclude each other", file=sys.stderr)
        return 2
    if sum(bool(x) for x in (args.apply, args.rollback, args.check_schema)) > 1:
        print("--apply, --rollback and --check-schema exclude each other", file=sys.stderr)
        return 2
    args.files = files or RootFiles()
    args.infisical = infisical or Infisical(args.infisical_env)
    writing = bool(args.apply) or (bool(args.rollback) and not args.dry_run)
    if api is None:
        api = Api(args.api, read_api_token(args.env_file), write_enabled=writing)
    else:
        api.write_enabled = writing
    mode = ("APPLY " + args.apply) if args.apply else (
        "ROLLBACK" + (" (dry-run)" if args.dry_run else "") if args.rollback else
        "CHECK-SCHEMA (read-only)" if args.check_schema else "DRY-RUN")
    print(f"apply_identity.py {VERSION}  mode={mode}  api={api.base}")
    print(f"token: {TOKEN_ENV_KEY} from {args.env_file} (read into memory, not shown)")
    if args.rollback:
        return rollback(api, args.rollback, args.dry_run, args.force, args.files, args.state_dir)
    if args.check_schema:
        return check_schema(api)

    snap = Snapshot(api, args)
    print(f"authentik {snap.version}; {len(snap.users)} users, {len(snap.groups)} groups, "
          f"{len(snap.flows)} flows, {len(snap.policy_bindings)} policy bindings")
    if not snap.version.startswith(SUPPORTED_AUTHENTIK) and not args.allow_version:
        print(f"REFUSING: API shapes were checked against authentik {SUPPORTED_AUTHENTIK}x "
              "(use --allow-version after checking /api/v3/schema/)")
        return 2
    phases = [args.apply] if args.apply else (args.phase or list(PHASES))
    plans = [PLANNERS[ph](snap, args) for ph in phases]
    for p in plans:
        print_plan(p)

    if not args.apply:
        writes = [c for c in api.calls if c[0] != "GET"]
        print("\nSummary (dry-run): " + "; ".join(
            f"{p.phase}: {len(p.ops)} change(s){', apply refused until blockers clear' if p.blockers() else ''}"
            for p in plans))
        print(f"API calls made: {len(api.calls) - len(writes)} GET, {len(writes)} other")
        return 1 if writes else 0

    p = plans[0]
    blockers = p.blockers()
    if blockers:
        print(f"\nREFUSING to apply {p.phase}: {len(blockers)} blocker(s) above")
        return 2
    if not p.ops:
        print(f"\nNothing to do: phase {p.phase} is already applied")
        return 0
    log_path = apply_plan(api, p, args.state_dir, args.files)
    api.write_enabled = False
    again = PLANNERS[p.phase](Snapshot(api, args), args)
    if again.ops:
        print(f"\nWARNING: phase {p.phase} did not converge; a fresh plan still has "
              f"{len(again.ops)} change(s):")
        print_plan(again)
        return 3
    print(f"\nVerified: a fresh read-only plan for {p.phase} has no changes left. Log: {log_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
