"""Offline tests for apply_identity.py: a fake authentik API seeded with the live object ids
(read-only probe of 2026-10-05) and fake emails. Run: python3 -m unittest -v"""
import contextlib
import copy
import hashlib
import io
import ipaddress
import json
import os
import re
import sys
import tempfile
import textwrap
import time
import types
from datetime import datetime, timedelta, timezone
import unittest
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import apply_identity as ai  # noqa: E402

SECRET = "SECRET-TOKEN-KEY-0123456789abcdef"

# live ids (GET-only probe, 2026-10-05)
F_SELFREG = "efc68465-6a2d-4708-b641-5333ce78c2b5"
F_AUTH = "b9bcf7eb-fa37-4983-9192-a93ef547e164"
F_SETTINGS = "7a72c65a-e029-4557-8271-63c5c98ef2da"
F_ONBOARD = "230320f2-084d-46cf-a6a7-e853fb07db62"
F_BRAIN = "8b3bae77-93f2-4d38-804b-06e99d59fc13"
F_OOBE = "a1911584-268e-4f96-a3a2-ef53eaa171f7"
F_RECOVERY = "c3fa446f-c4c0-4fe9-8157-e80b8cb9ffdd"
F_IMPLICIT = "5bf034ea-0382-4e71-9197-c9b0b041498f"
F_PROV_INV = "0a32e6b3-a01e-47e6-9290-4baa0012b996"
S_SELFREG_PROMPT = "d4faf05a-c8e5-4fd4-91b9-7f0e0ccf536d"
S_SELFREG_WRITE = "b8423624-fd14-4966-ba3c-8c52834c1a20"
S_SELFREG_LOGIN = "1c390534-0ea7-4797-b95a-914d655884d8"
S_ONBOARD_PROMPT = "e8a6d805-66e6-427b-9f2d-1dca9e9a3966"
S_SETTINGS_PROMPT = "37d54f66-d38c-4cc6-9341-abcfb635a655"
S_OOBE_PROMPT = "fbc4c69e-2c73-484e-80ba-4514893caec2"
S_IDENT = "865680ad-8700-4b52-b614-513990008b5a"
S_RECOVERY_EMAIL = "48c54772-ffd2-43ef-b214-b353b66b9e43"
P_SETTINGS_AUTHZ = "90c54f59-a444-4311-81ec-5490bf4c83fd"
G_ADMINS = "49654bdb-d4a1-4dff-8d80-da456fc276ea"
G_DUP2 = "8b0c316d-229f-4849-8de8-9b0cf7c1a21f"
G_LJ = "88823a93-cad3-4a57-af1b-aee457db9a72"
APP_LJ = "c811f847-5ba3-4aad-8e19-e819b877c773"
APP_BARTER = "bc6baad9-d5b5-4efd-ab16-8b577bbc344a"
KEY_AK = "74158c91-a26e-4f14-aa7b-421b897089ff"
MAP_OPENID = "6efe2f53-d8c3-4bcf-a36f-fc3d1863f6d6"
S_PASSWORD = "5f0c2a9e-1b7d-4c3e-9a8f-2d6b4e1c7a90"


def prompt(pk, key, typ="text"):
    return {"pk": pk, "name": f"p-{key}-{pk[:4]}", "field_key": key, "type": typ}


def fixture():
    prompts = [prompt("a1", "username", "username"), prompt("a2", "name"),
               prompt("a3", "email", "email"), prompt("a4", "password", "password"),
               prompt("a5", "attributes.profile_complete", "hidden"),
               prompt("a6", "attributes.access_code")]
    stage_names = {}

    def fb(flow, stage, name, order, comp="ak-stage-prompt-form"):
        stage_names[stage] = name
        return {"pk": str(uuid.uuid4()), "target": flow, "stage": stage, "order": order,
                "stage_obj": {"name": name, "component": comp}}

    return {
        "version": "2025.12.4",
        "settings": {"default_user_change_email": False, "default_user_change_username": False},
        "flows": [{"pk": F_SELFREG, "slug": "self-registration", "designation": "enrollment",
                   "policy_engine_mode": "any"},
                  {"pk": F_AUTH, "slug": "default-authentication-flow",
                   "designation": "authentication", "policy_engine_mode": "any"},
                  {"pk": F_SETTINGS, "slug": "default-user-settings-flow"},
                  {"pk": F_ONBOARD, "slug": "user-onboarding"},
                  {"pk": F_BRAIN, "slug": "brainjoos-authentication",
                   "designation": "authentication", "policy_engine_mode": "any"},
                  {"pk": F_OOBE, "slug": "initial-setup"},
                  {"pk": F_RECOVERY, "slug": "password-recovery"},
                  {"pk": F_IMPLICIT, "slug": "default-provider-authorization-implicit-consent"},
                  {"pk": F_PROV_INV, "slug": "default-provider-invalidation-flow"}],
        "flow_bindings": [
            fb(F_SELFREG, S_SELFREG_PROMPT, "self-registration-prompt", 10),
            fb(F_SELFREG, S_SELFREG_WRITE, "self-registration-write", 20, "ak-stage-user-write-form"),
            fb(F_SELFREG, S_SELFREG_LOGIN, "self-registration-login", 30, "ak-stage-user-login-form"),
            fb(F_AUTH, S_IDENT, "default-authentication-identification", 10),
            fb(F_AUTH, S_PASSWORD, "default-authentication-password", 20, "ak-stage-password-form"),
            fb(F_BRAIN, S_IDENT, "default-authentication-identification", 10),
            fb(F_BRAIN, S_PASSWORD, "default-authentication-password", 20, "ak-stage-password-form"),
            fb(F_AUTH, S_ONBOARD_PROMPT, "onboarding-profile-prompt", 110),
            fb(F_BRAIN, S_ONBOARD_PROMPT, "onboarding-profile-prompt", 110),
            fb(F_ONBOARD, S_ONBOARD_PROMPT, "onboarding-profile-prompt", 10),
            fb(F_SETTINGS, S_SETTINGS_PROMPT, "default-user-settings", 20),
            fb(F_OOBE, S_OOBE_PROMPT, "stage-default-oobe-password", 10),
            fb(F_RECOVERY, S_RECOVERY_EMAIL, "recovery-email", 20, "ak-stage-email-form"),
        ],
        "prompt_stages": [
            {"pk": S_SELFREG_PROMPT, "name": "self-registration-prompt",
             "fields": ["a6", "a4", "a1", "a2", "a3"], "validation_policies": []},
            {"pk": S_ONBOARD_PROMPT, "name": "onboarding-profile-prompt",
             "fields": ["a2", "a5", "a1", "a3"], "validation_policies": []},
            {"pk": S_SETTINGS_PROMPT, "name": "default-user-settings",
             "fields": ["a1", "a2", "a3"], "validation_policies": [P_SETTINGS_AUTHZ]},
            {"pk": S_OOBE_PROMPT, "name": "stage-default-oobe-password",
             "fields": ["a3", "a4"], "validation_policies": []},
            {"pk": "38d92541-1351-4414-8a61-8c1a92aba064", "name": "default-source-enrollment-prompt",
             "fields": ["a1"], "validation_policies": []},
        ],
        "prompts": prompts,
        "email_stages": [{"pk": S_RECOVERY_EMAIL, "name": "recovery-email",
                          "use_global_settings": True, "template": "email/password_reset.html"}],
        "email_templates": [{"name": "email/password_reset.html"},
                            {"name": "email/account_confirmation.html"},
                            {"name": "wopr/email-account-confirmation.html"}],
        "user_write_stages": [{"pk": S_SELFREG_WRITE, "name": "self-registration-write",
                               "create_users_as_inactive": False, "create_users_group": None,
                               "user_path_template": ""}],
        "ident_stages": [{"pk": S_IDENT, "name": "default-authentication-identification",
                          "enrollment_flow": F_SELFREG, "user_fields": ["email", "username"],
                          "sources": []}],
        "expr_policies": [{"pk": P_SETTINGS_AUTHZ, "name": "default-user-settings-authorization",
                           "expression": "return True"}],
        "reputation_policies": [],
        "reputation_scores": [{"score": -5}, {"score": 1}],
        "password_stages": [{"pk": S_PASSWORD, "name": "default-authentication-password",
                             "failed_attempts_before_cancel": 5}],
        "captcha_stages": [],
        "policy_bindings": [{"pk": str(uuid.uuid4()), "target": str(uuid.uuid4()),
                             "group": G_ADMINS, "policy": None, "user": None, "order": 0}],
        "groups": [
            {"pk": G_ADMINS, "name": "WOPR Admins", "is_superuser": True, "parents": [],
             "users": [4, 7], "roles": [], "attributes": {}},
            {"pk": G_DUP2, "name": "WOPR Admins-dup2", "is_superuser": True, "parents": [],
             "users": [], "roles": [], "attributes": {}},
            {"pk": G_LJ, "name": "lovejoos-users", "is_superuser": False, "parents": [],
             "users": [], "roles": [], "attributes": {}},
        ],
        "users": [
            {"pk": 4, "username": "akadmin", "name": "admin", "email": "admin@example.org",
             "type": "internal", "path": "users", "is_active": True, "groups": [G_ADMINS],
             "roles": [], "attributes": {}, "uid": "u4"},
            {"pk": 7, "username": "nodez3r0", "name": "nz", "email": "nz@example.org",
             "type": "internal", "path": "users", "is_active": True, "groups": [G_ADMINS],
             "roles": [], "attributes": {}, "uid": "u7"},
            {"pk": 22, "username": "Thedude", "name": "Bink", "email": "dude@example.org",
             "type": "external", "path": "users", "is_active": True, "groups": [], "roles": [],
             "attributes": {}, "uid": "u22"},
            {"pk": 23, "username": "Sbinkerd1", "name": "Scott", "email": "sbinkerd1@gmail.com",
             "type": "external", "path": "users", "is_active": True, "groups": [], "roles": [],
             "attributes": {"access_code": "kept-secret-ish"},
             "uid": "cf778cafddfb365660ffe718aa9061f34932b9472d0f09a891873fd8e857969f"},
            {"pk": 40, "username": "ljfan", "name": "LJ Fan", "email": "LJFan@Example.org",
             "type": "external", "path": "users", "is_active": True, "groups": [], "roles": [],
             "attributes": {}, "uid": "u40"},
            {"pk": 32, "username": "ldap-bind", "name": "", "email": "", "type": "internal",
             "path": "users", "is_active": True, "groups": [], "roles": [], "attributes": {},
             "uid": "u32"},
        ],
        "oauth_sources": [
            {"pk": "12ff", "slug": "nodez3r0-beacon", "name": "NodeZ3r0 Beacon",
             "user_matching_mode": "email_link", "provider_type": "openidconnect",
             "authorization_url": "https://a.example/authorize", "access_token_url":
             "https://a.example/token", "profile_url": "https://a.example/userinfo"},
            {"pk": "2784", "slug": "federation-micro-reactor", "name": "Micro-Reactor Beacon",
             "user_matching_mode": "email_link", "provider_type": "openidconnect",
             "authorization_url": "https://b.example/authorize", "access_token_url":
             "https://b.example/token", "profile_url": "https://b.example/userinfo"},
        ],
        "source_connections": [{"pk": 1, "user": 7, "source_obj": {"slug": "nodez3r0-beacon"}}],
        "scope_mappings": [{"pk": MAP_OPENID, "managed": ai.OPENID_MAPPING_MANAGED,
                            "scope_name": "openid"}],
        "keypairs": [{"pk": KEY_AK, "name": "authentik Self-signed Certificate",
                      "private_key_available": True, "cert_expiry": "2027-01-26T10:29:31Z"}],
        "apps": [{"pk": APP_LJ, "slug": "lovejoos", "name": "LoveJoos", "provider": 162,
                  "policy_engine_mode": "any"},
                 {"pk": APP_BARTER, "slug": "barter-exchange", "name": "WOPR Barter Exchange",
                  "provider": 147, "policy_engine_mode": "any"}],
        "providers": [{"pk": 162, "client_id": "lovejoos", "name": "LoveJoos OAuth"},
                      {"pk": 147, "client_id": "barter", "name": "Barter Exchange OIDC"}],
        "roles": [{"pk": "fe48ac3c-4d60-4686-85a2-a860bb6c2b0d", "name": "WOPR Read-only"}],
        "role_perms": {},
        "tokens": [],
        "events": [
            {"action": "email_sent", "created": "2026-06-16T12:44:51Z",
             "context": {"subject": "authentik Test-Email", "from_email": "WOPR <noreply@x>"}},
            {"action": "authorize_application", "created": "2026-06-19T20:15:55Z",
             "user": {"pk": 7, "username": "nodez3r0"},
             "context": {"authorized_application": {"pk": APP_LJ.replace("-", "")}}},
        ],
    }


class FakeApi:
    """Just enough of the authentik 2025.12 API for apply_identity.py."""

    COLL = {  # list path -> (state key, id field, id kind)
        "/policies/expression/": ("expr_policies", "pk", "uuid"),
        "/stages/prompt/stages/": ("prompt_stages", "pk", "uuid"),
        "/stages/email/": ("email_stages", "pk", "uuid"),
        "/flows/bindings/": ("flow_bindings", "pk", "uuid"),
        "/stages/user_write/": ("user_write_stages", "pk", "uuid"),
        "/stages/identification/": ("ident_stages", "pk", "uuid"),
        "/policies/bindings/": ("policy_bindings", "pk", "uuid"),
        "/core/groups/": ("groups", "pk", "uuid"),
        "/rbac/roles/": ("roles", "pk", "uuid"),
        "/core/users/": ("users", "pk", "int"),
        "/core/tokens/": ("tokens", "identifier", "given"),
        "/providers/oauth2/": ("providers", "pk", "int"),
        "/core/applications/": ("apps", "slug", "given"),
        "/sources/oauth/": ("oauth_sources", "slug", "given"),
        "/flows/instances/": ("flows", "slug", "given"),
        "/stages/prompt/prompts/": ("prompts", "pk", "uuid"),
        "/sources/user_connections/oauth/": ("source_connections", "pk", "int"),
        "/propertymappings/provider/scope/": ("scope_mappings", "pk", "uuid"),
        "/crypto/certificatekeypairs/": ("keypairs", "pk", "uuid"),
        "/policies/reputation/": ("reputation_policies", "pk", "uuid"),
        "/stages/password/": ("password_stages", "pk", "uuid"),
        "/stages/captcha/": ("captcha_stages", "pk", "uuid"),
    }
    IGNORED = {"page", "page_size", "include_users", "include_groups", "ordering"}
    WRITE_ONLY = {"/stages/captcha/": ("private_key",)}  # authentik never returns these

    def __init__(self, state):
        self.st = state
        self.calls = []
        self.write_enabled = False
        self.base = "http://fake/api/v3"
        self.next_int = 100

    # -- helpers
    def _split(self, path):
        for prefix in sorted(self.COLL, key=len, reverse=True):
            if path.startswith(prefix):
                rest = path[len(prefix):].strip("/")
                parts = rest.split("/") if rest else []
                return prefix, parts
        return None, None

    def _item(self, prefix, ident):
        key, idf, kind = self.COLL[prefix]
        for it in self.st[key]:
            if str(it.get(idf)) == str(ident):
                return it
        return None

    def _public(self, prefix, obj):
        obj = copy.deepcopy(obj)
        for field in self.WRITE_ONLY.get(prefix, ()):
            obj.pop(field, None)
        return obj

    def _role_perms(self, role):
        return self.st["role_perms"].setdefault(role, {"global": set(), "object": set()})

    def _events(self, params):
        ev = [e for e in self.st["events"] if e["action"] == params.get("action", e["action"])]
        app = params.get("context_authorized_app")
        if app:
            ev = [e for e in ev if ((e.get("context") or {}).get("authorized_application") or {})
                  .get("pk") in (app, app.replace("-", ""))]
        if params.get("username"):
            ev = [e for e in ev if (e.get("user") or {}).get("username") == params["username"]]
        return ev

    # -- reads
    def get(self, path, **params):
        self.calls.append(("GET", path))
        return self._get(path, params, paginated=True)

    def get_or_none(self, path, **params):
        try:
            return self.get(path, **params)
        except ai.ApiError as exc:
            if exc.status == 404:
                return None
            raise

    def all(self, path, **params):
        self.calls.append(("GET", path))
        data = self._get(path, params, paginated=False)
        return data

    def _get(self, path, params, paginated):
        st = self.st
        if path == "/admin/version/":
            return {"version_current": st["version"]}
        if path == "/admin/settings/":
            return copy.deepcopy(st["settings"])
        if path == "/stages/email/templates/":
            return copy.deepcopy(st["email_templates"])
        if path == "/events/events/":
            ev = self._events(params)
            if params.get("ordering") == "created":
                ev = sorted(ev, key=lambda e: e["created"])
            return {"results": ev[: int(params.get("page_size", 100))],
                    "pagination": {"count": len(ev), "next": 0}} if paginated else ev
        if path == "/policies/reputation/scores/":
            return {"results": [], "pagination": {"count": len(st["reputation_scores"]), "next": 0}}
        if path in ("/oauth2/refresh_tokens/", "/oauth2/access_tokens/"):
            return [] if not paginated else {"results": [], "pagination": {"count": 0}}
        if path == "/rbac/permissions/":
            g = self._role_perms(params["role"])["global"]
            return [{"app_label": p.split(".")[0], "codename": p.split(".")[1]} for p in sorted(g)]
        if path == "/rbac/permissions/roles/":
            o = self._role_perms(params["uuid"])["object"]
            return [{"app_label": p.split(".")[0], "codename": p.split(".")[1],
                     "model": m.split(".")[1], "object_pk": obj} for p, m, obj in sorted(o)]
        if path == "/rbac/permissions/assigned_by_roles/":
            out = []
            for r in st["roles"]:
                rp = self._role_perms(r["pk"])
                out.append({"name": r["name"],
                            "model_permissions": [{"app_label": p.split(".")[0],
                                                   "codename": p.split(".")[1]}
                                                  for p in rp["global"]],
                            "object_permissions": [{"app_label": p.split(".")[0],
                                                    "codename": p.split(".")[1],
                                                    "object_pk": obj} for p, m, obj in rp["object"]]})
            return out
        if path == "/rbac/roles/" and "users" in params:
            user = self._item("/core/users/", params["users"]) or {}
            return [copy.deepcopy(r) for r in st["roles"] if r["pk"] in (user.get("roles") or [])]
        prefix, parts = self._split(path)
        if prefix is None:
            raise ai.ApiError("GET", path, 404, "no route")
        key, idf, kind = self.COLL[prefix]
        if not parts:
            items = st[key]
            for k, v in params.items():
                if k in self.IGNORED:
                    continue
                items = [it for it in items if str(it.get(k)) == str(v)]
            items = [self._public(prefix, x) for x in items]
            return {"results": items, "pagination": {"next": 0}} if paginated else items
        it = self._item(prefix, parts[0])
        if it is None:
            raise ai.ApiError("GET", path, 404, "not found")
        if len(parts) == 1:
            return self._public(prefix, it)
        if parts[1] == "used_by":
            return []
        if parts[1] == "view_key":
            return {"key": SECRET}
        raise ai.ApiError("GET", path, 404, "no route")

    # -- writes
    def write(self, method, path, body=None):
        if not self.write_enabled:
            raise RuntimeError("write in read-only mode")
        self.calls.append((method, path))
        st = self.st
        body = copy.deepcopy(body)
        m = re.match(r"^/rbac/permissions/assigned_by_roles/([^/]+)/(assign|unassign)/$", path)
        if m:
            role, action = m.groups()
            rp = self._role_perms(role)
            model, obj = body.get("model"), body.get("object_pk")
            if model:  # authentik: a missing object silently makes the grant GLOBAL
                prefix = {"authentik_core.group": "/core/groups/"}[model]
                if self._item(prefix, obj) is None:
                    model = obj = None
            for perm in body["permissions"]:
                entry = (perm, model, obj) if model else perm
                target = rp["object"] if model else rp["global"]
                (target.add if action == "assign" else target.discard)(entry)
            return (200, [{"id": "1"}]) if action == "assign" else (204, None)
        if path == "/admin/settings/" and method == "PATCH":
            st["settings"].update(body)
            return 200, copy.deepcopy(st["settings"])
        prefix, parts = self._split(path)
        if prefix is None:
            raise ai.ApiError(method, path, 404, "no route")
        key, idf, kind = self.COLL[prefix]
        if prefix == "/policies/expression/" and isinstance(body, dict) and "expression" in body:
            body = dict(body, expression=body["expression"].strip())  # authentik trims on save
        if method == "POST" and not parts:
            obj = dict(body)
            if idf not in obj or kind != "given":
                if kind == "uuid":
                    obj[idf] = str(uuid.uuid4())
                elif kind == "int":
                    self.next_int += 1
                    obj[idf] = self.next_int
            if prefix == "/core/applications/":
                obj["pk"] = str(uuid.uuid4())
            if prefix == "/core/groups/" and any(g["name"] == obj["name"] for g in st["groups"]):
                raise ai.ApiError(method, path, 400, "name exists")
            if prefix == "/flows/bindings/":
                names = {s["pk"]: s["name"] for k in ("prompt_stages", "email_stages",
                                                      "user_write_stages", "captcha_stages")
                         for s in st[k]}
                obj["stage_obj"] = {"name": names.get(obj["stage"], "?"), "component": "x"}
            if prefix == "/core/users/":
                obj.setdefault("uid", "uid-" + str(obj["pk"]))
            st[key].append(obj)
            return 201, copy.deepcopy(obj)
        it = self._item(prefix, parts[0]) if parts else None
        if it is None:
            raise ai.ApiError(method, path, 404, "not found")
        if len(parts) == 2 and parts[1] in ("add_user", "remove_user"):
            if prefix == "/core/groups/":
                users = it.setdefault("users", [])
                if parts[1] == "add_user" and body["pk"] not in users:
                    users.append(body["pk"])
                if parts[1] == "remove_user" and body["pk"] in users:
                    users.remove(body["pk"])
                return 204, None
        if method == "PATCH" and len(parts) == 1:
            # serializer traps seen in authentik 2025.12.4
            if prefix == "/sources/oauth/" and "provider_type" not in body:
                raise ai.ApiError(method, path, 500, "KeyError: 'provider_type'")
            if prefix == "/stages/identification/" and not (body.get("user_fields")
                                                             or body.get("sources")):
                raise ai.ApiError(method, path, 400, "at least one source must be selected")
            if prefix == "/core/tokens/":
                body.setdefault("user", 4)  # TokenSerializer.validate(): user = caller
            it.update(body)
            return 200, copy.deepcopy(it)
        if method == "DELETE" and len(parts) == 1:
            st[key].remove(it)
            if prefix == "/rbac/roles/":
                st["role_perms"].pop(it["pk"], None)
            return 204, None
        raise ai.ApiError(method, path, 405, "unsupported")


class FakeFiles:
    def __init__(self):
        self.files = {}
        self.texts = {}  # read-only config files (the Caddy site)

    def read_text(self, path):
        return self.texts.get(path)

    def exists(self, path):
        return bool(self.files.get(path))

    def write_secret(self, path, content):
        self.files[path] = content

    def remove(self, path):
        self.files.pop(path, None)


class FakeInfisical:
    """Infisical at path /: `values` holds the secrets that exist."""

    def __init__(self, values=None, broken=False):
        self.values = dict(values or {})
        self.broken = broken
        self.value_reads = []

    def describe(self):
        return "fake Infisical"

    def missing(self, keys):
        if self.broken:
            raise ai.InfisicalUnavailable("fake: no answer")
        return [k for k in keys if not self.values.get(k)]

    def value(self, key):
        if self.broken or not self.values.get(key):
            raise ai.InfisicalUnavailable(f"{key} unavailable")
        self.value_reads.append(key)
        return self.values[key]


class FakeDisposable:
    """The domain-list files in the authentik container (WOPR-189). Installed by default."""

    def __init__(self, installed=True):
        self.files = {}
        if installed:
            text, _, _ = ai.load_disposable()
            self.files[ai.DISPOSABLE_DEST] = text

    def installed_sha256(self, dest):
        text = self.files.get(dest)
        return None if text is None else hashlib.sha256(text.encode("ascii")).hexdigest()

    def install(self, text, dest):
        self.files[dest] = text
        return self.installed_sha256(dest)


def run(argv, api, files=None, infisical=None, disposable=None):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = ai.main(argv, api=api, files=files or FakeFiles(),
                     infisical=infisical or FakeInfisical(), disposable=disposable or FakeDisposable())
    return rc, buf.getvalue()


def essence(st, files):
    """Comparable view of the fake state (ids of recreated objects ignored)."""
    pol = {p["pk"]: p["name"] for p in st["expr_policies"] + st["reputation_policies"]}
    grp = {g["pk"]: g["name"] for g in st["groups"]}
    return json.dumps({
        "settings": st["settings"],
        "reputation": sorted((p["name"], p.get("check_ip"), p.get("check_username"),
                              p.get("threshold")) for p in st["reputation_policies"]),
        "captcha": sorted(c["name"] for c in st["captcha_stages"]),
        "flow_modes": sorted((f["slug"], f.get("policy_engine_mode") or "") for f in st["flows"]),
        "policies": sorted((p["name"], p["expression"]) for p in st["expr_policies"]),
        "prompt": sorted((s["name"], [pol.get(x, x) for x in s["validation_policies"]])
                         for s in st["prompt_stages"]),
        "email_stages": sorted(s["name"] for s in st["email_stages"]),
        "fsb": sorted((b["target"], b["stage_obj"]["name"], b["order"]) for b in st["flow_bindings"]),
        "uw": sorted((s["name"], s["create_users_as_inactive"]) for s in st["user_write_stages"]),
        "ident": sorted((s["name"], s["enrollment_flow"]) for s in st["ident_stages"]),
        "sources": sorted((s["slug"], s["user_matching_mode"]) for s in st["oauth_sources"]),
        "groups": sorted((g["name"], g["is_superuser"], sorted(g["users"]), g["attributes"])
                         for g in st["groups"]),
        "users": sorted((u["pk"], u["username"], u.get("name"), u.get("attributes"),
                         u.get("roles")) for u in st["users"]),
        "roles": sorted(r["name"] for r in st["roles"]),
        "tokens": sorted(t["identifier"] for t in st["tokens"]),
        "providers": sorted(p["client_id"] for p in st["providers"]),
        "apps": sorted((a["slug"], a.get("provider"), a.get("policy_engine_mode")) for a in st["apps"]),
        "bindings": sorted((b["target"], pol.get(b.get("policy")), grp.get(b.get("group")),
                            bool(b.get("negate")), bool(b.get("failure_result")))
                           for b in st["policy_bindings"]),
        "perms": sorted((r, sorted(map(str, v["global"])), sorted(map(str, v["object"])))
                        for r, v in st["role_perms"].items() if v["global"] or v["object"]),
        "files": sorted(files.files),
    }, sort_keys=True, default=str)


class DryRunTests(unittest.TestCase):
    def test_dry_run_is_get_only_and_plans_every_phase(self):
        api = FakeApi(fixture())
        rc, out = run([], api)
        self.assertEqual(rc, 0, out)
        self.assertTrue(api.calls and all(m == "GET" for m, _ in api.calls))
        self.assertNotIn(SECRET, out)
        for needle in ("create expression policy 'wopr-email-guard'",
                       "add wopr-email-guard to prompt stage 'self-registration-prompt'",
                       "add wopr-email-guard to prompt stage 'onboarding-profile-prompt'",
                       "add wopr-email-guard to prompt stage 'default-user-settings'",
                       "prompt stage 'stage-default-oobe-password' writes email but is skipped",
                       "create email stage 'self-registration-email-verification'",
                       "at order 25", "create new users inactive",
                       "nodez3r0-beacon) uses email_link",
                       "create group 'wopr-verified'", "create group 'yourspace-members'",
                       "delete superuser group 'WOPR Admins-dup2'",
                       "create service account 'lovejoos-service'",
                       "authentik_core.add_user_to_group, authentik_core.remove_user_from_group, "
                       "authentik_core.view_group on group 'lovejoos-users' ONLY",
                       "create public OAuth2 provider client_id 'yourspace'",
                       "bind group 'yourspace-members' to app 'yourspace'",
                       "pk 23: username, name, attributes",
                       "add existing LoveJoos user nodez3r0 (pk 7) to lovejoos-users",
                       "bind group 'lovejoos-users' to app 'lovejoos'",
                       "create expression policy 'wopr-signup-relay'",
                       "create expression policy 'wopr-disposable-email'",
                       "add wopr-disposable-email, wopr-signup-ip-limit to prompt stage "
                       "'self-registration-prompt'",
                       "captcha off: no Turnstile keys in Infisical",
                       "reputation gate held back"):
            self.assertIn(needle, out)
        # the access_code attribute value is never shown
        self.assertNotIn("kept-secret-ish", out)
        # later phases name what they wait for
        self.assertIn("needs group yourspace-members (created by phase groups)", out)
        self.assertIn("--lovejoos-release-deployed", out)

    def test_ordering_inside_trust_bind_before_inactive(self):
        api = FakeApi(fixture())
        plan = ai.plan_trust(ai.Snapshot(api, None), types.SimpleNamespace(
            signup="verify", keep_source_email_link=False))
        keys = [op.key for op in plan.ops]
        self.assertLess(keys.index("fsb.email"), keys.index("stage.write.inactive"))
        self.assertEqual(plan.blockers(), [])

    def test_signup_close_mode(self):
        api = FakeApi(fixture())
        plan = ai.plan_trust(ai.Snapshot(api, None), types.SimpleNamespace(
            signup="close", keep_source_email_link=True))
        keys = [op.key for op in plan.ops]
        self.assertIn("policy.wopr-signup-closed", keys)
        self.assertIn("binding.signup_closed", keys)
        self.assertIn("ident.default-authentication-identification.enroll", keys)
        self.assertNotIn("stage.email", keys)
        self.assertFalse(any(k.startswith("source.") for k in keys))

    def test_no_mail_evidence_blocks_verify(self):
        st = fixture()
        st["events"] = [e for e in st["events"] if e["action"] != "email_sent"]
        plan = ai.plan_trust(ai.Snapshot(FakeApi(st), None), types.SimpleNamespace(
            signup="verify", keep_source_email_link=False))
        self.assertTrue(any("needs working central mail" in b for b in plan.blockers()))


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.st = fixture()
        self.orig = copy.deepcopy(self.st)
        self.api = FakeApi(self.st)
        self.files = FakeFiles()
        self.infisical = FakeInfisical()
        self.emails = os.path.join(self.tmp, "lj.txt")
        with open(self.emails, "w") as fh:
            fh.write("# LoveJoos users with a central login\nljfan@example.org\n"
                     "nobody@example.org\nsbinkerd1@gmail.com\n")

    def apply(self, phase, *extra):
        return run(["--apply", phase, "--state-dir", self.tmp, *extra], self.api, self.files,
                   self.infisical)

    def logs(self):
        return sorted(os.path.join(self.tmp, f) for f in os.listdir(self.tmp)
                      if f.endswith(".json") and "rollback" not in f)

    def test_full_cycle_idempotent_and_reversible(self):
        gate = ("--lovejoos-release-deployed", "--lovejoos-emails", self.emails)
        for phase, extra in (("trust", ()), ("antibot", ()), ("groups", ()), ("yourspace-app", ()),
                             ("bink", ()),
                             ("lovejoos-gate", gate)):
            rc, out = self.apply(phase, *extra)
            self.assertEqual(rc, 0, out)
            self.assertIn("Verified: a fresh read-only plan", out)
            self.assertNotIn(SECRET, out)
            rc, out = self.apply(phase, *extra)
            self.assertEqual(rc, 0, out)
            self.assertIn("Nothing to do", out)
        st = self.st
        # trust
        guard = next(p["pk"] for p in st["expr_policies"] if p["name"] == ai.POLICY_EMAIL_GUARD)
        for s in st["prompt_stages"]:
            want = s["name"] in ai.REQUIRED_EMAIL_STAGES
            self.assertEqual(guard in s["validation_policies"], want, s["name"])
        self.assertTrue(st["user_write_stages"][0]["create_users_as_inactive"])
        self.assertEqual(st["user_write_stages"][0]["user_path_template"], ai.SELF_REG_PATH)
        self.assertEqual({s["user_matching_mode"] for s in st["oauth_sources"]}, {"email_deny"})
        # antibot (X-Forwarded-For not pinned here: no reputation gate; no Turnstile keys)
        disp = next(p["pk"] for p in st["expr_policies"] if p["name"] == ai.POLICY_DISPOSABLE)
        ip_limit = next(p["pk"] for p in st["expr_policies"] if p["name"] == ai.POLICY_SIGNUP_IP)
        for s in st["prompt_stages"]:
            want = s["name"] in ai.REQUIRED_EMAIL_STAGES
            self.assertEqual(disp in s["validation_policies"], want, s["name"])
            self.assertEqual(ip_limit in s["validation_policies"], s["name"] == ai.SIGNUP_PROMPT)
        self.assertEqual((st["reputation_policies"], st["captcha_stages"]), ([], []))
        # groups
        names = {g["name"]: g for g in st["groups"]}
        self.assertNotIn("WOPR Admins-dup2", names)
        self.assertFalse(names["wopr-verified"]["is_superuser"])
        role = next(r for r in st["roles"] if r["name"] == ai.LJ_ROLE)
        perms = st["role_perms"][role["pk"]]
        self.assertEqual(perms["global"], {"authentik_core.view_user"})
        self.assertEqual(perms["object"], {(p, "authentik_core.group", G_LJ)
                                           for p in ai.LJ_GROUP_PERMS})
        sa = next(u for u in st["users"] if u["username"] == ai.LJ_SA_USERNAME)
        self.assertEqual((sa["type"], sa["groups"], sa["roles"]),
                         ("service_account", [], [role["pk"]]))
        tok = st["tokens"][0]
        self.assertEqual((tok["intent"], tok["expiring"], tok["user"]), ("api", False, sa["pk"]))
        self.assertEqual(self.files.files[ai.LJ_TOKEN_FILE_DEFAULT], SECRET + "\n")
        # yourspace-app
        prov = next(p for p in st["providers"] if p["client_id"] == "yourspace")
        self.assertEqual((prov["client_type"], prov["sub_mode"], prov["property_mappings"]),
                         ("public", "hashed_user_id", [MAP_OPENID]))
        self.assertEqual(prov["redirect_uris"], [{"matching_mode": "regex",
                                                  "url": ai.YS_REDIRECT_REGEX}])
        app = next(a for a in st["apps"] if a["slug"] == "yourspace")
        self.assertEqual((app["provider"], app["policy_engine_mode"]), (prov["pk"], "all"))
        app_binds = [b for b in st["policy_bindings"] if b["target"] == app["pk"]]
        self.assertEqual(len(app_binds), 2)
        # bink
        bink = next(u for u in st["users"] if u["pk"] == 23)
        self.assertEqual((bink["username"], bink["name"]), ("bink", "BINK"))
        self.assertEqual(bink["attributes"]["yourspace"], ai.BINK_YOURSPACE)
        self.assertEqual(bink["attributes"]["access_code"], "kept-secret-ish")
        # only the control-plane sync writes wopr-verified
        self.assertNotIn(23, names["wopr-verified"]["users"])
        self.assertIn(23, names["yourspace-members"]["users"])
        # gate: ljfan (export) + nodez3r0 (authorize event) in; BINK stays out
        self.assertEqual(sorted(names["lovejoos-users"]["users"]), [7, 40])
        lj_app = next(a for a in st["apps"] if a["slug"] == "lovejoos")
        self.assertEqual(lj_app["policy_engine_mode"], "all")
        # no secret in any log
        for path in self.logs():
            with open(path) as fh:
                self.assertNotIn(SECRET, fh.read())
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        # roll everything back, newest first
        for path in reversed(self.logs()):
            rc, out = run(["--rollback", path, "--state-dir", self.tmp], self.api, self.files)
            self.assertEqual(rc, 0, out)
        self.assertEqual(essence(self.st, self.files), essence(self.orig, FakeFiles()))

    def test_rollback_dry_run_changes_nothing(self):
        rc, out = self.apply("trust")
        self.assertEqual(rc, 0, out)
        before = essence(self.st, self.files)
        rc, out = run(["--rollback", self.logs()[0], "--dry-run", "--state-dir", self.tmp],
                      self.api, self.files)
        self.assertEqual(rc, 0, out)
        self.assertIn("undo", out)
        self.assertEqual(before, essence(self.st, self.files))

    def test_rollback_skips_objects_changed_since(self):
        self.apply("groups")
        rc, out = self.apply("bink")
        self.assertEqual(rc, 0, out)
        next(u for u in self.st["users"] if u["pk"] == 23)["name"] = "Changed later"
        bink_log = [p for p in self.logs() if p.endswith("-bink.json")][0]
        rc, out = run(["--rollback", bink_log, "--state-dir", self.tmp], self.api, self.files)
        self.assertEqual(rc, 4, out)
        self.assertIn("SKIPPED: changed since the apply", out)

    def test_bink_refuses_wrong_account(self):
        self.apply("groups")
        next(u for u in self.st["users"] if u["pk"] == 23)["email"] = "someone@else.org"
        rc, out = self.apply("bink")
        self.assertEqual(rc, 2, out)
        self.assertIn("refusing to rename the wrong account", out)

    def test_bink_refuses_barterra_orphan(self):
        self.apply("groups")
        self.st["events"].append({"action": "authorize_application", "created": "2026-07-01",
                                  "user": {"pk": 23, "username": "Sbinkerd1"},
                                  "context": {"authorized_application":
                                              {"pk": APP_BARTER.replace("-", "")}}})
        rc, out = self.apply("bink")
        self.assertEqual(rc, 2, out)
        self.assertIn("would orphan that link", out)
        rc, out = self.apply("bink", "--allow-barterra-orphan")
        self.assertEqual(rc, 0, out)

    def test_bink_before_groups_is_refused(self):
        rc, out = self.apply("bink")
        self.assertEqual(rc, 2, out)
        self.assertIn("created by phase groups", out)

    def test_yourspace_before_groups_is_refused(self):
        rc, out = self.apply("yourspace-app")
        self.assertEqual(rc, 2, out)

    def test_gate_needs_release_flag_and_export(self):
        rc, out = self.apply("lovejoos-gate")
        self.assertEqual(rc, 2, out)
        self.assertIn("--lovejoos-release-deployed", out)
        rc, out = self.apply("lovejoos-gate", "--lovejoos-release-deployed")
        self.assertEqual(rc, 2, out)
        self.assertIn("--lovejoos-emails FILE", out)
        self.assertEqual(self.st["groups"][2]["users"], [])

    def test_dup2_with_member_is_not_deleted(self):
        next(g for g in self.st["groups"] if g["pk"] == G_DUP2)["users"] = [7]
        rc, out = self.apply("groups")
        self.assertEqual(rc, 2, out)
        self.assertIn("not safe to delete", out)

    def test_missing_lovejoos_group_blocks_object_grant(self):
        self.st["groups"] = [g for g in self.st["groups"] if g["pk"] != G_LJ]
        rc, out = self.apply("groups")
        self.assertEqual(rc, 2, out)
        self.assertIn("GLOBALLY", out)
        self.assertFalse(any(v["global"] or v["object"] for v in self.st["role_perms"].values()))
        self.assertNotIn(ai.LJ_ROLE, [r["name"] for r in self.st["roles"]])

    def test_extra_role_permission_is_removed(self):
        self.apply("groups")
        role = next(r for r in self.st["roles"] if r["name"] == ai.LJ_ROLE)
        self.st["role_perms"][role["pk"]]["global"].add("authentik_core.add_user")
        rc, out = self.apply("groups")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.st["role_perms"][role["pk"]]["global"], {"authentik_core.view_user"})

    def test_lost_token_file_is_rewritten(self):
        self.apply("groups")
        self.files.files.clear()
        rc, out = self.apply("groups")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.files.files[ai.LJ_TOKEN_FILE_DEFAULT], SECRET + "\n")

    def test_signup_close_apply_and_rollback(self):
        rc, out = self.apply("trust", "--signup", "close")
        self.assertEqual(rc, 0, out)
        self.assertIsNone(self.st["ident_stages"][0]["enrollment_flow"])
        self.assertEqual(self.st["ident_stages"][0]["user_fields"], ["email", "username"])
        rc, out = run(["--rollback", self.logs()[0], "--state-dir", self.tmp], self.api, self.files)
        self.assertEqual(rc, 0, out)
        self.assertEqual(essence(self.st, self.files), essence(self.orig, FakeFiles()))

    def test_expiring_token_is_fixed_without_changing_owner(self):
        self.apply("groups")
        sa = next(u for u in self.st["users"] if u["username"] == ai.LJ_SA_USERNAME)
        self.st["tokens"][0]["expiring"] = True
        rc, out = self.apply("groups")
        self.assertEqual(rc, 0, out)
        self.assertEqual((self.st["tokens"][0]["expiring"], self.st["tokens"][0]["user"]),
                         (False, sa["pk"]))

    def test_service_account_managed_role_is_left_alone(self):
        self.apply("groups")
        sa = next(u for u in self.st["users"] if u["username"] == ai.LJ_SA_USERNAME)
        managed = {"pk": str(uuid.uuid4()), "name": f"ak-managed-role--user-{sa['pk']}"}
        self.st["roles"].append(managed)
        sa["roles"].append(managed["pk"])
        rc, out = self.apply("groups")
        self.assertEqual(rc, 0, out)
        self.assertIn("Nothing to do", out)
        sa["roles"].append("fe48ac3c-4d60-4686-85a2-a860bb6c2b0d")  # WOPR Read-only
        rc, out = run(["--phase", "groups"], self.api, self.files)
        self.assertIn("also holds role(s) WOPR Read-only", out)
        self.assertIn("Planned changes: none", out)

    def test_dry_run_mode_cannot_write(self):
        api = FakeApi(fixture())
        with self.assertRaises(RuntimeError):
            api.write("POST", "/core/groups/", {"name": "x"})
        real = ai.Api("http://127.0.0.1:9", "t", write_enabled=False)
        with self.assertRaises(RuntimeError):
            real.write("DELETE", "/core/groups/x/")


class FakeQS:
    def __init__(self, users):
        self.users = users

    def exclude(self, pk):
        return FakeQS([u for u in self.users if u.pk != pk])

    def exists(self):
        return bool(self.users)

    def __iter__(self):
        return iter(list(self.users))


class FakeUser:
    def __init__(self, pk, email, can_change=None, path="users", is_active=True,
                 last_login="2026-01-01", joined_hours_ago=1000, store=None):
        self.pk, self.email, self.is_authenticated = pk, email, True
        self.username = f"u{pk}"
        self._attrs = {} if can_change is None else {"goauthentik.io/user/can-change-email": can_change}
        self.path, self.is_active, self.last_login = path, is_active, last_login
        self.date_joined = datetime.now(timezone.utc) - timedelta(hours=joined_hours_ago)
        self._store = store

    def delete(self):
        self._store.remove(self)

    def group_attributes(self, _req):
        return self._attrs


class ExpressionTests(unittest.TestCase):
    def run_expr(self, expr, request, users=(), modules=None, **names):
        models = types.ModuleType("authentik.core.models")
        models.USER_ATTRIBUTE_CHANGE_EMAIL = "goauthentik.io/user/can-change-email"

        class Manager:
            @staticmethod
            def filter(email__iexact):
                return FakeQS([u for u in users if u.email.lower() == email__iexact.lower()])

        models.User = type("User", (), {"objects": Manager})
        msgs = []
        mods = {"authentik": types.ModuleType("authentik"),
                "authentik.core": types.ModuleType("authentik.core"),
                "authentik.core.models": models}
        mods.update(modules or {})
        old = {k: sys.modules.get(k) for k in mods}
        sys.modules.update(mods)
        try:
            args = ", ".join(["request", "ak_message", "ak_logger", *names])
            src = f"def _f({args}):\n" + textwrap.indent(expr, "    ")
            # authentik's evaluator globals that these policies use
            g = {"ip_address": ipaddress.ip_address, "ip_network": ipaddress.ip_network}
            exec(compile(src, "expr", "exec"), g)
            log = types.SimpleNamespace(
                info=lambda *a, **k: self.__dict__.setdefault("logged", []).append((a, k)),
                warning=lambda *a, **k: self.__dict__.setdefault("logged", []).append((a, k)))
            return g["_f"](request, msgs.append, log, *names.values()), msgs
        finally:
            for k, v in old.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v

    def req(self, user, email=None, allow_default=False, has_email=True):
        data = {"email": email} if has_email else {"username": "x"}
        http = types.SimpleNamespace(tenant=types.SimpleNamespace(
            default_user_change_email=allow_default))
        return types.SimpleNamespace(user=user, context={"prompt_data": data}, http_request=http)

    def test_email_guard(self):
        anon = types.SimpleNamespace(is_authenticated=False, pk=None)
        bink = FakeUser(23, "sbinkerd1@gmail.com")
        other = FakeUser(40, "ljfan@example.org")
        users = [bink, other]
        E = ai.EMAIL_GUARD_EXPR
        self.assertEqual(self.run_expr(E, self.req(anon, "new@example.org"), users)[0], True)
        ok, msgs = self.run_expr(E, self.req(anon, " SBINKERD1@gmail.com "), users)
        self.assertFalse(ok)
        self.assertIn("already used by another account", msgs[0])
        self.assertTrue(self.run_expr(E, self.req(bink, "sbinkerd1@gmail.com"), users)[0])
        self.assertTrue(self.run_expr(E, self.req(bink, "SBinkerd1@Gmail.com"), users)[0])
        self.assertFalse(self.run_expr(E, self.req(bink, "ljfan@example.org"), users)[0])
        ok, msgs = self.run_expr(E, self.req(bink, "fresh@example.org"), users)
        self.assertFalse(ok)
        self.assertIn("can't be changed", msgs[0])
        self.assertTrue(self.run_expr(E, self.req(bink, "fresh@example.org", True), users)[0])
        allowed = FakeUser(23, "sbinkerd1@gmail.com", can_change=True)
        self.assertTrue(self.run_expr(E, self.req(allowed, "fresh@example.org"), [allowed])[0])
        no_http = types.SimpleNamespace(user=bink, context={"prompt_data": {"email": "x@y.org"}},
                                        http_request=None)
        self.assertFalse(self.run_expr(E, no_http, users)[0])
        noemail = FakeUser(32, "")
        self.assertTrue(self.run_expr(E, self.req(noemail, "fresh@example.org"), users)[0])
        self.assertTrue(self.run_expr(E, self.req(anon, has_email=False), users)[0])
        self.assertTrue(self.run_expr(E, self.req(anon, ""), users)[0])

    def test_email_guard_frees_only_an_abandoned_signup(self):
        self.logged = []
        anon = types.SimpleNamespace(is_authenticated=False, pk=None)
        E = ai.EMAIL_GUARD_EXPR
        self.assertIn(f'SELF_REG_PATH = "{ai.SELF_REG_PATH}"', E)
        self.assertIn(f"timedelta(hours={ai.ABANDONED_AFTER_HOURS})", E)
        users = []
        sr = dict(path=ai.SELF_REG_PATH, is_active=False, last_login=None, store=users)
        users.append(FakeUser(50, "gone@example.org", joined_hours_ago=30, **sr))
        ok, msgs = self.run_expr(E, self.req(anon, "Gone@example.org"), users)
        self.assertTrue(ok, msgs)
        self.assertEqual(users, [])
        self.assertEqual(len(self.logged), 1)
        # still inside its link's lifetime: kept, and the message says why
        users.append(FakeUser(51, "fresh@example.org", joined_hours_ago=3, **sr))
        ok, msgs = self.run_expr(E, self.req(anon, "fresh@example.org"), users)
        self.assertFalse(ok)
        self.assertIn("waiting to be confirmed", msgs[0])
        self.assertEqual([u.pk for u in users], [51])
        # never deleted: signed in once, active, made some other way, or another holder
        keep = [
            FakeUser(60, "a@example.org", path=ai.SELF_REG_PATH, is_active=False,
                     last_login="2026-05-01", joined_hours_ago=900, store=users),
            FakeUser(61, "b@example.org", path=ai.SELF_REG_PATH, is_active=True, last_login=None,
                     joined_hours_ago=900, store=users),
            FakeUser(62, "c@example.org", path="users", is_active=False, last_login=None,
                     joined_hours_ago=900, store=users),
        ]
        users.extend(keep)
        for u in keep:
            ok, msgs = self.run_expr(E, self.req(anon, u.email), users)
            self.assertFalse(ok, u.pk)
            self.assertIn("already used by another account", msgs[0])
        self.assertEqual(sorted(u.pk for u in users), [51, 60, 61, 62])

    def test_pkce_policy(self):
        def ctx(**kw):
            return types.SimpleNamespace(context=kw)
        P = ai.PKCE_EXPR
        base = {"oauth_response_type": "code", "oauth_code_challenge": "abc",
                "oauth_code_challenge_method": "S256"}
        self.assertTrue(self.run_expr(P, ctx(**base))[0])
        self.assertFalse(self.run_expr(P, ctx(**{**base, "oauth_code_challenge": None}))[0])
        self.assertFalse(self.run_expr(P, ctx(**{**base, "oauth_code_challenge_method": "plain"}))[0])
        self.assertFalse(self.run_expr(P, ctx(**{**base, "oauth_response_type": "code id_token"}))[0])
        self.assertTrue(self.run_expr(P, ctx(oauth_code_verifier="v", oauth_grant_type="x"))[0])
        self.assertTrue(self.run_expr(P, ctx())[0])

    def test_redirect_regex(self):
        rx = re.compile(ai.YS_REDIRECT_REGEX)
        good = ["https://bink.yourspace.you/login/oidc/callback",
                "https://my-site-2.yourspace.you/login/oidc/callback"]
        bad = ["http://bink.yourspace.you/login/oidc/callback",
               "https://a.b.yourspace.you/login/oidc/callback",
               "https://bink.yourspace.you.evil.com/login/oidc/callback",
               "https://evil.com/x.yourspace.you/login/oidc/callback",
               "https://bink.yourspace.you/login/oidc/callback?x=1",
               "https://bink.yourspace.you/login/oidc/callback/",
               "https://BINK.yourspace.you/login/oidc/callback",
               "https://yourspace.you/login/oidc/callback"]
        for u in good:
            self.assertTrue(rx.fullmatch(u), u)
        for u in bad:
            self.assertFalse(rx.fullmatch(u), u)


class TokenTests(unittest.TestCase):
    def test_parse_env_value(self):
        self.assertEqual(ai.parse_env_value('A=1\nAUTHENTIK_API_TOKEN="abc"\n', "AUTHENTIK_API_TOKEN"), "abc")
        self.assertEqual(ai.parse_env_value("export AUTHENTIK_API_TOKEN='x y'", "AUTHENTIK_API_TOKEN"), "x y")
        self.assertEqual(ai.parse_env_value("AUTHENTIK_API_TOKEN_OLD=z", "AUTHENTIK_API_TOKEN"), "")

    def test_read_token_from_readable_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("X=1\nAUTHENTIK_API_TOKEN=tok123\n")
        try:
            self.assertEqual(ai.read_api_token(fh.name), "tok123")
        finally:
            os.unlink(fh.name)


# ============================================================================
# antibot (WOPR-059)
# ============================================================================
SITE = ai.CADDY_SITE_DEFAULT
# auth.wopr.systems as it is on 2026-10-05 (shortened): X-Forwarded-For is NOT pinned.
UNPINNED_SITE = """http://auth.wopr.systems:18080 {
    header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    @userinfo path /application/o/userinfo/*
    handle @userinfo {
        reverse_proxy 127.0.0.1:9091 {
            header_down -Access-Control-Allow-Origin
        }
        header Access-Control-Allow-Origin "{header.Origin}"
    }

    reverse_proxy 127.0.0.1:9091 {
        header_up -Accept-Encoding
        header_up X-Forwarded-Proto https
    }
}
"""
PINNED_SITE = (UNPINNED_SITE
               .replace("            header_down -Access-Control-Allow-Origin\n",
                        "            header_down -Access-Control-Allow-Origin\n"
                        "            header_up X-Forwarded-For {client_ip}\n")
               .replace("        header_up X-Forwarded-Proto https\n",
                        "        header_up X-Forwarded-Proto https\n"
                        "        header_up X-Forwarded-For {client_ip}\n"))
TS_SITE = "0x4AAAAAAA-site-key-for-tests"
TS_SECRET = "0x4AAAAAAA-SECRET-KEY-MUST-NOT-LEAK"
TS_KEYS = {"TURNSTILE_SITE_KEY": TS_SITE, "TURNSTILE_SECRET_KEY": TS_SECRET}
IP_LIMIT_MSG = ("Too many new accounts were made from your network in the last 24 hours. "
                "Please try again tomorrow.")
DISPOSABLE_MSG = "Please use a permanent email address; throwaway inboxes can't be used here."


class AntibotPlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.st = fixture()
        self.orig = copy.deepcopy(self.st)
        self.api = FakeApi(self.st)
        self.files = FakeFiles()
        self.infisical = FakeInfisical()

    def run_ab(self, *argv, infisical=None):
        return run([*argv, "--state-dir", self.tmp], self.api, self.files,
                   infisical or self.infisical)

    def plan(self, argv=(), infisical=None):
        o = ai.build_parser().parse_args(list(argv))
        o.files, o.infisical = self.files, infisical or self.infisical
        return ai.plan_antibot(ai.Snapshot(self.api, o), o)

    def logs(self):
        return sorted(os.path.join(self.tmp, f) for f in os.listdir(self.tmp)
                      if f.endswith(".json") and "rollback" not in f)

    def rollback(self, path):
        rc, out = run(["--rollback", path, "--state-dir", self.tmp], self.api, self.files)
        self.assertEqual(rc, 0, out)
        return out

    def names(self, stage_name):
        pol = {p["pk"]: p["name"] for p in self.st["expr_policies"]}
        st = next(s for s in self.st["prompt_stages"] if s["name"] == stage_name)
        return [pol.get(x, x) for x in st["validation_policies"]]

    def test_list_file_must_be_installed_first(self):
        # WOPR-189: the policy reads the list from authentik's custom-templates volume
        o = ai.build_parser().parse_args([])
        o.files, o.infisical = self.files, self.infisical
        o.disposable_files = FakeDisposable(installed=False)
        plan = ai.plan_antibot(ai.Snapshot(self.api, o), o)
        self.assertTrue(any("--install-disposable-list" in b for b in plan.blockers()), plan.blockers())
        o.disposable_files = FakeDisposable(installed=True)
        plan = ai.plan_antibot(ai.Snapshot(self.api, o), o)
        self.assertFalse(any("--install-disposable-list" in b for b in plan.blockers()), plan.blockers())

    def test_dry_run_today_six_changes_captcha_off(self):
        self.files.texts[SITE] = UNPINNED_SITE  # as on the Rig today
        rc, out = self.run_ab("--dry-run", "--phase", "antibot")
        self.assertEqual(rc, 0, out)
        self.assertTrue(all(m == "GET" for m, _ in self.api.calls))
        self.assertIn("Planned changes (6):", out)
        for needle in ("create expression policy 'wopr-signup-relay'",
                       "create expression policy 'wopr-signup-ip-limit'",
                       "create expression policy 'wopr-disposable-email'",
                       "add wopr-disposable-email, wopr-signup-ip-limit to prompt stage "
                       "'self-registration-prompt'",
                       "add wopr-disposable-email to prompt stage 'onboarding-profile-prompt'",
                       "add wopr-disposable-email to prompt stage 'default-user-settings'",
                       "captcha off: no Turnstile keys in Infisical",
                       "reputation gate held back",
                       "0 of 2 reverse_proxy block(s) pin X-Forwarded-For",
                       "header_up X-Forwarded-For {client_ip}", "9205 domains",
                       "not printed", "phase trust is not applied yet"):
            self.assertIn(needle, out)
        self.assertNotIn("APPLY WOULD BE REFUSED", out)
        self.assertNotIn("0-mail.com", out)  # the list itself is never printed
        self.assertNotIn("yopmail", out)

    def test_apply_after_trust_idempotent_reversible_guard_untouched(self):
        rc, out = self.run_ab("--apply", "trust")
        self.assertEqual(rc, 0, out)
        guard_before = next(p for p in self.st["expr_policies"]
                            if p["name"] == ai.POLICY_EMAIL_GUARD)["expression"]
        rc, out = self.run_ab("--apply", "antibot")
        self.assertEqual(rc, 0, out)
        self.assertIn("Verified: a fresh read-only plan", out)
        rc, out = self.run_ab("--apply", "antibot")
        self.assertEqual(rc, 0, out)
        self.assertIn("Nothing to do", out)
        self.assertEqual(self.names("self-registration-prompt"),
                         [ai.POLICY_EMAIL_GUARD, ai.POLICY_DISPOSABLE, ai.POLICY_SIGNUP_IP])
        self.assertEqual(self.names("onboarding-profile-prompt"),
                         [ai.POLICY_EMAIL_GUARD, ai.POLICY_DISPOSABLE])
        self.assertEqual(self.names("default-user-settings"),
                         ["default-user-settings-authorization", ai.POLICY_EMAIL_GUARD,
                          ai.POLICY_DISPOSABLE])
        self.assertEqual(self.names("stage-default-oobe-password"), [])
        self.assertEqual(guard_before, next(p for p in self.st["expr_policies"]
                                            if p["name"] == ai.POLICY_EMAIL_GUARD)["expression"])
        disp = next(p for p in self.st["expr_policies"] if p["name"] == ai.POLICY_DISPOSABLE)
        # WOPR-189: the policy reads the installed list file instead of holding the list
        self.assertIn(ai.DISPOSABLE_DEST, disp["expression"])
        self.assertLess(len(disp["expression"]), ai.MAX_EXPRESSION)
        self.assertEqual((self.st["reputation_policies"], self.st["captcha_stages"]), ([], []))
        # undo antibot alone: the guard stays where trust put it
        trust_log, antibot_log = self.logs()
        self.assertTrue(antibot_log.endswith("-antibot.json"))
        self.rollback(antibot_log)
        self.assertEqual(self.names("self-registration-prompt"), [ai.POLICY_EMAIL_GUARD])
        self.assertEqual({p["name"] for p in self.st["expr_policies"]},
                         {"default-user-settings-authorization", ai.POLICY_EMAIL_GUARD})
        self.rollback(trust_log)
        self.assertEqual(essence(self.st, self.files), essence(self.orig, FakeFiles()))

    def test_rollback_ignores_the_order_authentik_returns(self):
        rc, out = self.run_ab("--apply", "antibot")
        self.assertEqual(rc, 0, out)
        st = next(s for s in self.st["prompt_stages"] if s["name"] == "default-user-settings")
        st["validation_policies"].reverse()
        out = self.rollback(self.logs()[0])
        self.assertNotIn("SKIPPED", out)
        self.assertEqual(essence(self.st, self.files), essence(self.orig, FakeFiles()))

    def test_pinned_site_gates_every_password_login_flow(self):
        self.files.texts[SITE] = PINNED_SITE
        plan = self.plan()
        keys = [op.key for op in plan.ops]
        self.assertEqual(plan.blockers(), [])
        self.assertEqual(keys[:5], ["policy.wopr-signup-relay", "policy.wopr-signup-ip-limit",
                                    "policy.wopr-disposable-email", "policy.wopr-reputation",
                                    "policy.wopr-reputation-gate"])
        gated = sorted(k.split("binding.repgate.", 1)[1] for k in keys
                       if k.startswith("binding.repgate."))
        self.assertEqual(gated, ["brainjoos-authentication", "default-authentication-flow"])
        for slug in gated:
            self.assertLess(keys.index(f"flow.{slug}.mode"), keys.index(f"binding.repgate.{slug}"))
        ops = {op.key: op for op in plan.ops}
        self.assertEqual(ops["policy.wopr-reputation"].body,
                         {"name": "wopr-reputation", "execution_logging": False, "check_ip": True,
                          "check_username": False, "threshold": -5})
        bind = ops["binding.repgate.default-authentication-flow"].body
        self.assertEqual((bind["target"], bind["failure_result"], bind["negate"]),
                         (F_AUTH, True, False))
        self.assertIn("wopr-reputation-gate", ai.show(
            ops["stage.self-registration-prompt.antibot"].body))
        rc, out = self.run_ab("--apply", "antibot")
        self.assertEqual(rc, 0, out)
        self.assertIn("Verified: a fresh read-only plan", out)
        rc, out = self.run_ab("--apply", "antibot")
        self.assertIn("Nothing to do", out)
        modes = {f["slug"]: f["policy_engine_mode"] for f in self.st["flows"]
                 if f.get("policy_engine_mode")}
        self.assertEqual(modes, {"self-registration": "any", "default-authentication-flow": "all",
                                 "brainjoos-authentication": "all"})
        self.assertEqual(self.names("self-registration-prompt"),
                         [ai.POLICY_DISPOSABLE, ai.POLICY_SIGNUP_IP, ai.POLICY_REPUTATION_GATE])
        self.rollback(self.logs()[0])
        self.assertEqual(essence(self.st, self.files), essence(self.orig, FakeFiles()))

    def test_unpinned_site_never_binds_the_gate(self):
        for text in (None, UNPINNED_SITE):
            if text is not None:
                self.files.texts[SITE] = text
            plan = self.plan()
            keys = [op.key for op in plan.ops]
            self.assertFalse([k for k in keys if "reputation" in k or "repgate" in k], keys)
            self.assertTrue(any(lvl == "WARN" and "X-Forwarded-For" in m for lvl, m in plan.checks))

    def test_login_flow_with_other_flow_bindings_is_left_alone(self):
        self.files.texts[SITE] = PINNED_SITE
        self.st["policy_bindings"].append({"pk": str(uuid.uuid4()), "target": F_BRAIN,
                                           "group": G_ADMINS, "policy": None, "user": None,
                                           "order": 0})
        plan = self.plan()
        keys = [op.key for op in plan.ops]
        self.assertNotIn("binding.repgate.brainjoos-authentication", keys)
        self.assertNotIn("flow.brainjoos-authentication.mode", keys)
        self.assertIn("binding.repgate.default-authentication-flow", keys)
        self.assertTrue(any(lvl == "WARN" and "NOT bound" in m for lvl, m in plan.checks))

    def test_captcha_is_planned_only_when_the_keys_exist(self):
        ready = ["--lovejoos-relay-ready"]
        plan = self.plan(ready)
        self.assertFalse([op for op in plan.ops if "captcha" in op.key])
        self.assertTrue(any(m.startswith("captcha off: no Turnstile keys in Infisical")
                            for _, m in plan.checks))
        half = FakeInfisical({"TURNSTILE_SITE_KEY": TS_SITE})
        plan = self.plan(ready, half)
        self.assertFalse([op for op in plan.ops if "captcha" in op.key])
        self.assertTrue(any("TURNSTILE_SECRET_KEY not found" in m for _, m in plan.checks))
        plan = self.plan((), FakeInfisical(TS_KEYS))  # keys, but LoveJoos not ready
        self.assertFalse([op for op in plan.ops if "captcha" in op.key])
        self.assertTrue(any(lvl == "WARN" and m.startswith("captcha held back")
                            for lvl, m in plan.checks))
        inf = FakeInfisical(TS_KEYS)
        plan = self.plan(ready, inf)
        self.assertEqual(plan.blockers(), [])
        self.assertEqual([op.key for op in plan.ops][-3:],
                         ["stage.captcha", "fsb.captcha", "binding.captcha_relay_skip"])
        ops = {op.key: op for op in plan.ops}
        fsb = ops["fsb.captcha"].body
        self.assertEqual((fsb["target"], fsb["order"]), (F_SELFREG, 15))
        skip = ops["binding.captcha_relay_skip"].body
        self.assertEqual((skip["negate"], skip["failure_result"]), (True, True))
        self.assertEqual(skip["policy"], ai.Ref("policy.wopr-signup-relay", ""))
        self.assertEqual(inf.value_reads, [])  # planning a new stage reads no secret

    def test_infisical_unreadable_means_captcha_off_and_still_passes(self):
        rc, out = self.run_ab("--dry-run", "--phase", "antibot", "--lovejoos-relay-ready",
                              infisical=FakeInfisical(broken=True))
        self.assertEqual(rc, 0, out)
        self.assertIn("captcha off: Infisical could not be read", out)
        self.assertNotIn("APPLY WOULD BE REFUSED", out)

    def test_captcha_apply_keeps_the_secret_out_of_output_and_logs(self):
        inf = FakeInfisical(TS_KEYS)
        rc, out = self.run_ab("--apply", "trust", infisical=inf)
        self.assertEqual(rc, 0, out)
        rc, out = self.run_ab("--apply", "antibot", "--lovejoos-relay-ready", infisical=inf)
        self.assertEqual(rc, 0, out)
        self.assertIn("Verified: a fresh read-only plan", out)
        self.assertNotIn(TS_SECRET, out)
        self.assertIn("<TURNSTILE_SECRET_KEY from Infisical, not shown>", out)
        for path in self.logs():
            with open(path) as fh:
                self.assertNotIn(TS_SECRET, fh.read())
        cap = self.st["captcha_stages"][0]
        self.assertEqual((cap["public_key"], cap["private_key"]), (TS_SITE, TS_SECRET))
        self.assertEqual({k: cap[k] for k in ai.TURNSTILE_ATTRS}, ai.TURNSTILE_ATTRS)
        orders = {b["stage_obj"]["name"]: b["order"] for b in self.st["flow_bindings"]
                  if b["target"] == F_SELFREG}
        self.assertEqual(orders, {"self-registration-prompt": 10, "wopr-turnstile": 15,
                                  "self-registration-write": 20,
                                  "self-registration-email-verification": 25,
                                  "self-registration-login": 30})
        fsb = next(b for b in self.st["flow_bindings"] if b["stage"] == cap["pk"])
        relay = next(p for p in self.st["expr_policies"] if p["name"] == ai.POLICY_RELAY)
        skip = [b for b in self.st["policy_bindings"] if b["target"] == fsb["pk"]]
        self.assertEqual([(b["policy"], b["negate"], b["failure_result"]) for b in skip],
                         [(relay["pk"], True, True)])
        rc, out = self.run_ab("--apply", "antibot", "--lovejoos-relay-ready", infisical=inf)
        self.assertIn("Nothing to do", out)
        rotated = FakeInfisical({**TS_KEYS, "TURNSTILE_SITE_KEY": "rotated-site-key"})
        rc, out = self.run_ab("--apply", "antibot", "--lovejoos-relay-ready", infisical=rotated)
        self.assertEqual(rc, 2, out)
        self.assertIn("another site key", out)
        for path in reversed(self.logs()):
            self.rollback(path)
        self.assertEqual(essence(self.st, self.files), essence(self.orig, FakeFiles()))

    def test_tampered_list_blocks_the_phase(self):
        bad = os.path.join(self.tmp, "list.txt")
        with open(ai.DISPOSABLE_FILE, "rb") as fh:
            data = fh.read()
        with open(bad, "wb") as fh:
            fh.write(data + b"gmail.com\n")
        old, ai.DISPOSABLE_FILE = ai.DISPOSABLE_FILE, bad
        try:
            plan = self.plan()
        finally:
            ai.DISPOSABLE_FILE = old
        self.assertTrue(any("sha256" in b for b in plan.blockers()))
        self.assertNotIn("policy.wopr-disposable-email", [op.key for op in plan.ops])

    def test_vendored_list_is_byte_for_byte_and_pinned(self):
        text, domains, commit = ai.load_disposable()
        self.assertEqual((len(domains), commit), (9205, ai.DISPOSABLE_COMMIT))
        with open(ai.DISPOSABLE_FILE, "rb") as fh:
            raw = fh.read()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), ai.DISPOSABLE_SHA256)
        self.assertNotIn(b"\r", raw)
        for name in ("gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com",
                     "proton.me", "wopr.systems", "yourspace.you", "lovejoos.com",
                     "barterra.store"):
            self.assertNotIn(name, domains)

    def test_existing_throwaway_accounts_are_reported_not_changed(self):
        self.st["users"].append({"pk": 70, "username": "old", "name": "", "type": "internal",
                                 "email": "old@sub.mailinator.com", "path": "users",
                                 "is_active": True, "groups": [], "roles": [], "attributes": {},
                                 "uid": "u70"})
        plan = self.plan()
        self.assertTrue(any("1 existing account(s) already use a throwaway domain" in m
                            and "ol***@sub.mailinator.com" in m for _, m in plan.checks))
        self.assertFalse([op for op in plan.ops if op.path[0].startswith("/core/users/")])


class CaddyCheckTests(unittest.TestCase):
    def test_xff_pin_detection(self):
        self.assertEqual(ai.caddy_xff_pinned(PINNED_SITE),
                         (True, "2 of 2 reverse_proxy block(s) pin X-Forwarded-For to the real "
                                "client"))
        self.assertFalse(ai.caddy_xff_pinned(UNPINNED_SITE)[0])
        one = PINNED_SITE.replace("            header_up X-Forwarded-For {client_ip}\n", "", 1)
        self.assertEqual(ai.caddy_xff_pinned(one)[0], False)
        self.assertIn("1 of 2", ai.caddy_xff_pinned(one)[1])
        cf = PINNED_SITE.replace("{client_ip}", "{http.request.header.CF-Connecting-IP}")
        self.assertTrue(ai.caddy_xff_pinned(cf)[0])
        commented = PINNED_SITE.replace("header_up X-Forwarded-For", "# header_up X-Forwarded-For")
        self.assertFalse(ai.caddy_xff_pinned(commented)[0])
        spoofable = PINNED_SITE.replace("{client_ip}", "{http.request.header.X-Forwarded-For}")
        self.assertFalse(ai.caddy_xff_pinned(spoofable)[0])
        self.assertEqual(ai.caddy_xff_pinned(None), (False, "could not be read"))
        self.assertFalse(ai.caddy_xff_pinned("http://x:18080 {\n respond 404\n}\n")[0])


class AllowlistTests(unittest.TestCase):
    """Every call any phase plans (and every undo) is in SCHEMA_USES, the list --check-schema
    checks against the live authentik."""

    def setUp(self):
        self.uses = []
        for method, path, fields in ai.SCHEMA_USES:
            rx = "^" + "[^/]+".join(re.escape(x) for x in re.split(r"\{[^}]+\}", path)) + "$"
            self.uses.append((method.upper(), re.compile(rx), set(fields)))

    def check(self, method, path, body, what):
        if method in ("TOKEN_FILE", "REMOVE_FILE"):
            return
        hits = [u for u in self.uses if u[0] == method and u[1].match(path)]
        self.assertTrue(hits, f"{what}: {method} {path} is not in SCHEMA_USES")
        if isinstance(body, dict) and method in ("POST", "PATCH"):
            self.assertTrue(any(set(body) <= u[2] for u in hits),
                            f"{what}: {method} {path} sends {sorted(body)}")

    def check_all(self, st):
        files = FakeFiles()
        files.texts[SITE] = PINNED_SITE
        o = ai.build_parser().parse_args(["--lovejoos-relay-ready", "--lovejoos-release-deployed",
                                          "--no-lovejoos-export"])
        o.files, o.infisical = files, FakeInfisical(TS_KEYS)
        seen = 0
        for phase in ai.PHASES:
            plan = ai.PLANNERS[phase](ai.Snapshot(FakeApi(st), o), o)
            for op in plan.ops:
                seen += 1
                self.check(op.method, ai.show_path(op.path), op.body, op.key)
                if op.inverse:
                    self.check(op.inverse["method"], ai.show_path(op.inverse["path"]),
                               op.inverse.get("body"), op.key + " (undo)")
        return seen

    def test_fresh_fixture(self):
        self.assertGreater(self.check_all(fixture()), 40)

    def test_drifted_antibot_objects(self):
        st = fixture()
        st["expr_policies"].append({"pk": str(uuid.uuid4()), "name": ai.POLICY_RELAY,
                                    "expression": "return False"})
        st["reputation_policies"].append({"pk": str(uuid.uuid4()), "name": ai.POLICY_REPUTATION,
                                          "check_ip": False, "check_username": True,
                                          "threshold": -5})
        st["captcha_stages"].append({"pk": str(uuid.uuid4()), "name": ai.CAPTCHA_STAGE,
                                     "public_key": TS_SITE, "js_url": "https://x.example/api.js",
                                     "api_url": ai.TURNSTILE_ATTRS["api_url"],
                                     "interactive": False, "error_on_invalid_score": True})
        self.assertGreater(self.check_all(st), 40)


class AntibotExpressionTests(unittest.TestCase):
    run_expr = ExpressionTests.run_expr

    # -- wopr-disposable-email
    def test_disposable_email(self):
        text, domains, commit = ai.load_disposable()
        tmp = tempfile.mkdtemp()
        listed, extra = os.path.join(tmp, "disposable_domains.txt"), os.path.join(tmp, "extra.txt")
        with open(listed, "w", encoding="ascii") as fh:
            fh.write(text)
        with open(extra, "w", encoding="ascii") as fh:
            fh.write("# bot domains seen\nformtests.info\n")
        E, shown = ai.disposable_expression(text, len(domains), commit, path=listed, extra=extra)
        anon = types.SimpleNamespace(is_authenticated=False, pk=None)

        def check(email, user=anon):
            return self.run_expr(E, types.SimpleNamespace(user=user,
                                                          context={"prompt_data": {"email": email}}))

        refused = ("bot@mailinator.com", " Bot@MAILINATOR.com ", "x@yopmail.com", "x@0-mail.com",
                   "x@mailinator.com.", f"x@{domains[-1]}",
                   # parent domains: any subdomain of a listed domain
                   "x@inbox.mailinator.com", "x@a.b.yopmail.com", "x@deep.0-mailer.dynv6.net")
        for email in refused:
            ok, msgs = check(email)
            self.assertFalse(ok, email)
            self.assertEqual(msgs, [DISPOSABLE_MSG], email)
        allowed = ("scott@gmail.com", "a@googlemail.com", "a@outlook.com", "a@hotmail.com",
                   "a@yahoo.com", "a@icloud.com", "a@proton.me", "a@protonmail.com",
                   "a@fastmail.com", "a@wopr.systems", "a@yourspace.you", "a@lovejoos.com",
                   "a@example.org",
                   # a listed name that is not the domain or a parent of it
                   "a@woprmailinator.com", "a@notyopmail.com", "a@yopmail.com.example.org",
                   # the parent of a listed subdomain is not itself listed
                   "a@dynv6.net")
        for email in allowed:
            ok, msgs = check(email)
            self.assertTrue(ok, email)
            self.assertEqual(msgs, [], email)
        for data in ({}, {"email": ""}, {"email": "no-at-sign"}, {"username": "x"}):
            req = types.SimpleNamespace(user=anon, context={"prompt_data": data})
            self.assertTrue(self.run_expr(E, req)[0], data)
        self.assertTrue(self.run_expr(E, types.SimpleNamespace(user=anon, context={}))[0])
        # a signed-in user keeps the address they have, but cannot move to a throwaway one
        old = FakeUser(60, "Old@Mailinator.com")
        self.assertTrue(check("old@mailinator.com", old)[0])
        self.assertFalse(check("new@yopmail.com", old)[0])
        self.assertFalse(check("new@yopmail.com", FakeUser(61, "me@gmail.com"))[0])
        # authentik's anonymous user is a User row (authenticated, no email): still checked
        self.assertFalse(check("x@mailinator.com", FakeUser(1, ""))[0])
        # WOPR-189: the extra bot-domain file counts too
        self.assertFalse(check("pjrvvvlskr@formtests.info")[0])
        self.assertFalse(check("x@mail.formtests.info")[0])
        # WOPR-189: the policy reads the list from the file; it never holds it (a policy that big
        # hung every sign-up in authentik's result pipe), and it stays far below the pipe buffer
        self.assertNotIn("mailinator", E)
        self.assertIn(listed, E)
        self.assertLess(len(E), ai.MAX_EXPRESSION)
        self.assertIn(ai.DISPOSABLE_COMMIT, E)
        self.assertIn(ai.DISPOSABLE_SHA256, E)
        self.assertIn(DISPOSABLE_MSG, E)
        self.assertIn("9205 domains", shown)
        # a missing list file lets the address through (and logs), so nobody is locked out
        gone, _ = ai.disposable_expression(text, len(domains), commit, path=os.path.join(tmp, "nope"),
                                           extra=os.path.join(tmp, "nope2"))
        ok, msgs = self.run_expr(gone, types.SimpleNamespace(
            user=anon, context={"prompt_data": {"email": "bot@mailinator.com"}}))
        self.assertTrue(ok)
        self.assertEqual(msgs, [])
        # the extra file is optional
        no_extra, _ = ai.disposable_expression(text, len(domains), commit, path=listed,
                                               extra=os.path.join(tmp, "nope2"))
        self.assertFalse(self.run_expr(no_extra, types.SimpleNamespace(
            user=anon, context={"prompt_data": {"email": "bot@mailinator.com"}}))[0])
        self.assertTrue(self.run_expr(no_extra, types.SimpleNamespace(
            user=anon, context={"prompt_data": {"email": "x@formtests.info"}}))[0])

    # -- wopr-signup-ip-limit
    def ip_limit(self, client, rows, relay=False):
        calls = []

        def ak_call_policy(name):
            calls.append(name)
            return types.SimpleNamespace(passing=relay and name == ai.POLICY_RELAY)

        tz = types.ModuleType("django.utils.timezone")
        tz.now = lambda: datetime.now(timezone.utc)
        mods = {"django": types.ModuleType("django"), "django.utils": types.ModuleType("django.utils"),
                "django.utils.timezone": tz,
                "authentik.events": types.ModuleType("authentik.events"),
                "authentik.events.models": events_module(rows)}
        req = types.SimpleNamespace(context={"prompt_data": {"email": "x@example.org"}},
                                    http_request=None)
        ok, msgs = self.run_expr(ai.SIGNUP_IP_EXPR, req, modules=mods,
                                 ak_client_ip=ipaddress.ip_address(client),
                                 ak_call_policy=ak_call_policy)
        return ok, msgs, calls

    def test_signup_ip_limit(self):
        now = datetime.now(timezone.utc)

        def ev(ip, hours=1.0, created=True, action="user_write"):
            return {"action": action, "client_ip": ip, "created": now - timedelta(hours=hours),
                    "context": {"created": created}}

        A, B = "8.8.8.8", "1.1.1.1"
        # the boundary: 2 sign-ups in 24h -> the 3rd goes through; 3 -> the 4th is refused
        ok, msgs, calls = self.ip_limit(A, [ev(A), ev(A, 23.9)])
        self.assertTrue(ok, msgs)
        self.assertEqual(calls, [ai.POLICY_RELAY])
        ok, msgs, _ = self.ip_limit(A, [ev(A), ev(A, 5), ev(A, 23.9)])
        self.assertFalse(ok)
        self.assertEqual(msgs, [IP_LIMIT_MSG])
        # what does not count: older than 24h, not a new account, another IP or action, no IP
        noise = [ev(A, 24.1), ev(A, 48), ev(A, created=False), ev(B), ev(B), ev(B),
                 ev(A, action="login"), ev(None), ev("not-an-ip")]
        self.assertTrue(self.ip_limit(A, [ev(A), ev(A)] + noise)[0])
        self.assertFalse(self.ip_limit(B, [ev(A), ev(A)] + noise)[0])
        # IPv6 counts per /64
        V = "2606:4700:4700::1111"
        same64 = ["2606:4700:4700::1001", "2606:4700:4700::64", "2606:4700:4700:0:1::5"]
        self.assertFalse(self.ip_limit(V, [ev(x) for x in same64])[0])
        other64 = ["2606:4700:4700:1::1", "2606:4700:4700:2::1", "2606:4700:4701::1"]
        self.assertTrue(self.ip_limit(V, [ev(x) for x in other64])[0])
        # an IPv4-mapped client is that IPv4 client
        self.assertFalse(self.ip_limit("::ffff:8.8.8.8", [ev(A)] * 3)[0])
        # exemption 1: LoveJoos's relay proof
        ok, msgs, calls = self.ip_limit(A, [ev(A)] * 5, relay=True)
        self.assertTrue(ok, msgs)
        self.assertEqual(calls, [ai.POLICY_RELAY])
        # exemption 2: callers inside the Rig (not a public address), relay not even asked
        for inside in ("172.19.0.7", "10.0.0.3", "127.0.0.1", "192.168.0.250",
                       "255.255.255.255", "::1", "fd00::5"):
            ok, msgs, calls = self.ip_limit(inside, [ev(inside)] * 5)
            self.assertTrue(ok, inside)
            self.assertEqual(calls, [], inside)
        E = ai.SIGNUP_IP_EXPR
        self.assertIn(f"LIMIT = {ai.SIGNUP_IP_LIMIT}\n", E)
        self.assertIn(f"WINDOW = timedelta(hours={ai.SIGNUP_IP_WINDOW_HOURS})\n", E)
        self.assertIn(f'ak_call_policy("{ai.POLICY_RELAY}")', E)

    # -- wopr-signup-relay
    KEY = "k" * 32 + "Z" * 32

    def relay(self, headers, token, http=True):
        lookups = []

        class QS:
            def select_related(self, *_):
                return self

            def first(self):
                return token

        class Token:
            @staticmethod
            def filter_not_expired(**kw):
                lookups.append(kw)
                return QS()

        core = types.ModuleType("authentik.core.models")
        core.Token, core.TokenIntents = Token, types.SimpleNamespace(INTENT_API="api")
        req = types.SimpleNamespace(
            context={}, http_request=types.SimpleNamespace(headers=headers) if http else None)
        ok, _ = self.run_expr(ai.RELAY_EXPR, req, modules={"authentik.core.models": core})
        return ok, lookups

    def test_relay_proof(self):
        sa = types.SimpleNamespace(username=ai.LJ_SA_USERNAME, is_active=True)
        good = types.SimpleNamespace(key=self.KEY, user=sa)
        ok, lookups = self.relay({ai.RELAY_HEADER: self.KEY}, good)
        self.assertTrue(ok)
        self.assertEqual(lookups, [{"identifier": ai.LJ_TOKEN_ID, "intent": "api"}])
        self.assertTrue(self.relay({ai.RELAY_HEADER: f" {self.KEY} "}, good)[0])
        for headers in ({}, {ai.RELAY_HEADER: ""}, {ai.RELAY_HEADER: self.KEY[:-1] + "X"},
                        {ai.RELAY_HEADER: self.KEY + "X"}, {"X-Other": self.KEY},
                        {"Authorization": "Bearer " + self.KEY}):
            self.assertFalse(self.relay(headers, good)[0], headers)
        self.assertEqual(self.relay({}, good)[1], [])  # no header: no token lookup at all
        other = types.SimpleNamespace(key=self.KEY, user=types.SimpleNamespace(
            username="akadmin", is_active=True))
        off = types.SimpleNamespace(key=self.KEY, user=types.SimpleNamespace(
            username=ai.LJ_SA_USERNAME, is_active=False))
        for token in (None, other, off):
            self.assertFalse(self.relay({ai.RELAY_HEADER: self.KEY}, token)[0])
        self.assertFalse(self.relay(None, good, http=False)[0])
        for needle in (f'"{ai.RELAY_HEADER}"', f'identifier="{ai.LJ_TOKEN_ID}"',
                       f'"{ai.LJ_SA_USERNAME}"'):
            self.assertIn(needle, ai.RELAY_EXPR)

    # -- wopr-reputation-gate
    def gate(self, client, bad):
        calls = []

        def ak_call_policy(name):
            calls.append(name)
            return types.SimpleNamespace(passing=bad)

        ok, msgs = self.run_expr(ai.REPUTATION_GATE_EXPR, types.SimpleNamespace(context={}),
                                 ak_client_ip=ipaddress.ip_address(client),
                                 ak_call_policy=ak_call_policy)
        return ok, msgs, calls

    def test_reputation_gate(self):
        ok, msgs, calls = self.gate("8.8.8.8", bad=True)
        self.assertFalse(ok)
        self.assertEqual(calls, [ai.POLICY_REPUTATION])
        self.assertIn("Reset your password", msgs[0])
        self.assertTrue(self.gate("8.8.8.8", bad=False)[0])
        self.assertTrue(self.gate("2606:4700:4700::1111", bad=False)[0])
        for inside in ("172.19.0.7", "10.0.0.3", "127.0.0.1", "255.255.255.255"):
            ok, msgs, calls = self.gate(inside, bad=True)
            self.assertTrue(ok, inside)
            self.assertEqual(calls, [], inside)

    def test_install_disposable_list(self):
        fake = FakeDisposable(installed=False)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ai.install_disposable_list(fake)
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertEqual(fake.installed_sha256(ai.DISPOSABLE_DEST), ai.DISPOSABLE_SHA256)
        self.assertIn("matches the pinned list", buf.getvalue())
        if os.path.exists(ai.EXTRA_BLOCKED_FILE):
            self.assertIn("formtests.info", fake.files[ai.EXTRA_BLOCKED_DEST])

    def test_expressions_compile_the_way_authentik_runs_them(self):
        text, domains, commit = ai.load_disposable()
        big, _ = ai.disposable_expression(text, len(domains), commit)
        ctx = "ak_message,ak_user_has_authenticator,ak_is_sso_flow,ak_client_ip,http_request," \
              "request,context"
        for name, expr in ((ai.POLICY_DISPOSABLE, big), (ai.POLICY_RELAY, ai.RELAY_EXPR),
                           (ai.POLICY_SIGNUP_IP, ai.SIGNUP_IP_EXPR),
                           (ai.POLICY_REPUTATION_GATE, ai.REPUTATION_GATE_EXPR)):
            # WOPR-189: authentik pipes every policy result back with the policy in it; a policy
            # over the 64 KB pipe buffer hangs the flow forever. Keep all of them small.
            self.assertLess(len(expr), ai.MAX_EXPRESSION, name)
            wrapped = (f"def handler({ctx}):\n" + textwrap.indent(expr, "    ")
                       + f"\nresult = handler({ctx})")
            t0 = time.perf_counter()
            compile(wrapped, name, "exec")
            self.assertLess(time.perf_counter() - t0, 0.5, name)


def events_module(rows):
    """authentik.events.models for wopr-signup-ip-limit: `rows` are user_write-like events."""
    mod = types.ModuleType("authentik.events.models")

    class QS:
        def __init__(self, items):
            self.items = items

        def exclude(self, client_ip):
            assert client_ip is None
            return QS([r for r in self.items if r["client_ip"] is not None])

        def values_list(self, field, flat=False):
            assert flat
            return [r[field] for r in self.items]

    class Manager:
        @staticmethod
        def filter(action, context__created, created__gte):
            return QS([r for r in rows if r["action"] == action
                       and (r.get("context") or {}).get("created") == context__created
                       and r["created"] >= created__gte])

    mod.Event = type("Event", (), {"objects": Manager})
    mod.EventAction = types.SimpleNamespace(USER_WRITE="user_write")
    return mod


if __name__ == "__main__":
    unittest.main()
