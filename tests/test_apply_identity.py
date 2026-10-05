"""Offline tests for apply_identity.py: a fake authentik API seeded with the live object ids
(read-only probe of 2026-10-05) and fake emails. Run: python3 -m unittest -v"""
import contextlib
import copy
import io
import json
import os
import re
import sys
import tempfile
import textwrap
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
        "flows": [{"pk": F_SELFREG, "slug": "self-registration"},
                  {"pk": F_AUTH, "slug": "default-authentication-flow"},
                  {"pk": F_SETTINGS, "slug": "default-user-settings-flow"},
                  {"pk": F_ONBOARD, "slug": "user-onboarding"},
                  {"pk": F_BRAIN, "slug": "brainjoos-authentication"},
                  {"pk": F_OOBE, "slug": "initial-setup"},
                  {"pk": F_RECOVERY, "slug": "password-recovery"},
                  {"pk": F_IMPLICIT, "slug": "default-provider-authorization-implicit-consent"},
                  {"pk": F_PROV_INV, "slug": "default-provider-invalidation-flow"}],
        "flow_bindings": [
            fb(F_SELFREG, S_SELFREG_PROMPT, "self-registration-prompt", 10),
            fb(F_SELFREG, S_SELFREG_WRITE, "self-registration-write", 20, "ak-stage-user-write-form"),
            fb(F_SELFREG, S_SELFREG_LOGIN, "self-registration-login", 30, "ak-stage-user-login-form"),
            fb(F_AUTH, S_IDENT, "default-authentication-identification", 10),
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
                            {"name": "email/account_confirmation.html"}],
        "user_write_stages": [{"pk": S_SELFREG_WRITE, "name": "self-registration-write",
                               "create_users_as_inactive": False, "create_users_group": None,
                               "user_path_template": ""}],
        "ident_stages": [{"pk": S_IDENT, "name": "default-authentication-identification",
                          "enrollment_flow": F_SELFREG, "user_fields": ["email", "username"],
                          "sources": []}],
        "expr_policies": [{"pk": P_SETTINGS_AUTHZ, "name": "default-user-settings-authorization",
                           "expression": "return True"}],
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
    }
    IGNORED = {"page", "page_size", "include_users", "include_groups", "ordering"}

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
            items = copy.deepcopy(items)
            return {"results": items, "pagination": {"next": 0}} if paginated else items
        it = self._item(prefix, parts[0])
        if it is None:
            raise ai.ApiError("GET", path, 404, "not found")
        if len(parts) == 1:
            return copy.deepcopy(it)
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
                                                      "user_write_stages") for s in st[k]}
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

    def exists(self, path):
        return bool(self.files.get(path))

    def write_secret(self, path, content):
        self.files[path] = content

    def remove(self, path):
        self.files.pop(path, None)


def run(argv, api, files=None):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = ai.main(argv, api=api, files=files or FakeFiles())
    return rc, buf.getvalue()


def essence(st, files):
    """Comparable view of the fake state (ids of recreated objects ignored)."""
    pol = {p["pk"]: p["name"] for p in st["expr_policies"]}
    grp = {g["pk"]: g["name"] for g in st["groups"]}
    return json.dumps({
        "settings": st["settings"],
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
        "bindings": sorted((b["target"], pol.get(b.get("policy")), grp.get(b.get("group")))
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
                       "bind group 'lovejoos-users' to app 'lovejoos'"):
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
        self.emails = os.path.join(self.tmp, "lj.txt")
        with open(self.emails, "w") as fh:
            fh.write("# LoveJoos users with a central login\nljfan@example.org\n"
                     "nobody@example.org\nsbinkerd1@gmail.com\n")

    def apply(self, phase, *extra):
        return run(["--apply", phase, "--state-dir", self.tmp, *extra], self.api, self.files)

    def logs(self):
        return sorted(os.path.join(self.tmp, f) for f in os.listdir(self.tmp)
                      if f.endswith(".json") and "rollback" not in f)

    def test_full_cycle_idempotent_and_reversible(self):
        gate = ("--lovejoos-release-deployed", "--lovejoos-emails", self.emails)
        for phase, extra in (("trust", ()), ("groups", ()), ("yourspace-app", ()), ("bink", ()),
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
        self.assertIn(23, names["wopr-verified"]["users"])
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
    def run_expr(self, expr, request, users=()):
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
        old = {k: sys.modules.get(k) for k in mods}
        sys.modules.update(mods)
        try:
            src = "def _f(request, ak_message, ak_logger):\n" + textwrap.indent(expr, "    ")
            g = {}
            exec(compile(src, "expr", "exec"), g)
            log = types.SimpleNamespace(
                info=lambda *a, **k: self.__dict__.setdefault("logged", []).append((a, k)))
            return g["_f"](request, msgs.append, log), msgs
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


if __name__ == "__main__":
    unittest.main()
