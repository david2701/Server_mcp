"""Accesos de IA al MCP remoto (/mcp).

Dos formas de conectarse, y ambas acaban en un "permiso" con alcance:
  {"name": "...", "servers": ["web", ...] | ["*"], "secrets": ["openai", ...] | ["*"]}

- Token `mt_…` creado en el panel: para Claude Code, Cursor, Codex, agentes propios…
  (cabecera Authorization: Bearer mt_…).
- OAuth 2.1 con registro dinámico: para Claude.ai, ChatGPT y cualquier cliente que lo
  pida. El cliente te manda al panel, inicias sesión como administrador, eliges qué
  servidores y APIs le das, y apruebas. Los tokens caducan en 1 h y se renuevan.

La bóveda solo guarda hashes. Los códigos de autorización viven 5 min en memoria.
"""

from __future__ import annotations

import secrets
import time
from typing import Any

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthClientInformationFull,
    OAuthToken,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)

from .bundle import Bundle, hash_token
from .config import NAME_RE

ACCESS_TTL = 3600
REFRESH_TTL = 30 * 24 * 3600
CODE_TTL = 300
SCOPE = "vault"


def _store(bundle: Bundle) -> dict:
    store = bundle.admin.setdefault("access", {})
    for k in ("tokens", "clients", "oauth_access", "oauth_refresh"):
        store.setdefault(k, {})
    return store


def _clean_scope(bundle: Bundle, servers: list[str], apis: list[str]) -> tuple[list[str], list[str]]:
    srv = ["*"] if "*" in servers else sorted(set(servers) & bundle.servers.keys())
    api = ["*"] if "*" in apis else sorted(set(apis) & {n for n, s in bundle.secrets.items() if s.get("base_url")})
    return srv, api


def allows(grant: dict[str, Any], kind: str, name: str) -> bool:
    items = grant.get("servers" if kind == "server" else "secrets", [])
    return "*" in items or name in items


# ─── Tokens mt_ (creados en el panel) ───────────────────────────────────────────

def create_token(bundle: Bundle, name: str, servers: list[str], apis: list[str]) -> str:
    if not NAME_RE.match(name):
        raise ValueError(f"nombre inválido: {name!r}")
    store = _store(bundle)
    if any(t["name"] == name for t in store["tokens"].values()):
        raise ValueError(f"ya existe un acceso {name!r}")
    srv, api = _clean_scope(bundle, servers, apis)
    if not srv and not api:
        raise ValueError("elige al menos un servidor o una API")
    token = "mt_" + secrets.token_urlsafe(32)
    store["tokens"][hash_token(token)] = {"name": name, "servers": srv, "secrets": api,
                                          "created": int(time.time()), "kind": "token"}
    return token


def list_access(bundle: Bundle) -> list[dict]:
    store = _store(bundle)
    out = [dict(t) for t in store["tokens"].values()]
    seen = set()
    for r in store["oauth_refresh"].values():
        if r["expires"] > time.time() and r["name"] not in seen:
            seen.add(r["name"])
            out.append({"name": r["name"], "servers": r["servers"], "secrets": r["secrets"],
                        "created": r.get("created", 0), "kind": "oauth", "client_id": r["client_id"]})
    return sorted(out, key=lambda t: t["name"])


def revoke(bundle: Bundle, name: str) -> bool:
    store = _store(bundle)
    before = sum(len(store[k]) for k in ("tokens", "oauth_access", "oauth_refresh"))
    for k in ("tokens", "oauth_access", "oauth_refresh"):
        store[k] = {h: t for h, t in store[k].items() if t["name"] != name}
    return sum(len(store[k]) for k in ("tokens", "oauth_access", "oauth_refresh")) < before


def lookup(bundle: Bundle, token: str | None) -> dict | None:
    if not token:
        return None
    store = _store(bundle)
    h = hash_token(token)
    if token.startswith("mt_"):
        return store["tokens"].get(h)
    if token.startswith("mo_"):
        g = store["oauth_access"].get(h)
        if g and g["expires"] > time.time():
            return g
    return None


# ─── OAuth ──────────────────────────────────────────────────────────────────────

class Provider:
    """OAuthAuthorizationServerProvider del SDK de MCP, con consentimiento en el panel."""

    def __init__(self, gw):
        self.gw = gw                      # Gateway: bundle, save(), public_url
        self.pending: dict[str, dict] = {}  # id → petición de /authorize esperando consentimiento
        self.codes: dict[str, dict] = {}

    @property
    def store(self) -> dict:
        return _store(self.gw.bundle)

    # Registro dinámico de clientes (RFC 7591)
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        raw = self.store["clients"].get(client_id)
        return OAuthClientInformationFull.model_validate(raw) if raw else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if len(self.store["clients"]) >= 200:
            raise ValueError("demasiados clientes registrados")
        self.store["clients"][client_info.client_id] = client_info.model_dump(mode="json")
        self.gw.save()

    # Autorización: lleva al usuario a la pantalla de consentimiento del panel
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource and str(params.resource).rstrip("/") != f"{self.gw.public_url}/mcp":
            raise AuthorizeError("invalid_request", "este servidor solo emite tokens para su propio MCP")
        now = time.time()
        self.pending = {k: v for k, v in self.pending.items() if v["expires"] > now}
        rid = secrets.token_urlsafe(24)
        self.pending[rid] = {"client_id": client.client_id, "client_name": client.client_name or client.client_id,
                             "params": params, "expires": now + 600}
        return f"{self.gw.public_url}/_vault/oauth/consent?req={rid}"

    def approve(self, rid: str, name: str, servers: list[str], apis: list[str]) -> str:
        req = self.pending.pop(rid, None)
        if not req:
            raise ValueError("la petición caducó; vuelve a conectar desde tu IA")
        if not NAME_RE.match(name):
            raise ValueError(f"nombre inválido: {name!r}")
        srv, api = _clean_scope(self.gw.bundle, servers, apis)
        p: AuthorizationParams = req["params"]
        code = secrets.token_urlsafe(32)
        self.codes[code] = {
            "code": AuthorizationCode(code=code, scopes=[SCOPE], expires_at=time.time() + CODE_TTL,
                                      client_id=req["client_id"], code_challenge=p.code_challenge,
                                      redirect_uri=p.redirect_uri,
                                      redirect_uri_provided_explicitly=p.redirect_uri_provided_explicitly,
                                      resource=p.resource),
            "grant": {"name": name, "servers": srv, "secrets": api},
        }
        return construct_redirect_uri(str(p.redirect_uri), code=code, state=p.state)

    def deny(self, rid: str) -> str:
        req = self.pending.pop(rid, None)
        if not req:
            raise ValueError("la petición caducó")
        p: AuthorizationParams = req["params"]
        return construct_redirect_uri(str(p.redirect_uri), error="access_denied", state=p.state)

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str):
        entry = self.codes.get(authorization_code)
        if not entry or entry["code"].client_id != client.client_id or entry["code"].expires_at < time.time():
            return None
        return entry["code"]

    def _issue(self, client_id: str, grant: dict, resource) -> OAuthToken:
        access, refresh = "mo_" + secrets.token_urlsafe(32), "mr_" + secrets.token_urlsafe(32)
        now = time.time()
        base = {**grant, "client_id": client_id, "resource": str(resource) if resource else None}
        self.store["oauth_access"][hash_token(access)] = {**base, "expires": now + ACCESS_TTL}
        self.store["oauth_refresh"][hash_token(refresh)] = {**base, "expires": now + REFRESH_TTL,
                                                            "created": grant.get("created", int(now))}
        self.store["oauth_access"] = {h: t for h, t in self.store["oauth_access"].items() if t["expires"] > now}
        self.store["oauth_refresh"] = {h: t for h, t in self.store["oauth_refresh"].items() if t["expires"] > now}
        self.gw.save()
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=ACCESS_TTL,
                          refresh_token=refresh, scope=SCOPE)

    async def exchange_authorization_code(self, client, authorization_code: AuthorizationCode) -> OAuthToken:
        entry = self.codes.pop(authorization_code.code, None)  # un solo uso
        if not entry:
            raise TokenError("invalid_grant", "código ya usado o inexistente")
        return self._issue(client.client_id, entry["grant"], authorization_code.resource)

    async def load_refresh_token(self, client, refresh_token: str) -> RefreshToken | None:
        r = self.store["oauth_refresh"].get(hash_token(refresh_token))
        if not r or r["client_id"] != client.client_id or r["expires"] < time.time():
            return None
        return RefreshToken(token=refresh_token, client_id=client.client_id, scopes=[SCOPE],
                            expires_at=int(r["expires"]))

    async def exchange_refresh_token(self, client, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        r = self.store["oauth_refresh"].pop(hash_token(refresh_token.token), None)  # rotación
        if not r:
            raise TokenError("invalid_grant", "refresh token inválido")
        grant = {k: r[k] for k in ("name", "servers", "secrets")} | {"created": r.get("created")}
        return self._issue(client.client_id, grant, r.get("resource"))

    async def load_access_token(self, token: str) -> AccessToken | None:
        g = lookup(self.gw.bundle, token)
        if not g:
            return None
        # Todos nuestros tokens solo valen para este MCP: declaramos su URL como recurso.
        return AccessToken(token=token, client_id=g.get("client_id", g["name"]), scopes=[SCOPE],
                           expires_at=int(g["expires"]) if g.get("expires") else None,
                           resource=f"{self.gw.public_url}/mcp")

    async def revoke_token(self, token) -> None:
        h = hash_token(token.token)
        for k in ("oauth_access", "oauth_refresh"):
            self.store[k].pop(h, None)
        self.gw.save()


__all__ = ["Provider", "create_token", "list_access", "revoke", "lookup", "allows", "AuthorizeError"]
