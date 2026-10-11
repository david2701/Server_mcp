"""Pasarela con panel web y API de administración."""

import http.cookiejar
import json
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta
from http.server import HTTPServer

import pytest
import uvicorn

from ssh_vault import bundle as B
from ssh_vault import keys as K
from ssh_vault.llmproxy import build_app
from test_portable import KEY, Upstream, Device

PASSWORD = "contraseña-del-panel-123"


class Browser:
    def __init__(self, base):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),
                                                  NoRedirect())

    def req(self, method, path, data=None, headers=None):
        body = urllib.parse.urlencode(data, doseq=True).encode() if isinstance(data, dict) else data
        r = urllib.request.Request(self.base + path, data=body, method=method, headers=headers or {})
        try:
            with self.opener.open(r, timeout=20) as resp:
                return resp.status, resp.read().decode(), {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), {k.lower(): v for k, v in e.headers.items()}

    def login(self, pw=PASSWORD):
        status, _, _ = self.req("POST", "/_vault/login", {"password": pw})
        return status

    def csrf(self):
        _, html, _ = self.req("GET", "/_vault/")
        return re.search(r"name=csrf value='([^']+)'", html).group(1)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


@pytest.fixture
def gateway():
    up = HTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    b = B.Bundle(secrets={
        "openai": {"value": KEY, "base_url": f"http://127.0.0.1:{up.server_port}/v1/",
                   "description": "<script>alert(1)</script>"},
        "db": {"value": "postgres://x"},  # sin base_url: no aparece en la pasarela
    })
    K.set_admin_password(b, PASSWORD)
    admin_token = K.create_admin_token(b, "deploy")
    saves = []
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(build_app(b, None, save=lambda x: saves.append(x.revision), panel=True),
                                           host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", b, admin_token, saves
    server.should_exit = True
    up.shutdown()


def call_api(base, key):
    r = urllib.request.Request(f"{base}/openai/chat/completions", data=b"{}", method="POST",
                               headers={"Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, None


def test_login_and_security_headers(gateway):
    base, *_ = gateway
    br = Browser(base)
    status, html, headers = br.req("GET", "/_vault/")
    assert status == 200 and "Contraseña de administrador" in html
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert headers["referrer-policy"] == "same-origin"  # con no-referrer el navegador manda Origin: null
    assert br.login("mala") == 401
    assert br.login() == 303
    cookie = next(c for c in br.jar)
    assert cookie.has_nonstandard_attr("HttpOnly") and cookie.path == "/_vault"
    _, html, _ = br.req("GET", "/_vault/")
    assert "Nueva API key" in html
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html  # escapado
    assert "postgres" not in html and ">db<" not in html


def test_login_rate_limit(gateway):
    base, *_ = gateway
    br = Browser(base)
    for _ in range(5):
        assert br.login("mala") == 401
    assert br.login() == 429  # bloqueado aunque ahora acierte


def test_create_use_and_revoke_key_from_panel(gateway):
    base, b, _, saves = gateway
    br = Browser(base)
    br.login()
    csrf = br.csrf()
    status, html, _ = br.req("POST", "/_vault/keys", {"csrf": csrf, "name": "mi-servicio", "apis": ["openai"]})
    key = re.search(r"(vt_[A-Za-z0-9_-]{20,})", html).group(1)
    assert status == 200 and f"OPENAI_BASE_URL={base}/openai" in html
    assert saves, "la bóveda debe guardarse al crear una key"
    assert key not in json.dumps(b.tokens)  # solo se guarda el hash

    status, data = call_api(base, key)
    assert status == 200 and data["auth"] == f"Bearer {KEY}"

    _, html, _ = br.req("GET", "/_vault/")
    assert "mi-servicio" in html
    br.req("POST", "/_vault/keys/revoke", {"csrf": csrf, "name": "mi-servicio"})
    assert call_api(base, key)[0] == 401


def test_csrf_and_origin_required(gateway):
    base, b, _, _ = gateway
    br = Browser(base)
    br.login()
    status, html, _ = br.req("POST", "/_vault/keys", {"csrf": "falso", "name": "x", "apis": ["openai"]})
    assert status == 403 and not b.tokens
    csrf = br.csrf()
    status, _, _ = br.req("POST", "/_vault/keys", {"csrf": csrf, "name": "x", "apis": ["openai"]},
                          headers={"Origin": "https://evil.example"})
    assert status == 403 and not b.tokens


def test_null_origin_rejected(gateway):
    base, *_ = gateway
    br = Browser(base)
    assert br.req("POST", "/_vault/login", {"password": PASSWORD}, headers={"Origin": "null"})[0] == 403
    assert br.req("POST", "/_vault/login", {"password": PASSWORD}, headers={"Origin": base})[0] == 303


def test_panel_validation_errors(gateway):
    base, b, _, _ = gateway
    br = Browser(base)
    br.login()
    csrf = br.csrf()
    _, html, _ = br.req("POST", "/_vault/keys", {"csrf": csrf, "name": "<b>x</b>", "apis": ["openai"]})
    assert "nombre inválido" in html and "<b>x</b>" not in html
    _, html, _ = br.req("POST", "/_vault/keys", {"csrf": csrf, "name": "ok", "apis": ["db"]})
    assert "inexistentes" in html and not b.tokens


def admin(base, method, path, token, body=None):
    r = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body else None,
                               headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def test_admin_api_for_deployments(gateway):
    base, _, admin_token, _ = gateway
    assert admin(base, "GET", "/_vault/api/keys", "va_falso")[0] == 401
    assert admin(base, "GET", "/_vault/api/keys", "vt_no-sirve")[0] == 401

    status, apis = admin(base, "GET", "/_vault/api/apis", admin_token)
    assert status == 200 and [a["name"] for a in apis] == ["openai"]

    status, created = admin(base, "POST", "/_vault/api/keys", admin_token,
                            {"name": "despliegue-42", "apis": ["openai"], "expires_days": 30})
    assert status == 201 and created["env"]["OPENAI_API_KEY"] == created["key"]
    assert call_api(base, created["key"])[0] == 200

    status, listed = admin(base, "GET", "/_vault/api/keys", admin_token)
    assert listed[0]["name"] == "despliegue-42" and "expires" in listed[0]

    assert admin(base, "DELETE", "/_vault/api/keys/despliegue-42", admin_token)[0] == 204
    assert call_api(base, created["key"])[0] == 401
    assert admin(base, "DELETE", "/_vault/api/keys/despliegue-42", admin_token)[0] == 404


def test_expired_key_rejected(gateway):
    base, b, _, _ = gateway
    key = K.create_key(b, "temporal", ["openai"], 1)
    assert call_api(base, key)[0] == 200
    entry = b.tokens[B.hash_token(key)]
    entry["expires"] = (K.now() - timedelta(minutes=1)).isoformat()
    assert call_api(base, key)[0] == 401


def test_admin_token_cannot_call_apis(gateway):
    base, _, admin_token, _ = gateway
    assert call_api(base, admin_token)[0] == 401


def test_serve_panel_requires_password(tmp_path):
    d = Device(tmp_path, "srv", tmp_path / "v.age")
    d.vault("init", "--protect", "none", "--recovery-out", str(tmp_path / "r.txt"))
    r = d.vault("serve", "--panel", check=False)
    assert r.returncode != 0 and "vault admin password" in r.stderr
    d.env["VAULT_ADMIN_PASSWORD"] = PASSWORD
    d.vault("admin", "password")
    out = d.vault("admin", "token-create", "ci").stdout
    assert "va_" in out and "ci" in d.vault("admin", "token-list").stdout
