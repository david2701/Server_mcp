"""App autoalojada de punta a punta: alta de servidores con un comando, MCP remoto con
token y con OAuth (como Claude.ai/ChatGPT), contra un sshd real. Ninguna Mac implicada."""

import base64
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import HTTPServer

import anyio
import pytest
import uvicorn

from mcp.client.client import Client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client
from ssh_vault import bundle as B
from ssh_vault import keys as K
from ssh_vault.hosted import build_hosted_app
from test_panel import PASSWORD, Browser
from test_portable import KEY, Upstream
from test_servers import Sshd
import test_servers

pytestmark = test_servers.pytestmark  # requiere OpenSSH (sshd, ssh-agent)

os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def app(tmp_path):
    up = HTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    b = B.Bundle(secrets={"openai": {"value": KEY, "base_url": f"http://127.0.0.1:{up.server_port}/v1/"}})
    K.set_admin_password(b, PASSWORD)
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    saves = []
    asgi = build_hosted_app(b, lambda x: saves.append(1), base, tmp_path / "audit.log")
    server = uvicorn.Server(uvicorn.Config(asgi, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    br = Browser(base)
    assert br.login() == 303
    yield base, b, br, tmp_path
    server.should_exit = True
    asgi.state.gateway.agent.close()
    up.shutdown()


def csrf(br):
    _, html, _ = br.req("GET", "/_vault/")
    return re.search(r"name=csrf value='([^']+)'", html).group(1)


def flash(br):
    _, html, _ = br.req("GET", "/_vault/")
    m = re.search(r"class='card flash[^']*'><b>(.*?)</b>(?:<pre>(.*?)</pre>)?", html, re.S)
    import html as h
    return (h.unescape(m.group(1)), h.unescape(m.group(2) or "")) if m else ("", "")


def post(br, path, data):
    return br.req("POST", path, {**data, "csrf": csrf(br)})


def enroll_server(base, br, tmp_path, name="web", egress="127.0.0.1"):
    """Crea el servidor en el panel y ejecuta el comando de alta en un 'servidor' real."""
    post(br, "/_vault/settings", {"egress_ip": egress})
    sshd = Sshd(tmp_path / name if (tmp_path / name).mkdir() is None else tmp_path, "")
    home = tmp_path / name / "home"
    home.mkdir()
    sshd.ak = home / ".ssh" / "authorized_keys"
    sshd.start()
    post(br, "/_vault/servers", {"name": name, "target": "root@127.0.0.1", "port": str(sshd.port),
                                 "description": "pruebas", "mode": "full"})
    msg, detail = flash(br)
    assert "creado con su propia llave" in msg, msg
    cmd = re.search(r"(curl -fsSL \S+ \| sh)", detail).group(1)
    env = {**os.environ, "HOME": str(home), "VAULT_HOSTKEYS": str(sshd.dir / "hostkey.pub")}
    r = subprocess.run(["sh", "-c", cmd], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr + r.stdout
    return sshd, home, cmd


def mcp_call(base, token, tool, args=None):
    async def run():
        http = create_mcp_http_client(headers={"Authorization": f"Bearer {token}"})
        async with Client(streamable_http_client(f"{base}/mcp", http_client=http)) as c:
            r = await c.call_tool(tool, args or {})
            return r.content[0].text if r.content else "", r.is_error
    return anyio.run(run)


def test_enroll_test_and_mcp_token(app):
    base, b, br, tmp_path = app
    sshd, home, cmd = enroll_server(base, br, tmp_path)
    try:
        line = (home / ".ssh" / "authorized_keys").read_text()
        assert line.startswith('from="127.0.0.1/32",restrict ssh-ed25519 ') and line.strip().endswith("ssh-vault:web")
        assert b.servers["web"]["status"] == "instalado"
        assert b.servers["web"]["host_keys"] == [" ".join((sshd.dir / "hostkey.pub").read_text().split()[:2])]
        assert "PRIVATE KEY" in b.ssh_keys["srv-web"]["private"]

        # El comando de alta es de un solo uso
        r = subprocess.run(["sh", "-c", cmd], env={**os.environ, "HOME": str(home)}, capture_output=True, text=True)
        assert "404" in r.stderr

        post(br, "/_vault/servers/test", {"name": "web"})
        assert "correcta" in flash(br)[0]

        # Token para Claude Code / Cursor con acceso solo a "web"
        post(br, "/_vault/access", {"name": "claude-code", "servers": ["web"], "apis": ["openai"]})
        msg, detail = flash(br)
        token = re.search(r"(mt_[A-Za-z0-9_-]+)", detail).group(1)
        assert "claude mcp add --transport http vault" in detail

        text, err = mcp_call(base, token, "list_servers")
        assert "web (root@127.0.0.1" in text
        text, err = mcp_call(base, token, "run_command", {"server": "web", "command": "id -un"})
        assert not err and "root" in text and "exit_code: 0" in text
        text, err = mcp_call(base, token, "call_api", {"secret": "openai", "path": "chat", "method": "POST", "body": {}})
        assert not err and "[SECRETO]" in text and KEY not in text

        # Un token sin servidores no ve ni puede usar "web"
        post(br, "/_vault/access", {"name": "solo-apis", "apis": ["openai"]})
        limited = re.search(r"(mt_[A-Za-z0-9_-]+)", flash(br)[1]).group(1)
        assert "No hay servidores" in mcp_call(base, limited, "list_servers")[0]
        assert mcp_call(base, limited, "run_command", {"server": "web", "command": "id"})[1]

        # Actividad visible en el panel
        _, html, _ = br.req("GET", "/_vault/")
        assert "claude-code" in html and "id -un" in html

        # Revocar → 401
        post(br, "/_vault/access/revoke", {"name": "claude-code"})
        with pytest.raises(Exception):
            mcp_call(base, token, "list_servers")
    finally:
        sshd.stop()


def test_from_restriction_blocks_other_ips(app):
    base, b, br, tmp_path = app
    sshd, home, _ = enroll_server(base, br, tmp_path, egress="10.9.9.9")
    try:
        assert 'from="10.9.9.9/32"' in (home / ".ssh" / "authorized_keys").read_text()
        post(br, "/_vault/servers/test", {"name": "web"})
        msg, detail = flash(br)
        assert "falló" in msg and "permission denied" in detail.lower()
    finally:
        sshd.stop()


def test_rotation_replaces_key(app):
    base, b, br, tmp_path = app
    sshd, home, _ = enroll_server(base, br, tmp_path)
    try:
        old = b.ssh_keys["srv-web"]["public"]
        post(br, "/_vault/servers/rotate", {"name": "web"})
        msg, detail = flash(br)
        assert "rotada" in msg and b.ssh_keys["srv-web"]["public"] != old
        post(br, "/_vault/servers/test", {"name": "web"})
        assert "falló" in flash(br)[0]  # la nueva aún no está instalada
        post(br, "/_vault/servers/enroll", {"name": "web"})
        cmd = re.search(r"(curl -fsSL \S+ \| sh)", flash(br)[1]).group(1)
        subprocess.run(["sh", "-c", cmd], env={**os.environ, "HOME": str(home),
                                               "VAULT_HOSTKEYS": str(sshd.dir / "hostkey.pub")}, check=True,
                       capture_output=True)
        lines = (home / ".ssh" / "authorized_keys").read_text().splitlines()
        assert len([l for l in lines if l.endswith("ssh-vault:web")]) == 1 and old.split()[1] not in lines[0]
        post(br, "/_vault/servers/test", {"name": "web"})
        assert "correcta" in flash(br)[0]
    finally:
        sshd.stop()


def test_enroll_endpoints_need_valid_token(app):
    base, b, br, tmp_path = app
    post(br, "/_vault/servers", {"name": "x", "target": "root@127.0.0.1", "port": "22", "mode": "full"})
    url = re.search(r"curl -fsSL (\S+) \|", flash(br)[1]).group(1)
    anon = Browser(base)
    # Sin haber descargado el script no se aceptan huellas
    assert anon.req("POST", urllib.parse.urlsplit(url).path + "/hostkeys", b"ssh-ed25519 " + b"A" * 68)[0] == 404
    assert anon.req("GET", "/_vault/enroll/inventado")[0] == 404
    assert anon.req("POST", "/_vault/servers", {"name": "y", "target": "a@b"})[0] == 403  # sin sesión


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def http(method, url, data=None, headers=None, form=False):
    body = urllib.parse.urlencode(data).encode() if form else (json.dumps(data).encode() if data else None)
    h = {"Content-Type": "application/x-www-form-urlencoded" if form else "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, r.read().decode(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def test_oauth_flow_like_claude_ai(app):
    base, b, br, tmp_path = app
    sshd, home, _ = enroll_server(base, br, tmp_path)
    try:
        status, meta, _ = http("GET", f"{base}/.well-known/oauth-authorization-server")
        meta = json.loads(meta)
        assert status == 200 and meta["registration_endpoint"].endswith("/register")

        redirect = "http://127.0.0.1:9/callback"
        status, reg, _ = http("POST", meta["registration_endpoint"], {
            "client_name": "Claude", "redirect_uris": [redirect], "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"], "token_endpoint_auth_method": "none"})
        assert status == 201, reg
        client_id = json.loads(reg)["client_id"]

        verifier, challenge = pkce()
        q = urllib.parse.urlencode({"response_type": "code", "client_id": client_id, "redirect_uri": redirect,
                                    "code_challenge": challenge, "code_challenge_method": "S256", "state": "xyz",
                                    "scope": "vault", "resource": f"{base}/mcp"})
        status, _, headers = http("GET", f"{meta['authorization_endpoint']}?{q}")
        consent = headers.get("location") or headers.get("Location")
        assert status == 302 and "/_vault/oauth/consent?req=" in consent

        # Sin sesión → pide iniciar sesión; con sesión → pantalla de consentimiento
        assert "Contraseña de administrador" in Browser(base).req("GET", urllib.parse.urlsplit(consent).path + "?" +
                                                                 urllib.parse.urlsplit(consent).query)[1]
        path = consent.split(base, 1)[1]
        _, html, _ = br.req("GET", path)
        assert "Conectar «Claude»" in html
        rid = re.search(r"name=req value='([^']+)'", html).group(1)
        token_csrf = re.search(r"name=csrf value='([^']+)'", html).group(1)
        status, _, headers = br.req("POST", "/_vault/oauth/consent", {
            "csrf": token_csrf, "req": rid, "name": "claude-ai", "servers": ["web"], "decision": "approve"})
        back = headers.get("location")
        assert status == 302 and back.startswith(redirect) and "state=xyz" in back
        code = urllib.parse.parse_qs(urllib.parse.urlsplit(back).query)["code"][0]

        status, tok, _ = http("POST", meta["token_endpoint"], {
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect, "client_id": client_id,
            "code_verifier": verifier, "resource": f"{base}/mcp"}, form=True)
        assert status == 200, tok
        tok = json.loads(tok)
        assert tok["access_token"].startswith("mo_")
        assert "web" in mcp_call(base, tok["access_token"], "list_servers")[0]
        text, err = mcp_call(base, tok["access_token"], "run_command", {"server": "web", "command": "hostname"})
        assert not err and "exit_code: 0" in text
        assert mcp_call(base, tok["access_token"], "list_secrets")[0].startswith("No hay APIs")  # no se le dieron

        # El código es de un solo uso
        status, _, _ = http("POST", meta["token_endpoint"], {
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect, "client_id": client_id,
            "code_verifier": verifier}, form=True)
        assert status == 400

        # Renovación con rotación
        status, tok2, _ = http("POST", meta["token_endpoint"], {
            "grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": client_id}, form=True)
        assert status == 200, tok2
        status, _, _ = http("POST", meta["token_endpoint"], {
            "grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": client_id}, form=True)
        assert status == 400  # el refresh viejo ya no sirve

        _, html, _ = br.req("GET", "/_vault/")
        assert "claude-ai" in html and "OAuth" in html
        post(br, "/_vault/access/revoke", {"name": "claude-ai"})
        with pytest.raises(Exception):
            mcp_call(base, json.loads(tok2)["access_token"], "list_servers")
    finally:
        sshd.stop()


def test_oauth_deny(app):
    base, b, br, _ = app
    _, reg, _ = http("POST", f"{base}/register", {"client_name": "X", "redirect_uris": ["http://127.0.0.1:9/cb"],
                                                  "token_endpoint_auth_method": "none"})
    cid = json.loads(reg)["client_id"]
    _, ch = pkce()
    q = urllib.parse.urlencode({"response_type": "code", "client_id": cid, "redirect_uri": "http://127.0.0.1:9/cb",
                                "code_challenge": ch, "code_challenge_method": "S256", "state": "s"})
    _, _, h = http("GET", f"{base}/authorize?{q}")
    _, html, _ = br.req("GET", h["location"].split(base, 1)[1])
    rid = re.search(r"name=req value='([^']+)'", html).group(1)
    tc = re.search(r"name=csrf value='([^']+)'", html).group(1)
    status, _, headers = br.req("POST", "/_vault/oauth/consent", {"csrf": tc, "req": rid, "name": "x", "decision": "deny"})
    assert status == 302 and "error=access_denied" in headers["location"]


def test_provider_keys_from_panel(app):
    base, b, br, _ = app
    post(br, "/_vault/secrets", {"name": "anthropic", "provider": "anthropic", "value": "sk-ant-SECRETO"})
    assert b.secrets["anthropic"]["base_url"] == "https://api.anthropic.com/"
    _, html, _ = br.req("GET", "/_vault/")
    assert "sk-ant-SECRETO" not in html and "anthropic" in html
    post(br, "/_vault/secrets", {"name": "propia", "provider": "", "value": "k", "base_url": "http://evil.example/"})
    assert "https" in flash(br)[0] and "propia" not in b.secrets
    post(br, "/_vault/secrets/rm", {"name": "anthropic"})
    assert "anthropic" not in b.secrets


def test_mcp_requires_auth(app):
    base, *_ = app
    status, _, headers = http("POST", f"{base}/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                              headers={"Accept": "application/json, text/event-stream"})
    assert status == 401 and "resource_metadata" in (headers.get("www-authenticate") or headers.get("WWW-Authenticate"))


def test_first_run_setup(tmp_path):
    b = B.Bundle()
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    asgi = build_hosted_app(b, lambda x: None, base, tmp_path / "a.log", setup_token="tok-setup")
    server = uvicorn.Server(uvicorn.Config(asgi, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    try:
        br = Browser(base)
        assert "configuración inicial" in br.req("GET", "/_vault/")[1]
        assert br.req("GET", "/_vault/setup?t=malo")[0] == 403
        assert br.req("POST", "/_vault/setup?t=tok-setup", {"password": "corta", "password2": "corta"})[0] == 200
        assert br.req("POST", "/_vault/setup?t=tok-setup", {"password": PASSWORD, "password2": PASSWORD})[0] == 303
        assert br.req("GET", "/_vault/setup?t=tok-setup")[0] == 403  # ya configurado
        assert br.login() == 303
        _, manifest, _ = br.req("GET", "/_vault/manifest.webmanifest")
        assert json.loads(manifest)["display"] == "standalone"
    finally:
        server.should_exit = True
        asgi.state.gateway.agent.close()
