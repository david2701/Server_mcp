"""Bóveda portátil: varios "dispositivos" (HOME distintos) comparten un archivo cifrado."""

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import anyio
import pytest
import uvicorn

from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters
from ssh_vault import bundle as B
from ssh_vault.llmproxy import build_app

ROOT = Path(__file__).resolve().parents[1]
KEY = "sk-live-SUPERSECRETO-123"


class Device:
    def __init__(self, tmp: Path, name: str, vault_file: Path):
        self.home = tmp / name
        self.home.mkdir()
        self.env = {
            **os.environ,
            "HOME": str(self.home),
            "SSH_VAULT_HOME": str(self.home / ".config/ssh-vault"),
            "VAULT_IDENTITY_FILE": str(self.home / ".config/ssh-vault/identity.txt"),
            "VAULT_FILE": str(vault_file),
            "PYTHONPATH": str(ROOT),
        }

    def vault(self, *args, input=None, check=True):
        r = subprocess.run([sys.executable, "-m", "ssh_vault.cli", *args], env=self.env, cwd=self.home,
                           input=input, capture_output=True, text=True)
        if check and r.returncode != 0:
            raise AssertionError(f"vault {' '.join(args)} falló:\n{r.stderr}")
        return r


@pytest.fixture
def devices(tmp_path):
    vault_file = tmp_path / "icloud" / "vault.age"
    vault_file.parent.mkdir()
    a = Device(tmp_path, "macbook-pro", vault_file)
    b = Device(tmp_path, "macbook-air", vault_file)
    a.vault("init", "--name", "macbook-pro")
    a.vault("set", "openai", "--provider", "openai", "--stdin", input=KEY)
    return a, b, vault_file


def test_file_is_encrypted_and_readable_by_owner(devices):
    a, _, vault_file = devices
    raw = vault_file.read_text()
    assert raw.startswith("-----BEGIN AGE ENCRYPTED FILE-----")
    assert KEY not in raw and "openai" not in raw
    assert a.vault("get", "openai").stdout == KEY
    assert "https://api.openai.com/v1/" in a.vault("list").stdout


def test_second_device_flow(devices):
    a, b, _ = devices
    assert b.vault("get", "openai", check=False).returncode != 0  # sin identidad
    pub = b.vault("whoami").stdout.strip()
    assert pub.startswith("age1")
    assert b.vault("get", "openai", check=False).returncode != 0  # aún no autorizada
    a.vault("device", "add", "macbook-air", pub)
    assert b.vault("get", "openai").stdout == KEY
    # b también puede escribir, y a lo ve
    b.vault("set", "groq", "--provider", "groq", "--stdin", input="gsk_x")
    assert a.vault("get", "groq").stdout == "gsk_x"
    # revocar
    a.vault("device", "rm", "macbook-air")
    assert b.vault("get", "openai", check=False).returncode != 0


def test_interoperable_with_age_cli(devices):
    a, _, vault_file = devices
    if not shutil.which("age"):
        pytest.skip("age no instalado")
    out = subprocess.run(["age", "-d", "-i", a.env["VAULT_IDENTITY_FILE"], str(vault_file)],
                         capture_output=True, text=True, check=True).stdout
    assert json.loads(out)["secrets"]["openai"]["value"] == KEY


def test_identity_file_must_be_private(devices):
    a, _, _ = devices
    Path(a.env["VAULT_IDENTITY_FILE"]).chmod(0o644)
    assert a.vault("get", "openai", check=False).returncode != 0


def test_run_injects_env(devices):
    a, _, _ = devices
    r = a.vault("run", "OPENAI_API_KEY=openai", "--", "sh", "-c", 'printf %s "$OPENAI_API_KEY"')
    assert r.stdout == KEY


def sshkey(tmp_path, name):
    path = tmp_path / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path), "-C", name], check=True)
    return path


@pytest.mark.skipif(not shutil.which("ssh-keygen"), reason="sin OpenSSH")
def test_ssh_keys_import_export_and_agent(devices, tmp_path):
    a, _, _ = devices
    key = sshkey(tmp_path, "servidores")
    a.vault("ssh", "import", "servidores", str(key))
    assert "ssh-ed25519" in a.vault("ssh", "list").stdout

    dest = tmp_path / "exportada"
    a.vault("ssh", "export", "servidores", str(dest))
    assert dest.read_text() == key.read_text()
    assert oct(dest.stat().st_mode & 0o777) == "0o600"

    sock = tmp_path / "agent.sock"
    agent = subprocess.Popen(["ssh-agent", "-D", "-a", str(sock)], stdout=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if sock.exists():
                break
            time.sleep(0.05)
        a.env["SSH_AUTH_SOCK"] = str(sock)
        a.vault("ssh", "add", "servidores", "--ttl", "1h")
        listed = subprocess.run(["ssh-add", "-l"], env=a.env, capture_output=True, text=True).stdout
        assert "servidores" in listed
    finally:
        agent.terminate()


@pytest.mark.skipif(not shutil.which("ssh-keygen"), reason="sin OpenSSH")
def test_share_with_someone_by_ssh_key(devices, tmp_path):
    a, _, _ = devices
    friend_key = sshkey(tmp_path, "amigo")
    pkg = tmp_path / "para-amigo.age"
    a.vault("share", "openai", "--to", str(friend_key) + ".pub", "-o", str(pkg))
    assert KEY not in pkg.read_text()

    # El amigo, con su propia bóveda, lo importa usando su llave SSH
    friend = Device(tmp_path, "amigo-home", tmp_path / "amigo-vault.age")
    friend.vault("init")
    friend.vault("import", str(pkg), "--identity", str(friend_key))
    assert friend.vault("get", "openai").stdout == KEY

    # Y sin instalar nada, con age
    if shutil.which("age"):
        out = subprocess.run(["age", "-d", "-i", str(friend_key), str(pkg)],
                             capture_output=True, text=True, check=True).stdout
        assert json.loads(out)["secrets"]["openai"]["value"] == KEY

    # Un tercero no puede abrirlo
    other = sshkey(tmp_path, "otro")
    stranger = Device(tmp_path, "otro-home", tmp_path / "otro-vault.age")
    stranger.vault("init")
    assert stranger.vault("import", str(pkg), "--identity", str(other), check=False).returncode != 0


# ─── API proxy ──────────────────────────────────────────────────────────────────

class Upstream(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode()
        if self.path.endswith("/stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for i in range(3):
                self.wfile.write(f"data: {i}\n\n".encode())
                self.wfile.flush()
            return
        data = json.dumps({
            "path": self.path, "auth": self.headers.get("Authorization"),
            "x_api_key": self.headers.get("x-api-key"), "version": self.headers.get("anthropic-version"),
            "body": body,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def proxy():
    up = HTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{up.server_port}/"
    b = B.Bundle(secrets={
        "openai": {"value": KEY, "base_url": base + "v1/"},
        "anthropic": {"value": "ant-key", "base_url": base, "header": "x-api-key: {secret}",
                      "extra_headers": {"anthropic-version": "2023-06-01"}},
    })
    b.tokens[B.hash_token("vt_app")] = {"name": "mi-app", "secrets": ["openai"]}
    b.tokens[B.hash_token("vt_claude")] = {"name": "otra", "secrets": ["anthropic"]}
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(build_app(b), host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    while not server.started:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    up.shutdown()


def post(url, headers, body=b"{}"):
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_proxy_openai_style(proxy):
    status, body = post(f"{proxy}/openai/chat/completions", {"Authorization": "Bearer vt_app"}, b'{"m":1}')
    data = json.loads(body)
    assert status == 200
    assert data["path"] == "/v1/chat/completions" and data["body"] == '{"m":1}'
    assert data["auth"] == f"Bearer {KEY}"  # el proveedor recibe la clave real; la app nunca la tuvo


def test_proxy_anthropic_style(proxy):
    status, body = post(f"{proxy}/anthropic/v1/messages", {"x-api-key": "vt_claude", "anthropic-version": "2024-01-01"})
    data = json.loads(body)
    assert status == 200 and data["x_api_key"] == "ant-key" and data["auth"] is None
    assert data["version"] == "2024-01-01"  # la del SDK gana sobre la por defecto


def test_proxy_rejects_bad_tokens(proxy):
    assert post(f"{proxy}/openai/x", {"Authorization": "Bearer nope"})[0] == 401
    assert post(f"{proxy}/openai/x", {})[0] == 401
    assert post(f"{proxy}/anthropic/v1/messages", {"Authorization": "Bearer vt_app"})[0] == 403
    assert post(f"{proxy}/openai/..%2f..%2fadmin", {"Authorization": "Bearer vt_app"})[0] in (400, 404)


def test_proxy_streams(proxy):
    status, body = post(f"{proxy}/openai/stream", {"Authorization": "Bearer vt_app"})
    assert status == 200 and body == "data: 0\n\ndata: 1\n\ndata: 2\n\n"


def test_token_cli(devices):
    a, _, _ = devices
    out = a.vault("token", "create", "mi-app", "--secrets", "openai").stdout
    token = next(w for w in out.split() if w.startswith("vt_"))
    assert "OPENAI_BASE_URL=http://127.0.0.1:8787/openai" in out
    assert token not in Path(a.env["VAULT_FILE"]).read_text()
    assert "mi-app" in a.vault("token", "list").stdout
    assert a.vault("token", "create", "x", "--secrets", "noexiste", check=False).returncode != 0
    a.vault("token", "rm", "mi-app")
    assert "mi-app" not in a.vault("token", "list").stdout


def test_serve_refuses_public_without_tls(devices):
    a, _, _ = devices
    r = a.vault("serve", "--host", "0.0.0.0", check=False)
    assert r.returncode != 0 and "tls" in r.stderr.lower()


def test_local_mcp_uses_vault_without_revealing(devices):
    a, _, _ = devices
    up = HTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    a.vault("set", "local", "--base-url", f"http://127.0.0.1:{up.server_port}/v1/", "--stdin", input=KEY)

    params = StdioServerParameters(command=sys.executable, args=["-m", "ssh_vault.cli", "mcp"],
                                   env=a.env, cwd=str(a.home))

    async def scenario():
        async with Client(params) as c:
            listing = (await c.call_tool("list_secrets", {})).content[0].text
            assert "local" in listing and KEY not in listing
            r = await c.call_tool("call_api", {"secret": "local", "path": "chat", "method": "POST", "body": {"q": 1}})
            return r.content[0].text

    text = anyio.run(scenario)
    up.shutdown()
    assert '"auth": "Bearer [SECRETO]"' in text and KEY not in text
