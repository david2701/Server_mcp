import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import anyio
import pytest

from mcp.client.client import Client
from ssh_vault import apiproxy
from ssh_vault.config import load_config
from ssh_vault.server import build_mcp

ROOT = Path(__file__).resolve().parents[1]
KEY = "sk-test-0123456789abcdef"


class EchoHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _reply(self):
        if self.path.endswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/robar")
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length") or 0)
        payload = {
            "method": self.command,
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "version": self.headers.get("x-version"),
            "body": self.rfile.read(length).decode() if length else None,
        }
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_DELETE = _reply


@pytest.fixture(scope="module")
def api():
    httpd = HTTPServer(("127.0.0.1", 0), EchoHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}/v1/"
    httpd.shutdown()


@pytest.fixture
def cfg_path(tmp_path, api):
    store = tmp_path / "secrets.json"
    store.write_text(json.dumps({"llm": KEY, "db_password": "hunter2"}))
    store.chmod(0o600)
    path = tmp_path / "config.toml"
    path.write_text(f"""
audit_log = "{tmp_path / 'audit.log'}"
secrets_backend = "file"
secrets_file = "{store}"

[secrets.llm]
description = "API de pruebas"
base_url = "{api}"
header = "Authorization: Bearer {{secret}}"
extra_headers = {{ "x-version" = "2023-06-01" }}

[secrets.db_password]
description = "solo para apps"

[clients.prod-server]
reveal = ["db_password"]
""")
    return path


def call(cfg_path, tool, args):
    async def scenario():
        async with Client(build_mcp(load_config(cfg_path), client="air")) as client:
            return await client.call_tool(tool, args)
    return anyio.run(scenario)


def test_list_secrets_never_shows_values(cfg_path):
    text = call(cfg_path, "list_secrets", {}).content[0].text
    assert "llm" in text and "db_password" in text
    assert KEY not in text and "hunter2" not in text


def test_call_api_injects_key_and_redacts(cfg_path):
    r = call(cfg_path, "call_api", {"secret": "llm", "path": "chat", "method": "POST", "body": '{"q": 1}'})
    text = r.content[0].text
    assert not r.is_error and text.startswith("status: 200")
    payload = json.loads(text.split("\n", 1)[1])
    assert payload["path"] == "/v1/chat" and json.loads(payload["body"]) == {"q": 1}
    assert payload["version"] == "2023-06-01"
    assert payload["auth"] == "Bearer [SECRETO]"  # el servidor la recibió, pero no vuelve a Claude
    assert KEY not in text


@pytest.mark.parametrize("path", [
    "../admin", "%2e%2e/admin", "http://evil.example/x", "a/../../x", "a\\..\\..\\x",
])
def test_call_api_cannot_leave_base_url(cfg_path, path):
    r = call(cfg_path, "call_api", {"secret": "llm", "path": path})
    assert r.is_error


def test_double_slash_stays_on_host(cfg_path):
    r = call(cfg_path, "call_api", {"secret": "llm", "path": "//evil.example/x"})
    assert json.loads(r.content[0].text.split("\n", 1)[1])["path"] == "/v1/evil.example/x"


def test_call_api_blocks_auth_override_and_redirects(cfg_path):
    r = call(cfg_path, "call_api", {"secret": "llm", "path": "x", "headers": {"authorization": "Bearer mio"}})
    assert r.is_error and "Cabecera" in r.content[0].text
    r = call(cfg_path, "call_api", {"secret": "llm", "path": "redirect"})
    assert r.is_error and "redirección" in r.content[0].text


def test_call_api_needs_base_url(cfg_path):
    r = call(cfg_path, "call_api", {"secret": "db_password", "path": "x"})
    assert r.is_error and "base_url" in r.content[0].text


def test_rejects_plain_http_remote(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text('[secrets.x]\nbase_url = "http://api.example.com/"\n')
    with pytest.raises(ValueError):
        load_config(path)


def test_build_url():
    from ssh_vault.config import Secret
    s = Secret(name="x", base_url="https://api.example.com/v1/")
    assert apiproxy.build_url(s, "/models?limit=2") == "https://api.example.com/v1/models?limit=2"


def vault(cfg_path, client, role, original_command):
    env = {**os.environ, "SSH_ORIGINAL_COMMAND": original_command}
    return subprocess.run(
        [sys.executable, "-m", "ssh_vault", "--config", str(cfg_path), "--client", client, "--role", role],
        cwd=ROOT, env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )


def test_get_respects_reveal_list(cfg_path):
    r = vault(cfg_path, "prod-server", "app", "get db_password")
    assert r.returncode == 0 and r.stdout == "hunter2\n"

    r = vault(cfg_path, "prod-server", "app", "get llm")
    assert r.returncode == 1 and KEY not in r.stdout

    r = vault(cfg_path, "macbook-air", "mcp", "get db_password")  # cliente no declarado
    assert r.returncode == 1 and r.stdout == ""

    events = [json.loads(l) for l in load_config(cfg_path).audit_log.read_text().splitlines()]
    assert [(e["client"], e["secret"], e["denied"]) for e in events] == [
        ("prod-server", "db_password", False),
        ("prod-server", "llm", True),
        ("macbook-air", "db_password", True),
    ]


def test_app_role_cannot_use_mcp_or_other_commands(cfg_path):
    assert vault(cfg_path, "prod-server", "app", "").returncode == 2
    assert vault(cfg_path, "prod-server", "app", "mcp").returncode == 2
    assert vault(cfg_path, "macbook-air", "mcp", "cat /etc/passwd").returncode == 2
    assert vault(cfg_path, "macbook-air", "mcp", "get 'x").returncode == 2


def test_file_store_requires_0600(cfg_path, tmp_path):
    (tmp_path / "secrets.json").chmod(0o644)
    r = vault(cfg_path, "prod-server", "app", "get db_password")
    assert r.returncode != 0 and "hunter2" not in r.stdout
