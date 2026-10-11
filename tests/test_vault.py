import json
import socket
import stat
import sys
import threading
import time
from pathlib import Path

import anyio
import httpx2
import pytest
import uvicorn

from mcp.client.client import Client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client
from ssh_vault.config import load_config
from ssh_vault.runner import ssh_argv
from ssh_vault.server import build_app

TOKEN = "t" * 40

FAKE_SSH = f"""#!{sys.executable}
import sys
args = sys.argv[1:]
host, command = args[args.index("--") + 1:]
print(f"host={{host}} cmd={{command}}")
"""


@pytest.fixture
def cfg(tmp_path: Path):
    fake = tmp_path / "ssh"
    fake.write_text(FAKE_SSH)
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    path = tmp_path / "config.toml"
    path.write_text(f"""
ssh_binary = "{fake}"
audit_log = "{tmp_path / 'audit.log'}"

[servers.web]
host = "web-alias"
description = "producción"

[servers.db]
host = "deploy@db.example.com"
read_only = true
""")
    return load_config(path)


def test_ssh_argv_hardening(cfg):
    argv = ssh_argv(cfg, cfg.servers["web"], "ls")
    assert "BatchMode=yes" in argv and "ForwardAgent=no" in argv
    assert argv[-3:] == ["--", "web-alias", "ls"]


def test_read_only_policy(cfg):
    db = cfg.servers["db"]
    assert db.is_allowed("uptime")
    assert db.is_allowed("systemctl status nginx")
    assert not db.is_allowed("rm -rf /")
    assert not db.is_allowed("uptime; rm -rf /")
    assert cfg.servers["web"].is_allowed("anything")


def test_rejects_bad_host(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text('[servers.x]\nhost = "-oProxyCommand=evil"\n')
    with pytest.raises(ValueError):
        load_config(path)


@pytest.fixture
def base_url(cfg):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(build_app(cfg, TOKEN), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/mcp"
    server.should_exit = True
    thread.join(5)


def test_requires_token(base_url):
    r = httpx2.post(base_url, json={}, headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401
    assert httpx2.post(base_url, json={}).status_code == 401


def test_end_to_end(base_url, cfg):
    async def scenario():
        http = create_mcp_http_client(headers={"Authorization": f"Bearer {TOKEN}"})
        async with Client(streamable_http_client(base_url, http_client=http)) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            assert names == {"list_servers", "test_connection", "run_command"}

            listing = await client.call_tool("list_servers", {})
            assert "web" in listing.content[0].text and "solo lectura" in listing.content[0].text

            ok = await client.call_tool("run_command", {"server": "web", "command": "uname -a"})
            assert "host=web-alias cmd=uname -a" in ok.content[0].text

            denied = await client.call_tool("run_command", {"server": "db", "command": "rm -rf /"})
            assert denied.is_error

    anyio.run(scenario)
    events = [json.loads(line) for line in cfg.audit_log.read_text().splitlines()]
    assert [e.get("denied", False) for e in events] == [False, True]
