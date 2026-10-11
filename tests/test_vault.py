import json
import stat
import sys
from pathlib import Path

import anyio
import pytest

from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters
from ssh_vault.config import load_config
from ssh_vault.runner import ssh_argv
from ssh_vault.server import build_mcp

ROOT = Path(__file__).resolve().parents[1]

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
    return path


def test_ssh_argv_hardening(cfg):
    cfg = load_config(cfg)
    argv = ssh_argv(cfg, cfg.servers["web"], "ls")
    assert "BatchMode=yes" in argv and "ForwardAgent=no" in argv
    assert argv[-3:] == ["--", "web-alias", "ls"]


def test_read_only_policy(cfg):
    cfg = load_config(cfg)
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


async def exercise(client):
    names = {t.name for t in (await client.list_tools()).tools}
    assert names == {"list_servers", "test_connection", "run_command"}

    listing = await client.call_tool("list_servers", {})
    assert "web" in listing.content[0].text and "solo lectura" in listing.content[0].text

    ok = await client.call_tool("run_command", {"server": "web", "command": "uname -a"})
    assert "host=web-alias cmd=uname -a" in ok.content[0].text

    denied = await client.call_tool("run_command", {"server": "db", "command": "rm -rf /"})
    assert denied.is_error
    assert "no permitido" in denied.content[0].text


def audit_events(cfg_path):
    return [json.loads(line) for line in load_config(cfg_path).audit_log.read_text().splitlines()]


def test_in_memory(cfg):
    async def scenario():
        async with Client(build_mcp(load_config(cfg), client="air")) as client:
            await exercise(client)

    anyio.run(scenario)
    events = audit_events(cfg)
    assert [e.get("denied", False) for e in events] == [False, True]
    assert {e["client"] for e in events} == {"air"}


def test_stdio_process(cfg):
    """Igual que lo lanzaría authorized_keys: un proceso que habla MCP por stdio."""
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "ssh_vault", "--config", str(cfg), "--client", "macbook-pro"],
        cwd=ROOT,
    )

    async def scenario():
        async with Client(params) as client:
            await exercise(client)

    anyio.run(scenario)
    assert {e["client"] for e in audit_events(cfg)} == {"macbook-pro"}


def test_rejects_bad_client_name(cfg):
    import subprocess
    r = subprocess.run([sys.executable, "-m", "ssh_vault", "--config", str(cfg), "--client", "a b"],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode != 0
