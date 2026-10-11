"""Servidores en la bóveda contra un sshd real: cualquier "Mac" (HOME limpio) se conecta
con la llave de la bóveda, sin ~/.ssh, y los agentes lo hacen a través del MCP."""

import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import anyio
import pytest

from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters
from ssh_vault.config import server_from_spec
from ssh_vault.runner import ssh_argv
from ssh_vault.config import Config
from test_portable import Device

SSHD = shutil.which("sshd") or "/usr/sbin/sshd"
pytestmark = pytest.mark.skipif(not Path(SSHD).exists() or not shutil.which("ssh-agent"),
                                reason="requiere OpenSSH (sshd, ssh-agent)")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Sshd:
    def __init__(self, tmp: Path, authorized_pub: str):
        self.dir = tmp / "sshd"
        self.dir.mkdir()
        self.port = free_port()
        (self.dir / "authorized_keys").write_text(authorized_pub + "\n")
        self.new_host_key()

    def new_host_key(self):
        for f in self.dir.glob("hostkey*"):
            f.unlink()
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.dir / "hostkey")], check=True)

    def start(self):
        (self.dir / "sshd_config").write_text(f"""
Port {self.port}
ListenAddress 127.0.0.1
HostKey {self.dir}/hostkey
AuthorizedKeysFile {self.dir}/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
StrictModes no
PidFile {self.dir}/pid
""")
        Path("/run/sshd").mkdir(exist_ok=True)
        self.proc = subprocess.Popen([SSHD, "-D", "-e", "-f", str(self.dir / "sshd_config")],
                                     stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("sshd no arrancó")

    def stop(self):
        self.proc.terminate()
        self.proc.wait(5)


@pytest.fixture
def env(tmp_path):
    keyfile = tmp_path / "servidores"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(keyfile), "-C", "boveda"], check=True)
    sshd = Sshd(tmp_path, (tmp_path / "servidores.pub").read_text().strip())
    sshd.start()

    vault_file = tmp_path / "sync" / "vault.age"
    vault_file.parent.mkdir()
    pro = Device(tmp_path, "pro", vault_file)
    pro.vault("init", "--protect", "none", "--recovery-out", str(tmp_path / "rec.txt"))
    pro.vault("ssh", "import", "servidores", str(keyfile))
    keyfile.unlink()  # la llave ya solo existe dentro de la bóveda
    (tmp_path / "servidores.pub").unlink()
    pro.vault("server", "add", "web", f"root@127.0.0.1", "-p", str(sshd.port), "--key", "servidores", "-y",
              "--description", "servidor de pruebas")
    pro.vault("server", "add", "db", f"root@127.0.0.1", "-p", str(sshd.port), "--key", "servidores", "-y",
              "--read-only")

    # Otra Mac, sin nada en ~/.ssh: solo la bóveda sincronizada.
    air = Device(tmp_path, "air", vault_file)
    pro.vault("device", "add", "air", air.vault("whoami", "--protect", "none").stdout.strip())
    yield pro, air, sshd, tmp_path
    sshd.stop()


def test_connect_from_any_mac(env):
    _, air, _, _ = env
    assert not (air.home / ".ssh").exists()
    r = air.vault("connect", "web", "echo", "hola desde", "$(hostname)")
    assert r.stdout.startswith("hola desde ")
    assert "servidor de pruebas" in air.vault("server", "list").stdout


def test_agents_via_mcp(env):
    _, air, _, _ = env
    params = StdioServerParameters(command=sys.executable, args=["-m", "ssh_vault", "mcp"],
                                   env=air.env, cwd=str(air.home))

    async def scenario():
        async with Client(params) as c:
            listing = (await c.call_tool("list_servers", {})).content[0].text
            assert "web (root@127.0.0.1" in listing and "solo lectura" in listing
            assert (await c.call_tool("test_connection", {"server": "web"})).content[0].text == "OK"
            ok = await c.call_tool("run_command", {"server": "web", "command": "id -un"})
            assert "root" in ok.content[0].text and "exit_code: 0" in ok.content[0].text
            denied = await c.call_tool("run_command", {"server": "db", "command": "rm -rf /tmp/x"})
            assert denied.is_error
            allowed = await c.call_tool("run_command", {"server": "db", "command": "uptime"})
            assert "exit_code: 0" in allowed.content[0].text

    anyio.run(scenario)
    # Nada de la llave privada quedó en disco en el HOME de la Mac
    leaked = [p for p in air.home.rglob("*") if p.is_file() and "OPENSSH PRIVATE KEY" in p.read_text(errors="ignore")]
    assert leaked == []


def test_changed_host_key_is_rejected(env):
    _, air, sshd, _ = env
    sshd.stop()
    sshd.new_host_key()  # ¿servidor suplantado o reinstalado?
    sshd.start()
    r = air.vault("connect", "web", "true", check=False)
    assert r.returncode != 0
    assert "host key" in r.stderr.lower() or "verification failed" in r.stderr.lower()


def test_ignores_local_ssh_config(tmp_path):
    cfg = Config(known_hosts="/k", agent_sock="/a.sock", keys_dir="/keys")
    s = server_from_spec("web", {"host": "example.com", "user": "deploy", "port": 2222, "key": "k"})
    argv = ssh_argv(cfg, s, "ls")
    assert argv[1:3] == ["-F", "none"]
    assert "UserKnownHostsFile=/k" in argv and "IdentityAgent=/a.sock" in argv
    assert "IdentityFile=/keys/k.pub" in argv and "IdentitiesOnly=yes" in argv
    assert argv[-3:] == ["--", "example.com", "ls"] and ["-p", "2222"] == argv[argv.index("-p"):argv.index("-p") + 2]


@pytest.mark.parametrize("spec", [
    {"host": "-oProxyCommand=evil"}, {"host": "a b"}, {"host": "ok", "user": "-x"}, {"host": "ok", "port": 0},
])
def test_rejects_bad_server_specs(spec):
    with pytest.raises(ValueError):
        server_from_spec("x", spec)


def test_import_rejects_passphrase_keys(tmp_path):
    d = Device(tmp_path, "m", tmp_path / "v.age")
    d.vault("init", "--protect", "none", "--recovery-out", str(tmp_path / "r.txt"))
    k = tmp_path / "conclave"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "frase-secreta", "-f", str(k)], check=True)
    r = d.vault("ssh", "import", "k", str(k), check=False)
    assert r.returncode != 0 and "frase de paso" in r.stderr
