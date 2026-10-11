"""Carga de configuración y del token de acceso."""

from __future__ import annotations

import os
import re
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG = Path("~/.config/ssh-vault/config.toml").expanduser()
KEYCHAIN_SERVICE = "ssh-vault-mcp"
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


@dataclass(frozen=True)
class Server:
    name: str
    host: str  # alias de ~/.ssh/config o user@host
    description: str = ""
    read_only: bool = False
    allow_commands: tuple[re.Pattern[str], ...] = ()

    def is_allowed(self, command: str) -> bool:
        if not self.allow_commands:
            return not self.read_only
        return any(p.fullmatch(command) for p in self.allow_commands)


@dataclass(frozen=True)
class Config:
    servers: dict[str, Server]
    listen_host: str = "127.0.0.1"
    listen_port: int = 8765
    allowed_hosts: tuple[str, ...] = ()
    command_timeout: int = 60
    max_output_bytes: int = 64 * 1024
    audit_log: Path = field(default_factory=lambda: Path("~/.local/state/ssh-vault/audit.log").expanduser())
    ssh_binary: str = "ssh"


# Comandos permitidos por defecto en servidores read_only sin lista propia.
READ_ONLY_DEFAULTS = (
    r"(uptime|df -h|free -m|whoami|hostname|uname -a)",
    r"(systemctl status|journalctl -u) [A-Za-z0-9_.@-]+( -n [0-9]+)?( --no-pager)?",
    r"(docker ps|docker compose ps)( -a)?",
    r"tail -n [0-9]+ /var/log/[A-Za-z0-9_./-]+",
)


def load_config(path: Path | None = None) -> Config:
    path = path or Path(os.environ.get("SSH_VAULT_CONFIG", DEFAULT_CONFIG))
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)

    servers: dict[str, Server] = {}
    for name, spec in raw.get("servers", {}).items():
        if not NAME_RE.match(name):
            raise ValueError(f"nombre de servidor inválido: {name!r}")
        host = spec.get("host", name)
        if host.startswith("-") or any(c.isspace() for c in host):
            raise ValueError(f"host inválido para {name!r}: {host!r}")
        read_only = bool(spec.get("read_only", False))
        patterns = spec.get("allow_commands")
        if patterns is None and read_only:
            patterns = READ_ONLY_DEFAULTS
        servers[name] = Server(
            name=name,
            host=host,
            description=spec.get("description", ""),
            read_only=read_only,
            allow_commands=tuple(re.compile(p) for p in (patterns or ())),
        )

    kwargs = {k: raw[k] for k in ("listen_host", "listen_port", "command_timeout", "max_output_bytes", "ssh_binary") if k in raw}
    if "allowed_hosts" in raw:
        kwargs["allowed_hosts"] = tuple(raw["allowed_hosts"])
    if "audit_log" in raw:
        kwargs["audit_log"] = Path(raw["audit_log"]).expanduser()
    return Config(servers=servers, **kwargs)


def load_token() -> str:
    """Token desde la variable SSH_VAULT_TOKEN o desde el Llavero de macOS."""
    token = os.environ.get("SSH_VAULT_TOKEN")
    if not token:
        try:
            token = subprocess.run(
                ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
        except (FileNotFoundError, subprocess.CalledProcessError):
            token = ""
    if len(token) < 32:
        raise SystemExit(
            "Falta un token de al menos 32 caracteres. Ejecuta deploy/install.sh "
            "o define SSH_VAULT_TOKEN."
        )
    return token
