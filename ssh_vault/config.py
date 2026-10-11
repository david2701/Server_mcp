"""Modelos de servidores y secretos, construidos a partir del contenido de la bóveda."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
HOST_RE = re.compile(r"^[A-Za-z0-9_.:\[\]-]{1,253}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$", re.IGNORECASE)

# Comandos permitidos por defecto en servidores read_only sin lista propia.
READ_ONLY_DEFAULTS = (
    r"(uptime|df -h|free -m|whoami|hostname|uname -a)",
    r"(systemctl status|journalctl -u) [A-Za-z0-9_.@-]+( -n [0-9]+)?( --no-pager)?",
    r"(docker ps|docker compose ps)( -a)?",
    r"tail -n [0-9]+ /var/log/[A-Za-z0-9_./-]+",
)


@dataclass(frozen=True)
class Server:
    name: str
    host: str
    user: str = "root"
    port: int = 22
    key: str = ""                       # nombre de la llave SSH de la bóveda
    host_keys: tuple[str, ...] = ()     # huellas fijadas al dar de alta el servidor
    description: str = ""
    read_only: bool = False
    allow_commands: tuple[re.Pattern[str], ...] = ()

    def is_allowed(self, command: str) -> bool:
        if not self.allow_commands:
            return not self.read_only
        return any(p.fullmatch(command) for p in self.allow_commands)


@dataclass(frozen=True)
class Secret:
    name: str
    description: str = ""
    # Con base_url, la bóveda puede usar el secreto como proxy SOLO contra ese prefijo.
    base_url: str | None = None
    auth_header: str = "Authorization"
    auth_format: str = "Bearer {secret}"
    extra_headers: tuple[tuple[str, str], ...] = ()


def default_audit_log() -> Path:
    return Path(os.environ.get("VAULT_AUDIT_LOG", "~/.local/state/ssh-vault/audit.log")).expanduser()


@dataclass
class Config:
    servers: dict[str, Server] = field(default_factory=dict)
    secrets: dict[str, Secret] = field(default_factory=dict)
    value_of: Callable[[str], str | None] = lambda name: None
    command_timeout: int = 60
    max_output_bytes: int = 64 * 1024
    audit_log: Path = field(default_factory=lambda: default_audit_log())
    ssh_binary: str = "ssh"
    agent_sock: str | None = None       # ssh-agent efímero con las llaves de la bóveda
    known_hosts: str | None = None      # archivo temporal con las huellas fijadas
    keys_dir: str | None = None         # partes públicas de las llaves, para elegir cuál usar


def secret_from_spec(name: str, spec: dict) -> Secret:
    if not NAME_RE.match(name):
        raise ValueError(f"nombre de secreto inválido: {name!r}")
    base_url = spec.get("base_url")
    if base_url is not None:
        parts = urlsplit(base_url)
        local = parts.hostname in ("127.0.0.1", "localhost", "::1")
        if parts.scheme != "https" and not (parts.scheme == "http" and local):
            raise ValueError(f"{name}: base_url debe usar https")
        if not parts.hostname or parts.query or parts.fragment or "@" in parts.netloc:
            raise ValueError(f"{name}: base_url inválida: {base_url!r}")
        if not base_url.endswith("/"):
            base_url += "/"
    header_name, _, header_fmt = (spec.get("header") or "Authorization: Bearer {secret}").partition(":")
    if "{secret}" not in header_fmt:
        raise ValueError(f"{name}: 'header' debe contener {{secret}}")
    return Secret(
        name=name,
        description=spec.get("description", ""),
        base_url=base_url,
        auth_header=header_name.strip(),
        auth_format=header_fmt.strip(),
        extra_headers=tuple((str(k), str(v)) for k, v in (spec.get("extra_headers") or {}).items()),
    )


def server_from_spec(name: str, spec: dict) -> Server:
    if not NAME_RE.match(name):
        raise ValueError(f"nombre de servidor inválido: {name!r}")
    host, user = spec["host"], spec.get("user", "root")
    if host.startswith("-") or not HOST_RE.match(host):
        raise ValueError(f"host inválido para {name!r}: {host!r}")
    if not USER_RE.match(user):
        raise ValueError(f"usuario inválido para {name!r}: {user!r}")
    port = int(spec.get("port", 22))
    if not 0 < port < 65536:
        raise ValueError(f"puerto inválido para {name!r}")
    read_only = bool(spec.get("read_only", False))
    patterns = spec.get("allow_commands")
    if not patterns and read_only:
        patterns = READ_ONLY_DEFAULTS
    return Server(
        name=name, host=host, user=user, port=port, key=spec.get("key", ""),
        host_keys=tuple(spec.get("host_keys", ())), description=spec.get("description", ""),
        read_only=read_only, allow_commands=tuple(re.compile(p) for p in (patterns or ())),
    )
