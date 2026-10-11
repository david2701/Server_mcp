"""Carga de configuración."""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .secrets import FileStore, KeychainStore, SecretStore

DEFAULT_CONFIG = Path("~/.config/ssh-vault/config.toml").expanduser()
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
class Secret:
    name: str
    description: str = ""
    # Si hay base_url, la bóveda puede usar el secreto como proxy (call_api) SOLO
    # contra ese prefijo. Sin base_url, el secreto solo sirve para `get`.
    base_url: str | None = None
    auth_header: str = "Authorization"
    auth_format: str = "Bearer {secret}"
    extra_headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Client:
    name: str
    reveal: frozenset[str] = frozenset()  # secretos que puede leer en claro


@dataclass(frozen=True)
class Config:
    servers: dict[str, Server]
    secrets: dict[str, Secret] = field(default_factory=dict)
    clients: dict[str, Client] = field(default_factory=dict)
    store: SecretStore = field(default_factory=KeychainStore)
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


def load_config(path: Path | None = None) -> Config:
    path = path or Path(os.environ.get("SSH_VAULT_CONFIG", DEFAULT_CONFIG))
    if not path.exists() and path == DEFAULT_CONFIG:
        raw = {}  # sin config.toml: sin servidores, todo sale de la bóveda portátil
    else:
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

    secrets: dict[str, Secret] = {}
    for name, spec in raw.get("secrets", {}).items():
        if not NAME_RE.match(name):
            raise ValueError(f"nombre de secreto inválido: {name!r}")
        secrets[name] = secret_from_spec(name, spec)

    clients: dict[str, Client] = {}
    for name, spec in raw.get("clients", {}).items():
        reveal = frozenset(spec.get("reveal", ()))
        unknown = reveal - secrets.keys()
        if unknown:
            raise ValueError(f"cliente {name!r}: secretos no declarados {sorted(unknown)}")
        clients[name] = Client(name=name, reveal=reveal)

    store: SecretStore
    backend = raw.get("secrets_backend", "keychain")
    if backend == "keychain":
        store = KeychainStore()
    elif backend == "file":
        store = FileStore(Path(raw["secrets_file"]).expanduser())
    else:
        raise ValueError(f"secrets_backend desconocido: {backend!r}")

    kwargs = {k: raw[k] for k in ("command_timeout", "max_output_bytes", "ssh_binary") if k in raw}
    if "audit_log" in raw:
        kwargs["audit_log"] = Path(raw["audit_log"]).expanduser()
    return Config(servers=servers, secrets=secrets, clients=clients, store=store, **kwargs)
