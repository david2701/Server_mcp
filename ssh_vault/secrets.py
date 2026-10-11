"""Almacenes de secretos de la bóveda (API keys, tokens...)."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Protocol

KEYCHAIN_SERVICE = "ssh-vault"


class SecretStore(Protocol):
    def get(self, name: str) -> str | None: ...


class KeychainStore:
    """Llavero de macOS: servicio "ssh-vault", cuenta = nombre del secreto.

    Alta desde la bóveda con deploy/secret.sh set <nombre>.
    """

    def get(self, name: str) -> str | None:
        try:
            out = subprocess.run(
                ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", name, "-w"],
                capture_output=True, text=True, check=True,
            ).stdout
        except (FileNotFoundError, subprocess.CalledProcessError):
            return None
        return out.rstrip("\n") or None


class FileStore:
    """Archivo JSON {nombre: valor} con permisos 0600. Pensado para bóvedas Linux
    con disco cifrado; en macOS usa el Llavero."""

    def __init__(self, path: Path):
        self.path = path

    def get(self, name: str) -> str | None:
        mode = os.stat(self.path).st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise PermissionError(f"{self.path} debe tener permisos 0600")
        with open(self.path, encoding="utf-8") as fh:
            value = json.load(fh).get(name)
        return value if isinstance(value, str) and value else None
