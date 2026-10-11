"""Bóveda portátil: un archivo cifrado con age que puedes llevar a cualquier parte.

- El archivo (por defecto ~/.config/ssh-vault/vault.age) está cifrado en formato age
  estándar y en ASCII, así que puedes guardarlo en iCloud, en un repo git privado o
  en un USB. Si alguien lo copia, no puede leerlo sin una identidad autorizada.
- Cada dispositivo tiene su propia identidad age (en el Llavero de macOS o en un
  archivo 0600). El archivo se cifra para todos los dispositivos autorizados, más
  una llave de recuperación que guardas fuera de línea.
- Compatible con el CLI oficial: `age -d -i identidad.txt vault.age`.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pyrage
from pyrage import ssh, x25519

CONFIG_DIR = Path(os.environ.get("SSH_VAULT_HOME", "~/.config/ssh-vault")).expanduser()
KEYCHAIN_SERVICE = "ssh-vault-identity"


def default_vault_path() -> Path:
    return Path(os.environ.get("VAULT_FILE", CONFIG_DIR / "vault.age")).expanduser()


# ─── Identidad del dispositivo ──────────────────────────────────────────────────

def _identity_file() -> Path:
    return Path(os.environ.get("VAULT_IDENTITY_FILE", CONFIG_DIR / "identity.txt")).expanduser()


def _use_keychain() -> bool:
    return sys.platform == "darwin" and "VAULT_IDENTITY_FILE" not in os.environ


def load_identity() -> x25519.Identity | None:
    if _use_keychain():
        try:
            secret = subprocess.run(
                ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", "default", "-w"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
        except subprocess.CalledProcessError:
            return None
        return x25519.Identity.from_str(secret)
    path = _identity_file()
    if not path.exists():
        return None
    if path.stat().st_mode & 0o077:
        raise PermissionError(f"{path} debe tener permisos 0600")
    lines = [l for l in path.read_text().splitlines() if l.startswith("AGE-SECRET-KEY-")]
    return x25519.Identity.from_str(lines[0]) if lines else None


def create_identity() -> x25519.Identity:
    identity = x25519.Identity.generate()
    if _use_keychain():
        subprocess.run(
            ["security", "add-generic-password", "-U", "-s", KEYCHAIN_SERVICE, "-a", "default",
             "-T", "/usr/bin/security", "-w", str(identity)],
            check=True, capture_output=True,
        )
    else:
        path = _identity_file()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(f"# identidad de ssh-vault; pública: {identity.to_public()}\n{identity}\n")
    return identity


# ─── Destinatarios ──────────────────────────────────────────────────────────────

def parse_recipient(text: str):
    """age1…, ssh-ed25519 …, ssh-rsa …"""
    text = text.strip()
    if text.startswith("age1"):
        return x25519.Recipient.from_str(text)
    if text.startswith(("ssh-ed25519 ", "ssh-rsa ")):
        return ssh.Recipient.from_str(" ".join(text.split()[:2]))
    raise ValueError(f"destinatario no reconocido: {text[:30]!r} (usa age1… o ssh-ed25519 …)")


def resolve_recipients(spec: str) -> list[str]:
    """Acepta una llave, una ruta a .pub o github:usuario (sus llaves SSH públicas)."""
    if spec.startswith("github:"):
        import urllib.request
        user = spec.split(":", 1)[1]
        if not user.replace("-", "").isalnum():
            raise ValueError(f"usuario de GitHub inválido: {user!r}")
        with urllib.request.urlopen(f"https://github.com/{user}.keys", timeout=15) as resp:
            keys = [k for k in resp.read().decode().splitlines() if k.startswith(("ssh-ed25519 ", "ssh-rsa "))]
        if not keys:
            raise ValueError(f"github:{user} no tiene llaves ed25519/rsa públicas")
        return keys
    path = Path(spec).expanduser()
    if path.is_file():
        return [l.strip() for l in path.read_text().splitlines() if l.strip() and not l.startswith("#")]
    return [spec]


# ─── Contenido ──────────────────────────────────────────────────────────────────

@dataclass
class Bundle:
    secrets: dict[str, dict[str, Any]] = field(default_factory=dict)
    ssh_keys: dict[str, dict[str, str]] = field(default_factory=dict)
    tokens: dict[str, dict[str, Any]] = field(default_factory=dict)       # sha256(token) → {name, secrets}
    recipients: dict[str, str] = field(default_factory=dict)              # nombre → llave pública

    def to_json(self) -> bytes:
        return json.dumps({"version": 1, "secrets": self.secrets, "ssh_keys": self.ssh_keys,
                           "tokens": self.tokens, "recipients": self.recipients}).encode()

    @classmethod
    def from_json(cls, data: bytes) -> "Bundle":
        raw = json.loads(data)
        if raw.get("version") != 1:
            raise ValueError("versión de bóveda no soportada")
        return cls(raw.get("secrets", {}), raw.get("ssh_keys", {}), raw.get("tokens", {}),
                   raw.get("recipients", {}))

    def token_lookup(self, token: str) -> dict[str, Any] | None:
        return self.tokens.get(hash_token(token))


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def encrypt(bundle: Bundle, recipients: list[str]) -> bytes:
    if not recipients:
        raise ValueError("la bóveda necesita al menos un destinatario")
    return pyrage.encrypt(bundle.to_json(), [parse_recipient(r) for r in recipients], armored=True)


def decrypt(data: bytes, identities: list) -> Bundle:
    try:
        return Bundle.from_json(pyrage.decrypt(data, identities))
    except pyrage.DecryptError:
        raise PermissionError("este dispositivo no está autorizado para abrir la bóveda") from None


def ssh_identity(path: Path):
    return ssh.Identity.from_buffer(path.expanduser().read_bytes())


def read(path: Path | None = None, identities: list | None = None) -> Bundle:
    path = path or default_vault_path()
    if identities is None:
        identity = load_identity()
        if identity is None:
            raise SystemExit("Este dispositivo no tiene identidad. Ejecuta `vault init` o `vault whoami`.")
        identities = [identity]
    return decrypt(path.read_bytes(), identities)


def write(bundle: Bundle, path: Path | None = None) -> None:
    """Escritura atómica: nunca deja la bóveda a medias."""
    path = path or default_vault_path()
    data = encrypt(bundle, list(bundle.recipients.values()))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".vault-")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)
