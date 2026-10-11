"""Bóveda portátil: un archivo cifrado con age que puedes llevar a cualquier parte.

- El archivo (por defecto ~/.config/ssh-vault/vault.age) está cifrado en formato age
  estándar y en ASCII: puedes guardarlo en iCloud, en un repo git privado o en un USB.
- Cada dispositivo tiene su propia identidad, y abrirla siempre exige algo tuyo:
    touchid    → la llave vive en el Secure Enclave del Mac (age-plugin-se) y no se
                 puede copiar; cada apertura pide Touch ID.
    passphrase → identidad cifrada con frase de paso (scrypt); en un Mac sin terminal
                 se pide con un diálogo del sistema.
    none       → archivo 0600 sin protección; solo para servidores sin pantalla.
- Cada dispositivo recuerda qué destinatarios y qué revisión ha visto: si alguien añade
  un dispositivo a escondidas o restaura una versión vieja, la bóveda se niega a abrir.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pyrage
from pyrage import passphrase as age_passphrase
from pyrage import plugin, ssh, tag, x25519


def config_dir() -> Path:
    return Path(os.environ.get("SSH_VAULT_HOME", "~/.config/ssh-vault")).expanduser()


def default_vault_path() -> Path:
    return Path(os.environ.get("VAULT_FILE", config_dir() / "vault.age")).expanduser()


class VaultError(Exception):
    pass


class UntrustedRecipients(VaultError):
    pass


class Rollback(VaultError):
    pass


# ─── Interacción con el usuario (también sin terminal, p. ej. desde un MCP) ─────

def ask_secret(prompt: str) -> str:
    if os.environ.get("VAULT_PASSPHRASE"):  # automatización (servidores, pruebas)
        return os.environ["VAULT_PASSPHRASE"]
    if sys.stdin.isatty():
        import getpass
        return getpass.getpass(prompt)
    if sys.platform == "darwin" and shutil.which("osascript"):
        script = (f'display dialog "{prompt}" with title "ssh-vault" default answer "" '
                  'with hidden answer buttons {"Cancelar", "Abrir"} default button "Abrir"')
        r = subprocess.run(["osascript", "-e", script, "-e", "text returned of result"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.rstrip("\n")
        raise VaultError("desbloqueo cancelado")
    raise VaultError("no hay terminal para pedir la frase de paso")


class _PluginCallbacks:
    """Puente entre los plugins de age (Touch ID) y el usuario."""

    def display_message(self, message: str) -> None:
        print(message, file=sys.stderr)

    def confirm(self, message: str, yes: str, no: str | None) -> bool:
        print(message, file=sys.stderr)
        return True

    def request_public_string(self, description: str) -> str | None:
        return ask_secret(description)

    def request_passphrase(self, description: str) -> str | None:
        return ask_secret(description)


# ─── Identidad del dispositivo ──────────────────────────────────────────────────

def identity_file() -> Path:
    return Path(os.environ.get("VAULT_IDENTITY_FILE", config_dir() / "identity.txt")).expanduser()


def touchid_available() -> bool:
    return sys.platform == "darwin" and shutil.which("age-plugin-se") is not None


def _parse_identity_file(path: Path) -> tuple[str, str, str]:
    """→ (protección, llave pública, contenido)"""
    if path.stat().st_mode & 0o077:
        raise VaultError(f"{path} debe tener permisos 0600")
    text = path.read_text()
    meta = {}
    for line in text.splitlines():
        if line.startswith("# ") and ":" in line:
            k, _, v = line[2:].partition(":")
            meta[k.strip().lower()] = v.strip()
    if "AGE-PLUGIN-SE-1" in text:
        protection = "touchid"
    elif "BEGIN AGE ENCRYPTED FILE" in text:
        protection = "passphrase"
    else:
        protection = "none"
    public = meta.get("public key", "")
    pub_file = path.with_suffix(".pub")
    if not public and pub_file.exists():
        public = pub_file.read_text().strip()
    if not public and protection == "none":
        line = next(l for l in text.splitlines() if l.startswith("AGE-SECRET-KEY-"))
        public = str(x25519.Identity.from_str(line).to_public())
    return protection, public, text


def device_public_key() -> str | None:
    path = identity_file()
    return _parse_identity_file(path)[1] if path.exists() else None


def device_protection() -> str | None:
    path = identity_file()
    return _parse_identity_file(path)[0] if path.exists() else None


def unlock_identity():
    """Devuelve la identidad lista para descifrar. Pide Touch ID o la frase de paso."""
    path = identity_file()
    if not path.exists():
        raise VaultError("Este dispositivo no tiene identidad. Ejecuta `vault init` o `vault whoami`.")
    protection, _, text = _parse_identity_file(path)
    if protection == "touchid":
        line = next(l for l in text.splitlines() if l.startswith("AGE-PLUGIN-SE-1"))
        return plugin.IdentityPluginV1("se", [plugin.Identity.from_str(line)], _PluginCallbacks())
    if protection == "passphrase":
        armored = text[text.index("-----BEGIN AGE ENCRYPTED FILE-----"):].encode()
        for _ in range(3):
            try:
                secret = age_passphrase.decrypt(armored, ask_secret("Frase de paso de la bóveda: ")).decode()
                break
            except pyrage.DecryptError:
                print("Frase de paso incorrecta.", file=sys.stderr)
        else:
            raise VaultError("demasiados intentos fallidos")
        line = next(l for l in secret.splitlines() if l.startswith("AGE-SECRET-KEY-"))
        return x25519.Identity.from_str(line)
    line = next(l for l in text.splitlines() if l.startswith("AGE-SECRET-KEY-"))
    return x25519.Identity.from_str(line)


def _write_private(path: Path, content: str, public: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    if public:
        path.with_suffix(".pub").write_text(public + "\n")


def create_identity(protection: str, passphrase: str | None = None) -> str:
    """Crea la identidad de este dispositivo y devuelve su llave pública."""
    path = identity_file()
    if path.exists():
        raise VaultError(f"ya existe una identidad en {path}")
    if protection == "touchid":
        if not touchid_available():
            raise VaultError("Touch ID requiere macOS y `brew install age-plugin-se`")
        out = subprocess.run(
            ["age-plugin-se", "keygen", "--access-control=any-biometry-or-passcode"],
            capture_output=True, text=True, check=True,
        ).stdout
        line = next(l for l in out.splitlines() if l.startswith("AGE-PLUGIN-SE-1"))
        public = next((l.split(":", 1)[1].strip() for l in out.splitlines()
                       if l.lower().startswith("# public key:")), "")
        _write_private(path, f"# ssh-vault: touchid (Secure Enclave; no sirve en otro equipo)\n"
                             f"# public key: {public}\n{line}\n", public)
        return public
    identity = x25519.Identity.generate()
    public = str(identity.to_public())
    if protection == "passphrase":
        if not passphrase:
            raise VaultError("falta la frase de paso")
        armored = age_passphrase.encrypt(f"{identity}\n".encode(), passphrase, armored=True).decode()
        # Archivo age puro: `age -d -i identity.txt …` también funciona (pide la frase).
        _write_private(path, armored, public)
    elif protection == "none":
        _write_private(path, f"# ssh-vault: none (solo para servidores)\n# public key: {public}\n{identity}\n",
                       public)
    else:
        raise VaultError(f"protección desconocida: {protection}")
    return public


# ─── Destinatarios ──────────────────────────────────────────────────────────────

def parse_recipient(text: str):
    """age1… (X25519), age1se1… (Touch ID de otro Mac), age1tag1…, ssh-ed25519 …, ssh-rsa …"""
    text = text.strip()
    if text.startswith("age1se1"):
        return plugin.RecipientPluginV1("se", [plugin.Recipient.from_str(text)], [], _PluginCallbacks())
    if text.startswith("age1tag1"):
        return tag.Recipient.from_str(text)
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


def header_stanzas(data: bytes) -> list[str]:
    """Tipos de destinatario en la cabecera age (sin las entradas de relleno *-grease)."""
    if data.lstrip().startswith(b"-----BEGIN AGE ENCRYPTED FILE-----"):
        body = b"".join(l for l in data.strip().splitlines()[1:-1])
        data = base64.b64decode(body)
    header = data.split(b"\n---", 1)[0].decode("utf-8", "replace")
    types = [l.split()[1] for l in header.splitlines() if l.startswith("-> ") and len(l.split()) > 1]
    return [t for t in types if not t.endswith("-grease")]


# ─── Contenido ──────────────────────────────────────────────────────────────────

@dataclass
class Bundle:
    secrets: dict[str, dict[str, Any]] = field(default_factory=dict)
    ssh_keys: dict[str, dict[str, str]] = field(default_factory=dict)
    servers: dict[str, dict[str, Any]] = field(default_factory=dict)
    tokens: dict[str, dict[str, Any]] = field(default_factory=dict)       # sha256(token) → {name, secrets…}
    recipients: dict[str, str] = field(default_factory=dict)              # nombre → llave pública
    admin: dict[str, str] = field(default_factory=dict)                   # hash de la contraseña del panel
    revision: int = 0

    def to_json(self) -> bytes:
        return json.dumps({"version": 1, "revision": self.revision, "secrets": self.secrets,
                           "ssh_keys": self.ssh_keys, "servers": self.servers, "tokens": self.tokens,
                           "recipients": self.recipients, "admin": self.admin}).encode()

    @classmethod
    def from_json(cls, data: bytes) -> "Bundle":
        raw = json.loads(data)
        if raw.get("version") != 1:
            raise VaultError("versión de bóveda no soportada")
        return cls(raw.get("secrets", {}), raw.get("ssh_keys", {}), raw.get("servers", {}),
                   raw.get("tokens", {}), raw.get("recipients", {}), raw.get("admin", {}),
                   int(raw.get("revision", 0)))


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def encrypt(bundle: Bundle, recipients: list[str]) -> bytes:
    if not recipients:
        raise VaultError("la bóveda necesita al menos un destinatario")
    return pyrage.encrypt(bundle.to_json(), [parse_recipient(r) for r in recipients], armored=True)


def decrypt(data: bytes, identities: list) -> Bundle:
    try:
        return Bundle.from_json(pyrage.decrypt(data, identities))
    except pyrage.DecryptError as err:
        if "plugin" in str(err).lower():
            raise VaultError(str(err)) from None
        raise VaultError("este dispositivo no está autorizado para abrir la bóveda") from None


def ssh_identity(path: Path):
    return ssh.Identity.from_buffer(path.expanduser().read_bytes())


# ─── Estado local: destinatarios fijados y revisión vista ───────────────────────

def _state_path() -> Path:
    return config_dir() / "state.json"


def _load_state() -> dict:
    try:
        return json.loads(_state_path().read_text())
    except (FileNotFoundError, ValueError):
        return {}


def _save_state(state: dict) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".state-")
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh, indent=1)
    os.replace(tmp, path)


def _remember(path: Path, bundle: Bundle) -> None:
    state = _load_state()
    state[str(path.resolve())] = {"recipients": bundle.recipients, "revision": bundle.revision}
    _save_state(state)


def verify(path: Path, data: bytes, bundle: Bundle, *, trust_new: bool = False,
           allow_rollback: bool = False) -> list[str]:
    """Comprueba la bóveda contra lo que este dispositivo ya conocía.

    Devuelve los avisos a mostrar; lanza una excepción si algo es sospechoso.
    """
    notes: list[str] = []
    stanzas = header_stanzas(data)
    if len(stanzas) != len(bundle.recipients):
        raise UntrustedRecipients(
            f"el archivo está cifrado para {len(stanzas)} destinatario/s pero declara "
            f"{len(bundle.recipients)}: alguien pudo añadir una llave oculta. No lo uses.")

    known = _load_state().get(str(path.resolve()))
    if known is None:
        notes.append("Primera vez que este dispositivo abre esta bóveda. Dispositivos autorizados: "
                     + ", ".join(bundle.recipients))
    else:
        new = {n: k for n, k in bundle.recipients.items() if known["recipients"].get(n) != k}
        if new and not trust_new:
            raise UntrustedRecipients(
                "hay dispositivos nuevos que este equipo no conocía: "
                + ", ".join(f"{n} ({k[:20]}…)" for n, k in new.items())
                + ". Si los añadiste tú, ejecuta `vault device trust`.")
        if bundle.revision < known["revision"] and not allow_rollback:
            raise Rollback(
                f"la bóveda está en la revisión {bundle.revision}, pero este equipo ya vio la "
                f"{known['revision']}: alguien pudo restaurar una versión vieja. "
                "Si es intencionado, usa --allow-rollback.")
    _remember(path, bundle)
    return notes


def read(path: Path | None = None, identities: list | None = None, *, trust_new: bool = False,
         allow_rollback: bool = False, quiet: bool = False) -> Bundle:
    path = path or default_vault_path()
    data = path.read_bytes()
    bundle = decrypt(data, identities if identities is not None else [unlock_identity()])
    for note in verify(path, data, bundle, trust_new=trust_new, allow_rollback=allow_rollback):
        if not quiet:
            print(note, file=sys.stderr)
    return bundle


def write(bundle: Bundle, path: Path | None = None) -> None:
    """Escritura atómica; sube la revisión y actualiza lo que este equipo conoce."""
    path = path or default_vault_path()
    bundle.revision += 1
    data = encrypt(bundle, list(bundle.recipients.values()))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".vault-")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)
    _remember(path, bundle)
