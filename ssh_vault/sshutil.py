"""Utilidades SSH compartidas por el CLI y el panel local."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


class SshError(Exception):
    pass


def scan_host_keys(host: str, port: int) -> list[str]:
    """Huellas públicas del servidor (para fijarlas en la bóveda)."""
    if host.startswith("-"):
        raise SshError("host inválido")
    r = subprocess.run(["ssh-keyscan", "-T", "8", "-p", str(port), "--", host], capture_output=True, text=True)
    keys = sorted({f"{p[1]} {p[2]}" for line in r.stdout.splitlines()
                   if not line.startswith("#") and len(p := line.split()) >= 3})
    if not keys:
        raise SshError(f"no pude obtener las huellas de {host}:{port} ({r.stderr.strip() or 'sin respuesta'})")
    return keys


def fingerprints(keys: list[str]) -> list[str]:
    r = subprocess.run(["ssh-keygen", "-lf", "-"], input="".join(f"x {k}\n" for k in keys),
                       capture_output=True, text=True)
    return r.stdout.splitlines()


def _with_private_file(private: str, fn):
    """Algunas operaciones de ssh-keygen exigen un archivo: carpeta 0700, y se borra al acabar."""
    tmp = Path(tempfile.mkdtemp(prefix="ssh-vault-k-"))
    try:
        os.chmod(tmp, 0o700)
        path = tmp / "key"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(private if private.endswith("\n") else private + "\n")
        return fn(path)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def public_from_private(private: str) -> str:
    """Deriva la llave pública. Falla si la privada no es válida o tiene frase de paso."""
    if "PRIVATE KEY-----" not in private:
        raise SshError("no parece una llave privada")

    def derive(path: Path) -> str:
        r = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", str(path)], capture_output=True, text=True)
        if r.returncode != 0:
            raise SshError("la llave tiene frase de paso o no es válida (dentro de la bóveda no necesita frase)")
        return r.stdout.strip()

    return _with_private_file(private, derive)


def generate_key(comment: str) -> tuple[str, str]:
    """Genera un par ed25519 nuevo → (privada, pública)."""
    tmp = Path(tempfile.mkdtemp(prefix="ssh-vault-g-"))
    try:
        os.chmod(tmp, 0o700)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(tmp / "key")],
                       check=True, capture_output=True)
        return (tmp / "key").read_text(), (tmp / "key.pub").read_text().strip()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
