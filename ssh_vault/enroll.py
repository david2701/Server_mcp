"""Alta de servidores: una llave SSH propia por servidor y un comando de un solo uso.

1. El panel crea el servidor y genera su par ed25519 (la privada nunca sale de la app).
2. Muestra `curl -fsSL https://<app>/_vault/enroll/<token> | sh` (válido 30 min, un uso).
3. Ese script, ejecutado en el servidor como el usuario destino:
   - quita la llave anterior de ese servidor (si rotas) y añade la nueva a authorized_keys,
     restringida con `restrict` (sin reenvíos ni pty) y `from="<IP de la app>"` si la
     configuras: aunque alguien robara la llave, no podría usarla desde otro sitio;
   - devuelve las huellas reales del servidor (/etc/ssh/ssh_host_*_key.pub), que quedan
     fijadas: si alguien suplanta el servidor después, la app se niega a conectar.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
import time
from dataclasses import dataclass

from .bundle import Bundle
from .config import server_from_spec
from .sshutil import generate_key

ENROLL_TTL = 30 * 60
HOSTKEY_RE = re.compile(r"^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa) [A-Za-z0-9+/=]{40,}$")


def key_name(server: str) -> str:
    return f"srv-{server}"


def authorized_keys_line(public: str, server: str, egress_ip: str = "") -> str:
    opts = "restrict"
    if egress_ip:
        ips = [str(ipaddress.ip_network(ip.strip(), strict=False)) for ip in egress_ip.split(",") if ip.strip()]
        opts = f'from="{",".join(ips)}",{opts}'
    key = " ".join(public.split()[:2])
    return f"{opts} {key} ssh-vault:{server}"


def create_server(bundle: Bundle, name: str, target: str, port: int = 22, *, read_only: bool = False,
                  description: str = "") -> str:
    """Crea (o rota) el servidor con una llave nueva. Devuelve la llave pública."""
    user, _, host = target.strip().rpartition("@")
    spec = {"host": host, "user": user or "root", "port": int(port), "key": key_name(name),
            "host_keys": [], "description": description.strip(), "read_only": read_only, "status": "pendiente"}
    server_from_spec(name, spec)  # valida nombre, host, usuario y puerto
    private, public = generate_key(f"ssh-vault:{name}")
    bundle.ssh_keys[key_name(name)] = {"private": private, "public": public}
    bundle.servers[name] = spec
    return public


def rotate_key(bundle: Bundle, name: str) -> str:
    private, public = generate_key(f"ssh-vault:{name}")
    bundle.ssh_keys[key_name(name)] = {"private": private, "public": public}
    bundle.servers[name]["status"] = "pendiente"
    return public


def delete_server(bundle: Bundle, name: str) -> bool:
    spec = bundle.servers.pop(name, None)
    if spec is None:
        return False
    if spec.get("key") == key_name(name):
        bundle.ssh_keys.pop(key_name(name), None)
    return True


def parse_host_keys(text: str) -> list[str]:
    keys = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and HOSTKEY_RE.match(f"{parts[0]} {parts[1]}"):
            keys.append(f"{parts[0]} {parts[1]}")
    return sorted(set(keys))


@dataclass
class Enrollment:
    server: str
    expires: float
    fetched: bool = False


class Enrollments:
    """Tokens de alta de un solo uso (en memoria: caducan en 30 min)."""

    def __init__(self):
        self.items: dict[str, Enrollment] = {}

    def create(self, server: str) -> str:
        self.items = {t: e for t, e in self.items.items() if e.server != server and e.expires > time.time()}
        token = secrets.token_urlsafe(24)
        self.items[token] = Enrollment(server, time.time() + ENROLL_TTL)
        return token

    def get(self, token: str) -> Enrollment | None:
        e = self.items.get(token)
        if e and e.expires > time.time():
            return e
        self.items.pop(token, None)
        return None

    def consume(self, token: str) -> None:
        self.items.pop(token, None)


def script(base_url: str, token: str, line: str, server: str) -> str:
    """Script POSIX sh que se ejecuta en el servidor destino."""
    q = line.replace("'", "'\\''")
    return f"""#!/bin/sh
# Alta en ssh-vault del servidor «{server}». Se ejecuta como el usuario con el que conectará la app.
set -eu
umask 077
mkdir -p "$HOME/.ssh"
AK="$HOME/.ssh/authorized_keys"
touch "$AK"
# Quita una llave anterior de este mismo servidor (rotación) y añade la nueva.
grep -v ' ssh-vault:{server}$' "$AK" > "$AK.tmp" || true
printf '%s\\n' '{q}' >> "$AK.tmp"
mv "$AK.tmp" "$AK"
chmod 600 "$AK"
# Envía las huellas públicas de este servidor para fijarlas en la app.
cat ${{VAULT_HOSTKEYS:-/etc/ssh/ssh_host_*_key.pub}} 2>/dev/null \\
  | curl -fsS -X POST --data-binary @- '{base_url}/_vault/enroll/{token}/hostkeys'
echo
echo "Listo: la app ya puede conectarse a este servidor como $(id -un)."
"""
