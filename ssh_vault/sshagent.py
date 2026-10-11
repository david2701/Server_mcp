"""ssh-agent efímero con las llaves de la bóveda.

Las llaves privadas pasan por stdin directamente al agente y nunca se escriben en
disco. En la carpeta temporal (0700) solo quedan datos públicos: el socket del
agente, las huellas fijadas de los servidores y las partes públicas de las llaves.
Todo se destruye al salir.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from .bundle import Bundle
from .config import Config, Server, secret_from_spec, server_from_spec


def known_hosts_line(server: Server, host_key: str) -> str:
    host = server.host if server.port == 22 else f"[{server.host}]:{server.port}"
    return f"{host} {host_key}"


@contextmanager
def session(bundle: Bundle, base: Config | None = None):
    """Devuelve un Config listo para usar: servidores, secretos y agente efímero."""
    tmp = Path(tempfile.mkdtemp(prefix="ssh-vault-"))
    os.chmod(tmp, 0o700)
    agent = None
    try:
        servers = {n: server_from_spec(n, s) for n, s in bundle.servers.items()}
        secrets = {n: secret_from_spec(n, s) for n, s in bundle.secrets.items()}

        (tmp / "known_hosts").write_text(
            "".join(known_hosts_line(s, k) + "\n" for s in servers.values() for k in s.host_keys))
        keys_dir = tmp / "keys"
        keys_dir.mkdir()
        needed = {s.key for s in servers.values() if s.key} & bundle.ssh_keys.keys()
        for name in needed:
            if bundle.ssh_keys[name].get("public"):
                (keys_dir / f"{name}.pub").write_text(bundle.ssh_keys[name]["public"] + "\n")

        sock = tmp / "agent.sock"
        if needed:
            agent = subprocess.Popen(["ssh-agent", "-D", "-a", str(sock)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(100):
                if sock.exists():
                    break
                time.sleep(0.02)
            env = {**os.environ, "SSH_AUTH_SOCK": str(sock)}
            for name in sorted(needed):
                r = subprocess.run(["ssh-add", "-q", "-"], input=bundle.ssh_keys[name]["private"],
                                   text=True, env=env, capture_output=True)
                if r.returncode != 0:
                    raise RuntimeError(f"no se pudo cargar la llave {name!r}: {r.stderr.strip()} "
                                       "(¿tiene frase de paso? dentro de la bóveda no la necesita)")

        values = {n: s.get("value") for n, s in bundle.secrets.items()}
        cfg = replace(base or Config(), servers=servers, secrets=secrets, value_of=values.get,
                      agent_sock=str(sock) if needed else None,
                      known_hosts=str(tmp / "known_hosts"), keys_dir=str(keys_dir))
        yield cfg
    finally:
        if agent:
            agent.terminate()
            try:
                agent.wait(5)
            except subprocess.TimeoutExpired:
                agent.kill()
        shutil.rmtree(tmp, ignore_errors=True)
