"""ssh-agent privado con las llaves de la bóveda.

Las llaves privadas pasan por stdin directamente al agente y nunca se escriben en
disco. En la carpeta temporal (0700) solo hay datos públicos: el socket del agente,
las huellas fijadas de los servidores y las partes públicas de las llaves.

- `session()`: agente efímero para un comando o una sesión del CLI/MCP local.
- `AgentManager`: agente que vive mientras la app está en marcha y se resincroniza
  cuando añades, rotas o borras servidores desde el panel.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from .bundle import Bundle
from .config import Config, Server, secret_from_spec, server_from_spec


def known_hosts_line(server: Server, host_key: str) -> str:
    host = server.host if server.port == 22 else f"[{server.host}]:{server.port}"
    return f"{host} {host_key}"


class AgentManager:
    def __init__(self, base: Config | None = None):
        self.base = base or Config()
        self.tmp = Path(tempfile.mkdtemp(prefix="ssh-vault-"))
        os.chmod(self.tmp, 0o700)
        (self.tmp / "keys").mkdir()
        self.sock = self.tmp / "agent.sock"
        self.proc: subprocess.Popen | None = None
        self.loaded: dict[str, str] = {}  # nombre → pública cargada en el agente
        self.lock = threading.Lock()
        self.cfg = self.base

    def _env(self) -> dict[str, str]:
        return {**os.environ, "SSH_AUTH_SOCK": str(self.sock)}

    def _start(self) -> None:
        if self.proc and self.proc.poll() is None:
            return
        self.sock.unlink(missing_ok=True)
        self.proc = subprocess.Popen(["ssh-agent", "-D", "-a", str(self.sock)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(200):
            if self.sock.exists():
                return
            time.sleep(0.02)
        raise RuntimeError("ssh-agent no arrancó")

    def sync(self, bundle: Bundle) -> Config:
        """Ajusta agente, huellas y llaves públicas a lo que dice la bóveda."""
        with self.lock:
            servers = {n: server_from_spec(n, s) for n, s in bundle.servers.items()}
            secrets = {n: secret_from_spec(n, s) for n, s in bundle.secrets.items()}
            (self.tmp / "known_hosts").write_text(
                "".join(known_hosts_line(s, k) + "\n" for s in servers.values() for k in s.host_keys))

            needed = {s.key: bundle.ssh_keys[s.key] for s in servers.values()
                      if s.key and s.key in bundle.ssh_keys}
            if needed:
                self._start()
            for name, pub in list(self.loaded.items()):
                if needed.get(name, {}).get("public") != pub:
                    pub_file = self.tmp / "keys" / f"{name}.pub"
                    subprocess.run(["ssh-add", "-d", str(pub_file)], env=self._env(), capture_output=True)
                    pub_file.unlink(missing_ok=True)
                    del self.loaded[name]
            for name, key in needed.items():
                if name in self.loaded:
                    continue
                r = subprocess.run(["ssh-add", "-q", "-"], input=key["private"], text=True,
                                   env=self._env(), capture_output=True)
                if r.returncode != 0:
                    raise RuntimeError(f"no se pudo cargar la llave {name!r}: {r.stderr.strip()} "
                                       "(¿tiene frase de paso? dentro de la bóveda no la necesita)")
                (self.tmp / "keys" / f"{name}.pub").write_text(key["public"] + "\n")
                self.loaded[name] = key["public"]

            values = {n: s.get("value") for n, s in bundle.secrets.items()}
            self.cfg = replace(self.base, servers=servers, secrets=secrets, value_of=values.get,
                               agent_sock=str(self.sock) if self.loaded else None,
                               known_hosts=str(self.tmp / "known_hosts"), keys_dir=str(self.tmp / "keys"))
            return self.cfg

    def close(self) -> None:
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        shutil.rmtree(self.tmp, ignore_errors=True)


@contextmanager
def session(bundle: Bundle, base: Config | None = None):
    """Agente efímero: devuelve un Config listo para usar y lo destruye todo al salir."""
    manager = AgentManager(base)
    try:
        yield manager.sync(bundle)
    finally:
        manager.close()
