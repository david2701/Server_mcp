"""Ejecución de comandos remotos con el binario ssh del sistema.

Las llaves privadas nunca se leen desde Python: ssh usa ~/.ssh, el ssh-agent
y el Llavero de macOS como siempre.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from .config import Config, Server


@dataclass
class Result:
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool
    duration_s: float

    def render(self) -> str:
        parts = [f"exit_code: {self.exit_code} ({self.duration_s:.1f}s)"]
        if self.stdout:
            parts.append("--- stdout ---\n" + self.stdout)
        if self.stderr:
            parts.append("--- stderr ---\n" + self.stderr)
        if self.truncated:
            parts.append("[salida truncada]")
        return "\n".join(parts)


def ssh_argv(cfg: Config, server: Server, command: str) -> list[str]:
    return [
        cfg.ssh_binary,
        "-o", "BatchMode=yes",            # nunca pedir contraseñas de forma interactiva
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=yes",  # sólo hosts ya presentes en known_hosts
        "-o", "ForwardAgent=no",
        "-T",
        "--", server.host, command,
    ]


async def run(cfg: Config, server: Server, command: str, timeout: int | None = None) -> Result:
    timeout = min(timeout or cfg.command_timeout, cfg.command_timeout)
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *ssh_argv(cfg, server, command),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
        code = proc.returncode or 0
    except asyncio.TimeoutError:
        proc.kill()
        out, err = await proc.communicate()
        code = -1
        err += f"\n[timeout tras {timeout}s]".encode()

    limit = cfg.max_output_bytes
    truncated = len(out) > limit or len(err) > limit
    return Result(
        exit_code=code,
        stdout=out[-limit:].decode(errors="replace"),
        stderr=err[-limit:].decode(errors="replace"),
        truncated=truncated,
        duration_s=time.monotonic() - start,
    )


def audit(cfg: Config, **event: object) -> None:
    cfg.audit_log.parent.mkdir(parents=True, exist_ok=True)
    event = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), **event}
    with open(cfg.audit_log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")
