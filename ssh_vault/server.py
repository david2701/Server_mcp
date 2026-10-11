"""Servidor MCP de la bóveda: tus agentes usan tus servidores y tus APIs sin ver
ni las llaves SSH ni las claves.

- Local: `vault mcp` (stdio) en una Mac.
- Remoto: `/mcp` de la app autoalojada (ver hosted.py); cada acceso (token u OAuth)
  solo ve los servidores y APIs que le diste.
"""

from __future__ import annotations

import json
from typing import Callable

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import apiproxy, runner
from .config import Config


Access = Callable[[], "tuple[str, Callable[[str, str], bool]]"]


def build_mcp(cfg: Config | Callable[[], Config], client: str = "local", access: Access | None = None,
              **mcp_kwargs) -> MCPServer:
    """`cfg` puede ser un Config o una función que devuelve el actual (la app lo cambia en vivo).
    `access()` devuelve (quién llama, permitido(tipo, nombre)) para la petición en curso."""
    current = cfg if callable(cfg) else (lambda: cfg)
    access = access or (lambda: (client, lambda kind, name: True))
    mcp = MCPServer(**mcp_kwargs,
        name="ssh-vault",
        instructions=(
            "Bóveda personal del usuario. Ejecuta comandos en sus servidores "
            "(list_servers, run_command) y llama a APIs con sus claves "
            "(list_secrets, call_api). Las llaves SSH y los valores de los "
            "secretos nunca están disponibles a través de este servidor."
        ),
    )

    def get_server(name: str):
        who, allowed = access()
        server = current().servers.get(name)
        if server is None or not allowed("server", name):
            raise ToolError(f"Servidor desconocido o sin permiso: {name!r}. Usa list_servers.")
        return server, who

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def list_servers() -> str:
        """Lista los servidores a los que tienes acceso y sus restricciones."""
        _, allowed = access()
        visible = [s for s in current().servers.values() if allowed("server", s.name)]
        if not visible:
            return "No hay servidores disponibles para este acceso."
        lines = []
        for s in visible:
            if s.read_only:
                mode = "solo lectura"
            elif s.allow_commands:
                mode = "solo comandos permitidos"
            else:
                mode = "completo"
            lines.append(f"- {s.name} ({s.user}@{s.host}:{s.port}) [{mode}] {s.description}".rstrip())
        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def test_connection(server: str) -> str:
        """Comprueba que la bóveda puede autenticarse en el servidor."""
        s, who = get_server(server)
        cfg = current()
        result = await runner.run(cfg, s, "true", timeout=20)
        runner.audit(cfg, client=who, tool="test_connection", server=s.name, exit_code=result.exit_code)
        return "OK" if result.exit_code == 0 else result.render()

    @mcp.tool(annotations=ToolAnnotations(destructiveHint=True, openWorldHint=True))
    async def run_command(server: str, command: str, timeout_seconds: int | None = None) -> str:
        """Ejecuta un comando de shell en un servidor configurado y devuelve su salida.

        Args:
            server: nombre del servidor tal como aparece en list_servers.
            command: comando a ejecutar en el shell remoto.
            timeout_seconds: límite opcional (no puede superar el máximo configurado).
        """
        s, who = get_server(server)
        cfg = current()
        if not command.strip():
            raise ToolError("El comando está vacío.")
        if not s.is_allowed(command):
            runner.audit(cfg, client=who, tool="run_command", server=s.name, command=command, denied=True)
            raise ToolError(f"Comando no permitido en {s.name} por la configuración.")
        result = await runner.run(cfg, s, command, timeout_seconds)
        runner.audit(
            cfg, client=who, tool="run_command", server=s.name, command=command,
            exit_code=result.exit_code, duration_s=round(result.duration_s, 2),
        )
        return result.render()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def list_secrets() -> str:
        """Lista las APIs que puedes usar con call_api (nunca muestra las claves)."""
        _, allowed = access()
        visible = [x for x in current().secrets.values() if allowed("secret", x.name)]
        if not visible:
            return "No hay APIs disponibles para este acceso."
        lines = []
        for sec in visible:
            target = f"call_api → {sec.base_url}" if sec.base_url else "solo para apps (sin proxy)"
            lines.append(f"- {sec.name} [{target}] {sec.description}".rstrip())
        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(openWorldHint=True))
    async def call_api(
        secret: str,
        path: str,
        method: str = "GET",
        body: dict | list | str | None = None,
        headers: dict[str, str] | None = None,
    ) -> str:
        """Llama a una API usando una clave de la bóveda, que la inyecta sin revelarla.

        Args:
            secret: nombre del secreto tal como aparece en list_secrets.
            path: ruta relativa a la base_url del secreto (p. ej. "models" o "messages").
            method: GET, POST, PUT, PATCH o DELETE.
            body: cuerpo JSON (objeto o texto, opcional).
            headers: cabeceras extra (las de autenticación están prohibidas).
        """
        who, allowed = access()
        cfg = current()
        sec = cfg.secrets.get(secret)
        if sec is None or not allowed("secret", secret):
            raise ToolError(f"Secreto desconocido o sin permiso: {secret!r}. Usa list_secrets.")
        value = cfg.value_of(sec.name)
        if value is None:
            raise ToolError(f"El secreto {secret!r} no tiene valor en la bóveda.")
        if body is not None and not isinstance(body, str):
            body = json.dumps(body)
        try:
            resp = await apiproxy.call(sec, value, method, path, body, headers,
                                       cfg.command_timeout, cfg.max_output_bytes)
        except apiproxy.ProxyError as err:
            runner.audit(cfg, client=who, tool="call_api", secret=sec.name, method=method,
                         path=path, error=str(err))
            raise ToolError(str(err)) from None
        runner.audit(cfg, client=who, tool="call_api", secret=sec.name, method=method.upper(),
                     path=path, status=resp.status)
        return f"status: {resp.status}\n{resp.body}" + ("\n[respuesta truncada]" if resp.truncated else "")

    return mcp
