"""Servidor MCP "ssh-vault": expone tus servidores SSH sin exponer tus llaves.

Habla MCP por stdio. Las Macs cliente lo lanzan con `ssh <mac-bóveda>`, y la
bóveda lo fuerza con `command="..."` en authorized_keys (ver deploy/add-client.sh).
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import apiproxy, runner
from .config import NAME_RE, Config, load_config


def build_mcp(cfg: Config, client: str = "local") -> MCPServer:
    mcp = MCPServer(
        name="ssh-vault",
        instructions=(
            "Bóveda personal del usuario. Ejecuta comandos en sus servidores "
            "(list_servers, run_command) y llama a APIs con sus claves "
            "(list_secrets, call_api). Las llaves SSH y los valores de los "
            "secretos nunca están disponibles a través de este servidor."
        ),
    )

    def get_server(name: str):
        server = cfg.servers.get(name)
        if server is None:
            raise ToolError(f"Servidor desconocido: {name!r}. Usa list_servers.")
        return server

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def list_servers() -> str:
        """Lista los servidores configurados y sus restricciones."""
        if not cfg.servers:
            return "No hay servidores configurados."
        lines = []
        for s in cfg.servers.values():
            if s.read_only:
                mode = "solo lectura"
            elif s.allow_commands:
                mode = "solo comandos permitidos"
            else:
                mode = "completo"
            lines.append(f"- {s.name} [{mode}] {s.description}".rstrip())
        return "\n".join(lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def test_connection(server: str) -> str:
        """Comprueba que la Mac bóveda puede autenticarse en el servidor."""
        s = get_server(server)
        result = await runner.run(cfg, s, "true", timeout=20)
        runner.audit(cfg, client=client, tool="test_connection", server=s.name, exit_code=result.exit_code)
        return "OK" if result.exit_code == 0 else result.render()

    @mcp.tool(annotations=ToolAnnotations(destructiveHint=True, openWorldHint=True))
    async def run_command(server: str, command: str, timeout_seconds: int | None = None) -> str:
        """Ejecuta un comando de shell en un servidor configurado y devuelve su salida.

        Args:
            server: nombre del servidor tal como aparece en list_servers.
            command: comando a ejecutar en el shell remoto.
            timeout_seconds: límite opcional (no puede superar el máximo configurado).
        """
        s = get_server(server)
        if not command.strip():
            raise ToolError("El comando está vacío.")
        if not s.is_allowed(command):
            runner.audit(cfg, client=client, tool="run_command", server=s.name, command=command, denied=True)
            raise ToolError(f"Comando no permitido en {s.name} por la configuración.")
        result = await runner.run(cfg, s, command, timeout_seconds)
        runner.audit(
            cfg, client=client, tool="run_command", server=s.name, command=command,
            exit_code=result.exit_code, duration_s=round(result.duration_s, 2),
        )
        return result.render()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def list_secrets() -> str:
        """Lista los secretos de la bóveda (nunca sus valores) y a qué API dan acceso."""
        if not cfg.secrets:
            return "No hay secretos configurados."
        lines = []
        for sec in cfg.secrets.values():
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
        sec = cfg.secrets.get(secret)
        if sec is None:
            raise ToolError(f"Secreto desconocido: {secret!r}. Usa list_secrets.")
        value = cfg.store.get(sec.name)
        if value is None:
            raise ToolError(f"El secreto {secret!r} no tiene valor en la bóveda.")
        if body is not None and not isinstance(body, str):
            body = json.dumps(body)
        try:
            resp = await apiproxy.call(sec, value, method, path, body, headers,
                                       cfg.command_timeout, cfg.max_output_bytes)
        except apiproxy.ProxyError as err:
            runner.audit(cfg, client=client, tool="call_api", secret=sec.name, method=method,
                         path=path, error=str(err))
            raise ToolError(str(err)) from None
        runner.audit(cfg, client=client, tool="call_api", secret=sec.name, method=method.upper(),
                     path=path, status=resp.status)
        return f"status: {resp.status}\n{resp.body}" + ("\n[respuesta truncada]" if resp.truncated else "")

    return mcp


def reveal(cfg: Config, client: str, args: list[str]) -> int:
    """`get <secreto>...` para apps: imprime los valores solo si el cliente puede verlos.

    Un nombre: imprime el valor tal cual. Varios: imprime un objeto JSON.
    """
    allowed = cfg.clients[client].reveal if client in cfg.clients else frozenset()
    if not args:
        print("uso: get <secreto> [<secreto>...]", file=sys.stderr)
        return 2
    values: dict[str, str] = {}
    for name in args:
        value = cfg.store.get(name) if name in allowed else None
        runner.audit(cfg, client=client, tool="get", secret=name, denied=value is None)
        if name not in allowed:
            print(f"denegado: {client} no puede leer {name!r}", file=sys.stderr)
            return 1
        if value is None:
            print(f"el secreto {name!r} no tiene valor", file=sys.stderr)
            return 1
        values[name] = value
    if len(values) == 1:
        sys.stdout.write(next(iter(values.values())) + "\n")
    else:
        sys.stdout.write(json.dumps(values) + "\n")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Bóveda ssh-vault (MCP por stdio + secretos para apps)")
    parser.add_argument("--config", help="ruta a config.toml")
    parser.add_argument("--client", default="local", help="nombre del cliente, para permisos y auditoría")
    parser.add_argument("--role", choices=("mcp", "app"), default="mcp",
                        help="mcp: Claude + get; app: solo get (para apps y servidores)")
    args = parser.parse_args()
    if not NAME_RE.match(args.client):
        raise SystemExit(f"nombre de cliente inválido: {args.client!r}")
    cfg = load_config(Path(args.config) if args.config else None)

    # Con command= en authorized_keys, sshd pone aquí lo que pidió el cliente.
    try:
        requested = shlex.split(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    except ValueError:
        requested = ["<inválido>"]
    if requested[:1] == ["get"]:
        raise SystemExit(reveal(cfg, args.client, requested[1:]))
    if args.role != "mcp" or requested not in ([], ["mcp"]):
        print("solo se permite: get <secreto>" + (" o mcp" if args.role == "mcp" else ""), file=sys.stderr)
        raise SystemExit(2)
    build_mcp(cfg, client=args.client).run("stdio")


if __name__ == "__main__":
    main()
