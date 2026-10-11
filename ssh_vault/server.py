"""Servidor MCP "ssh-vault": expone tus servidores SSH sin exponer tus llaves.

Habla MCP por stdio. Las Macs cliente lo lanzan con `ssh <mac-bóveda>`, y la
bóveda lo fuerza con `command="..."` en authorized_keys (ver deploy/add-client.sh).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import runner
from .config import NAME_RE, Config, load_config


def build_mcp(cfg: Config, client: str = "local") -> MCPServer:
    mcp = MCPServer(
        name="ssh-vault",
        instructions=(
            "Ejecuta comandos en los servidores del usuario a través de la Mac que "
            "guarda sus llaves SSH. Usa list_servers primero. Las llaves privadas "
            "nunca están disponibles a través de este servidor."
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

    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="Servidor MCP ssh-vault (stdio)")
    parser.add_argument("--config", help="ruta a config.toml")
    parser.add_argument("--client", default="local", help="nombre de la Mac cliente, para la auditoría")
    args = parser.parse_args()
    if not NAME_RE.match(args.client):
        raise SystemExit(f"nombre de cliente inválido: {args.client!r}")

    cfg = load_config(Path(args.config) if args.config else None)
    build_mcp(cfg, client=args.client).run("stdio")


if __name__ == "__main__":
    main()
