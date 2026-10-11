"""Servidor MCP "ssh-vault": expone tus servidores SSH sin exponer tus llaves."""

from __future__ import annotations

import argparse
import asyncio
import hmac

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

from . import runner
from .config import Config, load_config, load_token


def build_mcp(cfg: Config) -> MCPServer:
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
            raise ValueError(f"Servidor desconocido: {name!r}. Usa list_servers.")
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
        runner.audit(cfg, tool="test_connection", server=s.name, exit_code=result.exit_code)
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
            raise ValueError("El comando está vacío.")
        if not s.is_allowed(command):
            runner.audit(cfg, tool="run_command", server=s.name, command=command, denied=True)
            raise PermissionError(f"Comando no permitido en {s.name} por la configuración.")
        result = await runner.run(cfg, s, command, timeout_seconds)
        runner.audit(
            cfg, tool="run_command", server=s.name, command=command,
            exit_code=result.exit_code, duration_s=round(result.duration_s, 2),
        )
        return result.render()

    return mcp


class BearerAuth:
    """Middleware ASGI: exige `Authorization: Bearer <token>` en cada petición HTTP."""

    def __init__(self, app, token: str):
        self.app = app
        self.expected = f"Bearer {token}".encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            supplied = dict(scope.get("headers") or []).get(b"authorization", b"")
            if not hmac.compare_digest(supplied, self.expected):
                await asyncio.sleep(1)  # frena intentos de fuerza bruta
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"text/plain"),
                                        (b"www-authenticate", b"Bearer")]})
                await send({"type": "http.response.body", "body": b"unauthorized"})
                return
        await self.app(scope, receive, send)


def build_app(cfg: Config, token: str):
    hosts = [f"{h}:*" for h in ("127.0.0.1", "localhost", *cfg.allowed_hosts)] + list(cfg.allowed_hosts)
    security = TransportSecuritySettings(
        allowed_hosts=hosts,
        allowed_origins=[f"https://{h}" for h in cfg.allowed_hosts],
    )
    app = build_mcp(cfg).streamable_http_app(transport_security=security, host=cfg.listen_host)
    return BearerAuth(app, token)


def main() -> None:
    parser = argparse.ArgumentParser(description="Servidor MCP ssh-vault")
    parser.add_argument("--config", help="ruta a config.toml")
    args = parser.parse_args()

    import uvicorn
    from pathlib import Path

    cfg = load_config(Path(args.config) if args.config else None)
    if cfg.listen_host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit(
            "ssh-vault sólo escucha en localhost; publícalo en tu red privada con "
            "`tailscale serve`, nunca directamente en Internet."
        )
    uvicorn.run(build_app(cfg, load_token()), host=cfg.listen_host, port=cfg.listen_port,
                log_level="info", proxy_headers=False)


if __name__ == "__main__":
    main()
