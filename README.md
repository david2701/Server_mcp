# ssh-vault — MCP personal para tus servidores SSH

Usa los accesos SSH que viven en **una** de tus MacBook desde **cualquiera** de tus
Macs (con Claude Code) sin copiar nunca las llaves privadas.

```
 MacBook A / B / C (clientes)                 MacBook "bóveda"                    Tus servidores
┌────────────────────────┐   Tailscale    ┌──────────────────────────┐    SSH     ┌───────────┐
│ Claude Code            │ ── HTTPS ────▶ │ tailscale serve :443     │ ─────────▶ │ web-prod  │
│  MCP "ssh-vault"       │  (WireGuard,   │   └▶ ssh-vault 127.0.0.1 │            │ db        │
│  Authorization: Bearer │   solo tu red) │       └▶ /usr/bin/ssh    │            │ backups   │
└────────────────────────┘                │  ~/.ssh + Llavero macOS  │            └───────────┘
                                          └──────────────────────────┘
```

## Modelo de seguridad

| Capa | Qué protege |
|---|---|
| **Las llaves no se mueven** | El servicio solo invoca `ssh`; ninguna herramienta MCP lee ni devuelve `~/.ssh`. Si roban una Mac cliente, no se lleva ninguna llave. |
| **Red privada (Tailscale)** | El servicio escucha solo en `127.0.0.1`; `tailscale serve` lo publica con HTTPS **solo** dentro de tu tailnet. No hay puertos abiertos a Internet. El servidor se niega a arrancar si `listen_host` no es localhost. |
| **Token Bearer** | 256 bits aleatorios guardados en el Llavero de macOS. Se comparan en tiempo constante, y cada intento fallido espera 1 s. |
| **Lista de servidores** | Solo se aceptan los servidores declarados en `config.toml`. Los alias se validan para evitar la inyección de opciones de `ssh`. |
| **Políticas por servidor** | `read_only = true` o `allow_commands = [regex…]` limitan qué se puede ejecutar. |
| **Ssh endurecido** | `BatchMode=yes`, `StrictHostKeyChecking=yes`, `ForwardAgent=no`, timeout y salida truncada. |
| **Auditoría** | Cada llamada, incluidas las denegadas, queda en `~/.local/state/ssh-vault/audit.log` (JSON Lines). |
| **DNS rebinding** | Los encabezados `Host` y `Origin` se validan contra `allowed_hosts`. |

Para endurecerlo más, puedes:
- usar las [ACL de Tailscale](https://tailscale.com/kb/1018/acls) para que solo tus Macs lleguen al puerto 443 de la bóveda;
- cifrar las llaves con frase de contraseña y guardarlas con `UseKeychain yes`;
- usar una llave **dedicada** para la bóveda, con `from="100.64.0.0/10"` o comandos restringidos en el `authorized_keys` del servidor.

## Instalación en la Mac bóveda

```bash
# Requisitos: Python 3.11+, Tailscale con sesión iniciada
git clone <este repo> ~/ssh-vault && cd ~/ssh-vault
./deploy/install.sh
nano ~/.config/ssh-vault/config.toml          # declara tus servidores y allowed_hosts
launchctl kickstart -k gui/$(id -u)/online.dvxlabs.ssh-vault
```

Antes de declarar un servidor, conéctate a él una vez a mano (`ssh web-prod`) para que quede en `known_hosts`.
Para que la bóveda siga accesible, no la dejes dormir cuando esté conectada a la corriente: `sudo pmset -c sleep 0`.

## Configuración en cada Mac cliente

```bash
# Instala Tailscale con la misma cuenta y luego:
./deploy/client-setup.sh https://mi-mac-boveda.tu-tailnet.ts.net/mcp
```

El script ejecuta `claude mcp add --transport http ssh-vault … --header "Authorization: Bearer …"`.
Para Claude Desktop, usa el puente local `npx mcp-remote <url> --header "Authorization: Bearer <token>"`. Los conectores remotos de claude.ai salen desde la nube y no pueden llegar a tu tailnet, lo cual es justamente lo que quieres.

## Herramientas MCP

| Herramienta | Descripción |
|---|---|
| `list_servers` | Muestra los servidores declarados y su modo (completo, solo lectura o comandos permitidos). |
| `test_connection(server)` | Comprueba que la bóveda puede autenticarse. |
| `run_command(server, command, timeout_seconds?)` | Ejecuta el comando y devuelve el código de salida, stdout y stderr. |

## Acceso SSH interactivo (sin Claude)

Con Tailscale SSH activado en la bóveda (`tailscale up --ssh`), desde cualquier Mac:

```bash
ssh -t mi-mac-boveda ssh web-prod
```

La sesión salta a través de la bóveda, así que la llave sigue sin salir de ella. Evita `ssh -A` (agent forwarding) y `ProxyJump` con llaves copiadas.

## Desarrollo

```bash
pip install -e '.[dev]' && pytest
```

Las pruebas usan un binario `ssh` falso y verifican la autenticación, las políticas, la auditoría y el flujo MCP completo.
