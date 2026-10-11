# ssh-vault — MCP personal para tus servidores SSH

Usa los accesos SSH que viven en **una** de tus MacBook desde **cualquiera** de tus
Macs (con Claude Code) sin copiar nunca las llaves privadas. El canal es el propio
SSH, así que no hay servidor HTTP, tokens ni servicios de terceros.

```
 MacBook cliente                          MacBook "bóveda"                       Tus servidores
┌──────────────────────┐   SSH (llave    ┌─────────────────────────────────┐ SSH ┌───────────┐
│ Claude Code          │   restringida)  │ sshd                            │ ──▶ │ web-prod  │
│  MCP: ssh -T         │ ──────────────▶ │  └▶ command="python -m ssh_vault│     │ db        │
│       ssh-vault      │   MCP por stdio │       --client macbook-air"     │     │ backups   │
└──────────────────────┘                 │  ~/.ssh + Llavero de macOS      │     └───────────┘
                                         └─────────────────────────────────┘
```

Claude Code lanza `ssh -T ssh-vault` como si fuera un MCP local. En la bóveda,
`authorized_keys` obliga a esa llave a ejecutar **solo** `ssh_vault`, que habla MCP
por stdin/stdout y usa las llaves de la bóveda para llegar a tus servidores.

## Modelo de seguridad

| Capa | Qué protege |
|---|---|
| **Las llaves no se mueven** | Ninguna herramienta MCP lee ni devuelve `~/.ssh`. Si roban una Mac cliente, no se lleva tus llaves de servidor. |
| **Llave de cliente restringida** | `restrict,command="…"` en `authorized_keys`: esa llave no abre una shell, no reenvía puertos, agente ni X11, e ignora el comando que pida. Solo puede hablar con el MCP. *(Verificado contra un sshd real.)* |
| **Una llave por Mac** | Cada cliente tiene su propia llave y su nombre aparece en la auditoría. Si pierdes una Mac, la revocas con `add-client.sh --remove <nombre>` sin afectar a las demás. |
| **sshd endurecido** | Solo llaves públicas: sin contraseñas, sin root y solo tu usuario (`deploy/sshd_config.d/000-ssh-vault.conf`). |
| **Lista de servidores** | Solo se aceptan los servidores declarados en `config.toml`. Los alias se validan para evitar la inyección de opciones de `ssh`. |
| **Políticas por servidor** | `read_only = true` o `allow_commands = [regex…]` limitan qué se puede ejecutar. |
| **ssh saliente endurecido** | `BatchMode=yes`, `StrictHostKeyChecking=yes`, `ForwardAgent=no`, timeout y salida truncada. |
| **Auditoría** | Cada llamada, incluidas las denegadas, queda en `~/.local/state/ssh-vault/audit.log` con el nombre de la Mac cliente. |

## 1. Mac bóveda (la que tiene las llaves)

```bash
git clone <este repo> ~/ssh-vault && cd ~/ssh-vault
./deploy/install.sh                              # venv + config de ejemplo + instrucciones
nano ~/.config/ssh-vault/config.toml             # declara tus servidores
```

Después:
1. Activa **Ajustes del Sistema → General → Compartir → Sesión remota** solo para tu usuario.
2. Aplica el endurecimiento de `sshd`. `install.sh` muestra los comandos exactos.
3. Conéctate una vez a mano a cada servidor (`ssh web-prod`) para que quede en `known_hosts`.
4. Evita que se duerma mientras esté conectada a la corriente: `sudo pmset -c sleep 0`.

## 2. Hacer accesible la bóveda desde fuera

Elige **una** opción:

**A. Abrir un puerto en el router** (si tienes IP pública)
- Redirige un puerto externo poco común (p. ej. `22022`) al puerto `22` de la bóveda.
- Usa DNS dinámico (por ejemplo, el de tu router o el de Cloudflare) para tener un nombre fijo.
- `sshd` solo acepta llaves y tu usuario, y la llave del cliente solo lanza el MCP.

**B. Túnel inverso a uno de tus servidores** (si tienes CGNAT o no puedes abrir puertos)
- La bóveda mantiene `ssh -R 127.0.0.1:2222:127.0.0.1:22 <tu-vps>` siempre activo. Para esto usa `deploy/tunnel.plist`.
- El puerto `2222` queda escuchando **solo en localhost** del VPS: no se expone a Internet.
- Los clientes saltan por el VPS con `ProxyJump`. En el VPS, dales una cuenta o llave limitada a ese túnel, por ejemplo `restrict,port-forwarding,permitopen="127.0.0.1:2222"`.

## 3. Cada Mac cliente

```bash
# Opción A
./deploy/client-setup.sh mi-casa.ddns.net 22022 tu_usuario
# Opción B (túnel por tu VPS, cuyo alias SSH es "vps")
./deploy/client-setup.sh localhost 2222 tu_usuario vps
```

El script:
1. crea una llave `~/.ssh/ssh_vault_ed25519` (con frase de paso guardada en el Llavero);
2. añade el host `ssh-vault` a `~/.ssh/config`;
3. te muestra el comando `add-client.sh …` que debes ejecutar en la bóveda;
4. hace la primera conexión, para que verifiques la huella de la bóveda;
5. registra el MCP: `claude mcp add --scope user ssh-vault -- ssh -T ssh-vault`.

Para Claude Desktop, añade lo mismo en `claude_desktop_config.json`:

```json
{ "mcpServers": { "ssh-vault": { "command": "ssh", "args": ["-T", "ssh-vault"] } } }
```

## Herramientas MCP

| Herramienta | Descripción |
|---|---|
| `list_servers` | Muestra los servidores declarados y su modo (completo, solo lectura o comandos permitidos). |
| `test_connection(server)` | Comprueba que la bóveda puede autenticarse. |
| `run_command(server, command, timeout_seconds?)` | Ejecuta el comando y devuelve el código de salida, stdout y stderr. |

## Notas

- **Llaves con frase de paso en la bóveda.** Las sesiones que abre `sshd` no heredan el ssh-agent de la sesión gráfica de macOS. `ssh_vault` lo busca automáticamente (`/private/tmp/com.apple.launchd.*/Listeners`), así que la bóveda debe tener tu sesión iniciada y las llaves cargadas (`ssh-add --apple-use-keychain`).
- **Revocar un cliente:** `deploy/add-client.sh --remove <nombre>`.
- **Acceso de terminal "a mano":** usa una llave distinta, sin `command=`, para entrar a la bóveda y desde ahí `ssh web-prod`. Así la llave del MCP sigue limitada.

## Desarrollo

```bash
pip install -e '.[dev]' && pytest
```

Las pruebas usan un binario `ssh` falso y comprueban las políticas, la auditoría y el flujo MCP completo, tanto en memoria como como proceso stdio.
