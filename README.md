# ssh-vault — tu bóveda de servidores y API keys para cualquier IA

Una app que despliegas **en un servidor tuyo** (un VPS cualquiera) y que:

- **Genera una llave SSH propia para cada uno de tus servidores.** La privada nunca sale
  de la app, y la llave solo funciona desde la IP de la app.
- **Deja que cualquier IA se conecte a tus servidores** por MCP:
  - Claude.ai, ChatGPT y cualquier cliente con OAuth: apruebas la conexión en el panel;
  - Claude Code, Cursor, Codex o tus propios agentes: con un token.
- **Hace de proxy de tus APIs de LLM:** cada servicio tuyo recibe su propia API key
  revocable, y la clave real nunca sale de la app.

No depende de ninguna Mac: funciona desde cualquier dispositivo con navegador, y el
panel se puede instalar como app.

```
  Claude.ai / ChatGPT ──OAuth──┐
  Claude Code / Cursor ─token──┼──► https://vault.tudominio.com ──SSH (llave por servidor)──► web, db, staging…
  tus servicios ─────── vt_… ──┘      ├─ /_vault/  panel (app)
                                      ├─ /mcp      MCP remoto           ──HTTPS (clave real)──► OpenAI, Anthropic…
                                      └─ /<api>/   proxy de LLMs
```

## Despliegue (5 minutos)

En tu VPS, con Docker:

```bash
git clone https://github.com/david2701/server_mcp && cd server_mcp
echo "VAULT_DOMAIN=vault.tudominio.com" > .env      # apunta antes su DNS a este VPS
docker compose up -d
docker compose logs vault                           # → enlace de configuración inicial (un solo uso)
```

Abre ese enlace, elige la contraseña del panel y listo. Caddy obtiene el certificado
HTTPS automáticamente.

> **Primer arranque:** la app crea su bóveda cifrada y deja una **llave de recuperación**
> en el volumen (`/data/recovery-key.txt`). Cópiala fuera del servidor y bórrala de ahí:
> `docker compose exec vault cat /data/recovery-key.txt`.

Sin Docker: `pip install .` y `vault serve --public-url https://vault.tudominio.com`,
detrás de Caddy (`deploy/Caddyfile`) o con systemd (`deploy/vault-gateway.service`).

## 1. Añadir un servidor

En el panel, **Servidores → Añadir servidor** (nombre, `usuario@host`, puerto). La app
genera su llave y te da un comando de un solo uso, válido 30 minutos:

```bash
curl -fsSL https://vault.tudominio.com/_vault/enroll/… | sh    # en el servidor, como ese usuario
```

Ese comando:
- añade la llave a `~/.ssh/authorized_keys` con `restrict` (sin reenvíos ni terminal) y,
  si configuraste la IP en **Ajustes**, con `from="IP-de-la-app"`: aunque alguien robara
  la llave, no podría usarla desde otro sitio;
- devuelve a la app las **huellas reales** del servidor, que quedan fijadas. Si alguien
  lo suplanta después, la app se niega a conectar.

Luego pulsa **Probar**. También puedes **Rotar llave** (el comando de alta borra la vieja
del servidor) o hacerlo a mano: pegar la línea de `authorized_keys` y **Escanear huellas**.

## 2. Conectar tus IAs

URL del MCP: `https://vault.tudominio.com/mcp`

- **Claude.ai o ChatGPT:** añade un *conector personalizado* con esa URL. Te llevará al panel
  para aprobarlo y elegir **qué servidores y qué APIs** puede usar.
- **Claude Code, Cursor, Codex o tus agentes:** en **Accesos de IA → Nuevo token** eliges el
  alcance, y el panel te da el comando listo:

  ```bash
  claude mcp add --transport http vault https://vault.tudominio.com/mcp --header "Authorization: Bearer mt_…"
  ```

Herramientas que ve la IA: `list_servers`, `test_connection`, `run_command`, `list_secrets`
y `call_api`. Cada acceso solo ve lo que le diste. Los servidores en modo "solo diagnósticos"
únicamente aceptan comandos de lectura. Todo queda en **Actividad**, incluidos los intentos
denegados, y cualquier acceso se revoca con un clic.

## 3. API keys para tus servicios (proxy de LLMs)

1. En el panel, **Claves → Guardar clave** (OpenAI, Anthropic, Gemini, Groq…). Se guardan
   cifradas y no se vuelven a mostrar.
2. **API keys → Nueva**: eliges a qué APIs puede llamar el servicio y su caducidad.
3. El servicio solo necesita:

```bash
OPENAI_BASE_URL=https://vault.tudominio.com/openai
OPENAI_API_KEY=vt_…        # su key propia; la real nunca sale de la app
```

Funciona con los SDK oficiales y con streaming. Para automatizarlo desde tus despliegues:
`POST /_vault/api/keys` con un token de `vault admin token-create`.

## Seguridad

| Riesgo | Cómo se cubre |
|---|---|
| Roban una llave SSH | Una llave por servidor, con `restrict` y `from="IP de la app"`: no sirve desde otro sitio. Se rota en un clic. |
| Servidor suplantado (MITM) | Huellas reales enviadas por el propio servidor al darlo de alta (o escaneadas y confirmadas por ti), y `StrictHostKeyChecking=yes`. |
| Una IA hace algo que no debe | Alcance por acceso (servidores y APIs), modo solo diagnósticos, registro de todo y revocación inmediata. |
| Token de IA filtrado | Los de OAuth caducan en 1 h y rotan al renovarse. Todos se guardan solo como hash y valen únicamente para este MCP (`validate_token_resource`). |
| Ataques al panel | Contraseña con scrypt y límite de intentos; cookie `HttpOnly`/`SameSite=Strict`/`Secure`; CSRF y comprobación de origen; CSP estricta y sin JavaScript; todo el HTML escapado. |
| Robo del disco o de una copia de seguridad | Todo (llaves, claves, tokens) vive en una bóveda cifrada con [age](https://age-encryption.org). Incluye llave de recuperación. |
| Contenedor comprometido | Corre como usuario sin privilegios, con sistema de archivos de solo lectura, sin capacidades y con `no-new-privileges`. El puerto de la app no se publica: solo Caddy llega a ella. |

**Límites que conviene conocer:**
- La app tiene acceso a tus servidores; protege el VPS como protegerías tus llaves.
- Usa la IP de salida (`from=`) y el modo solo diagnósticos donde puedas.
- La identidad de la bóveda está en el volumen de datos para que la app arranque sola.
  Cifrar el disco del VPS añade otra capa.

## CLI y modo local (opcional)

El mismo paquete instala el comando `vault`. Gestiona la app desde el panel: no edites su
bóveda con el CLI mientras está en marcha, porque la app guarda su propia copia. El CLI sirve
para usarlo sin servidor:
- `vault mcp` (MCP local);
- `vault ui` (panel en `127.0.0.1`);
- `vault connect web`.

En una Mac con `brew install age-plugin-se`, la identidad local vive en el Secure Enclave
y cada apertura pide Touch ID.

## Desarrollo

```bash
pip install -e '.[dev]' && pytest
```

Las pruebas usan **servidores SSH reales** (`sshd`) y cubren:
- alta con el comando de un solo uso, restricción `from=` por IP, rotación, huella cambiada;
- MCP remoto con token y con el flujo OAuth completo (registro dinámico, PKCE, consentimiento,
  renovación con rotación, revocación);
- configuración inicial;
- proxy con los SDK oficiales;
- panel (CSRF, origen, XSS, límite de intentos);
- bóveda (destinatarios ocultos, restauración de versiones viejas, recuperación).
