# ssh-vault — tu bóveda portátil de llaves SSH y API keys

Un **único archivo cifrado** con tus llaves SSH, tus claves de LLMs (OpenAI, Anthropic,
Gemini, Groq…) y los secretos de tus apps. Lo llevas a cualquier equipo como quieras
(iCloud Drive, un repo git privado, un USB) y cada dispositivo lo abre con su propia
identidad. **No depende de ningún servidor, VPN ni Mac encendida.**

```
              vault.age  (cifrado con age; puedes sincronizarlo por cualquier medio)
       ┌──────────────────────────┼──────────────────────────┐
       ▼                          ▼                          ▼
  MacBook Pro               MacBook Air                 Servidor / VPS
  identidad en Llavero      identidad en Llavero        identidad en archivo 0600
  vault ssh add …           vault run … -- npm start    vault serve  (API para apps)
  vault mcp  (Claude)
```

## Instalación

```bash
git clone https://github.com/david2701/server_mcp && cd server_mcp && pip install .
```

Esto instala el comando `vault`. Requiere Python 3.11+.

## Uso en 2 minutos

```bash
# 1. Crear la bóveda (una sola vez, en tu Mac principal)
vault init
#    → guarda la LLAVE DE RECUPERACIÓN que imprime (papel o gestor de contraseñas)

# 2. Guardar claves de LLMs (el valor se pide sin mostrarlo)
vault set openai    --provider openai
vault set anthropic --provider anthropic
vault set gemini    --provider gemini
vault set db_prod   --description "Postgres producción"     # secreto genérico, sin API

# 3. Guardar tus llaves SSH
vault ssh import servidores ~/.ssh/id_ed25519

vault list
```

### Añadir otra Mac

```bash
# En la Mac nueva
vault whoami                  # imprime su llave pública: age1…

# En una Mac ya autorizada
vault device add macbook-air age1…
# Sincroniza vault.age (por iCloud, git...) y la Mac nueva ya puede abrirlo.
```

Por defecto la bóveda está en `~/.config/ssh-vault/vault.age`. Para tenerla en iCloud:
`export VAULT_FILE=~/Library/Mobile\ Documents/com~apple~CloudDocs/vault.age`.

## Usar tus llaves SSH en cualquier Mac

```bash
vault ssh add servidores            # carga la llave en ssh-agent durante 8 h, sin escribirla en disco
ssh web-prod                        # funciona como siempre
vault ssh add servidores --ttl 0    # sin límite de tiempo
vault ssh export servidores ~/.ssh/id_servidores   # solo si de verdad necesitas el archivo
```

## Usar las claves en tus apps

**Opción 1. Variables de entorno**, solo en memoria del proceso:

```bash
vault run OPENAI_API_KEY=openai DATABASE_URL=db_prod -- npm start
```

**Opción 2. API proxy de la bóveda** (recomendada para LLMs): tus apps nunca tienen la clave real.

```bash
vault token create mi-app --secrets openai,anthropic   # token revocable para esa app
vault serve                                             # http://127.0.0.1:8787
```

```bash
# La app usa el SDK oficial sin cambios de código:
OPENAI_BASE_URL=http://127.0.0.1:8787/openai        OPENAI_API_KEY=vt_…
ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic  ANTHROPIC_API_KEY=vt_…
```

- Cada app tiene su propio token y solo accede a las APIs que le diste.
- Si un token se filtra, lo revocas con `vault token rm mi-app` sin rotar tu clave de OpenAI.
- Funciona con streaming (SSE). Verificado con los SDK oficiales de OpenAI y Anthropic.
- La bóveda solo guarda el **hash** de cada token.
- Para servirlo a otras máquinas, ejecútalo en un servidor tuyo con HTTPS: `vault serve --host 0.0.0.0 --tls-cert … --tls-key …`, o detrás de Caddy/nginx. Sin TLS, se niega a escuchar fuera de localhost.

## Usar las claves desde Claude (MCP)

```bash
claude mcp add --scope user vault -- vault mcp
```

Claude obtiene `list_secrets` y `call_api`: llama a la API con tu clave **sin ver nunca el valor**.
La clave solo se envía al `base_url` del secreto; no se siguen redirecciones y, si la API la repite en la respuesta, se borra.
Si además tienes `~/.config/ssh-vault/config.toml` con servidores, también obtiene `run_command`, que usa tus llaves cargadas con `vault ssh add`.

## Compartir

```bash
# Con una persona, usando sus llaves SSH públicas de GitHub
vault share openai ssh:servidores --to github:usuario -o para-usuario.age

# Con un equipo concreto
vault share anthropic --to age1… -o paquete.age
```

El destinatario lo abre con `vault import paquete.age` o, **sin instalar nada**, con
`age -d -i ~/.ssh/id_ed25519 paquete.age`. Nadie más puede leerlo.

## Seguridad

| | |
|---|---|
| **Cifrado estándar** | Formato [age](https://age-encryption.org) (X25519 + ChaCha20-Poly1305). Si un día dejas de usar esta herramienta, abres el archivo con el CLI oficial `age`. |
| **Una identidad por dispositivo** | En macOS se guarda en el Llavero; en Linux, en un archivo 0600 (se rechaza si tiene otros permisos). Quitar un dispositivo (`vault device rm`) lo excluye de las versiones nuevas. |
| **Recuperación** | `vault init` crea una llave de recuperación para cuando pierdas todos tus dispositivos. Úsala con `VAULT_IDENTITY_FILE=recuperacion.txt vault device add …`. |
| **Sin valores en argumentos** | `vault set` pide el valor con `getpass` o lo lee de `--stdin`, así no queda en el historial ni en `ps`. Las llaves SSH van al agente por stdin. |
| **Escritura atómica** | La bóveda nunca queda a medias si algo falla al guardar. |
| **Auditoría** | Cada llamada al API proxy se registra en `~/.local/state/ssh-vault/audit.log`, sin claves ni cuerpos. |

> **Ten en cuenta:**
> - Quitar un dispositivo no borra lo que ya descifró. Si pierdes una Mac, rota las claves importantes.
> - `vault get`/`vault run` entregan el valor a cualquier programa de tu usuario, incluido un agente con terminal. Para Claude usa `vault mcp` (`call_api`), y para las apps, el proxy con tokens.

## Modo opcional: bóveda remota por SSH

Si prefieres que las llaves **nunca** salgan de una Mac concreta, puedes usarla como bóveda remota y acceder a ella por SSH con llaves restringidas (`command=` en `authorized_keys`). Los scripts están en `deploy/`: `install.sh`, `add-client.sh`, `client-setup.sh`, `secret.sh`, `vault-run`. La configuración de ejemplo está en `config.example.toml`.

## Desarrollo

```bash
pip install -e '.[dev]' && pytest
```

35 pruebas: varios dispositivos compartiendo y revocando, compatibilidad con el CLI `age`, carga en un `ssh-agent` real, compartir por llave SSH, proxy (tokens, permisos, streaming, cabeceras), MCP local y el modo remoto por SSH.
