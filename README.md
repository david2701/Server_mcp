# ssh-vault — tu bóveda de llaves SSH y API keys

Dos piezas que comparten la misma bóveda cifrada:

1. **En tus Macs (CLI + MCP):** en cualquier Mac pides a tus agentes que se conecten a tus
   servidores. Usan la llave SSH de la bóveda y no la ven nunca.
2. **En un servidor (pasarela web):** un panel donde generas una API key por servicio. El
   servicio llama a la pasarela como si fuera OpenAI o Anthropic, y la pasarela pone la
   clave real. Es proxy y API a la vez.

```
          vault.age (cifrado con age; lo sincronizas como quieras: iCloud, git, USB)
        ┌────────────────────────┼──────────────────────────┐
        ▼                        ▼                          ▼
   MacBook Pro              MacBook Air               Servidor "pasarela"
   Touch ID                 Touch ID                  (bóveda propia, solo claves de LLM)
   vault mcp ─► agentes     vault connect web         vault serve --panel
       │                        │                       │  panel web  /_vault/
       ▼ SSH                    ▼ SSH                    │  API admin  /_vault/api/keys
   tus servidores ◄─────────────┘                       ▼
                                                 tus servicios ──► OpenAI / Anthropic / …
                                                 (usan vt_…)       (con la clave real)
```

No es una web pública ni un servicio en la nube:

| Dónde | Qué | Cómo se abre |
|---|---|---|
| Tu Mac | **Panel local**: servidores SSH, llaves, claves de API, dispositivos, actividad de tus agentes | `vault ui` (solo `127.0.0.1`, Touch ID) |
| Tu Mac | **MCP** para tus agentes (SSH + APIs sin ver las llaves) | `vault mcp` |
| Tu Mac | **CLI** con todo lo anterior | `vault …` |
| Un servidor tuyo (opcional) | **Pasarela**: panel de API keys por servicio + proxy de LLMs | `vault serve --panel`, detrás de HTTPS |

Las llaves SSH **nunca** van a la pasarela: si alguien comprometiera ese servidor, no
tendría acceso a los demás.

## Instalación (cada Mac)

```bash
brew install age-plugin-se            # para Touch ID / Secure Enclave
git clone https://github.com/david2701/server_mcp && cd server_mcp && pip install .
```

## 1. Crear la bóveda

```bash
vault init
#  → la identidad de esta Mac queda en el Secure Enclave (Touch ID)
#  → guarda vault-recovery-key.txt fuera de línea y bórralo del equipo
```

### Añadir otra Mac

```bash
vault whoami                          # en la Mac nueva → age1se1…
vault device add macbook-air age1se1… # en una Mac ya autorizada
# sincroniza vault.age; las demás Macs te pedirán `vault device trust` (ver Seguridad)
```

Para tener la bóveda en iCloud:
`export VAULT_FILE=~/Library/Mobile\ Documents/com~apple~CloudDocs/vault.age`.

## 2. Tus agentes y tus servidores, desde cualquier Mac

**Con el panel local** (lo más cómodo):

```bash
vault ui        # Touch ID → se abre el navegador en http://127.0.0.1:<puerto>
```

- **Llaves SSH:** genera una nueva (te muestra la línea para `authorized_keys`) o importa la tuya pegándola.
- **Servidores:** usuario@host, puerto y llave. Te enseña las huellas del servidor para que las
  confirmes, y luego quedan fijadas. Con **Probar** verificas que la conexión funciona.
- **Actividad:** qué comandos ejecutaron tus agentes, desde qué Mac y con qué resultado
  (incluidos los denegados).

**O con la terminal:**

```bash
vault ssh generate servidores                      # llave nueva dentro de la bóveda (o:)
vault ssh import servidores ~/.ssh/id_ed25519      # la tuya entra en la bóveda
vault server add web deploy@203.0.113.10 --key servidores --description "Nginx + app"
vault server add db  root@203.0.113.11 --key servidores --read-only
#  → se fijan las huellas del servidor: todas tus Macs las verifican igual

claude mcp add --scope user vault -- vault mcp      # una vez por Mac
```

Luego basta con pedírselo al agente: *«revisa el espacio en disco de web y reinicia nginx»*.

- Al arrancar, `vault mcp` pide **Touch ID una vez** y carga la llave en un `ssh-agent`
  efímero y privado. No se escribe en disco y se destruye al cerrar.
- No usa tu `~/.ssh`: funciona igual en una Mac recién instalada.
- Herramientas MCP: `list_servers`, `test_connection`, `run_command`, `list_secrets` y `call_api`.
- `--read-only` o `--allow REGEX` limitan lo que el agente puede ejecutar en cada servidor.
- Para entrar tú mismo: `vault connect web`.

## 3. Pasarela con panel: API keys para tus servicios

**En el servidor** (Linux con Caddy):

```bash
pip install .                                      # como usuario "vault"
vault init --protect none --name pasarela          # bóveda propia del servidor
vault whoami                                       # → age1… del servidor
```

**En tu Mac:** comparte **solo** las claves de LLM, nunca tus llaves SSH.

```bash
vault set openai    --provider openai
vault set anthropic --provider anthropic
vault share openai anthropic --to age1…servidor -o llm.age
scp llm.age vault@servidor:
```

**De vuelta en el servidor:**

```bash
vault import llm.age && rm llm.age
vault admin password                               # contraseña del panel (mín. 12)
sudo cp deploy/vault-gateway.service /etc/systemd/system/ && sudo systemctl enable --now vault-gateway
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile && sudo systemctl reload caddy   # HTTPS automático
```

Abre `https://vault.tudominio.com/_vault/`: creas una key por servicio, eliges a qué
APIs puede llamar, le pones caducidad si quieres, ves su uso y la revocas con un clic.
El servicio solo necesita:

```bash
OPENAI_BASE_URL=https://vault.tudominio.com/openai
OPENAI_API_KEY=vt_…            # su key; la real nunca sale de la pasarela
```

Funciona con los SDK oficiales y con streaming.

**Desde tus despliegues (API de administración):**

```bash
vault admin token-create ci                        # token va_… para tu CI/CD
curl -X POST https://vault.tudominio.com/_vault/api/keys \
  -H "Authorization: Bearer va_…" \
  -d '{"name":"mi-servicio","apis":["openai"],"expires_days":90}'
# → {"key":"vt_…","env":{"OPENAI_BASE_URL":"…","OPENAI_API_KEY":"vt_…"}}
```

También: `GET /_vault/api/keys`, `DELETE /_vault/api/keys/{nombre}` y `GET /_vault/api/apis`.

## Otros usos

```bash
vault run OPENAI_API_KEY=openai -- npm run dev     # secretos en variables de entorno, solo en memoria
vault share openai --to github:usuario -o x.age    # compartir; se abre con `age -d -i ~/.ssh/id_ed25519`
vault ssh add servidores --ttl 8h                  # cargar la llave en tu ssh-agent
```

## Seguridad

| Riesgo | Cómo se cubre |
|---|---|
| Robo del archivo `vault.age` | Cifrado `age` (X25519 + ChaCha20-Poly1305). Sin una identidad autorizada no se puede abrir. |
| Malware en tu Mac lee la llave | La identidad vive en el **Secure Enclave**: no se puede copiar ni exportar, y cada apertura pide **Touch ID**. Sin Touch ID hay frase de paso (scrypt) con diálogo del sistema. |
| Un dispositivo comprometido añade a otro en silencio | Cada equipo recuerda los dispositivos autorizados y **se niega a abrir** si aparece uno nuevo, hasta que lo aceptas con `vault device trust`. También comprueba que la cabecera cifrada no tenga destinatarios ocultos. |
| Alguien restaura una versión vieja (p. ej. con una clave ya cambiada) | Cada equipo recuerda la última revisión vista y **rechaza** las anteriores (`--allow-rollback` si es intencionado). |
| Llave de recuperación expuesta | Se guarda en un archivo 0600, no se imprime en pantalla. |
| La llave SSH acaba en disco | Va de la bóveda al agente por stdin. El agente es efímero y se destruye al terminar. |
| Servidor suplantado | Huellas fijadas en la bóveda y `StrictHostKeyChecking=yes`. |
| Key de un servicio filtrada | Se revoca en el panel sin tocar la clave del proveedor. La pasarela solo guarda hashes, admite caducidad y solo envía la clave al dominio del proveedor (sin redirecciones). |
| Panel local expuesto | Solo escucha en `127.0.0.1`, con token de un solo uso en la URL, comprobación de `Host` contra DNS rebinding, CSRF, y nunca muestra llaves privadas ni valores de claves. |
| Ataques al panel | Contraseña con scrypt y límite de intentos; cookie `HttpOnly` + `SameSite=Strict` + `Secure`; CSRF y comprobación de origen; CSP estricta, sin JavaScript; todo el HTML escapado. |
| Servidor de la pasarela comprometido | Solo tiene las claves de LLM que le compartiste, nunca tus llaves SSH. Si ocurre, rota esas claves. |

**Límites que conviene conocer:**
- Quitar un dispositivo no borra lo que ya descifró; si pierdes uno, rota las claves importantes.
- Si sincronizas por git, el historial guarda versiones cifradas para los dispositivos de cada momento.
- La pasarela usa `--protect none` porque no hay nadie para poner el dedo. Protégela como cualquier servidor.

## Desarrollo

```bash
pip install -e '.[dev]' && pytest
```

Las pruebas cubren:
- varios dispositivos compartiendo la bóveda y revocando acceso;
- detección de dispositivos ocultos y de versiones restauradas;
- frase de paso y llave de recuperación;
- compatibilidad con el CLI `age`;
- conexiones a un **sshd real** desde una "Mac" sin `~/.ssh`;
- huella de servidor cambiada;
- el MCP;
- el panel local contra un sshd real (generar llave, añadir servidor, probar, huella cambiada, accesos);
- el panel de la pasarela (inicio de sesión, límite de intentos, CSRF, origen, XSS);
- la API de administración, caducidad y streaming;
- los SDK oficiales a través del proxy.
