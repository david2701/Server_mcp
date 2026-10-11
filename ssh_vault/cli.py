"""CLI `vault`: tu bóveda portátil de llaves SSH y API keys."""

from __future__ import annotations

import argparse
import getpass
import os
import platform
import socket
import subprocess
import sys
from pathlib import Path

from . import bundle as B
from .config import NAME_RE, secret_from_spec

# Plantillas para no tener que recordar URLs ni cabeceras.
PROVIDERS: dict[str, dict] = {
    "openai":     {"base_url": "https://api.openai.com/v1/", "env": "OPENAI"},
    "anthropic":  {"base_url": "https://api.anthropic.com/", "header": "x-api-key: {secret}",
                   "extra_headers": {"anthropic-version": "2023-06-01"}, "env": "ANTHROPIC"},
    "gemini":     {"base_url": "https://generativelanguage.googleapis.com/", "header": "x-goog-api-key: {secret}",
                   "env": "GEMINI"},
    "openrouter": {"base_url": "https://openrouter.ai/api/v1/", "env": "OPENROUTER"},
    "groq":       {"base_url": "https://api.groq.com/openai/v1/", "env": "GROQ"},
    "mistral":    {"base_url": "https://api.mistral.ai/v1/", "env": "MISTRAL"},
    "deepseek":   {"base_url": "https://api.deepseek.com/", "env": "DEEPSEEK"},
    "xai":        {"base_url": "https://api.x.ai/v1/", "env": "XAI"},
}


def die(msg: str, code: int = 1):
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def check_name(name: str) -> str:
    if not NAME_RE.match(name):
        die(f"nombre inválido: {name!r} (usa letras, números, _ . -)")
    return name


def read_value(prompt: str, from_stdin: bool) -> str:
    value = sys.stdin.read().strip() if from_stdin else getpass.getpass(prompt)
    if not value:
        die("valor vacío")
    return value


def device_name() -> str:
    name = platform.node().split(".")[0] or socket.gethostname()
    return "".join(c if c.isalnum() or c in "-_" else "-" for c in name).strip("-") or "dispositivo"


OPTS = {"trust_new": False, "allow_rollback": False}


_identity = None


def identity():
    """Desbloquea (Touch ID / frase de paso) una sola vez por ejecución."""
    global _identity
    if _identity is None:
        _identity = B.unlock_identity()
    return _identity


def read():
    return B.read(identities=[identity()], **OPTS)


def mutate(fn):
    b = read()
    result = fn(b)
    B.write(b)
    return result


def ask_new_passphrase() -> str:
    for _ in range(3):
        p1 = getpass.getpass("Frase de paso nueva (mínimo 12 caracteres): ")
        if len(p1) < 12:
            print("Demasiado corta.", file=sys.stderr)
            continue
        if getpass.getpass("Repítela: ") == p1:
            return p1
        print("No coinciden.", file=sys.stderr)
    die("no se pudo fijar la frase de paso")


def ensure_identity(protection: str | None) -> str:
    """Crea la identidad si no existe y devuelve la llave pública de este dispositivo."""
    public = B.device_public_key()
    if public:
        return public
    if protection is None:
        protection = "touchid" if B.touchid_available() else "passphrase"
    if protection == "passphrase" and os.environ.get("VAULT_PASSPHRASE"):
        secret = os.environ["VAULT_PASSPHRASE"]  # automatización
    else:
        secret = ask_new_passphrase() if protection == "passphrase" else None
    public = B.create_identity(protection, secret)
    print(f"Identidad de este dispositivo creada (protección: {protection}).", file=sys.stderr)
    if protection == "passphrase" and sys.platform == "darwin":
        print("Consejo: instala `brew install age-plugin-se` y usa --protect touchid "
              "para que la llave viva en el Secure Enclave.", file=sys.stderr)
    return public


# ─── Dispositivos ───────────────────────────────────────────────────────────────

def cmd_init(a):
    path = B.default_vault_path()
    if path.exists():
        die(f"Ya existe una bóveda en {path}")
    public = ensure_identity(a.protect)
    recovery = B.x25519.Identity.generate()
    out = Path(a.recovery_out).expanduser()
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(f"# Llave de recuperación de ssh-vault ({path})\n"
                 f"# public key: {recovery.to_public()}\n{recovery}\n")
    B.write(B.Bundle(recipients={
        check_name(a.name or device_name()): public,
        "recuperacion": str(recovery.to_public()),
    }), path)
    print(f"Bóveda creada en {path}\n")
    print(f"LLAVE DE RECUPERACIÓN guardada en {out} (0600).")
    print("Muévela YA a un sitio fuera de línea (gestor de contraseñas, USB cifrado, papel)")
    print("y bórrala de este equipo. Es la única forma de abrir la bóveda si pierdes todos")
    print("tus dispositivos. Para usarla: VAULT_IDENTITY_FILE=<archivo> vault ...")


def cmd_whoami(a):
    pub = ensure_identity(a.protect)
    print(pub)
    print(f"\nProtección: {B.device_protection()}. En un dispositivo ya autorizado ejecuta:\n"
          f"  vault device add {device_name()} {pub}\n"
          "y luego sincroniza vault.age a este equipo.", file=sys.stderr)


def cmd_device(a):
    if a.action == "list":
        for name, key in read().recipients.items():
            print(f"{name:20} {key[:60]}")
        return
    if a.action == "trust":
        b = B.read(identities=[identity()], allow_rollback=OPTS["allow_rollback"], trust_new=True, quiet=True)
        print("Dispositivos aceptados por este equipo:")
        for name, key in b.recipients.items():
            print(f"  {name:20} {key[:60]}")
        return
    if a.action == "add":
        keys = B.resolve_recipients(a.key)
        for k in keys:
            B.parse_recipient(k)  # valida antes de tocar la bóveda

        def add(b):
            for i, k in enumerate(keys):
                b.recipients[check_name(a.name if i == 0 else f"{a.name}-{i + 1}")] = k
        mutate(add)
        print(f"Dispositivo '{a.name}' autorizado ({len(keys)} llave/s). Sincroniza vault.age.\n"
              "Los demás equipos te pedirán confirmarlo con `vault device trust`.")
    elif a.action == "rm":
        def rm(b):
            if a.name not in b.recipients:
                die(f"no existe el dispositivo {a.name!r}")
            if len(b.recipients) == 1:
                die("no puedes quitar el último dispositivo")
            del b.recipients[a.name]
        mutate(rm)
        print(f"'{a.name}' ya no podrá abrir las versiones NUEVAS de la bóveda.\n"
              "Lo que ya descifró sigue en su poder: rota las claves importantes.")


# ─── Secretos ───────────────────────────────────────────────────────────────────

def cmd_set(a):
    name = check_name(a.name)
    preset = dict(PROVIDERS.get(a.provider or "", {}))
    preset.pop("env", None)
    spec = {
        "description": a.description or (a.provider or ""),
        "base_url": a.base_url or preset.get("base_url"),
        "header": a.header or preset.get("header"),
        "extra_headers": preset.get("extra_headers", {}),
    }
    for kv in a.extra_header or ():
        k, _, v = kv.partition("=")
        spec["extra_headers"][k] = v
    secret_from_spec(name, spec)  # valida base_url y cabecera
    value = read_value(f"Valor de '{name}': ", a.stdin)

    def put(b):
        b.secrets[name] = {**{k: v for k, v in spec.items() if v}, "value": value}
    mutate(put)
    print(f"Guardado '{name}'." + (f" API: {spec['base_url']}" if spec["base_url"] else ""))


def cmd_get(a):
    sec = read().secrets.get(a.name)
    if sec is None:
        die(f"no existe {a.name!r}")
    sys.stdout.write(sec["value"] + ("\n" if sys.stdout.isatty() else ""))


def cmd_list(a):
    b = read()
    for name, sec in sorted(b.secrets.items()):
        print(f"secreto  {name:20} {sec.get('base_url') or '(sin API)'}  {sec.get('description', '')}")
    for name, key in sorted(b.ssh_keys.items()):
        print(f"ssh      {name:20} {key.get('public', '')[:50]}")
    for name, srv in sorted(b.servers.items()):
        print(f"servidor {name:20} {srv.get('user', 'root')}@{srv['host']}:{srv.get('port', 22)}")
    for h, tok in sorted(b.tokens.items(), key=lambda x: x[1]["name"]):
        print(f"token    {tok['name']:20} → {', '.join(tok['secrets'])}")


def cmd_rm(a):
    def rm(b):
        if b.secrets.pop(a.name, None) is None:
            die(f"no existe {a.name!r}")
    mutate(rm)
    print(f"Borrado '{a.name}'.")


def cmd_run(a):
    argv = a.argv[1:] if a.argv[:1] == ["--"] else a.argv
    if "--" not in argv:
        die("uso: vault run VAR=secreto [...] -- comando")
    sep = argv.index("--")
    pairs, command = argv[:sep], argv[sep + 1:]
    if not pairs or not command:
        die("uso: vault run VAR=secreto [...] -- comando")
    b = read()
    env = dict(os.environ)
    for pair in pairs:
        var, _, name = pair.partition("=")
        if not var.isidentifier() or name not in b.secrets:
            die(f"par inválido o secreto inexistente: {pair}")
        env[var] = b.secrets[name]["value"]
    os.execvpe(command[0], command, env)


# ─── Llaves SSH ─────────────────────────────────────────────────────────────────

def cmd_ssh(a):
    if a.action == "list":
        for name, key in sorted(read().ssh_keys.items()):
            print(f"{name:20} {key.get('public', '')}")
    elif a.action == "import":
        path = Path(a.path).expanduser()
        private = path.read_text()
        if "PRIVATE KEY-----" not in private:
            die(f"{path} no parece una llave privada")
        derived = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", str(path)], capture_output=True, text=True)
        if derived.returncode == 0:
            public = derived.stdout.strip()
        else:
            pub_path = path.with_name(path.name + ".pub")
            if not a.keep_passphrase:
                die(f"{path} tiene frase de paso: tus agentes no podrían escribirla.\n"
                    "Dentro de la bóveda no hace falta (la bóveda ya la protege). Quítasela a una copia:\n"
                    f"  cp {path} /tmp/k && ssh-keygen -p -N '' -f /tmp/k && vault ssh import {a.name} /tmp/k && rm /tmp/k\n"
                    "o usa --keep-passphrase si solo la cargarás tú a mano.")
            if not pub_path.exists():
                die(f"no encuentro {pub_path}")
            public = pub_path.read_text().strip()

        def put(b):
            b.ssh_keys[check_name(a.name)] = {"private": private, "public": public}
        mutate(put)
        print(f"Llave '{a.name}' guardada en la bóveda. Ya puedes borrar {path} si quieres.")
    elif a.action == "add":
        key = read().ssh_keys.get(a.name) or die(f"no existe la llave {a.name!r}")
        cmd = ["ssh-add"] + (["-t", a.ttl] if a.ttl != "0" else []) + ["-"]
        # La llave va por stdin directo al agente: nunca toca el disco.
        r = subprocess.run(cmd, input=key["private"], text=True)
        if r.returncode == 0:
            print(f"Llave '{a.name}' cargada en ssh-agent" + (f" durante {a.ttl}." if a.ttl != "0" else "."))
        raise SystemExit(r.returncode)
    elif a.action == "export":
        key = read().ssh_keys.get(a.name) or die(f"no existe la llave {a.name!r}")
        dest = Path(a.path).expanduser()
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(key["private"])
        if key.get("public"):
            dest.with_name(dest.name + ".pub").write_text(key["public"] + "\n")
        print(f"Exportada a {dest} (0600).")
    elif a.action == "rm":
        def rm(b):
            if b.ssh_keys.pop(a.name, None) is None:
                die(f"no existe la llave {a.name!r}")
        mutate(rm)
        print(f"Llave '{a.name}' borrada de la bóveda.")


# ─── Servidores ─────────────────────────────────────────────────────────────────

def scan_host_keys(host: str, port: int) -> list[str]:
    r = subprocess.run(["ssh-keyscan", "-T", "8", "-p", str(port), "--", host], capture_output=True, text=True)
    keys = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and not line.startswith("#"):
            keys.append(f"{parts[1]} {parts[2]}")
    if not keys:
        die(f"no pude obtener las huellas de {host}:{port} ({r.stderr.strip() or 'sin respuesta'})")
    return sorted(set(keys))


def fingerprints(keys: list[str]) -> list[str]:
    r = subprocess.run(["ssh-keygen", "-lf", "-"], input="".join(f"x {k}\n" for k in keys),
                       capture_output=True, text=True)
    return r.stdout.splitlines()


def cmd_server(a):
    if a.action == "list":
        for name, s in sorted(read().servers.items()):
            mode = "solo lectura" if s.get("read_only") else ("lista blanca" if s.get("allow_commands") else "completo")
            print(f"{name:16} {s.get('user', 'root')}@{s['host']}:{s.get('port', 22):<6} llave={s.get('key', '-'):12} "
                  f"[{mode}] {s.get('description', '')}")
        return
    if a.action == "rm":
        def rm(b):
            if b.servers.pop(a.name, None) is None:
                die(f"no existe el servidor {a.name!r}")
        mutate(rm)
        print(f"Servidor '{a.name}' borrado.")
        return
    # add
    user, _, host = a.target.rpartition("@")
    user = user or "root"
    b = read()
    key = a.key or (next(iter(b.ssh_keys)) if len(b.ssh_keys) == 1 else None)
    if not key or key not in b.ssh_keys:
        die("indica --key <llave> (de `vault ssh list`)")
    host_keys = [a.host_key] if a.host_key else scan_host_keys(host, a.port)
    spec = {"host": host, "user": user, "port": a.port, "key": key, "host_keys": host_keys,
            "description": a.description or "", "read_only": a.read_only,
            "allow_commands": a.allow or []}
    from .config import server_from_spec
    server_from_spec(check_name(a.name), spec)  # valida
    if not a.host_key:
        print(f"Huellas de {host}:{a.port} (compruébalas con el proveedor o en el propio servidor):")
        for fp in fingerprints(host_keys):
            print("  " + fp)
        if not a.yes and input("¿Son correctas? [s/N] ").strip().lower() not in ("s", "si", "sí", "y", "yes"):
            die("cancelado")
    b.servers[a.name] = spec
    B.write(b)
    print(f"Servidor '{a.name}' guardado. Sus huellas quedan fijadas en la bóveda para todos tus equipos.")


def cmd_connect(a):
    """Sesión SSH interactiva desde cualquier Mac, sin tocar ~/.ssh."""
    from .runner import ssh_argv
    from .sshagent import session

    b = read()
    if a.name not in b.servers:
        die(f"no existe el servidor {a.name!r} (vault server list)")
    with session(b) as cfg:
        argv = ssh_argv(cfg, cfg.servers[a.name], " ".join(a.command) if a.command else None,
                        interactive=not a.command)
        env = {**os.environ, "SSH_AUTH_SOCK": cfg.agent_sock or ""}
        code = subprocess.run(argv, env=env).returncode
    raise SystemExit(code)


# ─── Compartir ──────────────────────────────────────────────────────────────────

def cmd_share(a):
    b = read()
    out = B.Bundle()
    for item in a.items:
        if item.startswith("ssh:"):
            name = item[4:]
            out.ssh_keys[name] = b.ssh_keys.get(name) or die(f"no existe la llave {name!r}")
        else:
            out.secrets[item] = b.secrets.get(item) or die(f"no existe el secreto {item!r}")
    keys = B.resolve_recipients(a.to)
    data = B.encrypt(out, keys)
    if a.output:
        Path(a.output).write_bytes(data)
        print(f"Paquete cifrado para {len(keys)} llave/s en {a.output}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(data)
    print("El destinatario lo abre con:  vault import <archivo>\n"
          "  o sin instalar nada:          age -d -i ~/.ssh/id_ed25519 <archivo>", file=sys.stderr)


def cmd_import(a):
    data = Path(a.file).read_bytes()
    ssh_ids = []
    for p in a.identity or ["~/.ssh/id_ed25519"]:
        try:
            ssh_ids.append(B.ssh_identity(Path(p)))
        except Exception:
            pass
    try:
        incoming = B.decrypt(data, ssh_ids) if ssh_ids else None
    except B.VaultError:
        incoming = None
    if incoming is None:  # quizá se compartió con la identidad de este dispositivo
        incoming = B.decrypt(data, [identity()])

    def merge(b):
        added, skipped = [], []
        for kind in ("secrets", "ssh_keys"):
            mine, theirs = getattr(b, kind), getattr(incoming, kind)
            for name, value in theirs.items():
                if name in mine and not a.overwrite:
                    skipped.append(name)
                else:
                    mine[name] = value
                    added.append(name)
        return added, skipped
    added, skipped = mutate(merge)
    print(f"Importados: {', '.join(added) or 'nada'}")
    if skipped:
        print(f"Ya existían (usa --overwrite): {', '.join(skipped)}")


# ─── Tokens y API ───────────────────────────────────────────────────────────────

def cmd_token(a):
    from . import keys as K

    if a.action == "list":
        for t in K.list_keys(read()):
            exp = f"  caduca {t['expires'][:10]}" if t.get("expires") else ""
            print(f"{t['name']:20} → {', '.join(t['secrets'])}{exp}")
        return
    if a.action == "rm":
        def rm(b):
            if not K.revoke_key(b, a.app):
                die(f"no existe la key {a.app!r}")
        mutate(rm)
        print(f"Key de '{a.app}' revocada (si `vault serve` está en marcha sin panel, reinícialo).")
        return
    apis = [s.strip() for s in a.secrets.split(",") if s.strip()]
    key = mutate(lambda b: K.create_key(b, a.app, apis, a.expires_days))
    print(f"API key para '{a.app}' (se muestra UNA vez; la bóveda solo guarda su hash):\n\n  {key}\n")
    print("Configura el servicio (con `vault serve` en marcha):")
    for k, v in K.env_example(apis, a.url or f"http://127.0.0.1:{a.port}", key).items():
        print(f"  {k}={v}")


def cmd_admin(a):
    from . import keys as K

    if a.action == "password":
        pw = os.environ.get("VAULT_ADMIN_PASSWORD") or ask_new_passphrase()
        mutate(lambda b: K.set_admin_password(b, pw))
        print("Contraseña del panel guardada. Reinicia `vault serve --panel`.")
    elif a.action == "token-create":
        token = mutate(lambda b: K.create_admin_token(b, check_name(a.name or "")))
        print(f"Token de administración '{a.name}' (se muestra UNA vez):\n\n  {token}\n")
        print("Úsalo en tus despliegues:  curl -X POST https://<pasarela>/_vault/api/keys \\\n"
              f"    -H 'Authorization: Bearer {token[:8]}…' -d '{{\"name\":\"mi-servicio\",\"apis\":[\"openai\"]}}'")
    elif a.action == "token-list":
        for t in read().admin.get("tokens", {}).values():
            print(f"{t['name']:20} creado {t['created'][:10]}")
    elif a.action == "token-rm":
        def rm(b):
            if not K.revoke_admin_token(b, a.name or ""):
                die(f"no existe el token {a.name!r}")
        mutate(rm)
        print(f"Token de administración '{a.name}' revocado.")


def cmd_serve(a):
    import uvicorn
    from .llmproxy import build_app

    local = a.host in ("127.0.0.1", "localhost", "::1")
    if not local and not (a.tls_cert and a.tls_key):
        die("Para escuchar fuera de localhost necesitas --tls-cert y --tls-key "
            "(o pon delante un proxy HTTPS como Caddy y deja --host 127.0.0.1).")
    b = read()
    if a.panel and not b.admin.get("password"):
        die("El panel necesita contraseña: ejecuta `vault admin password` primero.")
    if not b.tokens and not a.panel:
        print("Aviso: no hay API keys; crea una con `vault token create <app> --secrets ...`", file=sys.stderr)
    audit = Path(os.environ.get("VAULT_AUDIT_LOG", "~/.local/state/ssh-vault/audit.log")).expanduser()
    path = B.default_vault_path()
    app = build_app(b, audit, save=lambda bundle: B.write(bundle, path), panel=a.panel)
    if a.panel:
        print(f"Panel: http{'s' if a.tls_cert else ''}://{a.host}:{a.port}/_vault/", file=sys.stderr)
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning",
                ssl_certfile=a.tls_cert, ssl_keyfile=a.tls_key)


def cmd_mcp(a):
    """MCP local para tus agentes: servidores y APIs de la bóveda sin ver las llaves.

    Desbloquea la bóveda una vez (Touch ID o diálogo de frase de paso) al arrancar.
    """
    from .server import build_mcp
    from .sshagent import session

    b = read()
    with session(b) as cfg:
        build_mcp(cfg, client=device_name()).run("stdio")


# ─── main ───────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="vault", description="Bóveda portátil de llaves SSH y API keys")
    p.add_argument("--allow-rollback", action="store_true",
                   help="acepta una revisión de la bóveda más antigua que la última vista")
    sub = p.add_subparsers(dest="cmd", required=True)
    protect = dict(choices=["touchid", "passphrase", "none"],
                   help="cómo se protege la identidad de este equipo "
                        "(por defecto: touchid si hay age-plugin-se, si no passphrase; none solo para servidores)")

    s = sub.add_parser("init", help="crea la bóveda en este dispositivo")
    s.add_argument("--name", help="nombre de este dispositivo")
    s.add_argument("--protect", **protect)
    s.add_argument("--recovery-out", default="vault-recovery-key.txt",
                   help="dónde guardar la llave de recuperación (0600)")
    s.set_defaults(fn=cmd_init)
    s = sub.add_parser("whoami", help="muestra (o crea) la llave pública de este dispositivo")
    s.add_argument("--protect", **protect)
    s.set_defaults(fn=cmd_whoami)

    s = sub.add_parser("device", help="dispositivos autorizados")
    s.add_argument("action", choices=["list", "add", "rm", "trust"])
    s.add_argument("name", nargs="?")
    s.add_argument("key", nargs="?", help="age1…, ssh-ed25519 …, archivo .pub o github:usuario")
    s.set_defaults(fn=cmd_device)

    s = sub.add_parser("set", help="guarda un secreto (pide el valor sin mostrarlo)")
    s.add_argument("name")
    s.add_argument("--provider", choices=sorted(PROVIDERS), help="plantilla de API (base_url y cabecera)")
    s.add_argument("--base-url")
    s.add_argument("--header", help='p. ej. "x-api-key: {secret}"')
    s.add_argument("--extra-header", action="append", metavar="K=V")
    s.add_argument("--description")
    s.add_argument("--stdin", action="store_true", help="lee el valor de stdin")
    s.set_defaults(fn=cmd_set)

    s = sub.add_parser("get", help="imprime el valor de un secreto")
    s.add_argument("name")
    s.set_defaults(fn=cmd_get)
    sub.add_parser("list", help="lista secretos, llaves y tokens (sin valores)").set_defaults(fn=cmd_list)
    s = sub.add_parser("rm", help="borra un secreto")
    s.add_argument("name")
    s.set_defaults(fn=cmd_rm)
    s = sub.add_parser("run", help="ejecuta un comando con secretos en el entorno")
    s.add_argument("argv", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("ssh", help="llaves SSH en la bóveda")
    s.add_argument("action", choices=["list", "import", "add", "export", "rm"])
    s.add_argument("name", nargs="?")
    s.add_argument("path", nargs="?")
    s.add_argument("--ttl", default="8h", help="duración en ssh-agent (0 = sin límite)")
    s.add_argument("--keep-passphrase", action="store_true", help="importa una llave con frase de paso")
    s.set_defaults(fn=cmd_ssh)

    s = sub.add_parser("share", help="exporta secretos/llaves cifrados para otra persona o equipo")
    s.add_argument("items", nargs="+", help="nombres de secretos o ssh:<llave>")
    s.add_argument("--to", required=True, help="age1…, ssh-ed25519 …, archivo .pub o github:usuario")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_share)

    s = sub.add_parser("import", help="importa un paquete recibido con `vault share`")
    s.add_argument("file")
    s.add_argument("--identity", action="append", help="llave SSH privada para abrirlo")
    s.add_argument("--overwrite", action="store_true")
    s.set_defaults(fn=cmd_import)

    s = sub.add_parser("token", help="API keys de tus servicios (también desde el panel web)")
    s.add_argument("action", choices=["create", "list", "rm"])
    s.add_argument("app", nargs="?")
    s.add_argument("--secrets", default="", help="APIs permitidas, separadas por comas")
    s.add_argument("--expires-days", type=int)
    s.add_argument("--port", type=int, default=8787)
    s.add_argument("--url", help="URL pública de la pasarela, para el ejemplo de configuración")
    s.set_defaults(fn=cmd_token)

    s = sub.add_parser("admin", help="acceso al panel web y a la API de administración")
    s.add_argument("action", choices=["password", "token-create", "token-list", "token-rm"])
    s.add_argument("name", nargs="?")
    s.set_defaults(fn=cmd_admin)

    s = sub.add_parser("serve", help="pasarela: API proxy de LLMs (+ panel web con --panel)")
    s.add_argument("--panel", action="store_true", help="activa el panel web y la API de administración en /_vault/")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.add_argument("--tls-cert")
    s.add_argument("--tls-key")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("server", help="servidores SSH guardados en la bóveda")
    s.add_argument("action", choices=["list", "add", "rm"])
    s.add_argument("name", nargs="?")
    s.add_argument("target", nargs="?", help="usuario@host")
    s.add_argument("-p", "--port", type=int, default=22)
    s.add_argument("--key", help="llave SSH de la bóveda a usar")
    s.add_argument("--host-key", help="huella pública conocida (p. ej. 'ssh-ed25519 AAAA…'); evita el escaneo")
    s.add_argument("--read-only", action="store_true", help="los agentes solo pueden ejecutar diagnósticos")
    s.add_argument("--allow", action="append", metavar="REGEX", help="lista blanca de comandos")
    s.add_argument("--description")
    s.add_argument("-y", "--yes", action="store_true", help="acepta las huellas sin preguntar")
    s.set_defaults(fn=cmd_server)

    s = sub.add_parser("connect", help="abre una sesión SSH a un servidor de la bóveda")
    s.add_argument("name")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_connect)

    sub.add_parser("mcp", help="servidor MCP local (stdio) para tus agentes").set_defaults(fn=cmd_mcp)

    a = p.parse_args(argv)
    OPTS["allow_rollback"] = a.allow_rollback
    if a.cmd == "device" and a.action == "add" and not (a.name and a.key):
        die("uso: vault device add <nombre> <llave>")
    if a.cmd == "device" and a.action == "rm" and not a.name:
        die("uso: vault device rm <nombre>")
    if a.cmd == "server" and a.action != "list" and not a.name:
        die(f"uso: vault server {a.action} <nombre>" + (" usuario@host" if a.action == "add" else ""))
    if a.cmd == "server" and a.action == "add" and not a.target:
        die("uso: vault server add <nombre> usuario@host [-p puerto] [--key llave]")
    if a.cmd == "ssh" and a.action != "list" and not a.name:
        die(f"uso: vault ssh {a.action} <nombre>" + (" <ruta>" if a.action in ("import", "export") else ""))
    if a.cmd == "ssh" and a.action in ("import", "export") and not a.path:
        die(f"uso: vault ssh {a.action} <nombre> <ruta>")
    if a.cmd == "token" and a.action in ("create", "rm") and not a.app:
        die(f"uso: vault token {a.action} <app>" + (" --secrets a,b" if a.action == "create" else ""))
    if a.cmd == "token" and a.action == "create" and not a.secrets:
        die("indica --secrets openai,anthropic,...")
    try:
        a.fn(a)
    except (B.VaultError, ValueError, FileNotFoundError, PermissionError) as err:
        die(f"error: {err}")


if __name__ == "__main__":
    main()
