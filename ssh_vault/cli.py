"""CLI `vault`: tu bóveda portátil de llaves SSH y API keys."""

from __future__ import annotations

import argparse
import getpass
import os
import platform
import secrets as pysecrets
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


def mutate(fn):
    b = B.read()
    result = fn(b)
    B.write(b)
    return result


# ─── Dispositivos ───────────────────────────────────────────────────────────────

def cmd_init(a):
    path = B.default_vault_path()
    if path.exists():
        die(f"Ya existe una bóveda en {path}")
    identity = B.load_identity() or B.create_identity()
    recovery = B.x25519.Identity.generate()
    b = B.Bundle(recipients={
        check_name(a.name or device_name()): str(identity.to_public()),
        "recuperacion": str(recovery.to_public()),
    })
    B.write(b, path)
    print(f"Bóveda creada en {path}\n")
    print("LLAVE DE RECUPERACIÓN. Guárdala fuera de línea (papel o gestor de contraseñas).")
    print("Es la única forma de abrir la bóveda si pierdes todos tus dispositivos:\n")
    print(f"    {recovery}\n")
    print("Sincroniza el archivo como quieras (iCloud Drive, repo git privado, USB...).")


def cmd_whoami(a):
    identity = B.load_identity()
    if identity is None:
        identity = B.create_identity()
        print("Identidad nueva creada para este dispositivo.", file=sys.stderr)
    pub = str(identity.to_public())
    print(pub)
    print(f"\nEn un dispositivo ya autorizado ejecuta:\n  vault device add {device_name()} {pub}\n"
          "y luego sincroniza vault.age a este equipo.", file=sys.stderr)


def cmd_device(a):
    if a.action == "list":
        for name, key in B.read().recipients.items():
            print(f"{name:20} {key[:60]}")
        return
    if a.action == "add":
        keys = B.resolve_recipients(a.key)
        for k in keys:
            B.parse_recipient(k)  # valida antes de tocar la bóveda

        def add(b):
            for i, k in enumerate(keys):
                b.recipients[check_name(a.name if i == 0 else f"{a.name}-{i + 1}")] = k
        mutate(add)
        print(f"Dispositivo '{a.name}' autorizado ({len(keys)} llave/s). Sincroniza vault.age.")
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
    sec = B.read().secrets.get(a.name)
    if sec is None:
        die(f"no existe {a.name!r}")
    sys.stdout.write(sec["value"] + ("\n" if sys.stdout.isatty() else ""))


def cmd_list(a):
    b = B.read()
    for name, sec in sorted(b.secrets.items()):
        print(f"secreto  {name:20} {sec.get('base_url') or '(sin API)'}  {sec.get('description', '')}")
    for name, key in sorted(b.ssh_keys.items()):
        print(f"ssh      {name:20} {key.get('public', '')[:50]}")
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
    b = B.read()
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
        for name, key in sorted(B.read().ssh_keys.items()):
            print(f"{name:20} {key.get('public', '')}")
    elif a.action == "import":
        path = Path(a.path).expanduser()
        private = path.read_text()
        if "PRIVATE KEY-----" not in private:
            die(f"{path} no parece una llave privada")
        pub_path = path.with_name(path.name + ".pub")
        public = pub_path.read_text().strip() if pub_path.exists() else ""

        def put(b):
            b.ssh_keys[check_name(a.name)] = {"private": private, "public": public}
        mutate(put)
        print(f"Llave '{a.name}' guardada en la bóveda. Ya puedes borrar {path} si quieres.")
    elif a.action == "add":
        key = B.read().ssh_keys.get(a.name) or die(f"no existe la llave {a.name!r}")
        cmd = ["ssh-add"] + (["-t", a.ttl] if a.ttl != "0" else []) + ["-"]
        # La llave va por stdin directo al agente: nunca toca el disco.
        r = subprocess.run(cmd, input=key["private"], text=True)
        if r.returncode == 0:
            print(f"Llave '{a.name}' cargada en ssh-agent" + (f" durante {a.ttl}." if a.ttl != "0" else "."))
        raise SystemExit(r.returncode)
    elif a.action == "export":
        key = B.read().ssh_keys.get(a.name) or die(f"no existe la llave {a.name!r}")
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


# ─── Compartir ──────────────────────────────────────────────────────────────────

def cmd_share(a):
    b = B.read()
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
    identities = []
    own = B.load_identity()
    if own:
        identities.append(own)
    for p in a.identity or ["~/.ssh/id_ed25519"]:
        try:
            identities.append(B.ssh_identity(Path(p)))
        except Exception:
            pass
    if not identities:
        die("no hay identidades con las que abrir el paquete")
    incoming = B.decrypt(Path(a.file).read_bytes(), identities)

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
    if a.action == "list":
        for tok in sorted(B.read().tokens.values(), key=lambda t: t["name"]):
            print(f"{tok['name']:20} → {', '.join(tok['secrets'])}")
        return
    if a.action == "rm":
        def rm(b):
            before = len(b.tokens)
            b.tokens = {h: t for h, t in b.tokens.items() if t["name"] != a.app}
            if len(b.tokens) == before:
                die(f"no existe el token {a.app!r}")
        mutate(rm)
        print(f"Token de '{a.app}' revocado (reinicia `vault serve`).")
        return
    allowed = [s.strip() for s in a.secrets.split(",") if s.strip()]
    token = "vt_" + pysecrets.token_urlsafe(32)

    def create(b):
        missing = [s for s in allowed if s not in b.secrets or not b.secrets[s].get("base_url")]
        if missing:
            die(f"secretos inexistentes o sin base_url: {', '.join(missing)}")
        if any(t["name"] == a.app for t in b.tokens.values()):
            die(f"ya existe un token para {a.app!r}; revócalo antes")
        b.tokens[B.hash_token(token)] = {"name": check_name(a.app), "secrets": allowed}
    mutate(create)
    base = f"http://127.0.0.1:{a.port}"
    print(f"Token para '{a.app}' (se muestra UNA vez; la bóveda solo guarda su hash):\n\n  {token}\n")
    print("Configura tu app (con `vault serve` en marcha):")
    for s in allowed:
        env = PROVIDERS.get(s, {}).get("env", s.upper().replace("-", "_"))
        print(f"  {env}_BASE_URL={base}/{s}   {env}_API_KEY={token}")


def cmd_serve(a):
    import uvicorn
    from .llmproxy import build_app

    local = a.host in ("127.0.0.1", "localhost", "::1")
    if not local and not (a.tls_cert and a.tls_key):
        die("Para escuchar fuera de localhost necesitas --tls-cert y --tls-key "
            "(o pon delante un proxy HTTPS como Caddy y deja --host 127.0.0.1).")
    b = B.read()
    if not b.tokens:
        print("Aviso: no hay tokens; crea uno con `vault token create <app> --secrets ...`", file=sys.stderr)
    audit = Path("~/.local/state/ssh-vault/audit.log").expanduser()
    uvicorn.run(build_app(b, audit), host=a.host, port=a.port, log_level="warning",
                ssl_certfile=a.tls_cert, ssl_keyfile=a.tls_key)


def cmd_mcp(a):
    """MCP local: Claude usa call_api con las claves de la bóveda, sin verlas."""
    from dataclasses import replace

    from .config import load_config
    from .server import build_mcp

    b = B.read()

    class BundleStore:
        def get(self, name):
            sec = b.secrets.get(name)
            return sec["value"] if sec else None

    cfg = load_config()
    cfg = replace(cfg, store=BundleStore(), secrets={
        **cfg.secrets, **{n: secret_from_spec(n, s) for n, s in b.secrets.items()},
    })
    build_mcp(cfg, client=device_name()).run("stdio")


# ─── main ───────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="vault", description="Bóveda portátil de llaves SSH y API keys")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="crea la bóveda en este dispositivo")
    s.add_argument("--name", help="nombre de este dispositivo")
    s.set_defaults(fn=cmd_init)
    sub.add_parser("whoami", help="muestra (o crea) la llave pública de este dispositivo").set_defaults(fn=cmd_whoami)

    s = sub.add_parser("device", help="dispositivos autorizados")
    s.add_argument("action", choices=["list", "add", "rm"])
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

    s = sub.add_parser("token", help="tokens de API para tus apps")
    s.add_argument("action", choices=["create", "list", "rm"])
    s.add_argument("app", nargs="?")
    s.add_argument("--secrets", default="", help="secretos permitidos, separados por comas")
    s.add_argument("--port", type=int, default=8787)
    s.set_defaults(fn=cmd_token)

    s = sub.add_parser("serve", help="API proxy de LLMs para tus apps")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.add_argument("--tls-cert")
    s.add_argument("--tls-key")
    s.set_defaults(fn=cmd_serve)

    sub.add_parser("mcp", help="servidor MCP local (stdio) para Claude").set_defaults(fn=cmd_mcp)

    a = p.parse_args(argv)
    if a.cmd == "device" and a.action == "add" and not (a.name and a.key):
        die("uso: vault device add <nombre> <llave>")
    if a.cmd == "device" and a.action == "rm" and not a.name:
        die("uso: vault device rm <nombre>")
    if a.cmd == "ssh" and a.action != "list" and not a.name:
        die(f"uso: vault ssh {a.action} <nombre>" + (" <ruta>" if a.action in ("import", "export") else ""))
    if a.cmd == "ssh" and a.action in ("import", "export") and not a.path:
        die(f"uso: vault ssh {a.action} <nombre> <ruta>")
    if a.cmd == "token" and a.action in ("create", "rm") and not a.app:
        die(f"uso: vault token {a.action} <app>" + (" --secrets a,b" if a.action == "create" else ""))
    if a.cmd == "token" and a.action == "create" and not a.secrets:
        die("indica --secrets openai,anthropic,...")
    a.fn(a)


if __name__ == "__main__":
    main()
