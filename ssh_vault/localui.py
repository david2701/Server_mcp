"""Panel local (`vault ui`): gestiona servidores SSH, llaves, claves de API y dispositivos
desde el navegador de TU Mac.

- Escucha solo en 127.0.0.1 y en un puerto aleatorio; se desbloquea con Touch ID al arrancar.
- Se entra con un token de un solo uso en la URL que abre `vault ui` (como Jupyter).
- Comprueba la cabecera Host (protección contra DNS rebinding), usa cookie de sesión
  HttpOnly + SameSite=Strict, token CSRF en cada formulario y la misma CSP estricta
  que el panel de la pasarela. Nunca muestra llaves privadas ni valores de claves.
"""

from __future__ import annotations

import hmac
import json
import secrets
from collections import deque
from html import escape
from pathlib import Path

import anyio
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from . import runner
from .bundle import Bundle
from .config import Config, default_audit_log, secret_from_spec, server_from_spec
from .panel import SECURITY_HEADERS, page
from .sshutil import SshError, fingerprints, generate_key, public_from_private, scan_host_keys

COOKIE = "vault_local"
NAME = r"[A-Za-z0-9_.\-]{1,64}"

EXTRA_CSS = """<style>
nav{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 16px}nav a{color:var(--text);text-decoration:none;
padding:6px 12px;border:1px solid var(--line);border-radius:999px;background:var(--card);font-size:14px}
select,textarea{width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);
color:var(--text);font:inherit}textarea{font:13px ui-monospace,Menlo,monospace;min-height:120px}
.row{display:grid;grid-template-columns:2fr 1fr;gap:10px}.inline{display:inline}
.flash{border-color:var(--ok)}.flash.err{border-color:var(--danger)}
.tag{font-size:12px;padding:1px 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted);white-space:nowrap}
td form{margin:0}td .acts{display:flex;gap:6px;flex-wrap:wrap}
button.ghost{background:none;color:var(--accent);border:1px solid var(--accent);padding:4px 10px}
@media(max-width:720px){.row{grid-template-columns:1fr}}
</style>"""


def device_kind(key: str) -> str:
    if key.startswith("age1se1"):
        return "Touch ID"
    if key.startswith("ssh-"):
        return "llave SSH"
    return "age"


def build_app(bundle: Bundle, save, login_token: str, port: int,
              audit_log: Path | None = None, client: str = "panel-local") -> Starlette:
    audit_log = audit_log or default_audit_log()
    state = {"login_token": login_token}
    sessions: dict[str, dict] = {}
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    # ─── utilidades ────────────────────────────────────────────────────────────

    def session(request: Request) -> dict | None:
        return sessions.get(request.cookies.get(COOKIE, ""))

    async def checked_form(request: Request):
        s = session(request)
        form = await request.form()
        origin = request.headers.get("origin")
        if (not s or (origin and origin.split("://", 1)[-1] not in allowed_hosts)
                or not hmac.compare_digest(str(form.get("csrf", "")), s["csrf"])):
            return None, form
        return s, form

    def back(s: dict, kind: str, text: str, anchor: str, detail: str = "") -> Response:
        s["flash"] = (kind, text, detail)
        return RedirectResponse(f"/#{anchor}", 303, headers=SECURITY_HEADERS)

    def denied() -> Response:
        return PlainTextResponse("Sesión no válida. Vuelve a ejecutar `vault ui`.", 403, headers=SECURITY_HEADERS)

    def csrf_field(s: dict) -> str:
        return f"<input type=hidden name=csrf value='{escape(s['csrf'])}'>"

    def button(s: dict, action: str, label: str, fields: dict, cls: str = "danger") -> str:
        hidden = "".join(f"<input type=hidden name='{escape(k)}' value='{escape(v)}'>" for k, v in fields.items())
        return (f"<form class=inline method=post action='{action}'>{csrf_field(s)}{hidden}"
                f"<button class={cls} type=submit>{escape(label)}</button></form>")

    def recent_activity(limit: int = 40) -> list[dict]:
        if not audit_log.exists():
            return []
        events: deque = deque(maxlen=limit)
        with open(audit_log, encoding="utf-8") as fh:
            for line in fh:
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
        return list(reversed(events))

    # ─── página principal ──────────────────────────────────────────────────────

    def dashboard(s: dict) -> Response:
        from .cli import PROVIDERS

        b = bundle
        flash = ""
        if s.get("flash"):
            kind, text, detail = s.pop("flash")
            extra = f"<pre>{escape(detail)}</pre>" if detail else ""
            flash = f"<div class='card flash {'err' if kind == 'err' else ''}'><b>{escape(text)}</b>{extra}</div>"

        key_opts = "".join(f"<option value='{escape(k)}'>{escape(k)}</option>" for k in sorted(b.ssh_keys))
        srv_rows = ""
        for name, sp in sorted(b.servers.items()):
            mode = "solo lectura" if sp.get("read_only") else ("lista blanca" if sp.get("allow_commands") else "completo")
            srv_rows += (
                f"<tr><td><b>{escape(name)}</b><div class=muted>{escape(sp.get('description', ''))}</div></td>"
                f"<td><code>{escape(sp.get('user', 'root'))}@{escape(sp['host'])}:{int(sp.get('port', 22))}</code></td>"
                f"<td>{escape(sp.get('key', '—'))}</td><td><span class=tag>{mode}</span></td>"
                f"<td><div class=acts>{button(s, '/servers/test', 'Probar', {'name': name}, 'ghost')}"
                f"{button(s, '/servers/rm', 'Borrar', {'name': name})}</div></td></tr>")
        srv_rows = srv_rows or "<tr><td colspan=5 class=muted>Aún no hay servidores.</td></tr>"

        key_rows = ""
        for name, k in sorted(b.ssh_keys.items()):
            used = [n for n, sp in b.servers.items() if sp.get("key") == name]
            key_rows += (
                f"<tr><td><b>{escape(name)}</b></td><td><code>{escape(k.get('public', '')[:60])}…</code></td>"
                f"<td>{escape(', '.join(used) or '—')}</td>"
                f"<td><div class=acts>{button(s, '/keys/public', 'Ver pública', {'name': name}, 'ghost')}"
                f"{button(s, '/keys/rm', 'Borrar', {'name': name})}</div></td></tr>")
        key_rows = key_rows or "<tr><td colspan=4 class=muted>Aún no hay llaves. Genera una o importa la tuya.</td></tr>"

        api_rows = "".join(
            f"<tr><td><b>{escape(n)}</b></td><td class=muted>{escape(sp.get('base_url') or 'sin API (solo apps)')}</td>"
            f"<td>{escape(sp.get('description', ''))}</td><td>{button(s, '/secrets/rm', 'Borrar', {'name': n})}</td></tr>"
            for n, sp in sorted(b.secrets.items())) or "<tr><td colspan=4 class=muted>Aún no hay claves.</td></tr>"
        prov_opts = "<option value=''>Otra (sin plantilla)</option>" + "".join(
            f"<option value='{escape(p)}'>{escape(p)}</option>" for p in sorted(PROVIDERS))

        dev_rows = "".join(
            f"<tr><td><b>{escape(n)}</b></td><td><span class=tag>{device_kind(k)}</span></td>"
            f"<td><code>{escape(k[:48])}…</code></td></tr>" for n, k in b.recipients.items())

        act_rows = ""
        for ev in recent_activity():
            target = ev.get("server") or ev.get("secret") or ""
            what = ev.get("command") or ev.get("path") or ev.get("tool", "")
            if ev.get("denied"):
                result = "denegado"
            elif "exit_code" in ev:
                result = f"exit {ev['exit_code']}"
            else:
                result = str(ev.get("status", ev.get("error", "")))
            act_rows += (f"<tr><td class=muted>{escape(ev.get('ts', '')[5:16].replace('T', ' '))}</td>"
                         f"<td>{escape(ev.get('client') or ev.get('app', ''))}</td><td>{escape(target)}</td>"
                         f"<td><code>{escape(what[:80])}</code></td><td>{escape(result)}</td></tr>")
        act_rows = act_rows or "<tr><td colspan=5 class=muted>Sin actividad todavía.</td></tr>"

        c = csrf_field(s)
        body = f"""{EXTRA_CSS}
<header><h1>Bóveda · esta Mac</h1><span class=muted>solo accesible desde este equipo</span></header>
<nav><a href="#servidores">Servidores</a><a href="#llaves">Llaves SSH</a><a href="#apis">Claves de API</a>
<a href="#dispositivos">Dispositivos</a><a href="#actividad">Actividad</a></nav>
{flash}
<div class=card id=servidores><h2>Servidores SSH</h2>
<p class=muted>Tus agentes los usan con <code>vault mcp</code>; tú con <code>vault connect &lt;nombre&gt;</code>.
Las huellas quedan fijadas en la bóveda y todas tus Macs las verifican igual.</p>
<div class=scroll><table><thead><tr><th>Nombre</th><th>Acceso</th><th>Llave</th><th>Modo</th><th></th></tr></thead>
<tbody>{srv_rows}</tbody></table></div>
<h2 style="margin-top:18px">Añadir servidor</h2>
<form method=post action="/servers/scan">{c}
<div class=row><div><label for=sn>Nombre</label><input id=sn type=text name=name required pattern="{NAME}" placeholder="web"></div>
<div><label for=sp>Puerto</label><input id=sp type=number name=port value=22 min=1 max=65535></div></div>
<label for=st>Usuario@host</label><input id=st type=text name=target required placeholder="deploy@203.0.113.10">
<div class=row><div><label for=sk>Llave SSH</label><select id=sk name=key required>{key_opts or '<option value="">— crea una llave primero —</option>'}</select></div>
<div><label for=sm>Modo para los agentes</label><select id=sm name=mode><option value=full>completo</option>
<option value=ro>solo lectura (diagnósticos)</option></select></div></div>
<label for=sd>Descripción</label><input id=sd type=text name=description placeholder="Nginx + app">
<p><button type=submit>Comprobar huellas…</button></p></form></div>

<div class=card id=llaves><h2>Llaves SSH</h2>
<p class=muted>Viven cifradas en la bóveda. Nunca se escriben en disco: van directas a un ssh-agent temporal.</p>
<div class=scroll><table><thead><tr><th>Nombre</th><th>Pública</th><th>Usada por</th><th></th></tr></thead>
<tbody>{key_rows}</tbody></table></div>
<div class=grid style="margin-top:14px">
<form method=post action="/keys/generate">{c}<h2>Generar llave nueva</h2>
<label for=gn>Nombre</label><input id=gn type=text name=name required pattern="{NAME}" placeholder="servidores">
<p><button type=submit>Generar ed25519</button></p></form>
<form method=post action="/keys/import">{c}<h2>Importar llave existente</h2>
<label for=in>Nombre</label><input id=in type=text name=name required pattern="{NAME}">
<label for=ip>Llave privada (contenido de ~/.ssh/id_ed25519)</label>
<textarea id=ip name=private required placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
<p><button type=submit>Importar</button></p></form></div></div>

<div class=card id=apis><h2>Claves de API</h2>
<p class=muted>Tus agentes las usan con <code>call_api</code> sin ver el valor. Para tus servicios, compártelas con la
pasarela (<code>vault share … --to &lt;pasarela&gt;</code>).</p>
<div class=scroll><table><thead><tr><th>Nombre</th><th>API</th><th>Descripción</th><th></th></tr></thead>
<tbody>{api_rows}</tbody></table></div>
<h2 style="margin-top:18px">Añadir clave</h2>
<form method=post action="/secrets/add">{c}
<div class=row><div><label for=an>Nombre</label><input id=an type=text name=name required pattern="{NAME}" placeholder="openai"></div>
<div><label for=ap>Proveedor</label><select id=ap name=provider>{prov_opts}</select></div></div>
<label for=av>Valor</label><input id=av type=password name=value required autocomplete=off>
<label for=ad>Descripción</label><input id=ad type=text name=description>
<p><button type=submit>Guardar</button></p></form></div>

<div class=card id=dispositivos><h2>Dispositivos autorizados</h2>
<div class=scroll><table><thead><tr><th>Nombre</th><th>Tipo</th><th>Llave pública</th></tr></thead>
<tbody>{dev_rows}</tbody></table></div>
<p class=muted>Para añadir una Mac: en ella ejecuta <code>vault whoami</code> y aquí <code>vault device add &lt;nombre&gt; &lt;llave&gt;</code>.</p></div>

<div class=card id=actividad><h2>Actividad de tus agentes</h2>
<div class=scroll><table><thead><tr><th>Fecha (UTC)</th><th>Origen</th><th>Destino</th><th>Acción</th><th>Resultado</th></tr></thead>
<tbody>{act_rows}</tbody></table></div></div>"""
        return page("Bóveda · esta Mac", body)

    # ─── rutas ─────────────────────────────────────────────────────────────────

    async def login(request: Request) -> Response:
        token = request.query_params.get("t", "")
        if not state["login_token"] or not hmac.compare_digest(token, state["login_token"]):
            return denied()
        state["login_token"] = None  # un solo uso
        sid = secrets.token_urlsafe(32)
        sessions[sid] = {"csrf": secrets.token_urlsafe(32)}
        resp = RedirectResponse("/", 303, headers=SECURITY_HEADERS)
        resp.set_cookie(COOKIE, sid, httponly=True, samesite="strict", path="/")
        return resp

    async def home(request: Request) -> Response:
        s = session(request)
        return dashboard(s) if s else denied()

    async def servers_scan(request: Request) -> Response:
        s, f = await checked_form(request)
        if not s:
            return denied()
        user, _, host = str(f.get("target", "")).strip().rpartition("@")
        spec = {"host": host, "user": user or "root", "port": int(f.get("port") or 22),
                "key": str(f.get("key", "")), "description": str(f.get("description", "")).strip(),
                "read_only": f.get("mode") == "ro"}
        name = str(f.get("name", "")).strip()
        try:
            if spec["key"] not in bundle.ssh_keys:
                raise ValueError("elige una llave SSH de la bóveda")
            if name in bundle.servers:
                raise ValueError(f"ya existe el servidor {name!r}")
            server_from_spec(name, {**spec, "host_keys": []})
            spec["host_keys"] = await anyio.to_thread.run_sync(scan_host_keys, host, spec["port"])
        except (ValueError, SshError) as err:
            return back(s, "err", f"No se pudo añadir: {err}", "servidores")
        s["pending"] = (name, spec)
        fps = "".join(f"<li><code>{escape(fp)}</code></li>" for fp in fingerprints(spec["host_keys"]))
        return page("Confirmar huellas", f"""{EXTRA_CSS}<div class=card><h1>¿Es este tu servidor?</h1>
<p>Huellas de <code>{escape(host)}:{spec['port']}</code>. Compáralas con las de tu proveedor o con
<code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code> en el propio servidor.</p><ul>{fps}</ul>
<p class=muted>Si alguien suplanta el servidor más adelante, todas tus Macs se negarán a conectar.</p>
<form class=inline method=post action="/servers/confirm">{csrf_field(s)}<button type=submit>Sí, guardar «{escape(name)}»</button></form>
<form class=inline method=post action="/servers/cancel">{csrf_field(s)}<button class=link type=submit>Cancelar</button></form></div>""")

    async def servers_confirm(request: Request) -> Response:
        s, _ = await checked_form(request)
        if not s or not s.get("pending"):
            return denied()
        name, spec = s.pop("pending")
        bundle.servers[name] = spec
        save()
        return back(s, "ok", f"Servidor «{name}» guardado.", "servidores")

    async def servers_cancel(request: Request) -> Response:
        s, _ = await checked_form(request)
        if not s:
            return denied()
        s.pop("pending", None)
        return back(s, "ok", "Cancelado.", "servidores")

    async def servers_test(request: Request) -> Response:
        s, f = await checked_form(request)
        if not s:
            return denied()
        name = str(f.get("name", ""))
        if name not in bundle.servers:
            return back(s, "err", "Servidor desconocido.", "servidores")
        from .sshagent import session as agent_session

        def test():
            with agent_session(bundle, Config(audit_log=audit_log)) as cfg:
                res = anyio.from_thread.run(runner.run, cfg, cfg.servers[name], "true", 20)
                runner.audit(cfg, client=client, tool="test_connection", server=name, exit_code=res.exit_code)
                return res
        try:
            res = await anyio.to_thread.run_sync(test)
        except Exception as err:  # p. ej. llave inválida
            return back(s, "err", f"Error: {err}", "servidores")
        if res.exit_code == 0:
            return back(s, "ok", f"Conexión con «{name}» correcta ({res.duration_s:.1f}s).", "servidores")
        return back(s, "err", f"La conexión con «{name}» falló.", "servidores", res.stderr.strip()[-800:])

    async def servers_rm(request: Request) -> Response:
        s, f = await checked_form(request)
        if not s:
            return denied()
        if bundle.servers.pop(str(f.get("name", "")), None) is not None:
            save()
        return back(s, "ok", "Servidor borrado.", "servidores")

    async def keys_generate(request: Request) -> Response:
        s, f = await checked_form(request)
        if not s:
            return denied()
        name = str(f.get("name", "")).strip()
        if name in bundle.ssh_keys:
            return back(s, "err", f"Ya existe la llave «{name}».", "llaves")
        try:
            server_from_spec(name, {"host": "x"})  # valida el nombre
            private, public = await anyio.to_thread.run_sync(generate_key, f"ssh-vault {name}")
        except (ValueError, SshError) as err:
            return back(s, "err", str(err), "llaves")
        bundle.ssh_keys[name] = {"private": private, "public": public}
        save()
        return back(s, "ok", f"Llave «{name}» creada. Añade esta línea a ~/.ssh/authorized_keys de tus servidores:",
                    "llaves", public)

    async def keys_import(request: Request) -> Response:
        s, f = await checked_form(request)
        if not s:
            return denied()
        name = str(f.get("name", "")).strip()
        private = str(f.get("private", "")).replace("\r\n", "\n").strip() + "\n"
        try:
            server_from_spec(name, {"host": "x"})
            if name in bundle.ssh_keys:
                raise ValueError(f"ya existe la llave {name!r}")
            public = await anyio.to_thread.run_sync(public_from_private, private)
        except (ValueError, SshError) as err:
            return back(s, "err", f"No se pudo importar: {err}", "llaves")
        bundle.ssh_keys[name] = {"private": private, "public": public}
        save()
        return back(s, "ok", f"Llave «{name}» importada. Ya puedes borrar el archivo original si quieres.", "llaves")

    async def keys_public(request: Request) -> Response:
        s, f = await checked_form(request)
        if not s:
            return denied()
        k = bundle.ssh_keys.get(str(f.get("name", "")))
        if not k:
            return back(s, "err", "Llave desconocida.", "llaves")
        return back(s, "ok", "Llave pública (para authorized_keys):", "llaves", k.get("public", ""))

    async def keys_rm(request: Request) -> Response:
        s, f = await checked_form(request)
        if not s:
            return denied()
        name = str(f.get("name", ""))
        used = [n for n, sp in bundle.servers.items() if sp.get("key") == name]
        if used:
            return back(s, "err", f"La usan: {', '.join(used)}. Bórralos o cámbialos primero.", "llaves")
        if bundle.ssh_keys.pop(name, None) is not None:
            save()
        return back(s, "ok", "Llave borrada.", "llaves")

    async def secrets_add(request: Request) -> Response:
        from .cli import PROVIDERS

        s, f = await checked_form(request)
        if not s:
            return denied()
        name = str(f.get("name", "")).strip()
        preset = dict(PROVIDERS.get(str(f.get("provider", "")), {}))
        preset.pop("env", None)
        spec = {k: v for k, v in {**preset, "description": str(f.get("description", "")).strip()
                                  or str(f.get("provider", ""))}.items() if v}
        value = str(f.get("value", ""))
        try:
            secret_from_spec(name, spec)
            if not value:
                raise ValueError("el valor está vacío")
        except ValueError as err:
            return back(s, "err", str(err), "apis")
        bundle.secrets[name] = {**spec, "value": value}
        save()
        return back(s, "ok", f"Clave «{name}» guardada.", "apis")

    async def secrets_rm(request: Request) -> Response:
        s, f = await checked_form(request)
        if not s:
            return denied()
        if bundle.secrets.pop(str(f.get("name", "")), None) is not None:
            save()
        return back(s, "ok", "Clave borrada.", "apis")

    routes = [
        Route("/login", login), Route("/", home),
        Route("/servers/scan", servers_scan, methods=["POST"]),
        Route("/servers/confirm", servers_confirm, methods=["POST"]),
        Route("/servers/cancel", servers_cancel, methods=["POST"]),
        Route("/servers/test", servers_test, methods=["POST"]),
        Route("/servers/rm", servers_rm, methods=["POST"]),
        Route("/keys/generate", keys_generate, methods=["POST"]),
        Route("/keys/import", keys_import, methods=["POST"]),
        Route("/keys/public", keys_public, methods=["POST"]),
        Route("/keys/rm", keys_rm, methods=["POST"]),
        Route("/secrets/add", secrets_add, methods=["POST"]),
        Route("/secrets/rm", secrets_rm, methods=["POST"]),
    ]
    app = Starlette(routes=routes)

    async def guard(scope, receive, send):
        if scope["type"] == "http":
            host = dict(scope.get("headers") or []).get(b"host", b"").decode()
            if host not in allowed_hosts:
                await PlainTextResponse("Host no permitido", 403)(scope, receive, send)
                return
        await app(scope, receive, send)

    return guard
