"""App autoalojada: todo en un servidor tuyo, sin depender de ninguna Mac.

    https://vault.tudominio.com/_vault/   → panel (servidores, accesos de IA, API keys)
    https://vault.tudominio.com/mcp       → MCP remoto para cualquier LLM (token u OAuth)
    https://vault.tudominio.com/<api>/…   → proxy de LLMs para tus servicios (vt_…)

Cada servidor tiene su propia llave SSH, generada aquí; la privada nunca sale de la app.
"""

from __future__ import annotations

import json
from collections import deque
from html import escape
from pathlib import Path
from urllib.parse import urlsplit

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from . import access, enroll, runner
from .bundle import Bundle
from .config import Config, default_audit_log
from .llmproxy import Gateway, proxy_routes
from .panel import SECURITY_HEADERS, page, panel_routes
from .server import build_mcp
from .sshagent import AgentManager
from .sshutil import fingerprints

NAME = r"[A-Za-z0-9_.\-]{1,64}"


class HostedGateway(Gateway):
    title = "Servidores, accesos de IA y API keys"

    def __init__(self, bundle: Bundle, audit_log: Path | None, save, public_url: str,
                 setup_token: str | None = None):
        super().__init__(bundle, audit_log or default_audit_log(), save)
        self.public_url = public_url.rstrip("/")
        self.setup_token = setup_token
        self.agent = AgentManager(Config(audit_log=self.audit_log))
        self.enrollments = enroll.Enrollments()
        self.provider = access.Provider(self)
        self.agent.sync(bundle)

    @property
    def settings(self) -> dict:
        return self.bundle.admin.setdefault("settings", {})

    def changed(self) -> None:
        self.agent.sync(self.bundle)
        self.save()

    # ─── HTML de las secciones ─────────────────────────────────────────────────

    def _enroll_text(self, name: str) -> tuple[str, str]:
        token = self.enrollments.create(name)
        cmd = f"curl -fsSL {self.public_url}/_vault/enroll/{token} | sh"
        pub = self.bundle.ssh_keys[enroll.key_name(name)]["public"]
        line = enroll.authorized_keys_line(pub, name, self.settings.get("egress_ip", ""))
        detail = (f"Opción A · ejecuta en el servidor, como el usuario «{self.bundle.servers[name]['user']}» "
                  f"(válido 30 min, un solo uso):\n\n  {cmd}\n\n"
                  f"Opción B · a mano: añade esta línea a ~/.ssh/authorized_keys y pulsa «Escanear huellas»:\n\n  {line}")
        return cmd, detail

    def _activity(self, limit: int = 30) -> list[dict]:
        log = self.audit_log
        if not log or not log.exists():
            return []
        events: deque = deque(maxlen=limit)
        with open(log, encoding="utf-8") as fh:
            for line in fh:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if ev.get("tool") in ("run_command", "test_connection", "call_api"):
                    events.append(ev)
        return list(reversed(events))

    def sections(self, ctx, s: dict, request: Request) -> str:
        b, btn = self.bundle, ctx.button
        c = ctx.csrf_field(s)
        egress = self.settings.get("egress_ip", "")

        srv_rows = ""
        for name, sp in sorted(b.servers.items()):
            installed = sp.get("status") == "instalado" or (sp.get("host_keys") and sp.get("status") != "pendiente")
            state = "<span class='tag ok'>instalado</span>" if installed else "<span class='tag warn'>pendiente</span>"
            mode = "solo lectura" if sp.get("read_only") else "completo"
            acts = btn(s, "/_vault/servers/test", "Probar", {"name": name}, "ghost")
            if not installed:
                acts += btn(s, "/_vault/servers/enroll", "Comando de alta", {"name": name}, "ghost")
                acts += btn(s, "/_vault/servers/scan", "Escanear huellas", {"name": name}, "ghost")
            acts += btn(s, "/_vault/servers/rotate", "Rotar llave", {"name": name}, "ghost")
            acts += btn(s, "/_vault/servers/rm", "Borrar", {"name": name})
            srv_rows += (f"<tr><td><b>{escape(name)}</b><div class=muted>{escape(sp.get('description', ''))}</div></td>"
                         f"<td><code>{escape(sp.get('user', 'root'))}@{escape(sp['host'])}:{int(sp.get('port', 22))}</code></td>"
                         f"<td>{state}</td><td><span class=tag>{mode}</span></td><td><div class=acts>{acts}</div></td></tr>")
        srv_rows = srv_rows or "<tr><td colspan=5 class=muted>Aún no hay servidores.</td></tr>"
        warn = "" if egress else ("<p class=err>Configura la IP de salida de esta app en <a href='#ajustes'>Ajustes</a>: "
                                  "así las llaves solo funcionan desde aquí aunque alguien las robe.</p>")

        def checks(field: str, names: list[str]) -> str:
            boxes = f"<label><input type=checkbox name={field} value='*'> <b>todos</b></label>"
            return boxes + "".join(f"<label><input type=checkbox name={field} value='{escape(n)}'> {escape(n)}</label>"
                                   for n in names)
        apis = sorted(n for n, sp in b.secrets.items() if sp.get("base_url"))
        acc_rows = "".join(
            f"<tr><td><b>{escape(a['name'])}</b></td><td><span class=tag>{'OAuth' if a['kind'] == 'oauth' else 'token'}</span></td>"
            f"<td>{escape(', '.join(a['servers']) or '—')}</td><td>{escape(', '.join(a['secrets']) or '—')}</td>"
            f"<td>{btn(s, '/_vault/access/revoke', 'Revocar', {'name': a['name']})}</td></tr>"
            for a in access.list_access(b)) or "<tr><td colspan=5 class=muted>Ninguna IA conectada todavía.</td></tr>"

        act_rows = ""
        for ev in self._activity():
            if ev.get("denied"):
                res = "denegado"
            elif "exit_code" in ev:
                res = f"exit {ev['exit_code']}"
            else:
                res = str(ev.get("status", ev.get("error", "")))
            act_rows += (f"<tr><td class=muted>{escape(ev.get('ts', '')[5:16].replace('T', ' '))}</td>"
                         f"<td>{escape(ev.get('client', ''))}</td><td>{escape(ev.get('server') or ev.get('secret', ''))}</td>"
                         f"<td><code>{escape((ev.get('command') or ev.get('path') or ev.get('tool', ''))[:90])}</code></td>"
                         f"<td>{escape(res)}</td></tr>")
        act_rows = act_rows or "<tr><td colspan=5 class=muted>Sin actividad todavía.</td></tr>"
        mcp_url = f"{self.public_url}/mcp"
        from .cli import PROVIDERS
        prov_opts = "".join(f"<option value='{escape(p)}'>{escape(p)}</option>" for p in sorted(PROVIDERS))
        prov_opts += "<option value=''>otro (indica la URL base)</option>"
        prov_rows = "".join(
            f"<tr><td><b>{escape(n)}</b></td><td class=muted>{escape(sp.get('base_url') or '—')}</td>"
            f"<td>{btn(s, '/_vault/secrets/rm', 'Borrar', {'name': n})}</td></tr>"
            for n, sp in sorted(b.secrets.items())) or "<tr><td colspan=3 class=muted>Aún no hay claves.</td></tr>"

        return f"""
<div class=card id=servidores><h2>Servidores</h2>
<p class=muted>Cada servidor tiene su propia llave SSH, creada aquí. La privada nunca sale de la app.</p>{warn}
<div class=scroll><table><thead><tr><th>Nombre</th><th>Acceso</th><th>Estado</th><th>Modo</th><th></th></tr></thead>
<tbody>{srv_rows}</tbody></table></div>
<h2 style="margin-top:18px">Añadir servidor</h2>
<form method=post action="/_vault/servers">{c}
<div class=row><div><label for=sn>Nombre</label><input id=sn type=text name=name required pattern="{NAME}" placeholder="web"></div>
<div><label for=sp>Puerto SSH</label><input id=sp type=number name=port value=22 min=1 max=65535></div></div>
<label for=st>Usuario@host</label><input id=st type=text name=target required placeholder="deploy@203.0.113.10">
<div class=row><div><label for=sd>Descripción</label><input id=sd type=text name=description placeholder="Nginx + app"></div>
<div><label for=sm>Qué pueden hacer las IAs</label><select id=sm name=mode><option value=full>todo</option>
<option value=ro>solo diagnósticos</option></select></div></div>
<p><button type=submit>Crear llave y comando de alta</button></p></form></div>

<div class=card id=accesos><h2>Accesos de IA (MCP)</h2>
<p>URL del MCP: <code>{escape(mcp_url)}</code></p>
<p class=muted><b>Claude.ai, ChatGPT…</b>: añade un conector personalizado con esa URL; te traerá aquí para aprobarlo
y elegir a qué servidores y APIs accede. <b>Claude Code, Cursor, Codex, agentes propios</b>: crea un token.</p>
<div class=scroll><table><thead><tr><th>Nombre</th><th>Tipo</th><th>Servidores</th><th>APIs</th><th></th></tr></thead>
<tbody>{acc_rows}</tbody></table></div>
<h2 style="margin-top:18px">Nuevo token</h2>
<form method=post action="/_vault/access">{c}
<label for=tn>Nombre</label><input id=tn type=text name=name required pattern="{NAME}" placeholder="claude-code-portatil">
<label>Servidores</label><div class=apis>{checks("servers", sorted(b.servers))}</div>
<label>APIs (call_api)</label><div class=apis>{checks("apis", apis)}</div>
<p><button type=submit>Crear token</button></p></form></div>

<div class=card id=claves><h2>Claves de proveedores</h2>
<p class=muted>Se guardan cifradas en la bóveda y no se vuelven a mostrar. Las usan el proxy (API keys de tus
servicios) y las IAs con <code>call_api</code>, sin verlas.</p>
<div class=scroll><table><thead><tr><th>Nombre</th><th>Proveedor</th><th></th></tr></thead><tbody>{prov_rows}</tbody></table></div>
<form method=post action="/_vault/secrets">{c}
<div class=row><div><label for=pn>Nombre</label><input id=pn type=text name=name required pattern="{NAME}" placeholder="openai"></div>
<div><label for=pp>Proveedor</label><select id=pp name=provider>{prov_opts}</select></div></div>
<label for=pv>Clave</label><input id=pv type=password name=value required autocomplete=off>
<label for=pu>URL base (solo si eliges «otro»)</label><input id=pu type=text name=base_url placeholder="https://api.ejemplo.com/v1/">
<p><button type=submit>Guardar clave</button></p></form></div>

<div class=card id=actividad-ia><h2>Actividad de las IAs</h2>
<div class=scroll><table><thead><tr><th>Fecha (UTC)</th><th>Acceso</th><th>Destino</th><th>Acción</th><th>Resultado</th></tr></thead>
<tbody>{act_rows}</tbody></table></div></div>

<div class=card id=ajustes><h2>Ajustes</h2>
<form method=post action="/_vault/settings">{c}
<label for=eg>IP pública de salida de esta app</label>
<input id=eg type=text name=egress_ip value='{escape(egress)}' placeholder="203.0.113.5 (o varias, separadas por comas)">
<p class=muted>Se añade como <code>from="…"</code> a las llaves que instales a partir de ahora: solo funcionarán desde esta IP.
Averíguala en el servidor de la app con <code>curl -4 ifconfig.me</code>.</p>
<p><button type=submit>Guardar</button></p></form>
<p class=muted>Instala el panel como app: en Safari, Archivo → Añadir al Dock; en Chrome, «Instalar aplicación».</p></div>"""

    # ─── Rutas ─────────────────────────────────────────────────────────────────

    def routes(self, ctx) -> list[Route]:
        gw, b = self, self.bundle

        async def guarded(request: Request):
            s, form = await ctx.form_checked(request)
            if not s:
                return None, None, ctx.login_page("Sesión caducada; vuelve a entrar.", 403)
            return s, form, None

        async def server_add(request: Request) -> Response:
            s, f, err = await guarded(request)
            if err:
                return err
            name = str(f.get("name", "")).strip()
            if name in b.servers:
                return ctx.back(s, "err", f"Ya existe el servidor «{name}».", "servidores")
            try:
                enroll.create_server(b, name, str(f.get("target", "")), int(f.get("port") or 22),
                                     read_only=f.get("mode") == "ro", description=str(f.get("description", "")))
            except (ValueError, KeyError) as e:
                return ctx.back(s, "err", f"No se pudo crear: {e}", "servidores")
            gw.changed()
            _, detail = gw._enroll_text(name)
            return ctx.back(s, "ok", f"Servidor «{name}» creado con su propia llave. Ahora instálala:", "servidores", detail)

        async def server_enroll(request: Request) -> Response:
            s, f, err = await guarded(request)
            if err:
                return err
            name = str(f.get("name", ""))
            if name not in b.servers:
                return ctx.back(s, "err", "Servidor desconocido.", "servidores")
            _, detail = gw._enroll_text(name)
            return ctx.back(s, "ok", f"Comando de alta para «{name}»:", "servidores", detail)

        async def server_scan(request: Request) -> Response:
            from .sshutil import SshError, scan_host_keys
            import anyio
            s, f, err = await guarded(request)
            if err:
                return err
            name = str(f.get("name", ""))
            sp = b.servers.get(name)
            if not sp:
                return ctx.back(s, "err", "Servidor desconocido.", "servidores")
            try:
                keys = await anyio.to_thread.run_sync(scan_host_keys, sp["host"], int(sp.get("port", 22)))
            except SshError as e:
                return ctx.back(s, "err", str(e), "servidores")
            sp["host_keys"], sp["status"] = keys, "instalado"
            gw.changed()
            return ctx.back(s, "ok", f"Huellas de «{name}» fijadas. Compruébalas y pulsa «Probar»:", "servidores",
                            "\n".join(fingerprints(keys)))

        async def server_test(request: Request) -> Response:
            s, f, err = await guarded(request)
            if err:
                return err
            name = str(f.get("name", ""))
            cfg = gw.agent.cfg
            srv = cfg.servers.get(name)
            if not srv:
                return ctx.back(s, "err", "Servidor desconocido.", "servidores")
            if not srv.host_keys:
                return ctx.back(s, "err", f"«{name}» aún no está dado de alta (faltan sus huellas).", "servidores")
            res = await runner.run(cfg, srv, "true", 20)
            runner.audit(cfg, client="panel", tool="test_connection", server=name, exit_code=res.exit_code)
            if res.exit_code == 0:
                return ctx.back(s, "ok", f"Conexión con «{name}» correcta ({res.duration_s:.1f}s).", "servidores")
            return ctx.back(s, "err", f"La conexión con «{name}» falló.", "servidores", res.stderr.strip()[-800:])

        async def server_rotate(request: Request) -> Response:
            s, f, err = await guarded(request)
            if err:
                return err
            name = str(f.get("name", ""))
            if name not in b.servers:
                return ctx.back(s, "err", "Servidor desconocido.", "servidores")
            enroll.rotate_key(b, name)
            gw.changed()
            _, detail = gw._enroll_text(name)
            return ctx.back(s, "ok", f"Llave de «{name}» rotada: la anterior ya no se usa. Instala la nueva "
                                     "(el comando de alta borra la vieja del servidor):", "servidores", detail)

        async def server_rm(request: Request) -> Response:
            s, f, err = await guarded(request)
            if err:
                return err
            name = str(f.get("name", ""))
            if enroll.delete_server(b, name):
                gw.changed()
            return ctx.back(s, "ok", f"«{name}» borrado. En el servidor puedes quitar su llave con:", "servidores",
                            f"sed -i '/ ssh-vault:{name}$/d' ~/.ssh/authorized_keys")

        # Alta desde el propio servidor (sin sesión: lo autoriza el token de un solo uso)
        async def enroll_script(request: Request) -> Response:
            token = request.path_params["token"]
            e = gw.enrollments.get(token)
            if not e or e.server not in b.servers:
                return PlainTextResponse("echo 'Enlace de alta caducado o no válido' >&2; exit 1\n", 404)
            e.fetched = True
            pub = b.ssh_keys[enroll.key_name(e.server)]["public"]
            line = enroll.authorized_keys_line(pub, e.server, gw.settings.get("egress_ip", ""))
            return PlainTextResponse(enroll.script(gw.public_url, token, line, e.server),
                                     headers={"Cache-Control": "no-store"})

        async def enroll_hostkeys(request: Request) -> Response:
            token = request.path_params["token"]
            e = gw.enrollments.get(token)
            if not e or not e.fetched or e.server not in b.servers:
                return PlainTextResponse("enlace caducado o no válido\n", 404)
            body = (await request.body())[:65536].decode("utf-8", "replace")
            keys = enroll.parse_host_keys(body)
            if not keys:
                return PlainTextResponse("no llegaron huellas válidas\n", 400)
            gw.enrollments.consume(token)
            b.servers[e.server]["host_keys"] = keys
            b.servers[e.server]["status"] = "instalado"
            gw.changed()
            return PlainTextResponse(f"Huellas recibidas ({len(keys)}).\n")

        async def access_create(request: Request) -> Response:
            s, f, err = await guarded(request)
            if err:
                return err
            name = str(f.get("name", "")).strip()
            try:
                token = access.create_token(b, name, [str(x) for x in f.getlist("servers")],
                                            [str(x) for x in f.getlist("apis")])
            except ValueError as e:
                return ctx.back(s, "err", str(e), "accesos")
            gw.save()
            mcp_url = f"{gw.public_url}/mcp"
            detail = (f"{token}\n\nClaude Code:\n  claude mcp add --transport http vault {mcp_url} "
                      f"--header \"Authorization: Bearer {token}\"\n\nCursor / otros (JSON):\n"
                      + json.dumps({"mcpServers": {"vault": {"url": mcp_url,
                                                             "headers": {"Authorization": f"Bearer {token}"}}}},
                                   indent=2))
            return ctx.back(s, "ok", f"Token «{name}» creado. Cópialo ahora: no se volverá a mostrar.", "accesos", detail)

        async def access_revoke(request: Request) -> Response:
            s, f, err = await guarded(request)
            if err:
                return err
            if access.revoke(b, str(f.get("name", ""))):
                gw.save()
            return ctx.back(s, "ok", "Acceso revocado: deja de funcionar inmediatamente.", "accesos")

        async def settings(request: Request) -> Response:
            s, f, err = await guarded(request)
            if err:
                return err
            raw = str(f.get("egress_ip", "")).strip()
            try:
                if raw:
                    enroll.authorized_keys_line("ssh-ed25519 AAAA", "x", raw)  # valida las IPs
            except ValueError:
                return ctx.back(s, "err", "IP no válida.", "ajustes")
            gw.settings["egress_ip"] = raw
            gw.save()
            return ctx.back(s, "ok", "Ajustes guardados. Rota las llaves ya instaladas para aplicar la IP.", "ajustes")

        async def secret_add(request: Request) -> Response:
            from .cli import PROVIDERS
            from .config import secret_from_spec
            s, f, err = await guarded(request)
            if err:
                return err
            name, provider = str(f.get("name", "")).strip(), str(f.get("provider", ""))
            preset = {k: v for k, v in PROVIDERS.get(provider, {}).items() if k != "env"}
            spec = {**preset, "description": provider or "personalizada"}
            if not provider:
                spec["base_url"] = str(f.get("base_url", "")).strip() or None
            value = str(f.get("value", ""))
            try:
                secret_from_spec(name, spec)
                if not value:
                    raise ValueError("la clave está vacía")
            except ValueError as e:
                return ctx.back(s, "err", str(e), "claves")
            b.secrets[name] = {k: v for k, v in {**spec, "value": value}.items() if v}
            gw.changed()
            return ctx.back(s, "ok", f"Clave «{name}» guardada.", "claves")

        async def secret_rm(request: Request) -> Response:
            s, f, err = await guarded(request)
            if err:
                return err
            if b.secrets.pop(str(f.get("name", "")), None) is not None:
                gw.changed()
            return ctx.back(s, "ok", "Clave borrada.", "claves")

        # Consentimiento OAuth (Claude.ai, ChatGPT…)
        async def consent(request: Request) -> Response:
            rid = request.query_params.get("req") or ""
            s = ctx.current(request)
            if not s:
                return ctx.login_page(next_url=f"/_vault/oauth/consent?req={rid}")
            req = gw.provider.pending.get(rid)
            if not req:
                return page("Bóveda", "<div class=card><h1>Petición caducada</h1><p>Vuelve a conectar desde tu IA.</p></div>", 410)
            redirect = urlsplit(str(req["params"].redirect_uri)).netloc
            apis = sorted(n for n, sp in b.secrets.items() if sp.get("base_url"))

            def checks(field, names):
                return (f"<label><input type=checkbox name={field} value='*'> <b>todos</b></label>"
                        + "".join(f"<label><input type=checkbox name={field} value='{escape(n)}'> {escape(n)}</label>"
                                  for n in names))
            suggested = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in req["client_name"])[:40] or "ia"
            c = ctx.csrf_field(s)
            return page("Bóveda · conectar IA", f"""<div class=card style="max-width:560px;margin:6vh auto">
<h1>¿Conectar «{escape(req['client_name'])}»?</h1>
<p class=muted>Volverá a <code>{escape(redirect)}</code>. Solo podrá usar lo que marques; puedes revocarlo cuando quieras.</p>
<form method=post action="/_vault/oauth/consent">{c}<input type=hidden name=req value='{escape(rid)}'>
<label for=cn>Nombre de este acceso</label><input id=cn type=text name=name required pattern="{NAME}" value='{escape(suggested)}'>
<label>Servidores</label><div class=apis>{checks("servers", sorted(b.servers))}</div>
<label>APIs (call_api)</label><div class=apis>{checks("apis", apis)}</div>
<p><button type=submit name=decision value=approve>Permitir</button>
<button class=link type=submit name=decision value=deny>Rechazar</button></p></form></div>""")

        async def consent_post(request: Request) -> Response:
            s, f, err = await guarded(request)
            if err:
                return err
            rid = str(f.get("req", ""))
            try:
                if f.get("decision") == "approve":
                    url = gw.provider.approve(rid, str(f.get("name", "")).strip(),
                                              [str(x) for x in f.getlist("servers")], [str(x) for x in f.getlist("apis")])
                else:
                    url = gw.provider.deny(rid)
            except ValueError as e:
                return page("Bóveda", f"<div class=card><p class=err>{escape(str(e))}</p></div>", 400)
            return RedirectResponse(url, 302, headers=SECURITY_HEADERS)

        return [
            Route("/_vault/servers", server_add, methods=["POST"]),
            Route("/_vault/servers/enroll", server_enroll, methods=["POST"]),
            Route("/_vault/servers/scan", server_scan, methods=["POST"]),
            Route("/_vault/servers/test", server_test, methods=["POST"]),
            Route("/_vault/servers/rotate", server_rotate, methods=["POST"]),
            Route("/_vault/servers/rm", server_rm, methods=["POST"]),
            Route("/_vault/enroll/{token}", enroll_script),
            Route("/_vault/enroll/{token}/hostkeys", enroll_hostkeys, methods=["POST"]),
            Route("/_vault/access", access_create, methods=["POST"]),
            Route("/_vault/access/revoke", access_revoke, methods=["POST"]),
            Route("/_vault/settings", settings, methods=["POST"]),
            Route("/_vault/secrets", secret_add, methods=["POST"]),
            Route("/_vault/secrets/rm", secret_rm, methods=["POST"]),
            Route("/_vault/oauth/consent", consent),
            Route("/_vault/oauth/consent", consent_post, methods=["POST"]),
        ]


def build_hosted_app(bundle: Bundle, save, public_url: str, audit_log: Path | None = None,
                     setup_token: str | None = None):
    public_url = public_url.rstrip("/")
    gw = HostedGateway(bundle, audit_log, save, public_url, setup_token)

    def current_access():
        tok = get_access_token()
        grant = access.lookup(bundle, tok.token) if tok else None
        if not grant:
            return "desconocido", lambda kind, name: False
        return grant["name"], lambda kind, name: access.allows(grant, kind, name)

    mcp = build_mcp(
        lambda: gw.agent.cfg, access=current_access,
        auth_server_provider=gw.provider,
        auth=AuthSettings(
            issuer_url=public_url, resource_server_url=f"{public_url}/mcp",
            client_registration_options=ClientRegistrationOptions(enabled=True, valid_scopes=[access.SCOPE],
                                                                  default_scopes=[access.SCOPE]),
            revocation_options=RevocationOptions(enabled=True), required_scopes=[access.SCOPE],
            validate_token_resource=True),
    )
    host = urlsplit(public_url).netloc
    security = TransportSecuritySettings(
        allowed_hosts=[host, "127.0.0.1:*", "localhost:*"],
        allowed_origins=[public_url, "http://127.0.0.1:*", "http://localhost:*"])
    app = mcp.streamable_http_app(transport_security=security, host="0.0.0.0")
    app.router.routes.extend(panel_routes(gw) + proxy_routes(gw))
    app.state.gateway = gw
    return app
