"""Panel web y API de administración de la pasarela (todo bajo /_vault/).

- Panel (navegador): contraseña de administrador → crear/revocar API keys por servicio,
  ver qué APIs hay, cómo configurar cada servicio y la actividad reciente.
- API de administración (scripts de despliegue): Authorization: Bearer va_…
      POST   /_vault/api/keys        {"name": "mi-servicio", "apis": ["openai"], "expires_days": 90}
      GET    /_vault/api/keys
      DELETE /_vault/api/keys/{name}
      GET    /_vault/api/apis
"""

from __future__ import annotations

import hmac
import secrets
import time
from collections import defaultdict, deque
from html import escape
from typing import TYPE_CHECKING

import anyio
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from . import keys as K

if TYPE_CHECKING:
    from .llmproxy import Gateway

COOKIE = "vault_session"
SESSION_TTL = 8 * 3600
MAX_FAILS, FAIL_WINDOW = 5, 15 * 60

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; "
                               "manifest-src 'self'; form-action 'self' https: http://127.0.0.1:* http://localhost:*; "
                               "frame-ancestors 'none'; base-uri 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    # same-origin (no "no-referrer"): con no-referrer los navegadores envían Origin: null
    # en los formularios y la comprobación de origen bloquearía el propio panel.
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
}

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--text:#1d1d1b;--muted:#6b6b66;--line:#e4e4df;--accent:#2f5d50;
--accent-text:#fff;--danger:#a3342b;--code:#f0f0ec;--ok:#2f7a4f}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#1f1f1d;--text:#ecece8;--muted:#a1a19a;
--line:#33332f;--accent:#7fb8a4;--accent-text:#10201b;--danger:#e0786e;--code:#2a2a27;--ok:#7fcf9f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:20px}
h1{font-size:20px;margin:0}h2{font-size:16px;margin:0 0 12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px 6px;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
.scroll{overflow-x:auto}code,pre{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--code);
border-radius:6px}code{padding:1px 5px}pre{padding:12px;overflow-x:auto;margin:8px 0 0}
input[type=text],input[type=password],input[type=number]{width:100%;padding:9px 10px;border:1px solid var(--line);
border-radius:8px;background:var(--bg);color:var(--text);font:inherit}
label{display:block;margin:10px 0 4px;font-weight:600;font-size:14px}
.apis{display:flex;flex-wrap:wrap;gap:8px 16px;margin:6px 0}.apis label{font-weight:400;margin:0}
button{border:0;border-radius:8px;padding:9px 14px;font:inherit;font-weight:600;cursor:pointer;
background:var(--accent);color:var(--accent-text)}button.link{background:none;color:var(--muted);padding:4px}
button.danger{background:none;color:var(--danger);border:1px solid var(--danger);padding:4px 10px}
.muted{color:var(--muted)}.new{border-color:var(--ok)}.new pre{white-space:pre-wrap;word-break:break-all}.err{color:var(--danger);font-weight:600}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:720px){.grid{grid-template-columns:1fr}}
nav{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 16px}nav a{color:var(--text);text-decoration:none;
padding:6px 12px;border:1px solid var(--line);border-radius:999px;background:var(--card);font-size:14px}
select,textarea{width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);
color:var(--text);font:inherit}.row{display:grid;grid-template-columns:2fr 1fr;gap:10px}
@media(max-width:720px){.row{grid-template-columns:1fr}}.inline{display:inline}
.flash{border-color:var(--ok)}.flash.err{border-color:var(--danger)}.flash pre{white-space:pre-wrap;word-break:break-all}
.tag{font-size:12px;padding:1px 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted);white-space:nowrap}
.tag.ok{color:var(--ok);border-color:var(--ok)}.tag.warn{color:var(--danger);border-color:var(--danger)}
td form{margin:0}.acts{display:flex;gap:6px;flex-wrap:wrap}
button.ghost{background:none;color:var(--accent);border:1px solid var(--accent);padding:4px 10px}
"""

ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="112"
fill="#2f5d50"/><rect x="136" y="232" width="240" height="176" rx="28" fill="#fff"/><path d="M188 232v-52a68 68 0 0 1
136 0v52" fill="none" stroke="#fff" stroke-width="36" stroke-linecap="round"/><circle cx="256" cy="312" r="26"
fill="#2f5d50"/></svg>"""


def page(title: str, body: str, status: int = 200, headers: dict | None = None) -> HTMLResponse:
    html = (f"<!doctype html><html lang=es><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<meta name=theme-color content='#2f5d50'><meta name=apple-mobile-web-app-capable content=yes>"
            f"<link rel=manifest href='/_vault/manifest.webmanifest'><link rel=icon href='/_vault/icon.svg'>"
            f"<link rel=apple-touch-icon href='/_vault/icon.svg'>"
            f"<title>{escape(title)}</title><style>{CSS}</style></head><body><main>{body}</main></body></html>")
    return HTMLResponse(html, status_code=status, headers={**SECURITY_HEADERS, **(headers or {})})


def panel_routes(gw: "Gateway") -> list[Route]:
    sessions: dict[str, dict] = {}
    fails: dict[str, deque] = defaultdict(deque)

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "?"

    def current(request: Request) -> dict | None:
        sid = request.cookies.get(COOKIE)
        s = sessions.get(sid or "")
        if s and s["exp"] > time.time():
            return s
        sessions.pop(sid or "", None)
        return None

    def same_origin(request: Request) -> bool:
        origin = request.headers.get("origin")
        if not origin:
            return True
        return origin.split("://", 1)[-1] == request.headers.get("host", "")

    async def form_checked(request: Request):
        """Sesión válida + misma procedencia + token CSRF correcto."""
        s = current(request)
        form = await request.form()
        if not s or not same_origin(request) or not hmac.compare_digest(str(form.get("csrf", "")), s["csrf"]):
            return None, form
        return s, form

    def csrf_field(s: dict) -> str:
        return f"<input type=hidden name=csrf value='{escape(s['csrf'])}'>"

    def button(s: dict, action: str, label: str, fields: dict, cls: str = "danger") -> str:
        hidden = "".join(f"<input type=hidden name='{escape(k)}' value='{escape(str(v))}'>" for k, v in fields.items())
        return (f"<form class=inline method=post action='{escape(action)}'>{csrf_field(s)}{hidden}"
                f"<button class={cls} type=submit>{escape(label)}</button></form>")

    def back(s: dict, kind: str, text: str, anchor: str = "", detail: str = "") -> Response:
        s["flash"] = (kind, text, detail)
        return RedirectResponse(f"/_vault/#{anchor}" if anchor else "/_vault/", 303, headers=SECURITY_HEADERS)

    def safe_next(value: str) -> str:
        return value if value.startswith("/_vault/") and "//" not in value and "\\" not in value else "/_vault/"

    class Ctx:  # utilidades para las secciones que añade la app autoalojada
        pass
    ctx = Ctx()
    ctx.current, ctx.form_checked, ctx.csrf_field, ctx.button, ctx.back = current, form_checked, csrf_field, button, back

    def login_page(error: str = "", status: int = 200, next_url: str = "/_vault/") -> HTMLResponse:
        if not gw.bundle.admin.get("password"):
            hint = ("Abre el enlace de configuración inicial que aparece en los logs de la app."
                    if getattr(gw, "setup_token", None) else
                    "Fija una contraseña con <code>vault admin password</code> y reinicia <code>vault serve</code>.")
            return page("Bóveda", f"<div class=card><h1>Falta configurar el panel</h1><p>{hint}</p></div>", 503)
        err = f"<p class=err>{escape(error)}</p>" if error else ""
        return page("Bóveda · acceso", f"""
<div class=card style="max-width:380px;margin:12vh auto">
<h1>Bóveda</h1><p class=muted>{escape(getattr(gw, "title", "Panel de API keys"))}</p>{err}
<form method=post action="/_vault/login"><input type=hidden name=next value='{escape(safe_next(next_url))}'>
<label for=pw>Contraseña de administrador</label>
<input id=pw type=password name=password autocomplete=current-password autofocus required>
<p><button type=submit>Entrar</button></p></form></div>""", status)

    def dashboard(s: dict, request: Request, new: tuple[str, list[str]] | None = None,
                  error: str = "") -> HTMLResponse:
        b = gw.bundle
        base = str(request.base_url).rstrip("/")
        stats, recent = K.usage(gw.audit_log)
        apis = K.proxy_apis(b)
        csrf = escape(s["csrf"])

        new_html = ""
        if new:
            key, key_apis = new
            env = "\n".join(f"{k}={v}" for k, v in K.env_example(key_apis, base, key).items())
            new_html = f"""<div class="card new"><h2>API key creada: cópiala ahora</h2>
<p class=muted>No se volverá a mostrar: la bóveda solo guarda su hash.</p><pre>{escape(key)}</pre>
<p>Variables de entorno para el servicio (los SDK oficiales funcionan sin cambios):</p><pre>{escape(env)}</pre></div>"""
        err_html = f"<div class=card><p class=err>{escape(error)}</p></div>" if error else ""

        api_rows = "".join(
            f"<tr><td><code>{escape(n)}</code></td><td>{escape(b.secrets[n].get('description', ''))}</td>"
            f"<td><code>{escape(base)}/{escape(n)}</code></td><td class=muted>{escape(b.secrets[n]['base_url'])}</td></tr>"
            for n in apis) or "<tr><td colspan=4 class=muted>No hay APIs. Impórtalas con <code>vault import</code>.</td></tr>"

        checks = "".join(f"<label><input type=checkbox name=apis value='{escape(n)}'> {escape(n)}</label>" for n in apis)

        key_rows = ""
        for t in K.list_keys(b):
            st = stats.get(t["name"], {})
            exp = t.get("expires", "")[:10] or "nunca"
            key_rows += (
                f"<tr><td><b>{escape(t['name'])}</b></td><td>{escape(', '.join(t['secrets']))}</td>"
                f"<td>{escape(t.get('created', '')[:10])}</td><td>{escape(exp)}</td>"
                f"<td>{st.get('requests', 0)}<span class=muted> / {st.get('errors', 0)} err</span></td>"
                f"<td class=muted>{escape((st.get('last') or '—')[:16].replace('T', ' '))}</td>"
                f"<td><form method=post action='/_vault/keys/revoke'><input type=hidden name=csrf value='{csrf}'>"
                f"<input type=hidden name=name value='{escape(t['name'])}'>"
                f"<button class=danger type=submit>Revocar</button></form></td></tr>")
        key_rows = key_rows or "<tr><td colspan=7 class=muted>Todavía no hay API keys.</td></tr>"

        recent_rows = "".join(
            f"<tr><td class=muted>{escape(ev.get('ts', '')[5:16].replace('T', ' '))}</td><td>{escape(ev.get('app', ''))}</td>"
            f"<td>{escape(ev.get('secret', ''))}</td><td>{escape(ev.get('method', ''))} <code>{escape(ev.get('path', '')[:60])}</code></td>"
            f"<td>{'denegado' if ev.get('denied') else escape(str(ev.get('status', ev.get('error', ''))))}</td></tr>"
            for ev in recent) or "<tr><td colspan=5 class=muted>Sin actividad todavía.</td></tr>"

        flash = ""
        if s.get("flash"):
            kind, text, detail = s.pop("flash")
            extra = f"<pre>{escape(detail)}</pre>" if detail else ""
            flash = f"<div class='card flash {'err' if kind == 'err' else ''}'><b>{escape(text)}</b>{extra}</div>"
        hosted = gw.sections(ctx, s, request) if hasattr(gw, "sections") else ""
        nav = ("<nav><a href='#servidores'>Servidores</a><a href='#accesos'>Accesos de IA</a><a href='#claves'>Claves</a>"
               "<a href='#apikeys'>API keys</a><a href='#apis'>APIs</a><a href='#actividad'>Actividad</a>"
               "<a href='#ajustes'>Ajustes</a></nav>") if hosted else ""
        title = "Bóveda" if hosted else "Bóveda · API keys"
        return page("Bóveda · panel", f"""
<header><h1>{title}</h1>
<form method=post action="/_vault/logout"><input type=hidden name=csrf value='{csrf}'>
<button class=link type=submit>Salir</button></form></header>
{nav}{new_html}{err_html}{flash}{hosted}
<div class=grid id=apikeys>
<div class=card><h2>Nueva API key para un servicio</h2>
<form method=post action="/_vault/keys"><input type=hidden name=csrf value='{csrf}'>
<label for=n>Nombre del servicio</label><input id=n type=text name=name required pattern="[A-Za-z0-9_.\\-]{{1,64}}" placeholder="mi-app-produccion">
<label>APIs a las que puede llamar</label><div class=apis>{checks or '<span class=muted>No hay APIs</span>'}</div>
<label for=e>Caduca en (días, opcional)</label><input id=e type=number name=expires_days min=1 max=3650 placeholder="sin caducidad">
<p><button type=submit>Crear API key</button></p></form></div>
<div class=card><h2>Cómo funciona</h2>
<p>Cada servicio recibe su propia key <code>vt_…</code>. La pasarela la cambia por la clave real del proveedor,
que nunca sale de aquí. Si una key se filtra, la revocas sin tocar tu cuenta de OpenAI o Anthropic.</p>
<p class=muted>Para automatizarlo desde tus despliegues usa la API de administración
(<code>POST {escape(base)}/_vault/api/keys</code>) con un token de <code>vault admin token-create</code>.</p></div>
</div>
<div class=card><h2>API keys</h2><div class=scroll><table><thead><tr><th>Servicio</th><th>APIs</th><th>Creada</th>
<th>Caduca</th><th>Peticiones</th><th>Último uso (UTC)</th><th></th></tr></thead><tbody>{key_rows}</tbody></table></div></div>
<div class=card id=apis><h2>APIs disponibles</h2><div class=scroll><table><thead><tr><th>Nombre</th><th>Descripción</th>
<th>URL para tus servicios</th><th>Proveedor</th></tr></thead><tbody>{api_rows}</tbody></table></div></div>
<div class=card id=actividad><h2>Actividad de API keys</h2><div class=scroll><table><thead><tr><th>Fecha</th><th>Servicio</th>
<th>API</th><th>Petición</th><th>Estado</th></tr></thead><tbody>{recent_rows}</tbody></table></div></div>""")

    # ─── Panel ──────────────────────────────────────────────────────────────────

    async def home(request: Request) -> Response:
        if request.url.path == "/_vault":
            return RedirectResponse("/_vault/", 303)
        s = current(request)
        return dashboard(s, request) if s else login_page()

    async def login(request: Request) -> Response:
        ip = client_ip(request)
        window = fails[ip]
        while window and window[0] < time.time() - FAIL_WINDOW:
            window.popleft()
        if len(window) >= MAX_FAILS:
            return login_page("Demasiados intentos. Espera 15 minutos.", 429)
        if not same_origin(request):
            return login_page("Origen no permitido.", 403)
        form = await request.form()
        next_url = safe_next(str(form.get("next", "/_vault/")))
        ok = await anyio.to_thread.run_sync(K.check_admin_password, gw.bundle, str(form.get("password", "")))
        if not ok:
            window.append(time.time())
            await anyio.sleep(1)
            return login_page("Contraseña incorrecta.", 401, next_url)
        window.clear()
        sid = secrets.token_urlsafe(32)
        sessions[sid] = {"exp": time.time() + SESSION_TTL, "csrf": secrets.token_urlsafe(32)}
        resp = RedirectResponse(next_url, 303, headers=SECURITY_HEADERS)
        resp.set_cookie(COOKIE, sid, max_age=SESSION_TTL, path="/_vault", httponly=True, samesite="strict",
                        secure=request.url.scheme == "https")
        return resp

    async def logout(request: Request) -> Response:
        s, _ = await form_checked(request)
        if s:
            sessions.pop(request.cookies.get(COOKIE, ""), None)
        resp = RedirectResponse("/_vault/", 303, headers=SECURITY_HEADERS)
        resp.delete_cookie(COOKIE, path="/_vault")
        return resp

    async def create(request: Request) -> Response:
        s, form = await form_checked(request)
        if not s:
            return login_page("Sesión caducada; vuelve a entrar.", 403)
        name = str(form.get("name", "")).strip()
        apis = [str(v) for v in form.getlist("apis")]
        days = str(form.get("expires_days", "")).strip()
        try:
            key = K.create_key(gw.bundle, name, apis, int(days) if days else None)
            gw.save()
        except ValueError as err:
            return dashboard(s, request, error=str(err))
        return dashboard(s, request, new=(key, apis))

    async def revoke(request: Request) -> Response:
        s, form = await form_checked(request)
        if not s:
            return login_page("Sesión caducada; vuelve a entrar.", 403)
        if K.revoke_key(gw.bundle, str(form.get("name", ""))):
            gw.save()
        return RedirectResponse("/_vault/", 303, headers=SECURITY_HEADERS)

    # ─── API de administración ──────────────────────────────────────────────────

    async def admin_ok(request: Request) -> bool:
        auth = request.headers.get("authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else None
        if K.lookup_admin_token(gw.bundle, token):
            return True
        await anyio.sleep(1)
        return False

    def unauthorized() -> JSONResponse:
        return JSONResponse({"error": "token de administración inválido"}, 401)

    async def api_apis(request: Request) -> Response:
        if not await admin_ok(request):
            return unauthorized()
        base = str(request.base_url).rstrip("/")
        return JSONResponse([{"name": n, "url": f"{base}/{n}", "provider": gw.bundle.secrets[n]["base_url"],
                              "description": gw.bundle.secrets[n].get("description", "")}
                             for n in K.proxy_apis(gw.bundle)])

    async def api_keys(request: Request) -> Response:
        if not await admin_ok(request):
            return unauthorized()
        if request.method == "GET":
            stats, _ = K.usage(gw.audit_log)
            return JSONResponse([{**t, **stats.get(t["name"], {"requests": 0})} for t in K.list_keys(gw.bundle)])
        try:
            body = await request.json()
            apis = body.get("apis") or []
            key = K.create_key(gw.bundle, str(body.get("name", "")), [str(a) for a in apis],
                               body.get("expires_days"))
        except (ValueError, TypeError, AttributeError) as err:
            return JSONResponse({"error": str(err)}, 400)
        gw.save()
        base = str(request.base_url).rstrip("/")
        return JSONResponse({"name": body["name"], "key": key, "apis": apis,
                             "env": K.env_example(apis, base, key)}, 201)

    async def api_key_delete(request: Request) -> Response:
        if not await admin_ok(request):
            return unauthorized()
        if not K.revoke_key(gw.bundle, request.path_params["name"]):
            return JSONResponse({"error": "no existe"}, 404)
        gw.save()
        return Response(status_code=204)

    # ─── Configuración inicial (primer arranque de la app) ──────────────────────

    async def setup(request: Request) -> Response:
        token = getattr(gw, "setup_token", None)
        given = request.query_params.get("t", "")
        if gw.bundle.admin.get("password") or not token or not hmac.compare_digest(given, token):
            return page("Bóveda", "<div class=card><h1>Enlace no válido</h1><p>El panel ya está configurado "
                                  "o el enlace caducó.</p></div>", 403)
        err = ""
        if request.method == "POST":
            if not same_origin(request):
                return page("Bóveda", "<p class=err>Origen no permitido.</p>", 403)
            form = await request.form()
            pw, pw2 = str(form.get("password", "")), str(form.get("password2", ""))
            try:
                if pw != pw2:
                    raise ValueError("las contraseñas no coinciden")
                await anyio.to_thread.run_sync(K.set_admin_password, gw.bundle, pw)
            except ValueError as e:
                err = f"<p class=err>{escape(str(e))}</p>"
            else:
                gw.setup_token = None
                gw.save()
                return RedirectResponse("/_vault/", 303, headers=SECURITY_HEADERS)
        return page("Bóveda · configuración", f"""<div class=card style="max-width:420px;margin:10vh auto">
<h1>Bienvenido</h1><p class=muted>Elige la contraseña de administrador del panel (mínimo 12 caracteres).
Úsala solo aquí: protege tus servidores y tus claves.</p>{err}
<form method=post><label for=p1>Contraseña</label><input id=p1 type=password name=password minlength=12 required autofocus>
<label for=p2>Repítela</label><input id=p2 type=password name=password2 minlength=12 required>
<p><button type=submit>Guardar y entrar</button></p></form></div>""")

    async def manifest(request: Request) -> Response:
        return JSONResponse({"name": "Bóveda", "short_name": "Bóveda", "start_url": "/_vault/", "scope": "/_vault/",
                             "display": "standalone", "background_color": "#f7f7f5", "theme_color": "#2f5d50",
                             "icons": [{"src": "/_vault/icon.svg", "sizes": "any", "type": "image/svg+xml"}]},
                            media_type="application/manifest+json")

    async def icon(request: Request) -> Response:
        return Response(ICON_SVG, media_type="image/svg+xml", headers={"Cache-Control": "max-age=86400"})

    ctx.login_page = login_page
    extra = gw.routes(ctx) if hasattr(gw, "routes") else []
    return extra + [
        Route("/_vault/setup", setup, methods=["GET", "POST"]),
        Route("/_vault/manifest.webmanifest", manifest),
        Route("/_vault/icon.svg", icon),
        Route("/_vault", home),
        Route("/_vault/", home),
        Route("/_vault/login", login, methods=["POST"]),
        Route("/_vault/logout", logout, methods=["POST"]),
        Route("/_vault/keys", create, methods=["POST"]),
        Route("/_vault/keys/revoke", revoke, methods=["POST"]),
        Route("/_vault/api/apis", api_apis),
        Route("/_vault/api/keys", api_keys, methods=["GET", "POST"]),
        Route("/_vault/api/keys/{name}", api_key_delete, methods=["DELETE"]),
    ]
