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
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
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
"""


def page(title: str, body: str, status: int = 200, headers: dict | None = None) -> HTMLResponse:
    html = (f"<!doctype html><html lang=es><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
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

    def login_page(error: str = "", status: int = 200) -> HTMLResponse:
        if not gw.bundle.admin.get("password"):
            return page("Bóveda", "<div class=card><h1>Panel desactivado</h1><p>Fija una contraseña con "
                                  "<code>vault admin password</code> y reinicia <code>vault serve</code>.</p></div>", 503)
        err = f"<p class=err>{escape(error)}</p>" if error else ""
        return page("Bóveda · acceso", f"""
<div class=card style="max-width:380px;margin:12vh auto">
<h1>Bóveda</h1><p class=muted>Panel de API keys</p>{err}
<form method=post action="/_vault/login"><label for=pw>Contraseña de administrador</label>
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

        return page("Bóveda · panel", f"""
<header><h1>Bóveda · API keys</h1>
<form method=post action="/_vault/logout"><input type=hidden name=csrf value='{csrf}'>
<button class=link type=submit>Salir</button></form></header>
{new_html}{err_html}
<div class=grid>
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
(<code>POST {escape(base)}/_vault/api/keys</code>) con un token de <code>vault admin token create</code>.</p></div>
</div>
<div class=card><h2>API keys</h2><div class=scroll><table><thead><tr><th>Servicio</th><th>APIs</th><th>Creada</th>
<th>Caduca</th><th>Peticiones</th><th>Último uso (UTC)</th><th></th></tr></thead><tbody>{key_rows}</tbody></table></div></div>
<div class=card><h2>APIs disponibles</h2><div class=scroll><table><thead><tr><th>Nombre</th><th>Descripción</th>
<th>URL para tus servicios</th><th>Proveedor</th></tr></thead><tbody>{api_rows}</tbody></table></div></div>
<div class=card><h2>Actividad reciente</h2><div class=scroll><table><thead><tr><th>Fecha</th><th>Servicio</th>
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
        ok = await anyio.to_thread.run_sync(K.check_admin_password, gw.bundle, str(form.get("password", "")))
        if not ok:
            window.append(time.time())
            await anyio.sleep(1)
            return login_page("Contraseña incorrecta.", 401)
        window.clear()
        sid = secrets.token_urlsafe(32)
        sessions[sid] = {"exp": time.time() + SESSION_TTL, "csrf": secrets.token_urlsafe(32)}
        resp = RedirectResponse("/_vault/", 303, headers=SECURITY_HEADERS)
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

    return [
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
