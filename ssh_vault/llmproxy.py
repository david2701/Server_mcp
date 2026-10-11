"""API de la bóveda para tus apps: proxy de LLMs con tokens propios.

Tus apps nunca tienen la clave real. Usan un token de la bóveda (revocable por app)
y apuntan su SDK al proxy:

    OPENAI_BASE_URL=http://127.0.0.1:8787/openai      OPENAI_API_KEY=vt_…
    ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic ANTHROPIC_API_KEY=vt_…

El proxy quita el token, inyecta la clave real y solo la envía al base_url del
secreto. Las respuestas se transmiten en streaming (SSE incluido).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import anyio
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from . import apiproxy
from . import keys as K
from .bundle import Bundle
from .config import Secret, secret_from_spec

AUTH_HEADERS = {"authorization", "x-api-key", "x-goog-api-key", "api-key"}
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
              "trailer", "transfer-encoding", "upgrade", "host", "content-length", "accept-encoding",
              "cookie"}


def _token_from(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    for h in ("x-api-key", "x-goog-api-key", "api-key"):
        if request.headers.get(h):
            return request.headers[h].strip()
    return request.query_params.get("key")  # SDK de Gemini


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": {"type": "vault_error", "message": message}}, status_code=status)


class Gateway:
    """Estado compartido entre el proxy y el panel."""

    def __init__(self, bundle: Bundle, audit_log: Path | None, save):
        self.bundle = bundle
        self.audit_log = audit_log
        self._save = save

    def save(self) -> None:
        if self._save:
            self._save(self.bundle)


def build_app(bundle: Bundle, audit_log: Path | None = None, save=None, panel: bool = False) -> Starlette:
    gw = Gateway(bundle, audit_log, save)
    secrets: dict[str, Secret] = {
        name: secret_from_spec(name, spec) for name, spec in bundle.secrets.items() if spec.get("base_url")
    }

    def audit(**event):
        if audit_log is None:
            return
        audit_log.parent.mkdir(parents=True, exist_ok=True)
        event = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "tool": "api", **event}
        with open(audit_log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")

    async def proxy(request: Request) -> Response:
        name = request.path_params["secret"]
        grant = K.lookup_key(bundle, _token_from(request))
        if grant is None:
            await anyio.sleep(1)
            return _error(401, "API key de la bóveda inválida, revocada o caducada")
        sec = secrets.get(name)
        if sec is None or name not in grant.get("secrets", ()):
            audit(app=grant["name"], secret=name, denied=True)
            return _error(403, f"el token {grant['name']!r} no puede usar {name!r}")

        path = request.path_params["path"]
        query = [(k, v) for k, v in request.query_params.multi_items() if k != "key"]
        if query:
            from urllib.parse import urlencode
            path += "?" + urlencode(query)
        try:
            url = apiproxy.build_url(sec, path)
        except apiproxy.ProxyError as err:
            return _error(400, str(err))

        headers = {k: v for k, v in request.headers.items() if k.lower() not in AUTH_HEADERS | HOP_BY_HOP}
        present = {k.lower() for k in headers}
        headers.update({k: v for k, v in sec.extra_headers if k.lower() not in present})
        headers[sec.auth_header] = sec.auth_format.format(secret=bundle.secrets[name]["value"])
        body = await request.body()
        req = urllib.request.Request(url, data=body or None, method=request.method, headers=headers)

        start = time.monotonic()

        def open_upstream():
            try:
                return apiproxy._opener.open(req, timeout=300)
            except urllib.error.HTTPError as err:
                return err

        try:
            upstream = await anyio.to_thread.run_sync(open_upstream)
        except urllib.error.URLError as err:
            reason = err.reason if isinstance(err.reason, apiproxy.ProxyError) else f"no se pudo conectar: {err.reason}"
            audit(app=grant["name"], secret=name, method=request.method, path=path, error=str(reason))
            return _error(502, str(reason))

        status = getattr(upstream, "status", None) or upstream.code
        audit(app=grant["name"], secret=name, method=request.method, path=path, status=status,
              ms=round((time.monotonic() - start) * 1000))
        out_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP | {"set-cookie"}}

        def stream():
            with upstream:
                while chunk := upstream.read1(16384):
                    yield chunk

        return StreamingResponse(stream(), status_code=status, headers=out_headers)

    async def index(request: Request) -> Response:
        grant = K.lookup_key(bundle, _token_from(request))
        if grant is None:
            return _error(401, "API key de la bóveda inválida, revocada o caducada")
        return JSONResponse({"service": "ssh-vault", "app": grant["name"],
                             "apis": sorted(set(grant["secrets"]) & secrets.keys())})

    methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
    routes = []
    if panel:
        from .panel import panel_routes
        routes += panel_routes(gw)
    routes += [Route("/", index), Route("/{secret}/{path:path}", proxy, methods=methods)]
    return Starlette(routes=routes)
