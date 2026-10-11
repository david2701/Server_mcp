"""Proxy de APIs: la bóveda inyecta la clave y Claude nunca la ve."""

from __future__ import annotations

import asyncio
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from .config import Secret

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
# Cabeceras que el llamador nunca puede fijar.
BLOCKED_HEADERS = {"host", "cookie", "proxy-authorization", "authorization", "x-api-key", "api-key"}


class ProxyError(Exception):
    pass


@dataclass
class ApiResponse:
    status: int
    body: str
    truncated: bool


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # urllib copiaría la cabecera de autenticación al destino de la redirección.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProxyError(f"La API respondió con una redirección ({code}) a {newurl}; no se sigue.")


_opener = urllib.request.build_opener(_NoRedirect)


def build_url(secret: Secret, path: str) -> str:
    if not secret.base_url:
        raise ProxyError(f"El secreto {secret.name!r} no tiene base_url; no se puede usar como proxy.")
    path = path.lstrip("/")
    decoded = unquote(path)
    if "://" in decoded or "\\" in decoded or any(seg == ".." for seg in decoded.split("?")[0].split("/")):
        raise ProxyError("La ruta debe ser relativa a base_url (sin '..' ni URLs absolutas).")
    url = secret.base_url + path
    base, final = urlsplit(secret.base_url), urlsplit(url)
    if (final.scheme, final.netloc) != (base.scheme, base.netloc) or not final.path.startswith(base.path):
        raise ProxyError("La ruta sale de base_url.")
    return url


def _request(secret: Secret, value: str, method: str, url: str, body: str | None,
             headers: dict[str, str], timeout: int, limit: int) -> ApiResponse:
    req = urllib.request.Request(url, method=method, data=body.encode() if body is not None else None)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    for k, v in secret.extra_headers:
        req.add_header(k, v)
    req.add_header(secret.auth_header, secret.auth_format.format(secret=value))
    try:
        resp = _opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as err:
        resp = err
    except urllib.error.URLError as err:
        if isinstance(err.reason, ProxyError):
            raise err.reason
        raise ProxyError(f"No se pudo conectar: {err.reason}") from None
    with resp:
        raw = resp.read(limit + 1)
    text = raw[:limit].decode(errors="replace").replace(value, "[SECRETO]")
    return ApiResponse(status=resp.status if hasattr(resp, "status") else resp.code, body=text,
                       truncated=len(raw) > limit)


async def call(secret: Secret, value: str, method: str, path: str, body: str | None,
               headers: dict[str, str] | None, timeout: int, limit: int) -> ApiResponse:
    method = method.upper()
    if method not in METHODS:
        raise ProxyError(f"Método no permitido: {method}")
    headers = dict(headers or {})
    blocked = {secret.auth_header.lower(), *BLOCKED_HEADERS}
    for k, v in headers.items():
        if k.lower() in blocked or any(c in k + v for c in "\r\n"):
            raise ProxyError(f"Cabecera no permitida: {k}")
    url = build_url(secret, path)
    return await asyncio.to_thread(_request, secret, value, method, url, body, headers, timeout, limit)
