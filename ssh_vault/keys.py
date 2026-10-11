"""API keys de la pasarela: las que usan tus servicios (vt_…) y las de administración (va_…).

La bóveda solo guarda el hash SHA-256 de cada key: aunque alguien lea el archivo
descifrado, no puede usarlas. La contraseña del panel se guarda con scrypt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .bundle import Bundle, hash_token
from .config import NAME_RE

PROVIDER_ENV = {
    "openai": "OPENAI", "anthropic": "ANTHROPIC", "gemini": "GEMINI", "openrouter": "OPENROUTER",
    "groq": "GROQ", "mistral": "MISTRAL", "deepseek": "DEEPSEEK", "xai": "XAI",
}


def now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def proxy_apis(bundle: Bundle) -> list[str]:
    return sorted(n for n, s in bundle.secrets.items() if s.get("base_url"))


def env_example(apis: list[str], base_url: str, key: str) -> dict[str, str]:
    env = {}
    for api in apis:
        prefix = PROVIDER_ENV.get(api, api.upper().replace("-", "_").replace(".", "_"))
        env[f"{prefix}_BASE_URL"] = f"{base_url.rstrip('/')}/{api}"
        env[f"{prefix}_API_KEY"] = key
    return env


# ─── Keys de servicios ──────────────────────────────────────────────────────────

def create_key(bundle: Bundle, name: str, apis: list[str], expires_days: int | None = None) -> str:
    if not NAME_RE.match(name):
        raise ValueError(f"nombre inválido: {name!r} (letras, números, _ . -)")
    if any(t["name"] == name for t in bundle.tokens.values()):
        raise ValueError(f"ya existe una key para {name!r}; revócala antes")
    available = set(proxy_apis(bundle))
    if not apis or not set(apis) <= available:
        raise ValueError(f"APIs inexistentes o sin base_url: {sorted(set(apis) - available) or 'ninguna elegida'}")
    if expires_days is not None and not 0 < expires_days <= 3650:
        raise ValueError("la caducidad debe estar entre 1 y 3650 días")
    key = "vt_" + secrets.token_urlsafe(32)
    entry: dict[str, Any] = {"name": name, "secrets": sorted(set(apis)), "created": now().isoformat()}
    if expires_days:
        entry["expires"] = (now() + timedelta(days=expires_days)).isoformat()
    bundle.tokens[hash_token(key)] = entry
    return key


def revoke_key(bundle: Bundle, name: str) -> bool:
    before = len(bundle.tokens)
    bundle.tokens = {h: t for h, t in bundle.tokens.items() if t["name"] != name}
    return len(bundle.tokens) < before


def lookup_key(bundle: Bundle, key: str | None) -> dict[str, Any] | None:
    if not key or not key.startswith("vt_"):
        return None
    grant = bundle.tokens.get(hash_token(key))
    if grant and grant.get("expires") and datetime.fromisoformat(grant["expires"]) < now():
        return None
    return grant


def list_keys(bundle: Bundle) -> list[dict[str, Any]]:
    return sorted(bundle.tokens.values(), key=lambda t: t["name"])


# ─── Administración ─────────────────────────────────────────────────────────────

def _scrypt(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024)


def set_admin_password(bundle: Bundle, password: str) -> None:
    if len(password) < 12:
        raise ValueError("la contraseña del panel debe tener al menos 12 caracteres")
    salt = secrets.token_bytes(16)
    bundle.admin["password"] = {"salt": salt.hex(), "hash": _scrypt(password, salt).hex()}


def check_admin_password(bundle: Bundle, password: str) -> bool:
    stored = bundle.admin.get("password")
    if not stored:
        return False
    return hmac.compare_digest(_scrypt(password, bytes.fromhex(stored["salt"])).hex(), stored["hash"])


def create_admin_token(bundle: Bundle, name: str) -> str:
    if not NAME_RE.match(name):
        raise ValueError(f"nombre inválido: {name!r}")
    tokens = bundle.admin.setdefault("tokens", {})
    if any(t["name"] == name for t in tokens.values()):
        raise ValueError(f"ya existe un token de administración {name!r}")
    token = "va_" + secrets.token_urlsafe(32)
    tokens[hash_token(token)] = {"name": name, "created": now().isoformat()}
    return token


def revoke_admin_token(bundle: Bundle, name: str) -> bool:
    tokens = bundle.admin.get("tokens", {})
    keep = {h: t for h, t in tokens.items() if t["name"] != name}
    bundle.admin["tokens"] = keep
    return len(keep) < len(tokens)


def lookup_admin_token(bundle: Bundle, token: str | None) -> dict[str, Any] | None:
    if not token or not token.startswith("va_"):
        return None
    return bundle.admin.get("tokens", {}).get(hash_token(token))


# ─── Uso (a partir del registro de auditoría) ───────────────────────────────────

def usage(audit_log: Path | None, recent: int = 30) -> tuple[dict[str, dict], list[dict]]:
    stats: dict[str, dict] = {}
    last: deque = deque(maxlen=recent)
    if audit_log is None or not audit_log.exists():
        return stats, []
    with open(audit_log, encoding="utf-8") as fh:
        for line in fh:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("tool") != "api" or "app" not in ev:
                continue
            s = stats.setdefault(ev["app"], {"requests": 0, "errors": 0, "last": None})
            s["requests"] += 1
            if ev.get("denied") or ev.get("error") or int(ev.get("status") or 200) >= 400:
                s["errors"] += 1
            s["last"] = ev.get("ts")
            last.append(ev)
    return stats, list(reversed(last))
