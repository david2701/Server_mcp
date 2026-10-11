#!/usr/bin/env bash
# Instala ssh-vault en la Mac que guarda las llaves SSH (la "bóveda").
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$HOME/.local/share/ssh-vault"
CONF_DIR="$HOME/.config/ssh-vault"
PLIST="$HOME/Library/LaunchAgents/online.dvxlabs.ssh-vault.plist"
SERVICE="ssh-vault-mcp"

echo "==> Entorno virtual en $APP_DIR"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q "$REPO_DIR"

mkdir -p "$CONF_DIR" "$HOME/.local/state/ssh-vault"
chmod 700 "$CONF_DIR"
if [[ ! -f "$CONF_DIR/config.toml" ]]; then
  cp "$REPO_DIR/config.example.toml" "$CONF_DIR/config.toml"
  chmod 600 "$CONF_DIR/config.toml"
  echo "==> Edita $CONF_DIR/config.toml con tus servidores"
fi

if ! security find-generic-password -s "$SERVICE" >/dev/null 2>&1; then
  echo "==> Generando token y guardándolo en el Llavero (servicio: $SERVICE)"
  security add-generic-password -a "$USER" -s "$SERVICE" -w "$(openssl rand -hex 32)"
fi

echo "==> Servicio launchd"
sed -e "s#__PYTHON__#$APP_DIR/venv/bin/python#" -e "s#__HOME__#$HOME#g" \
  "$REPO_DIR/deploy/online.dvxlabs.ssh-vault.plist" > "$PLIST"
launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"

if command -v tailscale >/dev/null; then
  echo "==> Publicando en tu tailnet (solo tus dispositivos lo ven)"
  tailscale serve --bg 8765
  DNS="$(tailscale status --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))')"
  echo
  echo "URL MCP:  https://$DNS/mcp"
  echo "Añade \"$DNS\" a allowed_hosts en $CONF_DIR/config.toml y ejecuta:"
  echo "  launchctl kickstart -k gui/$(id -u)/online.dvxlabs.ssh-vault"
else
  echo "!! Instala Tailscale (https://tailscale.com/download) y ejecuta: tailscale serve --bg 8765"
fi
echo
echo "Ver el token:  security find-generic-password -s $SERVICE -w"
