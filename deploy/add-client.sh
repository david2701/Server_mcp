#!/usr/bin/env bash
# Autoriza a un cliente. Su llave SOLO podrá usar ssh-vault:
#   rol mcp (por defecto): Claude (MCP) + `get` de los secretos de su lista reveal
#   rol app (--app):       solo `get`; para apps y servidores, sin acceso al MCP
# Uso: deploy/add-client.sh [--app] <nombre> "<ssh-ed25519 AAAA... comentario>"
#      deploy/add-client.sh --remove <nombre>
set -euo pipefail

AUTH="$HOME/.ssh/authorized_keys"
PYTHON="${SSH_VAULT_PYTHON:-$HOME/.local/share/ssh-vault/venv/bin/python}"

if [[ "${1:-}" == "--remove" ]]; then
  NAME="${2:?Uso: $0 --remove <nombre>}"
  grep -v -- "--client $NAME\"" "$AUTH" > "$AUTH.tmp" || true
  mv "$AUTH.tmp" "$AUTH" && chmod 600 "$AUTH"
  echo "Cliente '$NAME' revocado."
  exit 0
fi

ROLE=mcp
if [[ "${1:-}" == "--app" ]]; then ROLE=app; shift; fi
NAME="${1:?Uso: $0 [--app] <nombre> \"<llave pública>\"}"
KEY="${2:?Falta la llave pública}"
[[ "$NAME" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || { echo "Nombre inválido"; exit 1; }
[[ "$KEY" =~ ^(ssh-ed25519|sk-ssh-ed25519@openssh.com|ecdsa-sha2-nistp256|sk-ecdsa-sha2-nistp256@openssh.com)\ [A-Za-z0-9+/=]+(\ .*)?$ ]] \
  || { echo "Llave pública no reconocida (usa ed25519 o ecdsa)"; exit 1; }
[[ -x "$PYTHON" ]] || { echo "No encuentro $PYTHON; ejecuta antes deploy/install.sh"; exit 1; }

mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
touch "$AUTH" && chmod 600 "$AUTH"
if grep -q -- "--client $NAME\"" "$AUTH"; then
  echo "Ya existe un cliente '$NAME'. Revócalo antes con --remove."; exit 1
fi
# restrict: sin terminal, sin reenvío de puertos, agente ni X11.
# command: ignora lo que pida el cliente y lanza siempre el MCP.
echo "restrict,command=\"$PYTHON -m ssh_vault --role $ROLE --client $NAME\" $KEY" >> "$AUTH"
echo "Cliente '$NAME' autorizado con rol $ROLE."
echo "Los secretos que pueda leer se declaran en [clients.$NAME] reveal = [...] de config.toml."
