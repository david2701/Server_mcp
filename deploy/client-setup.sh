#!/usr/bin/env bash
# Prepara una Mac cliente para usar el ssh-vault de la Mac bóveda.
# Uso: deploy/client-setup.sh <host-o-ip-de-la-bóveda> [puerto] [usuario] [relay]
#   relay: (opcional) alias SSH de tu VPS si usas el túnel inverso; entonces
#          host debe ser "localhost" y puerto el remoto del túnel (p. ej. 2222).
set -euo pipefail
HOST="${1:?Uso: $0 <host> [puerto] [usuario] [relay]}"
PORT="${2:-22}"
USER_REMOTE="${3:-$USER}"
RELAY="${4:-}"
KEY="$HOME/.ssh/ssh_vault_ed25519"

mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
if [[ ! -f "$KEY" ]]; then
  echo "==> Creando llave dedicada $KEY (ponle una frase de paso)"
  ssh-keygen -t ed25519 -f "$KEY" -C "ssh-vault $(scutil --get ComputerName 2>/dev/null || hostname)"
  ssh-add --apple-use-keychain "$KEY" 2>/dev/null || ssh-add "$KEY" || true
fi

if ! grep -q "^Host ssh-vault$" "$HOME/.ssh/config" 2>/dev/null; then
  {
    echo ""
    echo "Host ssh-vault"
    echo "  HostName $HOST"
    echo "  Port $PORT"
    echo "  User $USER_REMOTE"
    echo "  IdentityFile $KEY"
    echo "  IdentitiesOnly yes"
    echo "  IgnoreUnknown UseKeychain"
    echo "  UseKeychain yes"
    echo "  AddKeysToAgent yes"
    echo "  ServerAliveInterval 30"
    [[ -n "$RELAY" ]] && echo "  ProxyJump $RELAY"
  } >> "$HOME/.ssh/config"
  chmod 600 "$HOME/.ssh/config"
fi

NAME="$(scutil --get LocalHostName 2>/dev/null || hostname -s)"
cat <<MSG

==> En la Mac bóveda ejecuta:
deploy/add-client.sh $NAME "$(cat "$KEY.pub")"

MSG
read -rp "Pulsa Enter cuando esté hecho..."

echo "==> Primera conexión: verifica que la huella coincide con la de la bóveda"
ssh ssh-vault </dev/null >/dev/null

claude mcp add --scope user ssh-vault -- ssh -T ssh-vault
echo "Listo. Prueba en Claude Code: «lista mis servidores con ssh-vault»."
