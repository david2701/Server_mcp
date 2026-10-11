#!/usr/bin/env bash
# Conecta Claude Code de esta Mac al ssh-vault de la Mac bóveda.
# Uso: deploy/client-setup.sh https://mi-mac-boveda.tu-tailnet.ts.net/mcp
set -euo pipefail
URL="${1:?Uso: $0 https://<mac-boveda>.<tailnet>.ts.net/mcp}"
read -rsp "Token de ssh-vault (cópialo desde la Mac bóveda): " TOKEN; echo
claude mcp add --transport http --scope user ssh-vault "$URL" \
  --header "Authorization: Bearer $TOKEN"
echo "Listo. Prueba en Claude Code: «lista mis servidores con ssh-vault»."
