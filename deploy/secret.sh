#!/usr/bin/env bash
# Gestiona los secretos de la bóveda en el Llavero de macOS (servicio "ssh-vault").
# Uso: deploy/secret.sh set <nombre>    # pide el valor sin mostrarlo
#      deploy/secret.sh rm <nombre>
#      deploy/secret.sh list
set -euo pipefail
SERVICE="ssh-vault"
cmd="${1:-}"; name="${2:-}"

case "$cmd" in
  set)
    [[ "$name" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || { echo "Nombre inválido"; exit 1; }
    # -w al final: security pide el valor por la terminal (no queda en `ps` ni en el historial).
    # -T /usr/bin/security: permite leerlo sin diálogo desde las sesiones de ssh-vault.
    security add-generic-password -U -s "$SERVICE" -a "$name" -T /usr/bin/security -w
    echo "Guardado. Decláralo en [secrets.$name] de ~/.config/ssh-vault/config.toml"
    ;;
  rm)
    security delete-generic-password -s "$SERVICE" -a "$name" >/dev/null && echo "Borrado '$name'."
    ;;
  list)
    security dump-keychain 2>/dev/null \
      | awk -v svc="\"$SERVICE\"" '/"acct"<blob>=/{acct=$0} /"svce"<blob>=/{ if (index($0, svc)) { sub(/.*="/, "", acct); sub(/"$/, "", acct); print acct } }' \
      | sort -u
    ;;
  *)
    sed -n '2,6p' "$0"; exit 2 ;;
esac
