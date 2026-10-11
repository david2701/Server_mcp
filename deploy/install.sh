#!/usr/bin/env bash
# Instala ssh-vault en la Mac que guarda las llaves SSH (la "bóveda").
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$HOME/.local/share/ssh-vault"
CONF_DIR="$HOME/.config/ssh-vault"

echo "==> Entorno virtual en $APP_DIR"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q "$REPO_DIR"

mkdir -p "$CONF_DIR" "$HOME/.local/state/ssh-vault"
chmod 700 "$CONF_DIR"
if [[ ! -f "$CONF_DIR/config.toml" ]]; then
  cp "$REPO_DIR/config.example.toml" "$CONF_DIR/config.toml"
  chmod 600 "$CONF_DIR/config.toml"
fi

cat <<MSG

Siguientes pasos en esta Mac:
 1. Declara tus servidores:      nano $CONF_DIR/config.toml
 2. Activa "Sesión remota" (Remote Login) solo para tu usuario:
      Ajustes del Sistema > General > Compartir > Sesión remota
 3. Endurece sshd (solo llaves, sin contraseñas):
      sudo cp $REPO_DIR/deploy/sshd_config.d/000-ssh-vault.conf /etc/ssh/sshd_config.d/
      sudo sed -i '' "s/TU_USUARIO/$USER/" /etc/ssh/sshd_config.d/000-ssh-vault.conf
      sudo launchctl kickstart -k system/com.openssh.sshd
 4. Por cada Mac cliente:        $REPO_DIR/deploy/add-client.sh <nombre> "<llave pública>"

Huella de esta Mac (compárala la primera vez que conecte cada cliente):
MSG
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null || true
