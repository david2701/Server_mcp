"""Panel local (`vault ui`): gestión SSH desde el navegador, contra un sshd real."""

import re
import socket
import subprocess
import threading
import time

import pytest
import uvicorn

from ssh_vault import bundle as B
from ssh_vault.localui import build_app
from test_panel import Browser
from test_servers import Sshd
import test_servers

pytestmark = test_servers.pytestmark  # requiere OpenSSH (sshd, ssh-agent)


@pytest.fixture
def ui(tmp_path):
    b = B.Bundle()
    saves = []
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    app = build_app(b, lambda: saves.append(1), "token-de-un-uso", port, audit_log=tmp_path / "audit.log")
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", b, saves, tmp_path
    server.should_exit = True


def logged_in(base):
    br = Browser(base)
    assert br.req("GET", "/login?t=token-de-un-uso")[0] == 303
    return br


def csrf(br):
    _, html, _ = br.req("GET", "/")
    return re.search(r"name=csrf value='([^']+)'", html).group(1)


def flash(br):
    _, html, _ = br.req("GET", "/")
    m = re.search(r"class='card flash[^']*'><b>(.*?)</b>(?:<pre>(.*?)</pre>)?", html, re.S)
    return (m.group(1), m.group(2) or "") if m else ("", "")


def test_access_control(ui):
    base, *_ = ui
    br = Browser(base)
    assert br.req("GET", "/")[0] == 403
    assert br.req("GET", "/login?t=malo")[0] == 403
    assert br.req("GET", "/login?t=token-de-un-uso", headers={"Host": "evil.example"})[0] == 403  # DNS rebinding
    assert br.req("GET", "/login?t=token-de-un-uso")[0] == 303
    assert Browser(base).req("GET", "/login?t=token-de-un-uso")[0] == 403  # un solo uso
    status, html, headers = br.req("GET", "/")
    assert status == 200 and "Servidores SSH" in html and "frame-ancestors" in headers["content-security-policy"]


def test_csrf_required(ui):
    base, b, *_ = ui
    br = logged_in(base)
    assert br.req("POST", "/keys/generate", {"name": "k"})[0] == 403
    assert br.req("POST", "/keys/generate", {"name": "k", "csrf": csrf(br)},
                  headers={"Origin": "http://evil.example"})[0] == 403
    assert not b.ssh_keys


def test_full_ssh_flow(ui):
    base, b, saves, tmp_path = ui
    br = logged_in(base)

    # 1. Generar una llave dentro de la bóveda
    br.req("POST", "/keys/generate", {"name": "servidores", "csrf": csrf(br)})
    msg, public = flash(br)
    assert "creada" in msg and public.startswith("ssh-ed25519 ")
    assert "PRIVATE KEY" in b.ssh_keys["servidores"]["private"]
    _, html, _ = br.req("GET", "/")
    body = b.ssh_keys["servidores"]["private"].splitlines()[1]
    assert body not in html  # la privada nunca se muestra

    # 2. El usuario la pone en authorized_keys del servidor
    sshd = Sshd(tmp_path, public)
    sshd.start()
    try:
        # 3. Añadir servidor: escanea huellas → confirmar
        status, html, _ = br.req("POST", "/servers/scan", {
            "name": "web", "target": "root@127.0.0.1", "port": str(sshd.port), "key": "servidores",
            "mode": "full", "description": "<script>x</script>", "csrf": csrf(br)})
        assert status == 200 and "SHA256:" in html and "¿Es este tu servidor?" in html
        token = re.search(r"name=csrf value='([^']+)'", html).group(1)
        br.req("POST", "/servers/confirm", {"csrf": token})
        assert b.servers["web"]["host_keys"] and saves

        _, html, _ = br.req("GET", "/")
        assert "<script>x</script>" not in html and "&lt;script&gt;" in html

        # 4. Probar la conexión con la llave de la bóveda
        br.req("POST", "/servers/test", {"name": "web", "csrf": csrf(br)})
        msg, detail = flash(br)
        assert "correcta" in msg, detail

        # 5. La actividad aparece en el panel
        _, html, _ = br.req("GET", "/")
        assert "test_connection" in html and "exit 0" in html

        # 6. No se puede borrar una llave en uso
        br.req("POST", "/keys/rm", {"name": "servidores", "csrf": csrf(br)})
        assert "La usan" in flash(br)[0] and "servidores" in b.ssh_keys

        # 7. Huella cambiada → la prueba falla
        sshd.stop()
        sshd.new_host_key()
        sshd.start()
        br.req("POST", "/servers/test", {"name": "web", "csrf": csrf(br)})
        msg, detail = flash(br)
        assert "falló" in msg and "host key" in detail.lower()
    finally:
        sshd.stop()


def test_import_key_and_secrets(ui, tmp_path):
    base, b, *_ = ui
    br = logged_in(base)
    k = tmp_path / "k"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(k)], check=True)
    br.req("POST", "/keys/import", {"name": "mia", "private": k.read_text(), "csrf": csrf(br)})
    assert "importada" in flash(br)[0] and b.ssh_keys["mia"]["public"].startswith("ssh-ed25519")

    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "frase", "-f", str(tmp_path / "p")], check=True)
    br.req("POST", "/keys/import", {"name": "conclave", "private": (tmp_path / "p").read_text(), "csrf": csrf(br)})
    assert "frase de paso" in flash(br)[0] and "conclave" not in b.ssh_keys

    br.req("POST", "/secrets/add", {"name": "openai", "provider": "openai", "value": "sk-SECRETO", "csrf": csrf(br)})
    assert b.secrets["openai"]["base_url"] == "https://api.openai.com/v1/"
    _, html, _ = br.req("GET", "/")
    assert "sk-SECRETO" not in html and "api.openai.com" in html


def test_bad_server_input(ui):
    base, b, *_ = ui
    br = logged_in(base)
    br.req("POST", "/servers/scan", {"name": "x", "target": "root@-oProxyCommand=evil", "port": "22",
                                     "key": "nada", "csrf": csrf(br)})
    assert "No se pudo añadir" in flash(br)[0] and not b.servers
