"""Arreglos de seguridad: identidad protegida, destinatarios fijados, anti-retroceso."""

import json
import shutil

import pyrage
import pytest
from pyrage import x25519

from ssh_vault import bundle as B
from test_portable import KEY, Device


@pytest.fixture
def pair(tmp_path):
    vault_file = tmp_path / "sync" / "vault.age"
    vault_file.parent.mkdir()
    a = Device(tmp_path, "pro", vault_file)
    b = Device(tmp_path, "air", vault_file)
    a.vault("init", "--name", "pro", "--protect", "none", "--recovery-out", str(tmp_path / "rec.txt"))
    a.vault("set", "openai", "--provider", "openai", "--stdin", input=KEY)
    a.vault("device", "add", "air", b.vault("whoami", "--protect", "none").stdout.strip())
    assert b.vault("get", "openai").stdout == KEY  # air ve la bóveda por primera vez y la fija
    return a, b, vault_file, tmp_path


def test_passphrase_identity(tmp_path):
    d = Device(tmp_path, "mac", tmp_path / "v.age")
    d.vault("init", "--protect", "passphrase", "--recovery-out", str(tmp_path / "r.txt"))
    ident = (d.home / ".config/ssh-vault/identity.txt").read_text()
    assert ident.startswith("-----BEGIN AGE ENCRYPTED FILE-----") and "AGE-SECRET-KEY" not in ident
    d.vault("set", "x", "--stdin", input="valor")
    assert d.vault("get", "x").stdout == "valor"
    d.env["VAULT_PASSPHRASE"] = "incorrecta"
    r = d.vault("get", "x", check=False)
    assert r.returncode != 0 and "valor" not in r.stdout


def test_passphrase_identity_works_with_age_cli(tmp_path):
    if not shutil.which("age"):
        pytest.skip("age no instalado")
    d = Device(tmp_path, "mac", tmp_path / "v.age")
    d.vault("init", "--protect", "passphrase", "--recovery-out", str(tmp_path / "r.txt"))
    secret = pyrage.passphrase.decrypt((d.home / ".config/ssh-vault/identity.txt").read_bytes(),
                                       d.env["VAULT_PASSPHRASE"]).decode()
    assert secret.startswith("AGE-SECRET-KEY-")


def test_new_device_added_elsewhere_requires_trust(pair):
    a, b, _, tmp_path = pair
    intruder = Device(tmp_path, "intruso", b.env["VAULT_FILE"])
    b.vault("device", "add", "intruso", intruder.vault("whoami", "--protect", "none").stdout.strip())

    r = a.vault("get", "openai", check=False)
    assert r.returncode != 0 and "intruso" in r.stderr and KEY not in r.stdout
    a.vault("device", "trust")  # el usuario lo revisa y lo acepta
    assert a.vault("get", "openai").stdout == KEY


def test_hidden_recipient_is_detected(pair):
    a, b, vault_file, _ = pair
    # Un dispositivo comprometido reescribe la bóveda con una llave extra que NO declara.
    data = pyrage.decrypt(vault_file.read_bytes(), [x25519.Identity.from_str(
        [l for l in (b.home / ".config/ssh-vault/identity.txt").read_text().splitlines()
         if l.startswith("AGE-SECRET-KEY-")][0])])
    raw = json.loads(data)
    raw["revision"] += 1
    attacker = x25519.Identity.generate().to_public()
    recips = [B.parse_recipient(k) for k in raw["recipients"].values()] + [attacker]
    vault_file.write_bytes(pyrage.encrypt(json.dumps(raw).encode(), recips, armored=True))

    r = a.vault("get", "openai", check=False)
    assert r.returncode != 0 and "oculta" in r.stderr


def test_rollback_is_detected(pair):
    a, _, vault_file, tmp_path = pair
    old = tmp_path / "old.age"
    shutil.copy(vault_file, old)
    a.vault("set", "openai", "--provider", "openai", "--stdin", input="sk-NUEVA-rotada")
    shutil.copy(old, vault_file)  # alguien restaura la versión con la clave vieja

    r = a.vault("get", "openai", check=False)
    assert r.returncode != 0 and "revisión" in r.stderr
    assert a.vault("--allow-rollback", "get", "openai").stdout == KEY


def test_recovery_key(pair):
    a, _, vault_file, tmp_path = pair
    rec = tmp_path / "rec.txt"
    assert oct(rec.stat().st_mode & 0o777) == "0o600"
    lost = Device(tmp_path, "nuevo", vault_file)
    lost.env["VAULT_IDENTITY_FILE"] = str(rec)
    assert lost.vault("get", "openai").stdout == KEY


def test_recovery_not_printed(tmp_path):
    d = Device(tmp_path, "m", tmp_path / "v.age")
    out = d.vault("init", "--protect", "none", "--recovery-out", str(tmp_path / "r.txt"))
    assert "AGE-SECRET-KEY" not in out.stdout + out.stderr


def test_header_stanzas_ignore_grease():
    rs = [x25519.Identity.generate().to_public() for _ in range(2)]
    assert B.header_stanzas(pyrage.encrypt(b"x", rs, armored=True)) == ["X25519", "X25519"]


def test_touchid_needs_plugin(tmp_path):
    d = Device(tmp_path, "m", tmp_path / "v.age")
    r = d.vault("init", "--protect", "touchid", "--recovery-out", str(tmp_path / "r.txt"), check=False)
    assert r.returncode != 0 and "age-plugin-se" in r.stderr
