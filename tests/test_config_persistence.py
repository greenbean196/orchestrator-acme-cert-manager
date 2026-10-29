from __future__ import annotations

import json
import os
import subprocess
import sys

from app import config, preflight, store
from tests.conftest import make_server


def test_default_servers_file_is_under_config_dir():
    """With no SERVERS_FILE in the environment the default is CONFIG_DIR/servers.json."""
    env = {k: v for k, v in os.environ.items() if k not in ("SERVERS_FILE",)}
    env["CONFIG_DIR"] = "/cfgdir"
    env["DATA_DIR"] = "/datadir"
    out = subprocess.run([sys.executable, "-c", "from app import config; print(config.SERVERS_FILE)"],
                         env=env, capture_output=True, text=True, check=True).stdout.strip()
    assert out == "/cfgdir/servers.json"


def test_servers_file_env_override():
    env = dict(os.environ, SERVERS_FILE="/elsewhere/s.json")
    out = subprocess.run([sys.executable, "-c", "from app import config; print(config.SERVERS_FILE)"],
                         env=env, capture_output=True, text=True, check=True).stdout.strip()
    assert out == "/elsewhere/s.json"


def test_save_load_roundtrip_preserves_ssh_and_ca_bundle(layout):
    s = make_server(ssh_key_path="/data/ssh/orch_restart", ssh_known_hosts="/data/ssh/known_hosts",
                    ca_bundle="/data/ssh/ca.pem", verify_ssl=True)
    config.upsert_server(s)
    assert config.SERVERS_FILE.exists()
    assert oct(config.SERVERS_FILE.stat().st_mode & 0o777) == "0o600"
    back = config.get_server("orch-test")
    assert back.ssh_key_path == "/data/ssh/orch_restart"
    assert back.ssh_known_hosts == "/data/ssh/known_hosts"
    assert back.ca_bundle == "/data/ssh/ca.pem"
    assert back.requests_verify == "/data/ssh/ca.pem"


def test_missing_known_hosts_defaults_to_data_ssh(layout):
    config.SERVERS_FILE.write_text(json.dumps({"servers": [{
        "id": "a", "orchestrator_host": "h", "ssh": {"user": "u", "key_path": "/k"}}]}))
    s = config.get_server("a")
    assert s.ssh_known_hosts == config.DEFAULT_KNOWN_HOSTS
    assert s.restart_command == config.DEFAULT_RESTART_COMMAND


def test_invalid_json_is_a_config_error(layout):
    config.SERVERS_FILE.write_text("{not json")
    try:
        config.load_servers()
    except config.ConfigError as exc:
        assert "not valid JSON" in str(exc)
    else:
        raise AssertionError("expected ConfigError")


def _codes(findings):
    return {f.code: f.level for f in findings}


def test_preflight_fatal_when_only_legacy_config_exists(layout, monkeypatch):
    monkeypatch.setenv("IN_CONTAINER", "false")
    config.LEGACY_SERVERS_FILE.write_text('{"servers": []}')
    codes = _codes(preflight.check_config_paths(strict=True))
    assert codes["legacy-config-only"] == "fatal"
    assert _codes(preflight.check_config_paths(strict=False))["legacy-config-only"] == "warn"


def test_preflight_warns_on_divergent_legacy_and_active(layout):
    config.LEGACY_SERVERS_FILE.write_text('{"servers": [1]}')
    config.SERVERS_FILE.write_text('{"servers": []}')
    codes = _codes(preflight.check_config_paths(strict=True))
    assert codes["legacy-config-conflict"] == "warn"
    assert "legacy-config-only" not in codes


def test_preflight_identical_legacy_is_info(layout):
    config.LEGACY_SERVERS_FILE.write_text('{"servers": []}')
    config.SERVERS_FILE.write_text('{"servers": []}')
    codes = _codes(preflight.check_config_paths(strict=True))
    assert codes["legacy-config-duplicate"] == "info"


def test_preflight_unmounted_config_is_fatal_in_container(layout, monkeypatch):
    monkeypatch.setenv("IN_CONTAINER", "true")
    monkeypatch.setattr(preflight, "is_persistently_mounted", lambda p: False)
    codes = _codes(preflight.check_config_paths(strict=True))
    assert codes["config-not-mounted"] == "fatal"
    monkeypatch.setattr(preflight, "is_persistently_mounted", lambda p: True)
    assert "config-not-mounted" not in _codes(preflight.check_config_paths(strict=True))


def test_preflight_migrates_legacy_history_once(layout):
    store.LEGACY_HISTORY_FILE.write_text('[{"server_id": "x", "outcome": "success"}]')
    preflight.check_config_paths(strict=True)
    assert store.HISTORY_FILE.exists()
    assert store.latest_for("x")["outcome"] == "success"
    # legacy copy is left in place (copy, never move) and not re-applied
    store.HISTORY_FILE.write_text("[]")
    preflight.check_config_paths(strict=True)
    assert store._read() == []


def test_preflight_reports_ssh_problems_per_server(layout):
    config.upsert_server(make_server(ssh_key_path=""))
    rep = preflight.run(strict=False)
    assert "orch-test" in rep.ssh_problems
    assert any("key_path is empty" in p for p in rep.ssh_problems["orch-test"])
    assert rep.ok  # ssh problems are warnings, not fatal, at startup


def test_is_staging_ca():
    assert config.is_staging_ca("letsencrypt_test")
    assert config.is_staging_ca("https://acme-staging-v02.api.letsencrypt.org/directory")
    assert not config.is_staging_ca("letsencrypt")


def test_lab_ca_helpers(layout, monkeypatch):
    monkeypatch.setattr(config, "LAB_CA_HOST", "ca.lab.example.net")
    monkeypatch.setattr(config, "LAB_CA_PORT", 9000)
    monkeypatch.setattr(config, "LAB_CA_PROVISIONER", "lab")
    assert config.is_lab_ca("lab") and not config.is_lab_ca("letsencrypt")
    assert config.ca_environment("lab") == "lab"
    assert config.ca_environment("letsencrypt_test") == "staging"
    assert config.ca_environment("letsencrypt") == "production"
    assert config.lab_ca_acme_url() == "https://ca.lab.example.net:9000/acme/lab/directory"
    monkeypatch.setattr(config, "LAB_CA_ROOT", layout["data"] / "pki" / "certs" / "root_ca.crt")
    assert not config.lab_ca_available()


def _lab_pki(layout, monkeypatch):
    """Write a tiny root + intermediate and point config at them; return their subject names."""
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID
    d = layout["data"] / "pki" / "certs"
    d.mkdir(parents=True)
    now = dt.datetime.now(dt.timezone.utc)

    def mk(cn, issuer_name=None, signer=None):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name or name)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now).not_valid_after(now + dt.timedelta(days=30)))
        return b.sign(signer or key, hashes.SHA256()), key

    root, rkey = mk("Lab CA Root CA")
    inter, _ = mk("Lab CA Intermediate CA", root.subject, rkey)
    (d / "root_ca.crt").write_bytes(root.public_bytes(serialization.Encoding.PEM))
    (d / "intermediate_ca.crt").write_bytes(inter.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setattr(config, "LAB_CA_CERTS_DIR", d)
    monkeypatch.setattr(config, "LAB_CA_ROOT", d / "root_ca.crt")
    monkeypatch.setattr(config, "LAB_CA_INTERMEDIATE", d / "intermediate_ca.crt")
    monkeypatch.setattr(config, "LAB_CA_HOST", "ca.lab.example.net")
    monkeypatch.setattr(config, "_LAB_ISSUERS", (-1.0, frozenset()))
    return root, inter


def test_lab_ca_issuer_names_and_fingerprint(layout, monkeypatch):
    root, inter = _lab_pki(layout, monkeypatch)
    names = config.lab_ca_issuer_names()
    assert inter.subject.rfc4514_string() in names and root.subject.rfc4514_string() in names
    assert config.lab_ca_available()
    assert len(config.lab_ca_root_fingerprint()) == 64


def test_preflight_warns_when_lab_ca_selected_but_missing(layout, monkeypatch):
    monkeypatch.setattr(config, "LAB_CA_HOST", "")
    config.upsert_server(make_server(acme_ca="lab", ssh_key_path="/nope"))
    codes = {f.code for f in preflight.run(strict=False).findings}
    assert "lab-ca-missing" in codes
