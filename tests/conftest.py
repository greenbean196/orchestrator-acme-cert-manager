"""Test fixtures: isolate every test in a temporary config/data layout.

The app modules read their paths from the environment at import time, so the
environment is set here (conftest is imported before any test module) and the
module-level constants are re-pointed per test by the `layout` fixture.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

_ROOT = Path(tempfile.mkdtemp(prefix="oacm-tests-"))
os.environ["CONFIG_DIR"] = str(_ROOT / "config")
os.environ["DATA_DIR"] = str(_ROOT / "data")
os.environ.pop("SERVERS_FILE", None)
os.environ.pop("HISTORY_FILE", None)
os.environ["STRICT_STARTUP"] = "true"
os.environ["DEPLOY_RETRY_BACKOFF"] = "0"

from app import config, store  # noqa: E402
from app.models import ServerConfig  # noqa: E402


@pytest.fixture
def layout(tmp_path, monkeypatch):
    """Point config/data/history at a fresh tmp dir; return the paths."""
    cfg = tmp_path / "config"
    data = tmp_path / "data"
    cfg.mkdir()
    (data / "ssh").mkdir(parents=True)
    (data / "certs").mkdir()
    monkeypatch.setattr(config, "CONFIG_DIR", cfg)
    monkeypatch.setattr(config, "DATA_DIR", data)
    monkeypatch.setattr(config, "SERVERS_FILE", cfg / "servers.json")
    monkeypatch.setattr(config, "LEGACY_SERVERS_FILE", data / "servers.json")
    monkeypatch.setattr(config, "CERTS_DIR", data / "certs")
    monkeypatch.setattr(config, "SSH_DIR", data / "ssh")
    monkeypatch.setattr(config, "DEFAULT_SSH_KEY", str(data / "ssh" / "orch_restart"))
    monkeypatch.setattr(config, "DEFAULT_KNOWN_HOSTS", str(data / "ssh" / "known_hosts"))
    monkeypatch.setattr(store, "HISTORY_FILE", cfg / "history.json")
    monkeypatch.setattr(store, "LEGACY_HISTORY_FILE", data / "history.json")
    monkeypatch.delenv("IN_CONTAINER", raising=False)
    return {"cfg": cfg, "data": data, "ssh": data / "ssh", "certs": data / "certs"}


@pytest.fixture
def rsa_key(layout):
    """A valid, unencrypted RSA private key on disk; returns (path, pkey)."""
    import paramiko
    k = paramiko.RSAKey.generate(2048)
    p = layout["ssh"] / "orch_restart"
    k.write_private_key_file(str(p))
    os.chmod(p, 0o600)
    return p, k


@pytest.fixture
def known_hosts(layout, rsa_key):
    """known_hosts pinning orch.example.test on port 22 (reusing the test key as host key)."""
    _, k = rsa_key
    p = layout["ssh"] / "known_hosts"
    p.write_text(f"orch.example.test {k.get_name()} {k.get_base64()}\n")
    return p


def make_server(**overrides) -> ServerConfig:
    base = dict(
        id="orch-test", name="Test", orchestrator_host="orch.example.test",
        domain="orch.example.test", acme_email="ops@example.test", acme_ca="letsencrypt_test",
        ssh_user="admin", ssh_key_path="", ssh_known_hosts="", ssh_port=22,
        api_key="k", dns_api_token="t",
    )
    base.update(overrides)
    return ServerConfig(**base)


@pytest.fixture
def server(layout, rsa_key, known_hosts):
    return make_server(ssh_key_path=str(rsa_key[0]), ssh_known_hosts=str(known_hosts))


@pytest.fixture(autouse=True)
def _reset_webui_state():
    """Clear the web UI's in-memory login-failure and pending-run registries before and after every test.

    The module is looked up in sys.modules instead of being imported, so a test that never
    touches the web UI does not pull in Flask; once it is loaded, a lockout or a pending run
    left behind by one test can no longer leak into the next.
    """
    def _clear():
        web = sys.modules.get("app.webui.server")
        if web is None:
            return
        with web._FAIL_LOCK:
            web._FAILURES.clear()
        with web._PENDING_LOCK:
            web._PENDING.clear()

    _clear()
    yield
    _clear()
