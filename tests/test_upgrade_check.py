"""upgrade-check.sh against synthetic deployments, with a fake `docker` on PATH.

The script is read-only, so each scenario asserts the exit status, the findings
it must raise, and that the layout is byte-for-byte unchanged afterwards.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import paramiko
import pytest

REPO = Path(__file__).resolve().parent.parent
SSH_KEYGEN = shutil.which("ssh-keygen")

# The shim's behaviour is driven by files in $SHIM_STATE so one binary serves every scenario.
SHIM = r"""#!/bin/bash
st="${SHIM_STATE:?}"
case "$1" in
  info) exit 0 ;;
  --version) echo "Docker version 27.0.0, build test"; exit 0 ;;
  compose)
    case "$2" in
      version) echo "2.29.0"; exit 0 ;;
      config) cat "$st/compose.rendered" 2>/dev/null || { echo "yaml: bad" >&2; exit 1; } ;;
      *) exit 0 ;;
    esac ;;
  ps) cat "$st/ps.out" 2>/dev/null; exit 0 ;;
  exec)
    # docker exec <name> sh -c '<cmd>'
    cmd="${*: -1}"
    case "$cmd" in
      *"test -f /data/servers.json"*) [[ -f "$st/legacy-servers.json" ]] && echo yes || echo no ;;
      *"cat /data/servers.json"*) cat "$st/legacy-servers.json" 2>/dev/null ;;
      *"test -f /data/history.json"*) echo no ;;
      *) exit 0 ;;
    esac ;;
  inspect) echo "SERVERS_FILE=/data/servers.json"; exit 0 ;;
  image) [[ -f "$st/image-present" ]] && exit 0 || exit 1 ;;
  *) exit 0 ;;
esac
"""

RENDERED_OK = """services:
  orchestrator-acme-cert-manager:
    volumes:
      - type: bind
        source: /x/config
        target: /config
      - type: bind
        source: /x/data/pki/certs
        target: /data/pki/certs
"""


def _tree(root: Path) -> dict[str, str]:
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def _repo(tmp: Path, servers: str | None = None, env: str | None = None) -> Path:
    work = tmp / "repo"
    work.mkdir()
    for name in ("upgrade-check.sh", ".env.example", "docker-compose.yml"):
        shutil.copy(REPO / name, work / name)
    (work / "app").mkdir()
    shutil.copy(REPO / "app" / "__init__.py", work / "app" / "__init__.py")
    (work / "config").mkdir()
    shutil.copy(REPO / "config" / "servers.example.json", work / "config" / "servers.example.json")
    if servers is not None:
        (work / "config" / "servers.json").write_text(servers)
        (work / "config" / "servers.json").chmod(0o600)
    if env is not None:
        (work / ".env").write_text(env)
        (work / ".env").chmod(0o600)
    state = tmp / "state"
    state.mkdir()
    (state / "compose.rendered").write_text(RENDERED_OK)
    shim = tmp / "bin"
    shim.mkdir()
    (shim / "docker").write_text(SHIM)
    (shim / "docker").chmod(0o755)
    return work


def _run(work: Path, *args: str) -> subprocess.CompletedProcess:
    tmp = work.parent
    env = dict(os.environ, PATH=f"{tmp / 'bin'}:{os.environ['PATH']}", SHIM_STATE=str(tmp / "state"))
    for k in ("LAB_CA_DOMAIN", "LAB_CA_HOST", "LAB_CA_PORT"):
        env.pop(k, None)
    return subprocess.run(["bash", str(work / "upgrade-check.sh"), "--plain", *args],
                          env=env, capture_output=True, text=True, timeout=120, cwd=work)


def _good_ssh(work: Path, host: str = "orch.example.test") -> None:
    ssh = work / "data" / "ssh"
    ssh.mkdir(parents=True)
    k = paramiko.RSAKey.generate(2048)
    k.write_private_key_file(str(ssh / "orch_restart"))
    (ssh / "orch_restart").chmod(0o600)
    (ssh / "orch_restart.pub").write_text(f"{k.get_name()} {k.get_base64()} test\n")
    (ssh / "known_hosts").write_text(f"{host} {k.get_name()} {k.get_base64()}\n")
    for d in ("certs", "logs"):
        (work / "data" / d).mkdir()


SERVERS = """{"servers": [{"id": "orch-1", "name": "Orch", "orchestrator_host": "orch.example.test",
  "domain": "orch.example.test", "api_key": "", "verify_ssl": false,
  "acme": {"ca": "letsencrypt", "email": "ops@example.test", "key_type": "rsa2048"},
  "dns": {"provider": "cloudflare", "api_token": ""},
  "ssh": {"user": "admin", "key_path": "/data/ssh/orch_restart", "known_hosts": "/data/ssh/known_hosts", "port": 22}}]}
"""
ENV_OK = (f"SERVERS_FILE=/config/servers.json\nCF_DNS_API_TOKEN=cf-token-value\nORCH_API_KEY=orch-key-value\nTZ=UTC\n"
          f"OACM_UID={os.getuid()}\nOACM_GID={os.getgid()}\n")
ENV_PRE13 = "SERVERS_FILE=/config/servers.json\nCF_DNS_API_TOKEN=cf-token-value\nORCH_API_KEY=orch-key-value\nTZ=UTC\n"


def test_bare_checkout_is_not_ready_and_names_setup(tmp_path):
    work = _repo(tmp_path)
    before = _tree(work)
    r = _run(work)
    assert r.returncode == 1, r.stdout + r.stderr
    assert ".env missing" in r.stdout
    assert "./setup.sh" in r.stdout
    assert "Nothing was changed" in r.stdout
    assert _tree(work) == before                      # read-only


@pytest.mark.skipif(SSH_KEYGEN is None, reason="ssh-keygen not available")
def test_complete_layout_is_ready(tmp_path):
    work = _repo(tmp_path, servers=SERVERS, env=ENV_OK)
    _good_ssh(work)
    (work / "config" / "admin.json").write_text("{}")
    before = _tree(work)
    r = _run(work)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Ready." in r.stdout
    assert "host key pinned for orch.example.test" in r.stdout
    assert "Cloudflare DNS token available (.env)" in r.stdout
    assert "cf-token-value" not in r.stdout and "orch-key-value" not in r.stdout   # never echo secrets
    assert "/config directory mount present" in r.stdout
    assert _tree(work) == before


@pytest.mark.skipif(SSH_KEYGEN is None, reason="ssh-keygen not available")
def test_legacy_config_in_running_container_blocks_until_copied_out(tmp_path):
    work = _repo(tmp_path, servers=SERVERS, env=ENV_OK)
    _good_ssh(work)
    state = tmp_path / "state"
    (state / "ps.out").write_text("orchestrator-acme-cert-manager:latest|Up 3 days\n")
    (state / "legacy-servers.json").write_text(SERVERS.replace('"api_token": ""', '"api_token": "inline-only-in-container"'))
    r = _run(work)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "legacy path" in r.stdout and "copy" in r.stdout.lower()
    assert "inline-only-in-container" not in r.stdout
    # identical copies are fine
    (state / "legacy-servers.json").write_text(SERVERS)
    r = _run(work)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "identical to config/servers.json" in r.stdout


@pytest.mark.skipif(SSH_KEYGEN is None, reason="ssh-keygen not available")
def test_env_problems_are_found(tmp_path):
    env = "SERVERS_FILE=/data/servers.json\r\nCF_DNS_API_TOKEN=your-cloudflare-api-token\r\nORCH_API_KEY=pa$sword\r\n"
    work = _repo(tmp_path, servers=SERVERS, env=env)
    _good_ssh(work)
    r = _run(work)
    assert r.returncode == 1
    assert "CRLF" in r.stdout
    assert "SERVERS_FILE=/data/servers.json" in r.stdout
    assert "no Cloudflare DNS token" in r.stdout
    assert "unquoted $" in r.stdout


@pytest.mark.skipif(SSH_KEYGEN is None, reason="ssh-keygen not available")
def test_missing_host_key_pin_and_passphrase_key_are_blocking(tmp_path):
    work = _repo(tmp_path, servers=SERVERS, env=ENV_OK)
    _good_ssh(work, host="somewhere.else.test")       # pinned for the wrong host
    r = _run(work)
    assert r.returncode == 1
    assert "no known_hosts entry for orch.example.test" in r.stdout
    assert "--ssh-port 22" in r.stdout


def test_lab_ca_planning_and_online_root_key(tmp_path):
    work = _repo(tmp_path, servers=SERVERS, env=ENV_OK)
    r = _run(work, "--with-ca", "--lab-domain", "lab.example.net", "--no-docker")
    assert "planned identity ca.lab.example.net:9000" in r.stdout
    bad = _run(work, "--with-ca", "--lab-domain", "lab.example.net", "--ca-host", "ca.other.net", "--no-docker")
    assert bad.returncode == 1 and "not under --lab-domain" in bad.stdout
    # an initialised CA with the root key left online is blocking, and drift against .env is reported
    pki = work / "data" / "pki"
    (pki / "config").mkdir(parents=True)
    (pki / "certs").mkdir()
    (pki / "secrets").mkdir()
    (pki / "config" / "lab-ca.meta").write_text("LAB_CA_HOST=ca.lab.example.net\nLAB_CA_DOMAIN=lab.example.net\nLAB_CA_PORT=9443\nLAB_CA_NAME=Lab CA\n")
    (pki / "certs" / "root_ca.crt").write_text("-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n")
    (pki / "secrets" / "root_ca_key").write_text("nope")
    r = _run(work, "--no-docker")
    assert r.returncode == 1
    assert "ROOT KEY IS IN THE ONLINE VOLUME" in r.stdout
    assert ".env lacks LAB_CA_HOST" in r.stdout
    assert "COMPOSE_PROFILES does not include lab-ca" in r.stdout
    assert "initialised: ca.lab.example.net:9443" in r.stdout


def test_override_traps_are_blocking(tmp_path):
    work = _repo(tmp_path, servers=SERVERS, env=ENV_OK)
    (work / "docker-compose.override.yml").write_text(
        "services:\n  orchestrator-acme-cert-manager:\n    volumes:\n      - ./config/servers.json:/data/servers.json:ro\n")
    r = _run(work, "--no-docker")
    assert r.returncode == 1
    assert "single servers.json file" in r.stdout


def test_help_and_bad_option(tmp_path):
    work = _repo(tmp_path)
    assert _run(work, "--help").returncode == 0
    assert _run(work, "--bogus").returncode == 2


def test_missing_service_uid_blocks_with_the_setup_fix(tmp_path):
    """A 1.2 .env has no OACM_UID/OACM_GID: the unprivileged 1.3 container could not write config/."""
    work = _repo(tmp_path, env=ENV_PRE13)
    before = _tree(work)
    r = _run(work)
    assert r.returncode == 1
    assert "OACM_UID/OACM_GID not set in .env" in r.stdout
    assert f"OACM_UID={os.getuid()} OACM_GID={os.getgid()}" in r.stdout
    assert _tree(work) == before
