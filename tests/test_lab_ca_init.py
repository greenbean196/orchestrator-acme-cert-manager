"""Exercise pki/lab-ca-init.sh natively when a `step` binary is available.

CI runners have no step binary, so these tests skip there; they run in any
environment where `step` is on PATH (the sandbox used to develop the script).
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
STEP = shutil.which("step")
if STEP is None and os.environ.get("REQUIRE_STEP_CLI"):
    raise RuntimeError("REQUIRE_STEP_CLI is set but no `step` binary is on PATH; these tests must run, not skip")
pytestmark = pytest.mark.skipif(STEP is None, reason="step CLI not on PATH")


def _run(tmp: Path, **env_over) -> subprocess.CompletedProcess:
    env = dict(os.environ, STEPPATH=str(tmp / "online"), OFFLINE=str(tmp / "offline"),
               LAB_CA_TEMPLATE_DIR=str(REPO / "pki"), LAB_CA_HOST="ca.lab.example.net",
               LAB_CA_DOMAIN="lab.example.net", LAB_CA_PORT="9443")
    env.update(env_over)
    (tmp / "offline").mkdir(exist_ok=True)
    return subprocess.run(["bash", str(REPO / "pki" / "lab-ca-init.sh")], env=env,
                          capture_output=True, text=True, timeout=120)


def test_init_leaves_only_the_intermediate_key_online(tmp_path):
    r = _run(tmp_path)
    assert r.returncode == 0, r.stderr + r.stdout
    online, offline = tmp_path / "online", tmp_path / "offline"
    assert sorted(p.name for p in (online / "secrets").iterdir()) == ["intermediate_ca_key", "password"]
    assert (offline / "root_ca_key").is_file() and (offline / "root_password").is_file()
    assert (online / "certs" / "root-key-offline").is_file()
    meta = (online / "config" / "lab-ca.meta").read_text()
    assert "LAB_CA_HOST=ca.lab.example.net" in meta and "LAB_CA_PORT=9443" in meta
    ca = (online / "config" / "ca.json").read_text()
    assert '"idpURL": "https://ca.lab.example.net:9443/1.0/crl"' in ca
    assert "crlDistributionPoints" in ca and '"dns-01"' in ca and '":9443"' in ca
    inter = subprocess.run([STEP, "certificate", "inspect", str(online / "certs" / "intermediate_ca.crt"),
                            "--format", "text"], capture_output=True, text=True).stdout
    assert "Name Constraints: critical" in inter and "lab.example.net" in inter


def test_rerun_is_noop_and_drift_fails_closed(tmp_path):
    assert _run(tmp_path).returncode == 0
    again = _run(tmp_path)
    assert again.returncode == 0 and "nothing to do" in again.stdout
    drift = _run(tmp_path, LAB_CA_DOMAIN="other.example.net", LAB_CA_HOST="ca.other.example.net")
    assert drift.returncode == 3 and "differs" in drift.stderr
    port = _run(tmp_path, LAB_CA_PORT="9000")
    assert port.returncode == 3 and "LAB_CA_PORT" in port.stderr


def test_host_outside_domain_is_refused(tmp_path):
    r = _run(tmp_path, LAB_CA_HOST="ca.other.net")
    assert r.returncode == 2 and not (tmp_path / "online" / "config").exists()


def test_interrupted_init_is_resumed(tmp_path):
    """Fault-inject right after `step ca init`: the next run discards the partial state and completes."""
    broken = _run(tmp_path, LAB_CA_FAULT="after-init")
    assert broken.returncode == 99 and "fault injected" in broken.stderr
    online = tmp_path / "online"
    assert (online / "config" / "ca.json").is_file() and not (online / "config" / "lab-ca.meta").exists()
    assert (online / "config" / ".init-in-progress").is_file()
    again = _run(tmp_path)
    assert again.returncode == 0, again.stderr + again.stdout
    assert "interrupted" in again.stdout and "Lab CA initialised" in again.stdout
    assert (online / "config" / "lab-ca.meta").is_file() and not (online / "config" / ".init-in-progress").exists()
    assert sorted(p.name for p in (online / "secrets").iterdir()) == ["intermediate_ca_key", "password"]
    # the offline root was reused, not regenerated
    assert (tmp_path / "offline" / "root_ca_key").is_file()
    assert _run(tmp_path).returncode == 0


def test_provisioner_name_is_the_fixed_constant(tmp_path):
    from app import config
    assert _run(tmp_path).returncode == 0
    ca = (tmp_path / "online" / "config" / "ca.json").read_text()
    assert f'"name": "{config.LAB_CA_PROVISIONER}"' in ca and config.LAB_CA_PROVISIONER == "lab"


def _offline_fault(tmp_path, hook):
    r = _run(tmp_path, LAB_CA_FAULT=hook)
    assert r.returncode == 99 and "fault injected" in r.stderr
    offline = tmp_path / "offline"
    assert not (offline / "root_ca_key").exists() and not (offline / "root_password").exists()
    ok = _run(tmp_path)
    assert ok.returncode == 0, ok.stderr + ok.stdout
    assert not (offline / ".staging").exists()
    assert all((offline / f).is_file() for f in ("root_ca.crt", "root_ca_key", "root_password"))


def test_interrupted_offline_root_generation_is_recoverable(tmp_path):
    _offline_fault(tmp_path, "after-root-password")


def test_interrupted_offline_root_generation_after_create_is_recoverable(tmp_path):
    _offline_fault(tmp_path, "after-root-create")


def test_incomplete_offline_root_with_existing_ca_fails_with_instructions(tmp_path):
    """A partial offline root next to an initialised CA is refused, naming the gap and the way out.

    An empty offline directory is the documented steady state (the root was moved off the host)
    and stays a no-op; only a partial set (one or two files, or an empty one) fails closed.
    """
    assert _run(tmp_path).returncode == 0
    online, offline = tmp_path / "online", tmp_path / "offline"
    password, old_root = (offline / "root_password").read_bytes(), (offline / "root_ca.crt").read_bytes()
    (offline / "root_password").unlink()
    r = _run(tmp_path)
    assert r.returncode == 6, r.stderr + r.stdout
    assert "nothing to do" not in r.stdout
    assert "2 of 3" in r.stderr and "missing or empty: root_password" in r.stderr
    for step in ("Restore the missing file", "move the remaining file(s) off", "must be rebuilt"):
        assert step in r.stderr, step                       # the recovery steps, not only the diagnosis
    # nothing on either side was touched
    assert (online / "config" / "lab-ca.meta").is_file() and not (online / "config" / ".init-in-progress").exists()
    assert (offline / "root_ca_key").is_file() and (offline / "root_ca.crt").read_bytes() == old_root
    assert not (offline / "root_password").exists() and not (offline / ".staging").exists()
    # an empty file counts as missing
    (offline / "root_password").write_bytes(b"")
    assert _run(tmp_path).returncode == 6
    # restoring the file makes the re-run the usual no-op again
    (offline / "root_password").write_bytes(password)
    ok = _run(tmp_path)
    assert ok.returncode == 0 and "nothing to do" in ok.stdout, ok.stderr + ok.stdout
    # the whole root moved off the host is the documented steady state, not an error
    moved = tmp_path / "usb"
    moved.mkdir()
    for f in ("root_ca.crt", "root_ca_key", "root_password"):
        (offline / f).rename(moved / f)
    ok = _run(tmp_path)
    assert ok.returncode == 0 and "nothing to do" in ok.stdout, ok.stderr + ok.stdout
    # with NO CA online a partial set is abandoned material: discarded, and a new root is generated
    for f in ("root_ca.crt", "root_ca_key"):
        (moved / f).rename(offline / f)
    shutil.rmtree(online)
    r = _run(tmp_path)
    assert r.returncode == 0, r.stderr + r.stdout
    assert "discarding it and generating a new root" in r.stdout
    assert (offline / "root_password").is_file() and (offline / "root_ca.crt").read_bytes() != old_root


def test_acme_leaf_template_is_server_auth_only(tmp_path):
    """Sign a leaf offline with the initialised intermediate using the template step-ca will apply."""
    assert _run(tmp_path).returncode == 0
    online = tmp_path / "online"
    leaf = tmp_path / "leaf.crt"
    r = subprocess.run([STEP, "certificate", "create", "orch.lab.example.net", str(leaf), str(tmp_path / "leaf.key"),
                        "--template", str(online / "config" / "templates" / "leaf.tpl"),
                        "--ca", str(online / "certs" / "intermediate_ca.crt"),
                        "--ca-key", str(online / "secrets" / "intermediate_ca_key"),
                        "--ca-password-file", str(online / "secrets" / "password"),
                        "--no-password", "--insecure", "--not-after", "24h"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    text = subprocess.run([STEP, "certificate", "inspect", str(leaf), "--format", "text"],
                          capture_output=True, text=True).stdout
    assert "Server Authentication" in text and "Client Authentication" not in text
    assert "https://ca.lab.example.net:9443/1.0/crl" in text
    import json
    ca = json.loads((online / "config" / "ca.json").read_text())
    templates = {p["name"]: p.get("options", {}).get("x509", {}).get("template", "")
                 for p in ca["authority"]["provisioners"]}
    assert set(templates) == {"lab", "lab-admin"}
    for name, tpl in templates.items():
        assert "serverAuth" in tpl and "clientAuth" not in tpl, name
        assert "crlDistributionPoints" in tpl, name
