"""1.3 core: certificate + target configuration, run locks, renewal window,
driver contract, rollback environment guard, TLS failure kind, actor/source,
scheduler state and backup/restore."""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import requests

from app import backup, certs, config, deploy, drivers, locks, preflight, renew, restart, sshcheck, store
from app.drivers import base as drv_base
from app.models import Certificate, StepResult, Target
from tests.conftest import make_server


# --------------------------------------------------------------------------- helpers

def _leaf(path: Path, cn="orch.example.test", issuer_cn=None, days=90, age_days=0):
    """Write a self-signed (or fake-issuer) PEM leaf and return its parsed info."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=age_days)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(iss).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=days)).sign(key, hashes.SHA256()))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    path.with_suffix(".key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                           serialization.NoEncryption()))
    return certs.parse_pem(path.read_bytes())


def _bundle_files(d: Path, domain="orch.example.test", issuer_cn="CN=Fake LE Intermediate X1", days=90, age_days=0):
    d.mkdir(parents=True, exist_ok=True)
    info = _leaf(d / f"{domain}.cer", cn=domain, issuer_cn=issuer_cn, days=days, age_days=age_days)   # also writes {domain}.key
    (d / "ca.cer").write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    return info


# --------------------------------------------------------------------------- config v1 -> v2

V1 = {"servers": [{
    "id": "orch-lab", "name": "Lab Orchestrator", "orchestrator_host": "orch.example.test",
    "domain": "orch.example.test", "api_key_env": "ORCH_API_KEY", "api_key": "k", "verify_ssl": False,
    "ca_bundle": "", "acme": {"ca": "letsencrypt_test", "email": "a@b.c", "key_type": "rsa2048"},
    "dns": {"provider": "cloudflare", "api_token": "t"},
    "ssh": {"user": "admin", "key_path": "/data/ssh/orch_restart", "port": 22},
}]}


def test_v1_file_is_migrated_in_memory_and_rewritten_on_save(layout):
    config.SERVERS_FILE.write_text(json.dumps(V1))
    assert config.file_version() == 1
    certs_ = config.load_certificates()
    assert len(certs_) == 1
    c = certs_[0]
    assert c.id == "orch-lab" and c.domain == "orch.example.test" and c.acme_ca == "letsencrypt_test"
    assert [t.id for t in c.targets] == ["orch-lab"] and c.targets[0].driver == "orchestrator"
    assert c.targets[0].certificate is c
    # defaults the v1 loader applied are applied to the target settings too
    ssh = c.targets[0].settings["ssh"]
    assert ssh["known_hosts"] == config.DEFAULT_KNOWN_HOSTS and ssh["restart_command"] == config.DEFAULT_RESTART_COMMAND
    # the legacy view is unchanged
    s = config.get_server("orch-lab")
    assert s.api_key == "k" and s.dns_api_token == "t" and s.ssh_user == "admin" and s.restart_command == config.DEFAULT_RESTART_COMMAND
    # the file is untouched until something is saved
    assert json.loads(config.SERVERS_FILE.read_text()) == V1
    config.upsert_server(s)
    raw = json.loads(config.SERVERS_FILE.read_text())
    assert raw["version"] == 2 and raw["certificates"][0]["targets"][0]["driver"] == "orchestrator"
    assert raw["certificates"][0]["targets"][0]["settings"]["api_key"] == "k"
    assert config.file_version() == 2
    assert config.get_server("orch-lab").ssh_user == "admin"


def test_v2_roundtrip_with_two_targets_and_target_lookups(layout):
    c = Certificate(id="c1", name="C1", domain="c1.example.test", acme_email="a@b.c", acme_ca="letsencrypt",
                    dns_env={"AWS_ACCESS_KEY_ID": "x"}, dns_provider="route53",
                    targets=[Target("c1", "orchestrator", settings={"orchestrator_host": "c1.example.test", "ssh": {"user": "u", "key_path": "/k"}}),
                             Target("c1-nginx", "ssh", name="nginx", settings={"host": "web.example.test", "ssh_user": "u", "ssh_key_path": "/k",
                                                                               "remote_cert_path": "/etc/x.pem", "remote_key_path": "/etc/x.key"})])
    config.upsert_certificate(c)
    back = config.get_certificate("c1")
    assert [t.id for t in back.targets] == ["c1", "c1-nginx"] and back.dns_env == {"AWS_ACCESS_KEY_ID": "x"}
    cert, t = config.get_target("c1-nginx")
    assert cert.id == "c1" and t.driver == "ssh" and t.certificate is cert
    assert config.target_exists("c1-nginx") and config.server_exists("c1-nginx") and not config.target_exists("nope")
    assert [s.id for s in config.load_servers()] == ["c1"]          # legacy view: orchestrator targets only
    # upsert_server keeps the certificate's other targets
    s = config.get_server("c1")
    s.ssh_user = "other"
    config.upsert_server(s)
    back = config.get_certificate("c1")
    assert [t.id for t in back.targets] == ["c1", "c1-nginx"] and back.as_server().ssh_user == "other"
    # delete_target removes just the one; deleting the last removes the certificate
    assert config.delete_target("c1-nginx") and [t.id for t in config.get_certificate("c1").targets] == ["c1"]
    assert config.delete_target("c1") and config.load_certificates() == []


def test_duplicate_target_ids_are_rejected(layout):
    bad = {"version": 2, "certificates": [
        {"id": "a", "domain": "a.test", "targets": [{"id": "x", "driver": "ssh", "settings": {}}]},
        {"id": "b", "domain": "b.test", "targets": [{"id": "x", "driver": "ssh", "settings": {}}]}]}
    config.SERVERS_FILE.write_text(json.dumps(bad))
    with pytest.raises(config.ConfigError, match="duplicate target id"):
        config.load_certificates()


# --------------------------------------------------------------------------- locks (#5)

def test_run_lock_contends_and_releases(layout):
    with locks.run_lock("c1", "renew", actor="alice", source="web") as h:
        assert locks.is_locked("c1") and locks.holder("c1")["actor"] == "alice" and h["pid"] == os.getpid()
        with pytest.raises(locks.RunLocked) as exc:
            with locks.run_lock("c1"):
                pass
        assert "already running" in str(exc.value) and "alice" in str(exc.value)
        assert "c1" in locks.active()
    assert not locks.is_locked("c1") and locks.holder("c1") is None


def test_run_lock_is_cross_process(layout):
    """A lock held by another process (the scheduler) is seen and respected here."""
    code = f"""
import os, sys, time
sys.path.insert(0, {os.getcwd()!r})
os.environ['CONFIG_DIR'] = {str(layout['cfg'])!r}
os.environ['DATA_DIR'] = {str(layout['data'])!r}
from app import locks, config
with locks.run_lock('shared', 'scheduled', actor='scheduler', source='cron'):
    print('held', flush=True)
    time.sleep(3)
"""
    proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    assert proc.stdout.readline().strip() == "held"
    try:
        h = locks.holder("shared")
        assert h and h["pid"] == proc.pid and h["source"] == "cron"
        with pytest.raises(locks.RunLocked):
            with locks.run_lock("shared"):
                pass
    finally:
        proc.kill(); proc.wait()
    assert locks.holder("shared") is None          # released with the process; no stale lock


def test_two_concurrent_renews_one_runs_one_refuses(layout, monkeypatch):
    _bundle_files(layout["certs"] / "orch.example.test")
    started = threading.Event()
    release = threading.Event()

    def slow_issue(c, force=False):
        started.set(); release.wait(5)
        return StepResult("issue", True, "ok", {"renewed": True, "serial": "1", "expiry": "x"})
    monkeypatch.setattr(renew.issue, "issue_or_renew", slow_issue)
    monkeypatch.setattr(renew.deploy, "deploy", lambda s: StepResult("deploy", True, "ok"))
    monkeypatch.setattr(renew.restart, "restart", lambda s: StepResult("restart", True, "ok"))
    monkeypatch.setattr(renew.notify, "send", lambda r: None)
    s = make_server()
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("rec", renew.renew_server(s, force=True, actor="a", source="web")))
    t.start(); started.wait(5)
    with pytest.raises(locks.RunLocked):
        renew.renew_server(s, force=True)
    release.set(); t.join(5)
    assert out["rec"].outcome == "success" and out["rec"].actor == "a" and out["rec"].source == "web"
    assert out["rec"].targets == ["orch-test"] and out["rec"].steps[1]["target"] == "orch-test"


# --------------------------------------------------------------------------- renewal window (#9)

@pytest.mark.parametrize("lifetime,age,due", [(90, 10, False), (90, 61, True), (64, 40, False), (64, 43, True),
                                               (45, 20, False), (45, 31, True), (6, 2, False), (6, 3, True)])
def test_due_for_renewal_follows_lifetime_fraction(tmp_path, monkeypatch, lifetime, age, due):
    monkeypatch.delenv("RENEW_WINDOW_DAYS", raising=False)
    info = _leaf(tmp_path / "leaf.pem", days=lifetime, age_days=age)
    assert info["lifetime_days"] == lifetime
    got, why = certs.due_for_renewal(info)
    assert got is due, why
    assert str(lifetime) in why


def test_due_for_renewal_absolute_override(tmp_path, monkeypatch):
    info = _leaf(tmp_path / "leaf.pem", days=90, age_days=50)     # 40 days left
    monkeypatch.setenv("RENEW_WINDOW_DAYS", "45")
    assert certs.due_for_renewal(info)[0] is True
    monkeypatch.setenv("RENEW_WINDOW_DAYS", "30")
    assert certs.due_for_renewal(info)[0] is False
    assert certs.due_for_renewal(dict(certs.ABSENT))[0] is True


def test_scheduled_issue_skips_lego_when_not_due_and_disables_ari_across_environments(layout, monkeypatch):
    from app import issue
    d = layout["certs"] / "orch.example.test"
    (d / "certificates").mkdir(parents=True)
    _bundle_files(d, issuer_cn="CN=Fake LE Intermediate X1", days=90, age_days=10)   # staging, 80 days left
    (d / "certificates" / "orch.example.test.crt").write_text((d / "orch.example.test.cer").read_text())
    (d / "certificates" / "orch.example.test.key").write_text("k")
    (d / "certificates" / "orch.example.test.json").write_text('{"domain": "orch.example.test"}')
    calls = []
    monkeypatch.setattr(issue.subprocess, "run", lambda cmd, **k: calls.append(cmd) or (_ for _ in ()).throw(AssertionError("lego must not run")))
    monkeypatch.delenv("RENEW_WINDOW_DAYS", raising=False)
    res = issue.issue_or_renew(make_server(acme_ca="letsencrypt_test"), force=False)
    assert res.ok and res.detail["renewed"] is False and "no renewal needed" in res.message and calls == []

    class P:  # a fake successful lego run
        returncode, stdout, stderr = 0, "", ""
    monkeypatch.setattr(issue.subprocess, "run", lambda cmd, **k: calls.append(cmd) or P())
    # forced, configured for production while a staging cert is on disk -> ARI disabled
    issue.issue_or_renew(make_server(acme_ca="letsencrypt"), force=True)
    assert "--ari-disable" in calls[-1] and "--renew-force" in calls[-1]
    # same environment -> ARI left on
    issue.issue_or_renew(make_server(acme_ca="letsencrypt_test"), force=True)
    assert "--ari-disable" not in calls[-1]


def test_lego_environment_passes_dns_env_for_other_providers(layout, monkeypatch):
    from app import issue
    c = Certificate(id="c", name="c", domain="c.test", acme_email="a@b.c", dns_provider="route53",
                    dns_env={"AWS_ACCESS_KEY_ID": "id", "AWS_SECRET_ACCESS_KEY": "s"})
    env = issue.lego_environment(c, "")
    assert env["AWS_ACCESS_KEY_ID"] == "id" and env["AWS_SECRET_ACCESS_KEY"] == "s"
    res = issue.issue_or_renew(Certificate(id="c", name="c", domain="c.test", acme_email="a@b.c", dns_provider="route53"), force=True)
    assert not res.ok and "route53" in res.message and "variables" in res.message


# --------------------------------------------------------------------------- drivers

class FakeDriver(drv_base.Driver):
    name = "fake"
    label = "Fake"
    steps = ("deploy", "activate")

    def __init__(self):
        self.calls = []
        self.serve = None
        self.fail_activate = False

    def display_host(self, target):
        return target.settings.get("host", "fake")

    def deploy(self, target, bundle):
        self.calls.append(("deploy", target.id, bundle.serial_hex)); return StepResult("deploy", True, "up")

    def activate(self, target):
        self.calls.append(("activate", target.id))
        return StepResult("activate", not self.fail_activate, "act")

    def verify(self, target, serial, timeout):
        self.calls.append(("verify", target.id, format(serial, "x")))
        return (self.serve == serial), 0


@pytest.fixture
def fake_driver(monkeypatch):
    f = FakeDriver()
    drivers._load_builtin()
    monkeypatch.setitem(drivers._REGISTRY, "fake", f)
    return f


def test_renew_certificate_deploys_to_every_target_in_order(layout, monkeypatch, fake_driver):
    info = _bundle_files(layout["certs"] / "multi.example.test", domain="multi.example.test")
    serial = int(info["serial"], 16)
    fake_driver.serve = serial
    c = Certificate(id="multi", name="M", domain="multi.example.test", acme_email="a@b.c",
                    targets=[Target("t1", "fake", settings={"host": "h1"}), Target("t2", "fake", settings={"host": "h2"})])
    monkeypatch.setattr(renew.issue, "issue_or_renew",
                        lambda cert, force=False: StepResult("issue", True, "issued", {"renewed": True, "serial": info["serial"], "expiry": "x"}))
    monkeypatch.setattr(renew.notify, "send", lambda r: None)
    rec = renew.renew_certificate(c, force=True, actor="alice", source="web")
    assert rec.outcome == "success" and rec.targets == ["t1", "t2"]
    assert [s["step"] for s in rec.steps] == ["issue", "deploy", "activate", "deploy", "activate"]
    assert [s.get("target") for s in rec.steps] == [None, "t1", "t1", "t2", "t2"]
    assert [x[0] for x in fake_driver.calls] == ["deploy", "activate", "verify", "deploy", "activate", "verify"]
    # the verified bundle became each target's snapshot, with metadata
    snap = fake_driver.snapshot_dir(c.targets[1])
    assert (snap / "meta.json").is_file() and json.loads((snap / "meta.json").read_text())["environment"] == "staging"
    # redeploy for one target only touches that target
    fake_driver.calls.clear()
    rec = renew.redeploy_certificate(c, targets=[c.targets[1]], actor="bob", source="cli")
    assert rec.outcome == "success" and rec.targets == ["t2"] and [x[1] for x in fake_driver.calls] == ["t2", "t2", "t2"]
    assert store.latest_for("multi")["actor"] == "bob" and store.latest_for("multi")["source"] == "cli"


def test_activation_failure_rolls_back_same_environment_but_refuses_across(layout, monkeypatch, fake_driver):
    d = layout["certs"] / "rb.example.test"
    first = _bundle_files(d, domain="rb.example.test", issuer_cn="CN=Fake LE Intermediate X1")   # staging
    c = Certificate(id="rb", name="R", domain="rb.example.test", acme_email="a@b.c",
                    targets=[Target("rb", "fake", settings={"host": "h"})])
    t = c.targets[0]
    bundle = drv_base.CertBundle.for_certificate(c)
    fake_driver.snapshot(t, bundle)                     # a verified staging snapshot exists
    # new production cert whose activation fails: same-env rollback refused by default
    _bundle_files(d, domain="rb.example.test", issuer_cn="CN=R3,O=Let's Encrypt,C=US")
    bundle = drv_base.CertBundle.for_certificate(c)
    fake_driver.serve = None
    res = fake_driver.activate_step(t, bundle)
    assert not res.ok and res.detail["rolled_back"] is False and "refusing to roll back across CA environments" in res.message
    assert res.detail["snapshot_environment"] == "staging" and res.detail["failed_environment"] == "production"
    assert [x[0] for x in fake_driver.calls].count("deploy") == 0   # nothing was re-deployed
    # policy on: the staging snapshot is restored and the message says so
    t.settings["allow_cross_env_rollback"] = True
    fake_driver.serve = int(first["serial"], 16)
    res = fake_driver.activate_step(t, bundle)
    assert not res.ok and res.detail["rolled_back"] is True and res.detail["cross_environment"] is True
    assert "CROSS-ENVIRONMENT" in res.message and res.detail["restored_serial"] == first["serial"].lower()


def test_orchestrator_restart_refuses_cross_env_rollback(layout, monkeypatch):
    """The original restart.py path honours the same policy (issue #8)."""
    d = layout["certs"] / "orch.example.test"
    staging = _bundle_files(d, issuer_cn="CN=Fake LE Intermediate X1")
    s = make_server(acme_ca="letsencrypt")
    restart._promote_known_good(s)
    meta = json.loads((d / "rollback" / "meta.json").read_text())
    assert meta["environment"] == "staging" and meta["serial"] == staging["serial"].lower()
    _bundle_files(d, issuer_cn="CN=R3,O=Let's Encrypt,C=US")
    calls = []
    monkeypatch.setattr(restart.deploy, "deploy_paths", lambda *a, **k: calls.append(1) or StepResult("deploy", True, "ok"))
    res = restart._attempt_rollback(s, failed_serial=123)
    assert not res.ok and res.detail["rolled_back"] is False and calls == []
    assert "refusing to roll back across CA environments" in res.message
    s.allow_cross_env_rollback = True
    monkeypatch.setattr(restart, "_reload_nginx", lambda s: StepResult("restart", True, "ok"))
    monkeypatch.setattr(restart, "_wait_for_served_serial", lambda s, want, t: (True, 0))
    res = restart._attempt_rollback(s, failed_serial=123)
    assert res.detail["rolled_back"] is True and res.detail["cross_environment"] is True and calls == [1]


def test_last_stderr_line_is_reported(monkeypatch):
    assert restart._first_line("Redirecting to /bin/systemctl restart gms.service\nFailed to restart gms.service: Unit not found.\n") \
        == "Failed to restart gms.service: Unit not found."
    assert restart._first_line("") == "no output"


def test_command_warnings_flag_service_wrapper_missing_sudo_and_no_block():
    w = sshcheck.command_warnings("restart_command", "/usr/sbin/service gms restart", expect_no_block=True)
    assert any("sudo" in x for x in w) and any("'service' wrapper" in x for x in w)
    w = sshcheck.command_warnings("restart_command", "sudo /bin/systemctl restart gms.service", expect_no_block=True)
    assert len(w) == 1 and "--no-block" in w[0]
    assert sshcheck.command_warnings("restart_command", "sudo /bin/systemctl restart --no-block gms.service", expect_no_block=True) == []
    assert sshcheck.command_warnings("nginx_reload_command", "sudo /bin/systemctl reload nginx") == []
    assert sshcheck.warnings(make_server(restart_command="service gms restart"))


def test_tls_verification_failure_is_its_own_kind_and_never_retried(layout, monkeypatch):
    calls = []

    def fake_post(url, **k):
        calls.append(url)
        raise requests.exceptions.SSLError("certificate verify failed: self signed certificate")
    monkeypatch.setattr(deploy.requests, "post", fake_post)
    monkeypatch.setattr(deploy.time, "sleep", lambda s: None)
    d = layout["certs"] / "orch.example.test"
    _bundle_files(d)
    res = deploy.deploy_paths(make_server(), d / "orch.example.test.cer", d / "orch.example.test.key", d / "ca.cer")
    assert not res.ok and len(calls) == 1
    assert res.detail["kind"] == "tls" and res.detail["phase"] == "validation"
    assert "does not chain to a trusted root" in res.message and "verify_ssl" in res.message and "ca_bundle" in res.message


def test_preflight_warns_when_verify_ssl_on_with_staging_cert_and_reports_command_warnings(layout, server):
    s = make_server(ssh_key_path=server.ssh_key_path, ssh_known_hosts=server.ssh_known_hosts, verify_ssl=True,
                    restart_command="sudo /bin/systemctl restart gms.service")
    _bundle_files(layout["certs"] / "orch.example.test", issuer_cn="CN=Fake LE Intermediate X1")
    config.upsert_server(s)
    codes = {f.code: f.message for f in preflight.run(strict=False).findings}
    assert "tls-verify-vs-staging" in codes and "staging" in codes["tls-verify-vs-staging"]
    assert "command-warning" in codes and "--no-block" in codes["command-warning"]
    assert "config-v1" not in codes          # saved in the v2 shape


def test_scheduler_state_and_renew_all_outcomes(layout, monkeypatch):
    _bundle_files(layout["certs"] / "orch.example.test")
    config.upsert_server(make_server())
    monkeypatch.setattr(renew.issue, "issue_or_renew",
                        lambda c, force=False: StepResult("issue", True, "ok", {"renewed": False, "serial": "1", "expiry": "x"}))
    monkeypatch.setattr(renew.notify, "send", lambda r: None)
    recs = renew.renew_all(force=False)
    assert [r.outcome for r in recs] == ["skipped"] and recs[0].actor == "scheduler" and recs[0].source == "cron"
    st = store.scheduler_state()
    assert st["started"] and st["finished"] and st["outcomes"] == {"orch-test": "skipped"} and st["failed"] == []
    # a certificate locked by someone else is skipped, not queued, and reported
    with locks.run_lock("orch-test", "renew", actor="alice"):
        recs = renew.renew_all(force=False)
    assert recs == [] and store.scheduler_state()["outcomes"] == {"orch-test": "locked"}


def test_orchestrator_driver_matches_legacy_modules(layout, server, monkeypatch):
    """The driver delegates to deploy.py / restart.py / sshcheck.py with a flattened ServerConfig."""
    config.upsert_server(server)
    cert, t = config.get_target("orch-test")
    drv = drivers.get("orchestrator")
    assert drv.steps == ("deploy", "restart") and drv.probe_label == "Test SSH"
    assert drv.display_host(t) == "orch.example.test" and drv.preflight(t) == []
    seen = {}

    def record(name):
        def fn(s):
            seen[name] = s
            return StepResult(name, True, "ok")
        return fn
    monkeypatch.setattr(deploy, "deploy", record("deploy"))
    monkeypatch.setattr(restart, "restart", record("restart"))
    bundle = drv_base.CertBundle.for_certificate(cert)
    assert drv.deploy(t, bundle).ok and drv.activate_step(t, bundle).ok
    assert seen["deploy"].id == "orch-test" and seen["deploy"].ssh_user == "admin" and seen["restart"].domain == "orch.example.test"
    flat = drv.flat(t)
    assert flat["api_key"] == "" and flat["ssh_user"] == "admin"
    nested = drv.normalize(flat | {"api_key": "zz", "ssh_port": "2222"})
    assert nested["ssh"]["port"] == 2222 and nested["api_key"] == "zz" and nested["ssh"]["known_hosts"]
    with pytest.raises(config.ConfigError):
        drv.normalize(flat | {"ssh_port": "99999"})


def test_ssh_driver_schema_normalize_and_deploy_with_fake_sftp(layout, rsa_key, known_hosts, monkeypatch):
    drv = drivers.get("ssh")
    with pytest.raises(config.ConfigError, match="absolute"):
        drv.normalize({"host": "h", "ssh_user": "u", "remote_cert_path": "rel", "remote_key_path": "/k"})
    settings = drv.normalize({"host": "orch.example.test", "ssh_user": "u", "ssh_key_path": str(rsa_key[0]),
                              "ssh_known_hosts": str(known_hosts), "remote_cert_path": "/etc/ssl/x.pem",
                              "remote_key_path": "/etc/ssl/x.key", "remote_chain_path": "/etc/ssl/chain.pem",
                              "fullchain": "on", "activate_command": "sudo /bin/systemctl reload nginx",
                              "verify_port": "8443"})
    assert settings["fullchain"] is True and settings["verify_port"] == 8443 and settings["ssh_port"] == 22
    c = Certificate(id="web", name="W", domain="orch.example.test", acme_email="a@b.c",
                    targets=[Target("web", "ssh", settings=settings)])
    t = c.targets[0]
    assert drv.preflight(t) == [] and drv.verify_endpoint(t) == ("orch.example.test", 8443)
    _bundle_files(layout["certs"] / "orch.example.test")
    bundle = drv_base.CertBundle.for_certificate(c)

    events = []

    class FakeFile:
        def __init__(self, store, name): self.store, self.name = store, name
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def chmod(self, mode): events.append(("fchmod", self.name, mode)); sftp.modes[self.name] = mode
        def write(self, data): events.append(("write", self.name)); self.store[self.name] = data

    class FakeChannel:
        def settimeout(self, t): events.append(("timeout", t))

    class FakeSFTP:
        def __init__(self): self.files, self.modes, self.renamed = {}, {}, []
        def get_channel(self): return FakeChannel()
        def open(self, name, mode): events.append(("open", name)); return FakeFile(self.files, name)
        def chmod(self, name, mode): self.modes[name] = mode
        def remove(self, name): raise IOError("absent")
        def posix_rename(self, a, b): self.renamed.append((a, b)); self.files[b] = self.files.pop(a)
        def rename(self, a, b): raise AssertionError("posix_rename is available; plain rename must not be used")
        def close(self): pass

    sftp = FakeSFTP()

    class FakeClient:
        def get_transport(self): return None
        def open_sftp(self): return sftp
        def close(self): pass
    monkeypatch.setattr(sshcheck, "connect", lambda ep, extra=None: FakeClient())
    res = drv.deploy(t, bundle)
    assert res.ok and set(sftp.files) == {"/etc/ssl/x.pem", "/etc/ssl/x.key", "/etc/ssl/chain.pem"}
    assert sftp.modes["/etc/ssl/x.key.oacm-tmp"] == 0o600
    key_events = [e for e in events if len(e) > 1 and e[1] == "/etc/ssl/x.key.oacm-tmp"]
    assert [e[0] for e in key_events] == ["open", "fchmod", "write"]        # private before the first byte lands
    assert ("timeout", sshcheck.command_timeout()) in events
    # every file is staged before any is swapped in
    assert events.index(("open", "/etc/ssl/chain.pem.oacm-tmp")) < len(events) and sftp.renamed[0][1] == "/etc/ssl/x.pem"
    assert sftp.files["/etc/ssl/x.pem"].count(b"BEGIN CERTIFICATE") == 2       # fullchain
    assert all(a.endswith(".oacm-tmp") for a, _ in sftp.renamed)
    monkeypatch.setattr(sshcheck, "run", lambda client, cmd, timeout=0: (1, "", "Redirecting\nnginx: config broken"))
    act = drv.activate(t)
    assert not act.ok and act.message.endswith("nginx: config broken")


# --------------------------------------------------------------------------- backup / restore (#13)

def test_backup_and_restore_roundtrip_with_encryption(layout, tmp_path, monkeypatch):
    config.upsert_server(make_server(ssh_key_path="/data/ssh/orch_restart"))
    (layout["cfg"] / "trust").mkdir(); (layout["cfg"] / "trust" / "api-trust-x.pem").write_text("x")
    (layout["data"] / "logs").mkdir(); (layout["data"] / "logs" / "renew.log").write_text("noise")
    _bundle_files(layout["certs"] / "orch.example.test")
    (layout["ssh"] / "orch_restart").write_text("KEY"); os.chmod(layout["ssh"] / "orch_restart", 0o600)
    out = tmp_path / "b.tgz.enc"
    monkeypatch.setenv("BACKUP_PASSPHRASE", "correct horse")
    res = backup.create(out, passphrase="correct horse")
    assert res.encrypted and res.entries >= 5 and oct(out.stat().st_mode & 0o777) == "0o600"
    with pytest.raises(backup.BackupError, match="encrypted"):
        backup.read_manifest(out)
    with pytest.raises(backup.BackupError, match="passphrase"):
        backup.read_manifest(out, passphrase="wrong")
    m = backup.read_manifest(out, passphrase="correct horse")
    assert "config" in m["included"] and "data/certs" in m["included"] and m["include_root"] is False
    # restore into a fresh layout
    cfg2, data2 = tmp_path / "cfg2", tmp_path / "data2"
    monkeypatch.setattr(config, "CONFIG_DIR", cfg2); monkeypatch.setattr(config, "DATA_DIR", data2)
    monkeypatch.setattr(config, "SERVERS_FILE", cfg2 / "servers.json")
    r = backup.restore(out, passphrase="correct horse")
    assert r.entries == res.entries
    assert (cfg2 / "servers.json").is_file() and oct((cfg2 / "servers.json").stat().st_mode & 0o777) == "0o600"
    assert (data2 / "certs" / "orch.example.test" / "orch.example.test.key").is_file()
    assert oct((data2 / "ssh" / "orch_restart").stat().st_mode & 0o777) == "0o600"
    assert not (cfg2 / "trust").exists() and not (data2 / "logs").exists()
    assert config.get_server("orch-test").ssh_key_path == "/data/ssh/orch_restart"
    # a newer servers.json on the host is protected unless forced
    time.sleep(1.1); (cfg2 / "servers.json").write_text((cfg2 / "servers.json").read_text())
    with pytest.raises(backup.BackupError, match="newer"):
        backup.restore(out, passphrase="correct horse")
    assert backup.restore(out, force=True, passphrase="correct horse").entries == res.entries


def test_restore_refuses_traversal(tmp_path, layout):
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in ("backup.json", "../evil"):
            info = tarfile.TarInfo(name); data = b"{}"; info.size = len(data); tar.addfile(info, io.BytesIO(data))
    p = tmp_path / "evil.tgz"; p.write_bytes(buf.getvalue())
    with pytest.raises(backup.BackupError, match="outside"):
        backup.restore(p)


def test_cli_reports_lock_with_exit_code_3(layout, monkeypatch, capsys):
    from app import cli
    config.upsert_server(make_server())
    with locks.run_lock("orch-test", "renew", actor="alice"):
        rc = cli.main(["renew", "orch-test", "--force"])
    assert rc == cli.EXIT_LOCKED and "already running" in capsys.readouterr().err


def test_ari_cert_id_and_window_precedence(tmp_path, monkeypatch):
    """RFC 9773 CertID = b64url(AKI) '.' b64url(DER serial); an open ARI window wins over the lifetime rule."""
    from app import ari
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a.test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(0x8A_BC_DE).not_valid_before(now).not_valid_after(now + dt.timedelta(days=90))
            .add_extension(x509.AuthorityKeyIdentifier(b"\x01\x02\x03", None, None), critical=False)
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    assert ari.cert_id(pem) == "AQID.AIq83g"          # serial 0x8ABCDE needs a leading 0x00 in DER
    info = certs.parse_pem(pem)
    assert certs.due_for_renewal(info)[0] is False      # 90 days left
    window = {"start": now - dt.timedelta(hours=1), "end": now + dt.timedelta(hours=40)}
    due, why = certs.due_for_renewal(info, window)
    assert due and "ARI window open" in why
    later = {"start": now + dt.timedelta(days=1), "end": now + dt.timedelta(days=2)}
    assert certs.due_for_renewal(info, later)[0] is False
    monkeypatch.setenv("RENEW_WINDOW_DAYS", "100")      # the explicit override beats ARI
    assert certs.due_for_renewal(info, later)[0] is True

    class R:
        def __init__(self, status, body, headers=None): self.status_code, self._b, self.headers = status, body, headers or {}
        def json(self): return self._b
    calls = []

    def fake_get(url, timeout=None, verify=None):
        calls.append(url)
        if url.endswith("/directory"):
            return R(200, {"renewalInfo": "https://ca.test/acme/renewal-info"})
        return R(200, {"suggestedWindow": {"start": "2026-10-01T00:00:00Z", "end": "2026-10-02T00:00:00Z"}}, {"Retry-After": "21600"})
    monkeypatch.setattr(ari.requests, "get", fake_get)
    ari.reset_cache()
    win = ari.renewal_info("https://ca.test/directory", pem)
    assert win["start"].year == 2026 and win["retry_after"] == "21600" and calls[-1].endswith("/AQID.AIq83g")
    assert ari.renewal_info("https://ca.test/directory", pem) and calls.count("https://ca.test/directory") == 1   # directory cached
    monkeypatch.setattr(ari.requests, "get", lambda url, timeout=None, verify=None: R(200, {}))
    ari.reset_cache()
    assert ari.renewal_info("https://other.test/directory", pem) is None     # no renewalInfo advertised


def test_issue_retries_once_without_ari_when_the_ca_rejects_replaces(layout, monkeypatch):
    from app import issue
    d = layout["certs"] / "orch.example.test"
    (d / "certificates").mkdir(parents=True)
    _bundle_files(d, issuer_cn="CN=R3,O=Let's Encrypt,C=US", days=90, age_days=10)
    (d / "certificates" / "orch.example.test.crt").write_text((d / "orch.example.test.cer").read_text())
    (d / "certificates" / "orch.example.test.key").write_text("k")
    (d / "certificates" / "orch.example.test.json").write_text('{"domain": "orch.example.test"}')
    calls = []

    class P:
        def __init__(self, rc, err=""): self.returncode, self.stdout, self.stderr = rc, "", err
    outcomes = [P(1, '403 urn:ietf:params:acme:error:unauthorized :: requester account did not request the certificate being replaced by this order'), P(0)]
    monkeypatch.setattr(issue.subprocess, "run", lambda cmd, **k: calls.append(list(cmd)) or outcomes.pop(0))
    res = issue.issue_or_renew(make_server(acme_ca="letsencrypt"), force=True)
    assert res.ok and res.detail["ari_retry"] is True
    assert "--ari-disable" not in calls[0] and "--ari-disable" in calls[1]
    # an unrelated failure is not retried
    calls.clear(); outcomes[:] = [P(1, "dns: cloudflare: 403 forbidden")]
    res = issue.issue_or_renew(make_server(acme_ca="letsencrypt"), force=True)
    assert not res.ok and len(calls) == 1 and res.detail["ari_retry"] is False


def test_lego_environment_is_an_allow_list(monkeypatch):
    from app import issue
    monkeypatch.setenv("ORCH_API_KEY", "secret-orch")
    monkeypatch.setenv("CPPM_CLIENT_SECRET", "secret-cppm")
    monkeypatch.setenv("LEGO_DEBUG_ACME_HTTP_CLIENT", "1")
    monkeypatch.setenv("CLOUDFLARE_PROPAGATION_TIMEOUT", "300")
    env = issue.lego_environment(make_server(acme_ca="letsencrypt"), "tok")
    assert "ORCH_API_KEY" not in env and "CPPM_CLIENT_SECRET" not in env
    assert env["LEGO_DEBUG_ACME_HTTP_CLIENT"] == "1" and env["CLOUDFLARE_PROPAGATION_TIMEOUT"] == "300" and env["PATH"]
    other = Certificate(id="c", name="c", domain="c.test", dns_provider="route53", dns_env={"AWS_ACCESS_KEY_ID": "id"})
    env = issue.lego_environment(other, "")
    assert "CLOUDFLARE_PROPAGATION_TIMEOUT" not in env and env["AWS_ACCESS_KEY_ID"] == "id" and "CF_DNS_API_TOKEN" not in env
