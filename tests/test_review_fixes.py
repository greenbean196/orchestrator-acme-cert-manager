"""Regressions for the defects the branch review confirmed."""
import pytest

from app import certs, config, issue, renew, restart
from app.drivers import base as drv_base
from app.drivers import get as get_driver
from app.models import Certificate, StepResult, Target
from tests.conftest import make_server
from tests.test_core_v13 import _bundle_files, fake_driver   # noqa: F401 (fixture)


def _cert(layout, *targets):
    _bundle_files(layout["certs"] / "orch.example.test")
    c = Certificate(id="c", name="C", domain="orch.example.test", acme_email="a@b.c",
                    targets=[Target(tid, drv, settings=dict(st)) for tid, drv, st in targets])
    return c


def test_pending_targets_recognises_a_target_that_already_serves_the_issued_serial(layout, fake_driver, monkeypatch):  # noqa: F811
    c = _cert(layout, ("t1", "fake", {"host": "h1"}))
    bundle = drv_base.CertBundle.for_certificate(c)
    served = certs.parse_pem(bundle.cert.read_bytes())            # hex-string serial, as every driver reports it
    monkeypatch.setattr(fake_driver, "served_info", lambda t: dict(served, error=None))
    assert renew.pending_targets(c, c.targets) == []
    monkeypatch.setattr(fake_driver, "served_info", lambda t: dict(served, serial="ABCDEF"))
    assert [t.id for t in renew.pending_targets(c, c.targets)] == ["t1"]


def test_a_failing_target_does_not_stop_the_others_and_monitor_only_targets_are_skipped(layout, fake_driver, monkeypatch):  # noqa: F811
    c = _cert(layout, ("ec", "edgeconnect", {"orchestrator_host": "orch.example.test", "ne_pk": "3.NE", "api_key": "k"}),
              ("bad", "fake", {"host": "bad"}), ("good", "fake", {"host": "good"}))
    monkeypatch.setattr(renew.issue, "issue_or_renew",
                        lambda cert, force=False: StepResult("issue", True, "issued", {"renewed": True, "serial": "1", "expiry": "x"}))
    monkeypatch.setattr(renew.notify, "send", lambda r: None)
    real_deploy = fake_driver.deploy

    def deploy(t, b):
        if t.id == "bad":
            return StepResult("deploy", False, "boom", {"kind": "transport"})
        return real_deploy(t, b)
    monkeypatch.setattr(fake_driver, "deploy", deploy)
    fake_driver.serve = drv_base.CertBundle.for_certificate(c).serial
    rec = renew.renew_certificate(c, force=True, actor="alice", source="web")
    assert rec.outcome == "failed"
    by_target = {}
    for s in rec.steps:
        by_target.setdefault(s.get("target"), []).append(s)
    assert by_target["ec"][0]["skipped"] is True and "monitor-only" in by_target["ec"][0]["message"]
    assert [s["ok"] for s in by_target["bad"]] == [False]
    assert [s["step"] for s in by_target["good"]] == ["deploy", "activate"] and all(s["ok"] for s in by_target["good"])
    # the next scheduled run retries the failed target (it serves something else) and still skips the monitor-only one
    monkeypatch.setattr(fake_driver, "served_info", lambda t: dict(certs.ABSENT, present=True, serial="ABC", error=None))
    assert [t.id for t in renew.pending_targets(c, c.targets)] == ["bad"]


def test_orchestrator_secondary_target_snapshots_in_its_own_directory(layout):
    _bundle_files(layout["certs"] / "orch.example.test")
    s = make_server()
    c = s.to_certificate()
    t2 = Target("orch-dr", "orchestrator", settings=dict(c.targets[0].settings))
    c.targets.append(t2)
    c.attach()
    od = get_driver("orchestrator")
    assert od.snapshot_dir(c.targets[0]) == config.cert_dir_for(c) / "rollback"
    assert od.snapshot_dir(t2) == config.cert_dir_for(c) / "rollback" / "orch-dr"
    assert restart._rollback_dir(od.server(t2)) == od.snapshot_dir(t2)
    bundle = drv_base.CertBundle.for_certificate(c)
    od.snapshot(t2, bundle)
    assert od.snapshot_bundle(t2) is not None and od.snapshot_bundle(t2).serial == bundle.serial
    assert od.snapshot_bundle(c.targets[0]) is None


@pytest.mark.parametrize("output,expected", [
    ("primary-orch.example: error: one or more domains had a problem: DNS problem", False),
    ("[maria@example.test] acme: Registering account", False),
    ("acme: error: 409 :: urn:ietf:params:acme:error:alreadyReplaced :: certificate being replaced", True),
    ("acme: error: 403 :: urn:ietf:params:acme:error:unauthorized :: requester account did not request the certificate being replaced", True),
    ("time=... level=error msg=\"the 'replaces' field refers to a certificate not found\"", True),
])
def test_ari_rejection_matches_only_real_ca_wording(output, expected):
    assert issue._is_ari_rejection(output) is expected


def test_fetch_served_sends_the_certificate_name_as_sni(monkeypatch):
    seen = {}

    class FakeTLS:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def getpeercert(self, binary_form=True): return b""

    class FakeCtx:
        def __init__(self, *a, **k): pass
        check_hostname = True
        verify_mode = None
        def wrap_socket(self, sock, server_hostname=None):
            seen["sni"] = server_hostname
            return FakeTLS()

    class FakeSock:
        def __enter__(self): return self
        def __exit__(self, *a): pass
    monkeypatch.setattr(certs.ssl, "SSLContext", FakeCtx)
    monkeypatch.setattr(certs.socket, "create_connection", lambda addr, timeout=None: FakeSock())
    info = certs.fetch_served("10.0.0.5", 443, sni="orch.example.test")
    assert seen["sni"] == "orch.example.test" and not info["present"] and "no certificate" in info["error"]


def test_select_fields_reject_unknown_values():
    drv = get_driver("clearpass")
    good = {"host": "cppm.example.test", "client_id": "x", "callback_host": "10.0.0.9", "callback_port": 8765,
            "service_https_rsa": "on", "other_slot_policy": "warn"}
    assert drv.normalize(good)["other_slot_policy"] == "warn"
    with pytest.raises(config.ConfigError, match="must be one of"):
        drv.normalize(dict(good, other_slot_policy="Block"))
