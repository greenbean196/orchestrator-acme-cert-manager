from __future__ import annotations

import base64
import logging
from urllib.parse import urlsplit

import pytest
import requests

from app import deploy, renew, issue
from app.models import StepResult
from tests.conftest import make_server


class _Resp:
    def __init__(self, status, text="", headers=None):
        self.status_code = status
        self.text = text
        self.ok = status < 400
        self.headers = headers or {}


_CERT_PEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
_CHAIN_PEM = "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n"
_KEY_PEM = ("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQSECRETKEYMATERIAL\n"
            "-----END PRIVATE KEY-----\n")
_TOKEN = "tok-SECRET-0123456789abcdef"      # distinctive, so a leak into a log line or a message is unmistakable


def _files(layout, cert_text=_CERT_PEM, key_text=_CERT_PEM, ca_text=_CERT_PEM):
    d = layout["certs"] / "orch.example.test"
    d.mkdir(parents=True, exist_ok=True)
    cert, key, ca = d / "orch.example.test.cer", d / "orch.example.test.key", d / "ca.cer"
    for f, text in ((cert, cert_text), (key, key_text), (ca, ca_text)):
        f.write_text(text)
    return cert, key, ca


def _run(layout, monkeypatch, script, server=None, seen=None, sleeps=None, files=None):
    """script: list of responses/exceptions consumed by successive requests.post calls.

    A callable entry is invoked as item(url, call) with the recorded keyword arguments,
    so a scripted response can echo the request. `seen` collects one dict per call
    (url plus every keyword argument requests.post received); `sleeps` collects the
    retry back-off delays that would have been slept.
    """
    calls = []
    sleeps = [] if sleeps is None else sleeps

    def fake_post(url, json=None, headers=None, verify=None, timeout=None, **kw):
        call = {"url": url, "json": json, "headers": headers, "verify": verify, "timeout": timeout, **kw}
        calls.append(url)
        if seen is not None:
            seen.append(call)
        item = script.pop(0)
        if callable(item):
            item = item(url, call)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(deploy.requests, "post", fake_post)
    monkeypatch.setattr(deploy.time, "sleep", sleeps.append)
    monkeypatch.setattr(deploy, "VALIDATION_ATTEMPTS", 3)
    cert, key, ca = files or _files(layout)
    res = deploy.deploy_paths(server or make_server(), cert, key, ca)
    return res, calls


def test_validation_502_then_200_succeeds_without_reissue(layout, monkeypatch):
    res, calls = _run(layout, monkeypatch, [_Resp(502, "<html>Bad Gateway</html>"), _Resp(200, "{}"), _Resp(204)])
    assert res.ok
    assert res.detail["validation_attempts"] == 2
    assert [c.endswith("/validation") for c in calls] == [True, True, False]


def test_validation_502_three_times_fails_and_never_installs(layout, monkeypatch):
    res, calls = _run(layout, monkeypatch, [_Resp(502), _Resp(503), _Resp(504)])
    assert not res.ok
    assert len(calls) == 3 and all(c.endswith("/validation") for c in calls)
    d = res.detail
    assert d["phase"] == "validation" and d["kind"] == "transient"
    assert d["status"] == 504 and d["attempt"] == 3 and d["attempts"] == 3
    assert "Force deploy" in res.message and "HTTP 504" in res.message
    assert d["endpoint"] == "/httpsCertificate/validation"


def test_validation_400_is_not_retried(layout, monkeypatch):
    res, calls = _run(layout, monkeypatch, [_Resp(400, '{"error":"key mismatch"}')])
    assert not res.ok and len(calls) == 1
    assert res.detail["kind"] == "rejected"
    assert "key mismatch" in res.detail["response_excerpt"]


def test_validation_transport_error_is_retried(layout, monkeypatch):
    res, calls = _run(layout, monkeypatch, [requests.ConnectionError("boom"), _Resp(200), _Resp(204)])
    assert res.ok and len(calls) == 3


def test_install_is_never_retried(layout, monkeypatch):
    res, calls = _run(layout, monkeypatch, [_Resp(200), _Resp(502)])
    assert not res.ok and len(calls) == 2
    assert res.detail["phase"] == "install" and res.detail["attempts"] == 1


def test_install_transport_error_flags_unknown_state(layout, monkeypatch):
    res, calls = _run(layout, monkeypatch, [_Resp(200), requests.ReadTimeout("t/o")])
    assert not res.ok and len(calls) == 2
    assert "may or may not" in res.message


def test_success_detail_has_both_statuses(layout, monkeypatch):
    res, _ = _run(layout, monkeypatch, [_Resp(200, '{"issuer":"R3"}'), _Resp(204)])
    assert res.detail["validation_status"] == 200 and res.detail["install_status"] == 204


def test_missing_api_key_is_reported(layout, monkeypatch):
    monkeypatch.delenv("ORCH_API_KEY", raising=False)
    cert, key, ca = _files(layout)
    res = deploy.deploy_paths(make_server(api_key=""), cert, key, ca)
    assert not res.ok and "API key" in res.message


def test_redact_strips_key_material_and_secrets():
    body = ('{"keyData":"data:application/octet-stream;base64,QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=",'
            '"password":"hunter2","fullText":"-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"}')
    out = deploy.redact(body)
    assert "hunter2" not in out and "MIIE" not in out and "QUJDREVG" not in out
    assert "<redacted>" in out and "<pem-redacted>" in out
    assert len(deploy.redact("x" * 5000)) <= deploy._EXCERPT_LEN + 1


# --------------------------------------------------------------------------- request shape and secrecy


def _decode_data_uri(uri):
    head, _, b64 = uri.partition(",")
    assert head.startswith("data:") and head.endswith(";base64"), uri
    return head[len("data:"):-len(";base64")], base64.b64decode(b64, validate=True)


@pytest.mark.parametrize("verify_ssl", [False, True])
def test_requests_carry_token_json_payload_and_transport_guards(layout, monkeypatch, verify_ssl):
    """Both POSTs: X-Auth-Token + JSON, no redirects, the configured verify, a timeout, the PEM files as data URIs."""
    pinned = layout["data"] / "pinned-ca.pem"
    pinned.write_text("-----BEGIN CERTIFICATE-----\nPINNED\n-----END CERTIFICATE-----\n")
    server = make_server(api_key=_TOKEN, verify_ssl=verify_ssl, ca_bundle=str(pinned) if verify_ssl else "")
    files = _files(layout, cert_text=_CERT_PEM, key_text=_KEY_PEM, ca_text=_CHAIN_PEM)
    seen = []
    res, calls = _run(layout, monkeypatch, [_Resp(200, "{}"), _Resp(204)], server=server, seen=seen, files=files)
    assert res.ok
    assert calls == [f"{server.base_url}/validation", server.base_url]
    assert calls[0] == "https://orch.example.test/gms/rest/gms/httpsCertificate/validation"
    cert, key, ca = files
    assert len({cert.read_bytes(), key.read_bytes(), ca.read_bytes()}) == 3      # so the field mapping below means something
    for call in seen:
        assert call["headers"] == {"Content-Type": "application/json", "X-Auth-Token": _TOKEN}
        assert call["allow_redirects"] is False
        if verify_ssl:
            assert call["verify"] == str(pinned)
        else:
            assert call["verify"] is False
        assert call["timeout"] == deploy._TIMEOUT and call["timeout"] > 0
        assert "data" not in call and "files" not in call                          # the body goes through json=
        payload = call["json"]
        assert set(payload) == {"certificateData", "keyData", "intermediateCertFileContent"}
        assert _decode_data_uri(payload["certificateData"]) == ("application/x-x509-ca-cert", cert.read_bytes())
        assert _decode_data_uri(payload["keyData"]) == ("application/octet-stream", key.read_bytes())
        assert _decode_data_uri(payload["intermediateCertFileContent"]) == ("application/x-x509-ca-cert", ca.read_bytes())
    assert seen[0]["json"] == seen[1]["json"]


def test_private_key_and_api_key_never_reach_logs_or_excerpts(layout, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    server = make_server(api_key=_TOKEN)
    files = _files(layout, key_text=_KEY_PEM)
    key_b64 = base64.b64encode(_KEY_PEM.encode()).decode()

    def echo_request(url, call):        # a misbehaving appliance that reflects the upload in its error body
        return _Resp(400, '{"error":"rejected","request":{"keyData":"%s"}}' % call["json"]["keyData"])

    rejected, _ = _run(layout, monkeypatch, [echo_request], server=server, files=files)
    accepted, _ = _run(layout, monkeypatch, [_Resp(200, '{"issuer":"R3"}'), _Resp(204)], server=server, files=files)
    assert not rejected.ok and rejected.detail["kind"] == "rejected"
    assert accepted.ok
    # the deploy logger really was captured, so the negative checks below are meaningful
    assert "verify_ssl is off" in caplog.text
    assert "Certificate validation failed" in caplog.text
    assert "uploaded (validation 200, install 204)" in caplog.text
    for haystack in (caplog.text, rejected.message, str(rejected.detail), accepted.message, str(accepted.detail)):
        assert "SECRETKEYMATERIAL" not in haystack
        assert "PRIVATE KEY" not in haystack
        assert key_b64 not in haystack
        assert _TOKEN not in haystack
    assert "<redacted>" in rejected.detail["response_excerpt"]


# --------------------------------------------------------------------------- redirects


@pytest.mark.parametrize("status,location", [
    (301, "https://sso.example.test/login?next=%2Fgms%2Frest"),
    (302, "http://orch-old.example.test/gms/rest/gms/httpsCertificate/validation"),
    (307, "https://sso.example.test/"),
    (308, None),
])
def test_redirect_on_validation_is_reported_not_followed_and_not_retried(layout, monkeypatch, status, location):
    sleeps = []
    server = make_server(api_key=_TOKEN)
    headers = {"Location": location} if location else {}
    res, calls = _run(layout, monkeypatch, [_Resp(status, "", headers=headers)], server=server, sleeps=sleeps)
    assert not res.ok
    assert len(calls) == 1 and calls[0].endswith("/validation")        # no retry, no install
    assert sleeps == []
    d = res.detail
    assert d["phase"] == "validation" and d["kind"] == "redirect" and d["status"] == status
    assert d["attempt"] == 1 and d["attempts"] == 3
    assert d["endpoint"] == "/httpsCertificate/validation" and d["next_action"] == "fix orchestrator_host"
    assert "Certificate validation failed" in res.message and f"HTTP {status} (redirect)" in res.message
    assert "never follows" in res.message and "not retried" in res.message
    if location:
        assert urlsplit(location).hostname in d["response_excerpt"]
    assert _TOKEN not in res.message and _TOKEN not in str(d)


def test_redirect_on_install_is_reported_and_not_retried(layout, monkeypatch):
    sleeps = []
    server = make_server(api_key=_TOKEN)
    moved = _Resp(302, "", headers={"Location": "https://elsewhere.example.test/gms/rest/gms/httpsCertificate"})
    res, calls = _run(layout, monkeypatch, [_Resp(200, "{}"), moved], server=server, sleeps=sleeps)
    assert not res.ok and len(calls) == 2 and sleeps == []
    d = res.detail
    assert d["phase"] == "install" and d["kind"] == "redirect" and d["status"] == 302
    assert d["attempt"] == 1 and d["attempts"] == 1 and d["endpoint"] == "/httpsCertificate"
    assert "Certificate install failed" in res.message and "HTTP 302 (redirect)" in res.message
    assert "never follows" in res.message and "not retried" in res.message
    assert "elsewhere.example.test" in d["response_excerpt"]
    assert _TOKEN not in res.message and _TOKEN not in str(d)


# --------------------------------------------------------------------------- install-phase failures


@pytest.mark.parametrize("status", sorted(deploy.TRANSIENT_STATUSES))
def test_install_gateway_error_is_transient_not_retried_and_flags_possible_apply(layout, monkeypatch, status):
    sleeps = []
    gateway = _Resp(status, "<html>Gateway</html>", headers={"X-Request-Id": "req-42"})
    res, calls = _run(layout, monkeypatch, [_Resp(200, "{}"), gateway], sleeps=sleeps)
    assert not res.ok and len(calls) == 2 and sleeps == []
    d = res.detail
    assert d["phase"] == "install" and d["kind"] == "transient" and d["status"] == status
    assert d["attempt"] == 1 and d["attempts"] == 1 and d["request_id"] == "req-42"
    assert "Certificate install failed" in res.message and f"HTTP {status} (transient)" in res.message
    assert "may still have applied the upload" in res.message
    assert "do not re-issue" in d["next_action"] and "Force deploy" in d["next_action"]


@pytest.mark.parametrize("exc", [requests.ConnectionError("reset by peer"), requests.ReadTimeout("t/o"),
                                 requests.ConnectTimeout("slow")], ids=["connection", "read-timeout", "connect-timeout"])
def test_install_transport_exception_is_not_retried_and_flags_unknown_state(layout, monkeypatch, exc):
    sleeps = []
    res, calls = _run(layout, monkeypatch, [_Resp(200, "{}"), exc], sleeps=sleeps)
    assert not res.ok and len(calls) == 2 and sleeps == []
    d = res.detail
    assert d["phase"] == "install" and d["kind"] == "transport" and d["status"] is None
    assert d["attempt"] == 1 and d["attempts"] == 1
    assert "no HTTP response (transport)" in res.message and "may or may not have applied" in res.message
    assert "do not re-issue" in d["next_action"] and "Force deploy" in d["next_action"]


# --------------------------------------------------------------------------- authentication failures


@pytest.mark.parametrize("status", [401, 403])
def test_validation_401_403_is_not_retried_and_never_installs(layout, monkeypatch, status):
    sleeps = []
    server = make_server(api_key=_TOKEN)
    denied = _Resp(status, '{"error":"invalid or expired token"}')
    res, calls = _run(layout, monkeypatch, [denied], server=server, sleeps=sleeps)
    assert not res.ok
    assert len(calls) == 1 and calls[0].endswith("/validation") and sleeps == []
    d = res.detail
    assert d["phase"] == "validation" and d["status"] == status and d["attempt"] == 1
    assert d["kind"] != "transient"
    assert "Certificate validation failed" in res.message and f"HTTP {status}" in res.message
    assert "invalid or expired token" in d["response_excerpt"]
    assert _TOKEN not in res.message and _TOKEN not in str(d)


@pytest.mark.parametrize("status", [401, 403])
def test_validation_401_403_maps_to_auth_kind_with_api_key_guidance(layout, monkeypatch, status):
    res, _ = _run(layout, monkeypatch, [_Resp(status, '{"error":"invalid token"}')])
    assert res.detail["kind"] == "auth"
    assert "API key" in res.message


def test_force_deploy_never_contacts_the_ca(layout, monkeypatch):
    def no_ca(*a, **k):
        raise AssertionError("issue_or_renew must not be called by redeploy")
    monkeypatch.setattr(issue, "issue_or_renew", no_ca)
    _files(layout)
    monkeypatch.setattr(renew.deploy, "deploy", lambda s: StepResult("deploy", True, "ok"))
    monkeypatch.setattr(renew.restart, "restart", lambda s: StepResult("restart", True, "ok"))
    monkeypatch.setattr(renew.notify, "send", lambda r: None)
    rec = renew.redeploy_server(make_server())
    assert rec.outcome == "success" and [s["step"] for s in rec.steps] == ["deploy", "restart"]


def test_failed_deploy_is_recorded_as_failed_with_detail(layout, monkeypatch):
    _files(layout)
    bad = StepResult("deploy", False, "Certificate validation failed", detail={"phase": "validation", "status": 502})
    monkeypatch.setattr(renew.deploy, "deploy", lambda s: bad)
    monkeypatch.setattr(renew.restart, "restart", lambda s: StepResult("restart", True, "must not run"))
    monkeypatch.setattr(renew.notify, "send", lambda r: None)
    rec = renew.redeploy_server(make_server())
    assert rec.outcome == "failed"
    assert [s["step"] for s in rec.steps] == ["deploy"]
    assert rec.steps[0]["detail"]["status"] == 502


def test_lego_uses_lab_ca_directory_and_trust(layout, monkeypatch):
    from app import config as cfg
    monkeypatch.setattr(cfg, "LAB_CA_HOST", "ca.lab.example.net")
    monkeypatch.setattr(cfg, "LAB_CA_PORT", 9000)
    monkeypatch.setattr(cfg, "LAB_CA_PROVISIONER", "lab")
    monkeypatch.setattr(cfg, "LAB_CA_ROOT", layout["data"] / "pki" / "certs" / "root_ca.crt")
    s = make_server(acme_ca="lab")
    assert issue._acme_url(s) == "https://ca.lab.example.net:9000/acme/lab/directory"
    env = issue.lego_environment(s, "tok")
    assert env["LEGO_CA_CERTIFICATES"] == str(cfg.LAB_CA_ROOT)
    assert env[cfg.CF_TOKEN_ENV] == "tok"
    assert "LEGO_CA_CERTIFICATES" not in issue.lego_environment(make_server(acme_ca="letsencrypt"), "tok")
    # not configured -> issuance refuses with guidance before running lego
    res = issue.issue_or_renew(s, force=True)
    assert not res.ok and "setup.sh --with-ca" in res.message


def _lab_root(layout, monkeypatch, cfg):
    root = layout["data"] / "pki" / "certs" / "root_ca.crt"
    root.parent.mkdir(parents=True, exist_ok=True)
    root.write_text("-----BEGIN CERTIFICATE-----\nLABROOT\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(cfg, "LAB_CA_HOST", "ca.lab.example.net")
    monkeypatch.setattr(cfg, "LAB_CA_ROOT", root)
    monkeypatch.setattr(cfg, "TRUST_DIR", layout["cfg"] / "trust")
    return root


def test_api_trust_bundle_combines_system_lab_and_custom(layout, monkeypatch):
    from app import config as cfg
    import certifi
    monkeypatch.setattr(cfg, "LAB_CA_HOST", "")
    monkeypatch.setattr(cfg, "LAB_CA_ROOT", layout["data"] / "nope")
    assert cfg.api_trust_bundle() is True                      # nothing to add -> plain system trust
    _lab_root(layout, monkeypatch, cfg)
    path = cfg.api_trust_bundle()
    text = open(path).read()
    assert "LABROOT" in text and open(certifi.where()).read()[:40] in text
    custom = layout["data"] / "custom.pem"; custom.write_text("-----BEGIN CERTIFICATE-----\nCUSTOM\n-----END CERTIFICATE-----\n")
    # exclusive (default): the custom bundle is the ONLY trust, exactly as before the lab CA existed
    assert cfg.api_trust_bundle(str(custom)) == str(custom)
    # additive: custom + lab + system, in a distinct immutable file
    add = cfg.api_trust_bundle(str(custom), "additive")
    assert add != path and "CUSTOM" in open(add).read() and "LABROOT" in open(add).read()
    assert cfg.api_trust_bundle(str(custom), "additive") == add   # same content -> same file
    assert cfg.api_trust_bundle() == path                          # unchanged by the other call


def test_verified_calls_use_combined_trust_whatever_ca_is_configured(layout, monkeypatch):
    """Migration public->lab, lab->public and rollback all verify against system + lab roots."""
    from app import config as cfg
    root = _lab_root(layout, monkeypatch, cfg)
    seen = []

    def fake_post(url, json=None, headers=None, verify=None, timeout=None, **kw):
        seen.append(verify)
        return _Resp(200) if url.endswith("/validation") else _Resp(204)

    monkeypatch.setattr(deploy.requests, "post", fake_post)
    cert, key, ca = _files(layout)
    for ca_choice in ("lab", "letsencrypt", "letsencrypt_test"):
        assert deploy.deploy_paths(make_server(acme_ca=ca_choice, verify_ssl=True), cert, key, ca).ok
    assert len(set(seen)) == 1 and "/trust/api-trust-" in seen[0]
    text = open(seen[0]).read()
    assert "LABROOT" in text and "BEGIN CERTIFICATE" in text
    # rollback uses the same code path
    from app import restart
    monkeypatch.setattr(restart, "_reload_nginx", lambda s: StepResult("restart", True, "ok"))
    monkeypatch.setattr(restart, "_wait_for_served_serial", lambda s, want, t: (True, 0))
    rb = restart._rollback_dir(make_server()); rb.mkdir(parents=True, exist_ok=True)
    for name in ("orch.example.test.cer", "orch.example.test.key", "ca.cer"):
        (rb / name).write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(restart, "_deployed_serial_from", lambda p: 1)
    seen.clear()
    restart._attempt_rollback(make_server(acme_ca="lab", verify_ssl=True), failed_serial=2)
    assert seen and "/trust/api-trust-" in seen[0]
    # verify_ssl off still means no verification, root present or not
    seen.clear()
    deploy.deploy_paths(make_server(acme_ca="lab", verify_ssl=False), cert, key, ca)
    assert seen[0] is False
    assert root.is_file()



def test_missing_ca_bundle_fails_closed(layout, monkeypatch):
    from app import config as cfg
    _lab_root(layout, monkeypatch, cfg)
    custom = layout["data"] / "custom.pem"
    custom.write_text("-----BEGIN CERTIFICATE-----\nCUSTOM\n-----END CERTIFICATE-----\n")
    assert cfg.api_trust_bundle(str(custom)) == str(custom)
    custom.unlink()                                   # the operator's pinned CA disappears
    for mode in ("exclusive", "additive"):
        with __import__("pytest").raises(cfg.ConfigError):
            cfg.api_trust_bundle(str(custom), mode)
    calls = []
    monkeypatch.setattr(deploy.requests, "post", lambda *a, **k: calls.append(1))
    cert, key, ca = _files(layout)
    res = deploy.deploy_paths(make_server(verify_ssl=True, ca_bundle=str(custom)), cert, key, ca)
    assert not res.ok and "refusing to fall back" in res.message and calls == []


def test_exclusive_bundle_is_passed_verbatim_even_with_lab_ca(layout, monkeypatch):
    """A pinned private CA must not be widened by the lab root or system roots."""
    from app import config as cfg
    _lab_root(layout, monkeypatch, cfg)
    custom = layout["data"] / "private-ca.pem"
    custom.write_text("-----BEGIN CERTIFICATE-----\nPRIVATE\n-----END CERTIFICATE-----\n")
    seen = []
    monkeypatch.setattr(deploy.requests, "post", lambda url, **k: (seen.append(k["verify"]), _Resp(200) if url.endswith("/validation") else _Resp(204))[1])
    cert, key, ca = _files(layout)
    assert deploy.deploy_paths(make_server(acme_ca="lab", verify_ssl=True, ca_bundle=str(custom)), cert, key, ca).ok
    assert seen[0] == str(custom)
    text = open(seen[0]).read()
    assert "LABROOT" not in text and text.count("BEGIN CERTIFICATE") == 1


def test_concurrent_bundles_are_distinct_and_immutable(layout, monkeypatch):
    """Two deployments with different custom CAs in additive mode never share or truncate a file."""
    import threading
    from app import config as cfg
    _lab_root(layout, monkeypatch, cfg)
    a = layout["data"] / "a.pem"; a.write_text("-----BEGIN CERTIFICATE-----\nCUSTOMROOT-ALPHA\n-----END CERTIFICATE-----\n")
    b = layout["data"] / "b.pem"; b.write_text("-----BEGIN CERTIFICATE-----\nCUSTOMROOT-BRAVO\n-----END CERTIFICATE-----\n")
    results: dict[str, set] = {"a": set(), "b": set()}
    errors = []

    def worker(tag, path):
        try:
            for _ in range(25):
                out = cfg.api_trust_bundle(str(path), "additive")
                text = open(out).read()
                assert text.endswith("-----END CERTIFICATE-----\n"), "partial file observed"
                assert ("CUSTOMROOT-ALPHA" in text) == (tag == "a") and ("CUSTOMROOT-BRAVO" in text) == (tag == "b")
                results[tag].add(out)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(t, p)) for _ in range(3) for t, p in (("a", a), ("b", b))]
    for t in threads: t.start()
    for t in threads: t.join()
    assert not errors
    assert len(results["a"]) == 1 and len(results["b"]) == 1 and results["a"] != results["b"]
    assert not list((layout["cfg"] / "trust").glob(".*.tmp"))



def test_missing_lab_root_fails_closed_when_lab_is_configured(layout, monkeypatch):
    """LAB_CA_HOST set but root absent: no silent fallback to public trust, zero API calls."""
    from app import config as cfg
    root = _lab_root(layout, monkeypatch, cfg)
    assert cfg.api_trust_bundle() is not True
    root.unlink()
    with __import__("pytest").raises(cfg.ConfigError):
        cfg.api_trust_bundle()
    calls = []
    monkeypatch.setattr(deploy.requests, "post", lambda *a, **k: calls.append(1))
    cert, key, ca = _files(layout)
    for ca_choice in ("lab", "letsencrypt"):
        res = deploy.deploy_paths(make_server(acme_ca=ca_choice, verify_ssl=True), cert, key, ca)
        assert not res.ok and "lab root" in res.message
    assert calls == []
    # an exclusive custom bundle does not involve lab trust and still works
    custom = layout["data"] / "custom.pem"; custom.write_text("-----BEGIN CERTIFICATE-----\nCUSTOM\n-----END CERTIFICATE-----\n")
    assert cfg.api_trust_bundle(str(custom)) == str(custom)
    # lab not configured at all -> plain system trust
    monkeypatch.setattr(cfg, "LAB_CA_HOST", "")
    assert cfg.api_trust_bundle() is True


def test_retired_roots_stay_trusted_during_rollover(layout, monkeypatch):
    """Old-root -> new-root: verified deploy and rollback trust both roots, no verification off."""
    from app import config as cfg, restart
    root = _lab_root(layout, monkeypatch, cfg)
    retired = root.parent / "retired"; retired.mkdir()
    monkeypatch.setattr(cfg, "LAB_CA_RETIRED_DIR", retired)
    (retired / "root-old.crt").write_text("-----BEGIN CERTIFICATE-----\nOLDLABROOT\n-----END CERTIFICATE-----\n")
    seen = []
    monkeypatch.setattr(deploy.requests, "post", lambda url, **k: (seen.append(k["verify"]), _Resp(200) if url.endswith("/validation") else _Resp(204))[1])
    cert, key, ca = _files(layout)
    assert deploy.deploy_paths(make_server(acme_ca="lab", verify_ssl=True), cert, key, ca).ok
    text = open(seen[0]).read()
    assert "LABROOT" in text and "OLDLABROOT" in text
    monkeypatch.setattr(restart, "_reload_nginx", lambda s: StepResult("restart", True, "ok"))
    monkeypatch.setattr(restart, "_wait_for_served_serial", lambda s, want, t: (True, 0))
    monkeypatch.setattr(restart, "_deployed_serial_from", lambda p: 1)
    rb = restart._rollback_dir(make_server()); rb.mkdir(parents=True, exist_ok=True)
    for name in ("orch.example.test.cer", "orch.example.test.key", "ca.cer"):
        (rb / name).write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    seen.clear()
    restart._attempt_rollback(make_server(acme_ca="lab", verify_ssl=True), failed_serial=2)
    assert seen and "OLDLABROOT" in open(seen[0]).read()
    # once the retired root is removed the bundle changes (new immutable file) and no longer trusts it
    (retired / "root-old.crt").unlink()
    assert "OLDLABROOT" not in open(cfg.api_trust_bundle()).read()
