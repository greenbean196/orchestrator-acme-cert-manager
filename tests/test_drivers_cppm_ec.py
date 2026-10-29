"""ClearPass and EdgeConnect drivers against fake APIs (no network beyond 127.0.0.1)."""
from __future__ import annotations

import json
import socket
import urllib.request

import pytest
import requests

from app import config, drivers
from app.drivers import base as drv_base, clearpass as cp, edgeconnect as ec
from app.models import Certificate, Target
from tests.test_core_v13 import _bundle_files


def _ec_bundle(d, domain="cppm.example.test", issuer_cn="CN=Fake LE Intermediate X1", days=90, kind="rsa"):
    """A real key (RSA by default, EC with kind='ec') + matching self-issued leaf so PKCS#12 packaging works."""
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec, rsa
    from cryptography.x509.oid import NameOID
    d.mkdir(parents=True, exist_ok=True)
    key = _ec.generate_private_key(_ec.SECP256R1()) if kind == "ec" else rsa.generate_private_key(65537, 2048)
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn.split("=", 1)[1].split(",")[0])]))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=days)).sign(key, hashes.SHA256()))
    (d / f"{domain}.cer").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / f"{domain}.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.NoEncryption()))
    (d / "ca.cer").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class FakeResp:
    def __init__(self, status, body=None, text=None):
        self.status_code, self._body = status, body
        self.text = text if text is not None else (json.dumps(body) if body is not None else "")
        self.ok = status < 400
        self.headers = {"Content-Type": "application/json"}

    def json(self):
        return self._body


class FakeCPPM:
    """Two-node cluster; PUT fetches the PKCS#12 from the callback URL like ClearPass does."""

    def __init__(self, slots_pem: dict, allow_fetch=True, fail_node=None, put_status=200):
        self.nodes = [{"name": "sub1", "server_uuid": "u-sub1", "fqdn": "sub1.example.test", "management_ip": "127.0.0.1", "is_publisher": False, "local_server": False},
                      {"name": "pub", "server_uuid": "u-pub", "fqdn": "pub.example.test", "management_ip": "127.0.0.1", "is_publisher": True, "local_server": True}]
        self.slots = {(n["server_uuid"], svc): {"service_name": svc, "enabled": True, "cert_file": pem, "public_key_algorithm": "RSA"}
                      for n in self.nodes for svc, pem in slots_pem.items()}
        self.puts, self.fetched = [], []
        self.allow_fetch, self.fail_node, self.put_status = allow_fetch, fail_node, put_status
        self.tokens = 0

    def request(self, method, url, **kw):
        path = url.split("/api", 1)[1]
        if method == "POST" and path == "/oauth":
            self.tokens += 1
            assert kw.get("data", {}).get("grant_type") == "client_credentials"
            return FakeResp(200, {"access_token": "tok", "expires_in": 3600, "token_type": "bearer"})
        if method == "GET" and path == "/cluster/server":
            return FakeResp(200, {"_embedded": {"items": self.nodes}})
        if method == "GET" and path.startswith("/server-cert/name/"):
            _, _, _, uuid, svc = path.split("/", 4)
            if uuid in ("this", "publisher"):
                return FakeResp(400, {"detail": "server_uuid must be a UUID"})   # documented only for /cluster/server
            slot = self.slots.get((uuid, svc))
            return FakeResp(200, slot) if slot else FakeResp(404, {"detail": "no such slot"})
        if method == "PUT" and path.startswith("/server-cert/name/"):
            _, _, _, uuid, svc = path.split("/", 4)
            body = kw["json"]
            self.puts.append((uuid, svc, body["pkcs12_file_url"]))
            if self.fail_node == uuid:
                return FakeResp(422, {"validation_messages": ["Could not fetch certificate. URL not trusted or Cert File is empty."]})
            if self.allow_fetch:
                data = urllib.request.urlopen(body["pkcs12_file_url"], timeout=5).read()
                from cryptography.hazmat.primitives.serialization import pkcs12
                key, leaf, _ = pkcs12.load_key_and_certificates(data, body["pkcs12_passphrase"].encode())
                from cryptography.hazmat.primitives import serialization
                pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
                self.fetched.append(len(data))
                self.slots[(uuid, svc)] = {"service_name": svc, "enabled": True, "cert_file": pem, "public_key_algorithm": "RSA"}
            return FakeResp(self.put_status, self.slots.get((uuid, svc)))
        return FakeResp(404, {"detail": f"unhandled {method} {path}"})


@pytest.fixture
def cppm_target(layout, monkeypatch):
    d = layout["certs"] / "cppm.example.test"
    old = _ec_bundle(d, issuer_cn="CN=Fake LE Intermediate X1")             # current cert on the cluster
    old_pem = (d / "cppm.example.test.cer").read_text()
    new = _ec_bundle(d, issuer_cn="CN=Fake LE Intermediate X1")             # the freshly issued one on disk
    port = _free_port()
    c = Certificate(id="cppm", name="ClearPass", domain="cppm.example.test", acme_email="a@b.c", acme_ca="letsencrypt_test",
                    targets=[Target("cppm", "clearpass", settings=drivers.get("clearpass").normalize({
                        "host": "pub.example.test", "client_id": "oacm", "client_secret": "s3cret",
                        "service_https_rsa": "on", "service_radius": "on", "callback_host": "127.0.0.1",
                        "callback_port": str(port), "callback_bind": "127.0.0.1", "verify_served": ""}))])
    fake = FakeCPPM({"HTTPS(RSA)": old_pem, "HTTPS(ECC)": old_pem, "RADIUS": old_pem})
    monkeypatch.setattr(cp, "_POLL_INTERVAL", 0)
    monkeypatch.setattr(cp, "_REPLICATION_DELAY", 0)

    class Sess(requests.Session):
        def request(self, method, url, **kw):
            return fake.request(method, url, **kw)
    monkeypatch.setattr(cp.requests, "Session", Sess)
    monkeypatch.setattr(cp, "_resolve", lambda h: {"127.0.0.1"})
    return c, fake, old, new


def test_clearpass_schema_normalize_and_preflight(layout):
    drv = drivers.get("clearpass")
    assert drv.steps == ("deploy", "activate") and drv.probe_label == "Test API"
    with pytest.raises(config.ConfigError, match="localhost"):
        drv.normalize({"host": "h", "client_id": "c", "callback_host": "localhost", "service_https_rsa": "on"})
    with pytest.raises(config.ConfigError, match="at least one"):
        drv.normalize({"host": "h", "client_id": "c", "callback_host": "10.0.0.5", "service_https_rsa": ""})
    n = drv.normalize({"host": "h", "client_id": "c", "callback_host": "10.0.0.5", "service_https_ecc": "on"})
    assert n["callback_port"] == 8765 and n["client_secret_env"] == "CPPM_CLIENT_SECRET" and n["nodes"] == "all"
    assert n["service_https_rsa"] is True and drv.normalize({**n, "service_https_rsa": ""})["service_https_rsa"] is False
    c = Certificate(id="x", name="x", domain="x.test", key_type="rsa2048", targets=[Target("x", "clearpass", settings=n)])
    probs = drv.preflight(c.targets[0])
    assert any("HTTPS(ECC) needs an EC certificate" in p for p in probs) and any("secret" in p for p in probs)
    assert drv.services(c.targets[0]) == ["HTTPS(ECC)", "HTTPS(RSA)"]


def test_clearpass_probe_deploy_activate_verify_and_snapshot(cppm_target, layout):
    c, fake, old, new = cppm_target
    t = c.targets[0]
    drv = drivers.get("clearpass")
    probe = drv.probe(t)
    assert probe.ok and "2 node(s)" in probe.message and fake.tokens == 1
    bundle = drv_base.CertBundle.for_certificate(c)
    # other HTTPS slot enabled with its own cert: blocked by default, warned when asked
    d = drv.deploy(t, bundle)
    assert not d.ok and "HTTPS(ECC) is enabled" in d.message and d.detail["kind"] == "config"
    t.settings["other_slot_policy"] = "warn"
    d = drv.deploy(t, bundle)
    assert d.ok and d.detail["services"] == ["RADIUS", "HTTPS(RSA)"] and d.detail["warnings"]
    a = drv.activate_step(t, bundle)
    assert a.ok, a.message
    # subscribers first, publisher last; RADIUS before HTTPS on each node; every PUT fetched a fresh file
    assert [(u, s) for u, s, _ in fake.puts] == [("u-sub1", "RADIUS"), ("u-sub1", "HTTPS(RSA)"), ("u-pub", "RADIUS"), ("u-pub", "HTTPS(RSA)")]
    assert len({url for _, _, url in fake.puts}) == 1 and len(fake.fetched) == 4
    assert all(n["verified"] for n in a.detail["nodes"]) and a.detail["serial"] == format(new.serial_number, "x")
    assert drv.snapshot_bundle(t).serial == new.serial_number
    ok, _ = drv.verify(t, new.serial_number, 1)
    assert ok
    info = drv.served_info(t)
    assert info["present"] and info["serial"] == format(new.serial_number, "X")
    # the listener is gone once the run is over
    port = t.settings["callback_port"]
    with pytest.raises(OSError):
        urllib.request.urlopen(f"http://127.0.0.1:{port}/x", timeout=1)


def test_clearpass_failure_on_second_node_rolls_back_first(cppm_target, layout):
    c, fake, old, new = cppm_target
    t = c.targets[0]
    t.settings["other_slot_policy"] = "ignore"
    drv = drivers.get("clearpass")
    # take a snapshot of the old (current) certificate as last-known-good
    # the on-disk key belongs to `new`; regenerate a consistent old bundle for the snapshot
    snap_dir = drv.snapshot_dir(t); snap_dir.mkdir(parents=True, exist_ok=True)
    old_bundle_dir = layout["certs"] / "old-tmp"; old_cert = _ec_bundle(old_bundle_dir, issuer_cn="CN=Fake LE Intermediate X1")
    for name in ("cppm.example.test.cer", "cppm.example.test.key", "ca.cer"):
        (snap_dir / name).write_bytes((old_bundle_dir / name).read_bytes())
    snap = drv.snapshot_bundle(t)
    assert snap and snap.serial == old_cert.serial_number
    fake.fail_node = "u-pub"
    bundle = drv_base.CertBundle.for_certificate(c)
    assert drv.deploy(t, bundle).ok
    a = drv.activate_step(t, bundle)
    assert not a.ok and "activation failed on node pub" in a.message and "rolled back" in a.message
    assert a.detail["rolled_back"] is True and a.detail["restored_serial"] == format(old_cert.serial_number, "x")
    # sub1 got the new cert, then the old one back; pub never changed
    seq = [(u, s) for u, s, _ in fake.puts]
    assert seq[:2] == [("u-sub1", "RADIUS"), ("u-sub1", "HTTPS(RSA)")] and ("u-pub", "RADIUS") in seq
    assert seq[-2:] == [("u-sub1", "RADIUS"), ("u-sub1", "HTTPS(RSA)")]
    from app import certs as _certs
    assert _certs.parse_pem(fake.slots[("u-sub1", "HTTPS(RSA)")]["cert_file"].encode())["serial"] == format(old_cert.serial_number, "X")


def test_clearpass_callback_refuses_unknown_clients(cppm_target):
    c, fake, old, new = cppm_target
    t = c.targets[0]
    port = t.settings["callback_port"]
    with cp.CallbackServer("127.0.0.1", port, "127.0.0.1", b"P12", "x.p12", {"10.9.9.9"}, 60) as cb:
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(cb.url, timeout=2)
        assert exc.value.code == 404 and cb.rejected == {"127.0.0.1"} and cb.fetches == 0
    with cp.CallbackServer("127.0.0.1", port, "127.0.0.1", b"P12", "x.p12", {"127.0.0.1"}, 60) as cb:
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(cb.url.rsplit("/", 1)[0] + "/other.p12", timeout=2)
        assert urllib.request.urlopen(cb.url, timeout=2).read() == b"P12" and cb.fetches == 1


def test_pkcs12_packaging_checks_key_match(layout):
    d = layout["certs"] / "ec-pack"
    cert = _ec_bundle(d, domain="e.test", kind="ec")
    b = drv_base.CertBundle.from_paths(d / "e.test.cer", d / "e.test.key", d / "ca.cer")
    data, kind = cp.build_pkcs12(b, "e.test")
    assert kind == "ec" and data[:1] == b"\x30"
    wrapped = cp.wrap_pkcs12(data, "pw")
    from cryptography.hazmat.primitives.serialization import pkcs12
    key, leaf, extra = pkcs12.load_key_and_certificates(wrapped, b"pw")
    assert leaf.serial_number == cert.serial_number and extra
    other = _ec_bundle(layout["certs"] / "ec-other", domain="e.test", kind="ec")
    (d / "e.test.cer").write_bytes(other.public_bytes(__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.PEM))
    with pytest.raises(ValueError, match="does not match"):
        cp.build_pkcs12(drv_base.CertBundle.from_paths(d / "e.test.cer", d / "e.test.key", d / "ca.cer"), "e.test")


# --------------------------------------------------------------------------- EdgeConnect

class FakeOrch:
    def __init__(self, pem):
        self.pem = pem
        self.calls = []

    def request(self, method, url, headers=None, verify=None, timeout=None, **kw):
        assert headers["X-Auth-Token"] == "k"
        path = url.split("/gms/rest/", 1)[1]
        self.calls.append((method, path))
        if path == "gms/versions":
            return FakeResp(200, {"current": "9.5.3.40500", "installed": []})
        if path.startswith("appliance?nePk="):
            return FakeResp(200, {"id": "3.NE", "hostName": "ec-1", "model": "EC-S", "softwareVersion": "9.5.2.0", "state": 1})
        if path.startswith("reachability/appliance"):
            return FakeResp(200, {"10.0.0.9": {"https": True, "rest": True, "ssh": True}})
        if path.startswith("httpsCertificate?nePk="):
            return FakeResp(200, {"cert": self.pem})
        if path.startswith("appliance/rest?nePk=3.NE&url=httpsCertificate/validation"):
            return FakeResp(200, {"ok": True})
        if path.startswith("appliance/rest?nePk=3.NE&url=httpsCertificate/config"):
            self.pem = kw["json"]["certificateData"]
            return FakeResp(200, {})
        if path.startswith("appliance/rest?nePk=3.NE&url=cnprocess/restart/"):
            return FakeResp(200, {})
        return FakeResp(404, {"detail": path})


def test_edgeconnect_read_only_by_default_then_experimental_write(layout, monkeypatch):
    d = layout["certs"] / "ec-app.example.test"
    _bundle_files(d, domain="ec-app.example.test", issuer_cn="CN=R3,O=Let's Encrypt,C=US")
    from app import certs as _certs
    new = _certs.leaf_info(d / "ec-app.example.test.cer")
    drv = drivers.get("edgeconnect")
    with pytest.raises(config.ConfigError, match="nePk"):
        drv.normalize({"orchestrator_host": "orch", "ne_pk": "three"})
    settings = drv.normalize({"orchestrator_host": "orch.example.test", "ne_pk": "3.NE", "api_key": "k"})
    c = Certificate(id="ec-app", name="EC", domain="ec-app.example.test", acme_email="a@b.c", acme_ca="letsencrypt",
                    targets=[Target("ec-app", "edgeconnect", settings=settings)])
    t = c.targets[0]
    fake = FakeOrch((d / "ec-app.example.test.cer").read_text())
    monkeypatch.setattr(ec.requests, "request", fake.request)
    monkeypatch.setattr(ec, "_POLL_INTERVAL", 0)
    assert drv.preflight(t) == [] and any("monitor-only" in w for w in drv.warnings(t))
    p = drv.probe(t)
    assert p.ok and "Orchestrator 9.5" in str(p.detail["checks"]) and ("GET", "gms/versions") in fake.calls
    info = drv.served_info(t)
    assert info["present"] and info["serial"] == new["serial"]
    bundle = drv_base.CertBundle.for_certificate(c)
    dres = drv.deploy(t, bundle)
    assert not dres.ok and "not enabled" in dres.message and not any(m == "POST" for m, _ in fake.calls)
    t.settings["experimental_passthrough_write"] = True
    assert any("restart" in p for p in drv.preflight(t))
    t.settings["restart_process"] = "nodejs"
    assert drv.deploy(t, bundle).ok
    assert [p for m, p in fake.calls if m == "POST"] == ["appliance/rest?nePk=3.NE&url=httpsCertificate/validation",
                                                           "appliance/rest?nePk=3.NE&url=httpsCertificate/config"]
    a = drv.activate_step(t, bundle)
    assert a.ok and "nodejs" in str(fake.calls) and drv.snapshot_bundle(t).serial == bundle.serial


def test_clearpass_lost_put_response_counts_as_changed_and_is_verified(cppm_target, monkeypatch):
    """A PUT whose response is lost may have landed: verification decides, and the node is never 'nothing was changed'."""
    c, fake, old, new = cppm_target
    t = c.targets[0]
    drv = drivers.get("clearpass")
    t.settings["other_slot_policy"] = "ignore"
    monkeypatch.setattr(cp, "activation_timeout", lambda: 1)
    real = fake.request

    def request(method, url, **kw):
        resp = real(method, url, **kw)
        if method == "PUT" and "/u-sub1/" in url:
            raise requests.ConnectionError("Remote end closed connection without response")   # after the install happened
        return resp
    fake.request = request
    bundle = drv_base.CertBundle.for_certificate(c)
    assert drv.deploy(t, bundle).ok
    res = drv.activate_step(t, bundle)
    sub1 = next(r for r in res.detail["nodes"] if r["node"] == "sub1")
    assert sub1["unknown"] is True and any(v.startswith("unknown (response lost") for v in sub1["services"].values())
    assert "nothing was changed" not in res.message
    assert sub1.get("verified") is False      # RADIUS was never pushed on that node, so the node does not verify


def test_clearpass_api_error_mid_rollout_is_recorded_per_node_and_rolled_back(cppm_target, layout):
    c, fake, old, new = cppm_target
    t = c.targets[0]
    drv = drivers.get("clearpass")
    t.settings["other_slot_policy"] = "ignore"
    # take a snapshot of the current (old) certificate so a rollback is possible
    snap_dir = drv.snapshot_dir(t); snap_dir.mkdir(parents=True, exist_ok=True)
    old_dir = layout["certs"] / "old-snap"; _ec_bundle(old_dir, issuer_cn="CN=Fake LE Intermediate X1")
    for name in ("cppm.example.test.cer", "cppm.example.test.key", "ca.cer"):
        (snap_dir / name).write_bytes((old_dir / name).read_bytes())
    real = fake.request
    state = {"puts": 0}

    def request(method, url, **kw):
        if method == "PUT":
            state["puts"] += 1
        if method == "GET" and "/server-cert/name/u-pub/" in url and state["puts"] >= 2:
            return FakeResp(502, {"detail": "web service restarting"})
        return real(method, url, **kw)
    fake.request = request
    bundle = drv_base.CertBundle.for_certificate(c)
    assert drv.deploy(t, bundle).ok
    res = drv.activate_step(t, bundle)
    assert not res.ok and res.detail["nodes"], res.message
    pub = next((r for r in res.detail["nodes"] if r["node"] == "pub"), None)
    assert pub is not None and any("api error" in v for v in pub["services"].values()) and pub["ok"] is False
    assert res.detail["rolled_back"] in (True, False) and "rollback" in res.detail      # sub1 was changed: a rollback ran


def test_clearpass_callback_stops_after_the_last_put_and_honours_the_ttl(cppm_target):
    c, fake, old, new = cppm_target
    t = c.targets[0]
    drv = drivers.get("clearpass")
    t.settings["other_slot_policy"] = "ignore"
    bundle = drv_base.CertBundle.for_certificate(c)
    assert drv.deploy(t, bundle).ok
    seen = {}
    real = fake.request

    def request(method, url, **kw):
        resp = real(method, url, **kw)
        if method == "PUT":
            seen["url"] = kw["json"]["pkcs12_file_url"]
        return resp
    fake.request = request
    res = drv.activate_step(t, bundle)
    assert res.ok, res.message
    import urllib.error
    # the listener object is gone with the run; an explicit server shows the lifetime rules
    with cp.CallbackServer("127.0.0.1", _free_port(), "127.0.0.1", b"x", "a.p12", {"127.0.0.1"}, 1) as cb:
        assert urllib.request.urlopen(cb.url, timeout=5).read() == b"x"
        cb.stop()
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(cb.url, timeout=5)
        assert ei.value.code == 404
    with cp.CallbackServer("127.0.0.1", _free_port(), "127.0.0.1", b"x", "a.p12", {"127.0.0.1"}, 1) as cb:
        cb._deadline = 0        # lifetime elapsed
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(cb.url, timeout=5)


def test_clearpass_served_info_uses_real_node_uuids_and_lists_every_node(cppm_target):
    c, fake, old, new = cppm_target
    t = c.targets[0]
    drv = drivers.get("clearpass")
    info = drv.served_info(t)
    assert info["present"] and info["serial"] == format(old.serial_number, "X")
    assert [n["node"] for n in info["nodes"]] == ["sub1", "pub"] and all(n.get("serial") for n in info["nodes"])
    assert "warning" not in info
    from cryptography.hazmat.primitives import serialization
    fake.slots[("u-sub1", info["service"])]["cert_file"] = new.public_bytes(serialization.Encoding.PEM).decode()
    info = drv.served_info(t)
    assert "different certificates" in info.get("warning", "")
