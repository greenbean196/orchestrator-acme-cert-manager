from __future__ import annotations

import re
import time

import pytest

from app import config
from app.webui import auth, server as web
from tests.conftest import make_server


def _csrf(c, path="/login", **open_kw):
    """Fetch a page to receive the csrf cookie and read the matching form token (open_kw go to the test client)."""
    html = c.get(path, **open_kw).get_data(as_text=True)
    m = re.search(r'name="_csrf" value="([0-9a-f]+)"', html)
    assert m, f"no csrf token on {path}"
    return m.group(1)


def _post(c, url, data=None, path="/login", **open_kw):
    data = dict(data or {})
    data.setdefault("_csrf", _csrf(c, path, **open_kw))
    return c.post(url, data=data, **open_kw)


_NO_SERVED = {"present": False, "error": "not checked", "serial": None, "environment": None, "self_signed": None}


def test_environment_detection():
    assert web.environment_of("CN=(STAGING) Ersatz Emmer YR2,O=(STAGING) Let's Encrypt,C=US") == "staging"
    assert web.environment_of("CN=Fake LE Intermediate X1") == "staging"
    assert web.environment_of("CN=YR2,O=Let's Encrypt,C=US") == "production"
    assert web.environment_of(None) is None


def test_lifecycle_states():
    s = make_server(acme_ca="letsencrypt")
    issued = {"present": True, "serial": "AA", "environment": "production"}
    assert web.lifecycle(s, {"present": False}, {})["state"] == "none"
    assert web.lifecycle(s, issued, {"present": False, "error": "timed out"})["state"] == "unknown"
    live = web.lifecycle(s, issued, {"present": True, "serial": "AA", "environment": "production", "error": None})
    assert live["state"] == "live"
    pend = web.lifecycle(s, issued, {"present": True, "serial": "BB", "environment": "staging", "error": None})
    assert pend["state"] == "pending"
    assert "still serving staging certificate" in pend["message"]
    assert "Force deploy" in pend["message"]
    stale = web.lifecycle(s, {"present": True, "serial": "AA", "environment": "staging"},
                          {"present": True, "serial": "AA", "environment": "staging", "error": None})
    assert stale["state"] == "live" and "STAGING" in stale["message"]


def test_form_validation_rejects_bad_ssh(layout, known_hosts):
    flat = web._flat_blank()
    flat.update(id="x", orchestrator_host="orch.example.test", acme_email="a@b.c",
                ssh_user="", ssh_key_path="", ssh_known_hosts=str(known_hosts))
    errs = web._validate(flat, is_new=True)
    assert any("ssh.user is empty" in e for e in errs)
    assert any("key_path is empty" in e for e in errs)


def test_form_validation_accepts_good_ssh(server):
    flat = web._flat_from_server(server)
    flat["id"] = "y"
    assert web._validate(flat, is_new=True) == []


def _client(layout, monkeypatch):
    monkeypatch.setattr(web, "_served_info", lambda *a: dict(_NO_SERVED))
    auth.create_admin("admin", "password123")
    web.app.config["TESTING"] = True
    c = web.app.test_client()
    r = _post(c, "/login", {"username": "admin", "password": "password123"})
    assert r.status_code == 302
    return c


def test_dashboard_shows_config_path_and_ssh_problems(layout, known_hosts, monkeypatch):
    config.upsert_server(make_server(ssh_key_path="", ssh_known_hosts=str(known_hosts)))
    c = _client(layout, monkeypatch)
    html = c.get("/").get_data(as_text=True)
    assert str(config.SERVERS_FILE) in html
    assert "SSH configuration invalid" in html          # health reason on the fleet row
    assert "attention" in html
    detail = c.get("/server/orch-test").get_data(as_text=True)
    assert "Activation will fail" in detail
    assert "key_path is empty" in detail
    assert "unverified" in detail                       # API TLS verification is off
    frag = c.get("/partials/fleet").get_data(as_text=True)
    assert frag.lstrip().startswith("<div data-busy=")
    assert c.get("/server/does-not-exist").status_code == 404


def test_settings_save_rejects_empty_key_path(layout, known_hosts, monkeypatch):
    c = _client(layout, monkeypatch)
    r = _post(c, "/settings/save", {
        "id": "new1", "orchestrator_host": "orch.example.test", "acme_email": "a@b.c",
        "acme_ca": "letsencrypt_test", "key_type": "rsa2048", "ssh_user": "admin",
        "ssh_key_path": "", "ssh_known_hosts": str(known_hosts), "ssh_port": "22",
    })
    assert r.status_code == 400
    assert "key_path is empty" in r.get_data(as_text=True)
    assert not config.server_exists("new1")


def test_settings_save_persists_to_config_dir(layout, rsa_key, known_hosts, monkeypatch):
    c = _client(layout, monkeypatch)
    r = _post(c, "/settings/save", {
        "id": "new2", "orchestrator_host": "orch.example.test", "acme_email": "a@b.c",
        "acme_ca": "letsencrypt_test", "key_type": "rsa2048", "ssh_user": "admin",
        "ssh_key_path": str(rsa_key[0]), "ssh_known_hosts": str(known_hosts), "ssh_port": "22",
        "restart_command": "sudo /bin/systemctl restart --no-block gms.service",
        "nginx_reload_command": "sudo /bin/systemctl reload nginx",
    })
    assert r.status_code == 302
    assert config.SERVERS_FILE.exists() and config.server_exists("new2")


def test_api_status_reports_paths(layout, monkeypatch):
    c = _client(layout, monkeypatch)
    j = c.get("/api/status").get_json()
    assert j["servers_file"] == str(config.SERVERS_FILE)
    assert "findings" in j and "lab_ca" in j
    assert c.get("/settings").status_code == 200
    assert c.get("/settings/new").status_code == 200


def test_login_next_cannot_be_offsite(layout, monkeypatch):
    monkeypatch.setattr(web, "_served_info", lambda *a: dict(_NO_SERVED))
    auth.create_admin("admin", "password123")
    c = web.app.test_client()
    r = _post(c, "/login", {"username": "admin", "password": "password123", "next": "//evil.example"})
    assert r.headers["Location"].endswith("/")


def _row(**over):
    base = {"renewing": False, "ssh_problems": [], "cert": {"present": True, "days_left": 60, "environment": "production"},
            "lifecycle": {"state": "live", "configured_env": "production", "message": ""}, "last": {"outcome": "success"}}
    base.update(over)
    return base


def test_health_rollup_order():
    assert web.health(_row())["state"] == "ok"
    assert web.health(_row(renewing=True))["state"] == "working"
    assert web.health(_row(ssh_problems=["x"]))["state"] == "critical"
    assert web.health(_row(last={"outcome": "failed"}))["state"] == "critical"
    assert web.health(_row(cert={"present": True, "days_left": -1, "environment": "production"}))["state"] == "critical"
    w = web.health(_row(lifecycle={"state": "pending", "configured_env": "production", "message": ""}))
    assert w["state"] == "warning" and "not yet served" in w["reasons"][0]
    assert web.health(_row(cert={"present": True, "days_left": 12, "environment": "production"}))["state"] == "warning"
    assert web.health(_row(cert={"present": False}, lifecycle={"state": "none", "configured_env": "production", "message": ""}, last=None))["state"] == "none"
    assert web.health(_row(lifecycle={"state": "unknown", "configured_env": "production", "message": "m"}))["state"] == "unknown"


def test_fleet_summary_counts():
    rows = [
        {"health": {"state": "ok"}, "cert": {"present": True, "days_left": 60}, "renewing": False},
        {"health": {"state": "warning"}, "cert": {"present": True, "days_left": 12}, "renewing": False},
        {"health": {"state": "critical"}, "cert": {"present": False}, "renewing": False},
        {"health": {"state": "working"}, "cert": {"present": True, "days_left": 40}, "renewing": True},
    ]
    s = web.fleet_summary(rows)
    assert (s["servers"], s["healthy"], s["attention"], s["expiring"], s["working"], s["min_days"]) == (4, 1, 2, 1, 1, 12)


def test_relative_time():
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    assert web.relative_time((now - dt.timedelta(hours=3)).isoformat()) == "3h ago"
    assert web.relative_time((now - dt.timedelta(days=2)).isoformat()) == "2d ago"
    assert web.relative_time(None) == "—"


def test_server_partial_and_api(layout, server, monkeypatch):
    config.upsert_server(server)
    c = _client(layout, monkeypatch)
    frag = c.get("/partials/server/orch-test").get_data(as_text=True)
    assert frag.lstrip().startswith("<div data-busy=") and "Activation (SSH)" in frag
    j = c.get("/api/server/orch-test").get_json()
    assert j["server"]["health"]["state"] in ("none", "unknown")
    assert "history" in j


def test_environment_of_lab_and_form_choice(layout, monkeypatch):
    from tests.test_config_persistence import _lab_pki
    root, inter = _lab_pki(layout, monkeypatch)
    assert web.environment_of(inter.subject.rfc4514_string()) == "lab"
    assert web.environment_of("CN=YR2,O=Let's Encrypt,C=US") == "production"
    s = make_server(acme_ca="lab")
    issued = {"present": True, "serial": "AA", "environment": "lab"}
    live = web.lifecycle(s, issued, {"present": True, "serial": "AA", "environment": "lab", "error": None})
    assert live["state"] == "live" and live["configured_env"] == "lab" and "run Force renew" not in live["message"]
    mismatch = web.lifecycle(make_server(acme_ca="letsencrypt"), issued,
                             {"present": True, "serial": "AA", "environment": "lab", "error": None})
    assert "issued by the LAB CA" in mismatch["message"]
    flat = web._flat_blank(); flat.update(id="l1", orchestrator_host="orch.lab.example.net", acme_email="a@b.c", acme_ca="lab")
    assert not any("lab CA is not configured" in e for e in web._validate(flat, is_new=True))
    monkeypatch.setattr(config, "LAB_CA_HOST", "")
    assert any("lab CA is not configured" in e for e in web._validate(flat, is_new=True))


# ============================= auth: open redirect, logout, cookies, setup, lockout ====
def _freeze_clock(monkeypatch):
    """Pin time.time() (what auth tokens, revocation and the login throttle read); returns advance(seconds)."""
    now = [time.time()]
    monkeypatch.setattr(time, "time", lambda: now[0])

    def advance(seconds):
        now[0] += seconds
    return advance


def _cookie_attrs(resp, name):
    """Attributes of the named cookie in resp's Set-Cookie headers: {lower-cased name: value or None}."""
    for header in resp.headers.getlist("Set-Cookie"):
        first, _, rest = header.partition(";")
        if first.strip().split("=", 1)[0] == name:
            attrs = {}
            for part in rest.split(";"):
                k, sep, v = part.strip().partition("=")
                if k:
                    attrs[k.lower()] = v if sep else None
            return attrs
    raise AssertionError(f"no {name!r} cookie in {resp.headers.getlist('Set-Cookie')}")


def _login(c, **open_kw):
    r = _post(c, "/login", {"username": "admin", "password": "password123"}, **open_kw)
    assert r.status_code == 302
    return r


@pytest.mark.parametrize("raw", [
    "//evil.example", "/\\evil.example", "http://evil.example/x", "https:evil", "javascript:alert(1)", "",
    "///evil.example", " //evil.example", "/\t/evil.example",
])
def test_safe_next_rejects_offsite_destinations(raw):
    with web.app.test_request_context("/login"):
        assert web._safe_next(raw) == "/"


@pytest.mark.parametrize("raw", ["/server/x?tab=1", "/settings"])
def test_safe_next_keeps_local_paths(raw):
    with web.app.test_request_context("/login"):
        assert web._safe_next(raw) == raw


def test_logout_requires_post_with_csrf_and_revokes_every_session(layout, monkeypatch):
    advance = _freeze_clock(monkeypatch)
    c1 = _client(layout, monkeypatch)
    c2 = web.app.test_client()
    _login(c2)
    assert c1.get("/").status_code == 200 and c2.get("/").status_code == 200

    assert c1.get("/logout").status_code == 405
    assert c1.post("/logout").status_code == 403            # no CSRF token
    assert c1.get("/").status_code == 200                   # a rejected logout revokes nothing
    assert c2.get("/").status_code == 200

    # Revocation is stamped in whole seconds and only tokens issued before that second are
    # refused, so move past the second in which both sessions were created.
    advance(2)
    r = _post(c1, "/logout")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")
    assert _cookie_attrs(r, auth.COOKIE_NAME).get("max-age") == "0"
    for c in (c1, c2):                                      # c2 still holds its cookie: now refused
        r = c.get("/")
        assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_session_cookie_secure_follows_request_scheme_or_env(layout, monkeypatch):
    auth.create_admin("admin", "password123")
    web.app.config["TESTING"] = True
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)

    plain = _cookie_attrs(_login(web.app.test_client()), auth.COOKIE_NAME)
    assert "secure" not in plain
    assert "httponly" in plain and plain.get("samesite") == "Strict" and plain.get("max-age") == str(auth.SESSION_TTL)

    c = web.app.test_client()
    assert "secure" in _cookie_attrs(c.get("/login", base_url="https://localhost"), web.CSRF_COOKIE)
    tls = _cookie_attrs(_login(c, base_url="https://localhost"), auth.COOKIE_NAME)
    assert "secure" in tls and "httponly" in tls

    monkeypatch.setenv("SESSION_COOKIE_SECURE", "1")
    assert "secure" in _cookie_attrs(_login(web.app.test_client()), auth.COOKIE_NAME)


@pytest.mark.parametrize("bad", ["bad user", "semi;colon", "slash/x", "\u00fcn\u00efcode", "x" * 65])
def test_setup_rejects_invalid_usernames(layout, bad):
    assert not auth.USERNAME_RE.match(bad)
    web.app.config["TESTING"] = True
    c = web.app.test_client()
    assert auth.needs_setup()
    r = _post(c, "/setup", {"username": bad, "password": "password123", "confirm": "password123"}, path="/setup")
    assert r.status_code == 400
    assert "Username may contain only" in r.get_data(as_text=True)
    assert auth.needs_setup()                               # nothing was created


@pytest.mark.parametrize("good", ["ops.admin@example-1", "a" * 64])
def test_setup_accepts_valid_username_and_signs_in(layout, good):
    web.app.config["TESTING"] = True
    c = web.app.test_client()
    r = _post(c, "/setup", {"username": good, "password": "password123", "confirm": "password123"}, path="/setup")
    assert r.status_code == 302 and not auth.needs_setup()
    assert _cookie_attrs(r, auth.COOKIE_NAME).get("max-age") == str(auth.SESSION_TTL)
    assert c.get("/setup").headers["Location"].endswith("/login")    # setup is closed once an admin exists
    assert c.get("/settings/new").status_code == 200                # and the new session is accepted


def test_login_lockout_clears_after_window(layout, monkeypatch):
    advance = _freeze_clock(monkeypatch)
    auth.create_admin("admin", "password123")
    web.app.config["TESTING"] = True
    monkeypatch.setattr(web, "LOGIN_MAX_FAILURES", 3)
    monkeypatch.setattr(web, "LOGIN_LOCKOUT_S", 60)
    c = web.app.test_client()
    good = {"username": "admin", "password": "password123"}

    for _ in range(3):
        assert _post(c, "/login", {"username": "admin", "password": "wrong"}).status_code == 401
    r = _post(c, "/login", good)
    assert r.status_code == 429 and "Too many failed sign-in attempts" in r.get_data(as_text=True)
    assert not any(h.startswith(auth.COOKIE_NAME + "=") for h in r.headers.getlist("Set-Cookie"))
    assert _post(c, "/login", {"username": "ADMIN", "password": "password123"}).status_code == 429   # key is case-folded

    advance(59)                                             # still inside the window
    assert _post(c, "/login", good).status_code == 429
    advance(2)                                              # window elapsed: the failures expire
    assert _post(c, "/login", good).status_code == 302
    assert web._FAILURES == {}                              # success clears the record
    assert c.get("/settings/new").status_code == 200
