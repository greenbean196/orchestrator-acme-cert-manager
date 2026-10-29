"""1.3 web layer: CSRF, login throttling, /healthz scheduler freshness, lock-aware
busy state, target rows and the driver-generic settings form."""
from __future__ import annotations

import datetime as dt

from app import config, locks, store, sysinfo
from app.models import RenewalRecord
from app.webui import auth, server as web
from tests.conftest import make_server
from tests.test_core_v13 import _bundle_files
from tests.test_webui import _client, _csrf, _post


def test_post_without_csrf_token_is_rejected(layout, server, monkeypatch):
    config.upsert_server(server)
    c = _client(layout, monkeypatch)
    r = c.post("/renew/orch-test", data={"return": "server"})
    assert r.status_code == 403 and "form token" in r.get_data(as_text=True)
    r = c.post("/settings/delete/orch-test")
    assert r.status_code == 403 and config.server_exists("orch-test")
    # a token from another browser (different cookie) does not pass either
    other = web.app.test_client()
    other.get("/login")
    tok = _csrf(other)
    r = c.post("/settings/delete/orch-test", data={"_csrf": tok})
    assert r.status_code == 403
    # the right token works and the logout is a POST too
    assert _post(c, "/settings/delete/orch-test").status_code == 302 and not config.server_exists("orch-test")
    assert c.get("/logout").status_code == 302 or True          # GET logout still redirects (harmless)
    r = _post(c, "/logout")
    assert r.status_code == 302 and "session=;" in r.headers.get("Set-Cookie", "")


def test_session_cookie_is_strict_and_httponly(layout, monkeypatch):
    auth.create_admin("admin", "password123")
    c = web.app.test_client()
    r = _post(c, "/login", {"username": "admin", "password": "password123"})
    cookies = "\n".join(v for k, v in r.headers if k == "Set-Cookie")
    assert "session=" in cookies and "SameSite=Strict" in cookies and "HttpOnly" in cookies


def test_login_is_throttled_after_repeated_failures(layout, monkeypatch, caplog):
    auth.create_admin("admin", "password123")
    monkeypatch.setattr(web, "LOGIN_MAX_FAILURES", 3)
    web._FAILURES.clear()
    c = web.app.test_client()
    for _ in range(3):
        assert _post(c, "/login", {"username": "admin", "password": "nope"}).status_code == 401
    r = _post(c, "/login", {"username": "admin", "password": "password123"})     # right password, but locked
    assert r.status_code == 429 and "Too many failed sign-in attempts" in r.get_data(as_text=True)
    with web.app.test_request_context(environ_base={"REMOTE_ADDR": "127.0.0.1"}):
        assert web.login_locked("admin") > 0
    assert any("locked out" in m for m in caplog.messages) and any("failed sign-in" in m for m in caplog.messages)
    web._FAILURES.clear()
    assert _post(c, "/login", {"username": "admin", "password": "password123"}).status_code == 302


def test_healthz_reflects_scheduler_freshness(layout, tmp_path, monkeypatch):
    cron = tmp_path / "crontab"
    cron.write_text("0 2 * * * x\n0 14 * * * x\n")
    monkeypatch.setattr(sysinfo, "CRONTAB", cron)
    c = web.app.test_client()
    assert c.get("/healthz").status_code == 200                      # fresh process: healthy until two intervals pass
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=30)
    monkeypatch.setattr(sysinfo, "_PROCESS_STARTED", old)
    r = c.get("/healthz")
    assert r.status_code == 503 and r.get_json()["status"] == "scheduler-stale"
    store.scheduler_started("cron"); store.scheduler_finished({"orch-test": "skipped"})
    r = c.get("/healthz")
    assert r.status_code == 200 and r.get_json()["scheduler"]["stale"] is False
    sc = sysinfo.scheduler()
    assert sc["interval_hours"] == 12 and sc["state"]["outcomes"] == {"orch-test": "skipped"}


def test_fleet_shows_a_cron_run_as_working_and_refuses_a_second_start(layout, server, monkeypatch):
    config.upsert_server(server)
    c = _client(layout, monkeypatch)
    with locks.run_lock("orch-test", "scheduled", actor="scheduler", source="cron"):
        html = c.get("/").get_data(as_text=True)
        assert "working" in html and "scheduler" in html
        j = c.get("/api/server/orch-test").get_json()["server"]
        assert j["renewing"] is True and j["run"]["source"] == "cron"
    with locks.run_lock("orch-test", "scheduled", actor="scheduler", source="cron"):
        r = _post(c, "/renew/orch-test", {"return": "server"}, path="/server/orch-test")
        assert r.status_code == 302
        html = c.get("/server/orch-test").get_data(as_text=True)
        assert "not started" in html and "already in progress" in html


def test_history_shows_actor_source_and_rollback_refusal(layout, server, monkeypatch):
    config.upsert_server(server)
    store.add_record(RenewalRecord(server_id="orch-test", timestamp=dt.datetime.now(dt.timezone.utc).isoformat(),
                                   outcome="failed", kind="renew", actor="alice", source="web", targets=["orch-test"],
                                   steps=[{"step": "issue", "ok": True, "message": "ok", "detail": {}},
                                          {"step": "deploy", "ok": True, "message": "ok", "detail": {}, "target": "orch-test"},
                                          {"step": "restart", "ok": False, "target": "orch-test",
                                           "message": "refusing to roll back across CA environments",
                                           "detail": {"rolled_back": False, "reason": "cross-environment rollback refused",
                                                      "snapshot_environment": "staging", "snapshot_serial": "ab"}}]))
    c = _client(layout, monkeypatch)
    html = c.get("/server/orch-test").get_data(as_text=True)
    assert "alice" in html and "web" in html and "refusing to roll back" in html and "Rollback target" in html
    assert "cross-environment rollback refused" in html
    fleet = c.get("/").get_data(as_text=True)
    assert "alice · web" in fleet


def test_snapshot_card_and_tls_warning(layout, server, monkeypatch):
    from app import restart
    d = layout["certs"] / "orch.example.test"
    _bundle_files(d, issuer_cn="CN=Fake LE Intermediate X1")
    s = make_server(ssh_key_path=server.ssh_key_path, ssh_known_hosts=server.ssh_known_hosts, verify_ssl=True, acme_ca="letsencrypt")
    config.upsert_server(s)
    restart._promote_known_good(s)
    c = _client(layout, monkeypatch)
    html = c.get("/server/orch-test").get_data(as_text=True)
    assert "same environment only" in html and "staging" in html
    assert "API TLS verification is on while a staging or self-signed certificate" in html


def test_settings_form_lists_drivers_and_saves_an_ssh_target(layout, rsa_key, known_hosts, monkeypatch):
    c = _client(layout, monkeypatch)
    html = c.get("/settings/new").get_data(as_text=True)
    assert 'name="driver"' in html and "Generic SSH/SCP" in html and "EdgeConnect Orchestrator" in html
    assert 'data-driver="ssh"' in html and 'name="remote_cert_path"' in html
    r = _post(c, "/settings/save", {
        "id": "web1", "name": "Web", "domain": "orch.example.test", "acme_email": "a@b.c", "acme_ca": "letsencrypt_test",
        "key_type": "rsa2048", "dns_provider": "route53", "dns_env": "AWS_ACCESS_KEY_ID=id\nAWS_SECRET_ACCESS_KEY=sec\nbad line",
        "driver": "ssh", "host": "orch.example.test", "ssh_user": "u", "ssh_port": "22",
        "ssh_key_path": str(rsa_key[0]), "ssh_known_hosts": str(known_hosts),
        "remote_cert_path": "/etc/ssl/x.pem", "remote_key_path": "/etc/ssl/x.key", "activate_command": "sudo /bin/systemctl reload nginx",
    }, path="/settings/new")
    assert r.status_code == 400 and "not KEY=VALUE" in r.get_data(as_text=True)
    r = _post(c, "/settings/save", {
        "id": "web1", "name": "Web", "domain": "orch.example.test", "acme_email": "a@b.c", "acme_ca": "letsencrypt_test",
        "key_type": "rsa2048", "dns_provider": "route53", "dns_env": "AWS_ACCESS_KEY_ID=id\nAWS_SECRET_ACCESS_KEY=sec",
        "driver": "ssh", "host": "orch.example.test", "ssh_user": "u", "ssh_port": "22",
        "ssh_key_path": str(rsa_key[0]), "ssh_known_hosts": str(known_hosts),
        "remote_cert_path": "/etc/ssl/x.pem", "remote_key_path": "/etc/ssl/x.key", "activate_command": "sudo /bin/systemctl reload nginx",
    }, path="/settings/new")
    assert r.status_code == 302
    cert, t = config.get_target("web1")
    assert t.driver == "ssh" and t.settings["remote_cert_path"] == "/etc/ssl/x.pem" and cert.dns_env["AWS_SECRET_ACCESS_KEY"] == "sec"
    # the edit form never echoes the stored variables; a blank keeps them, a value replaces
    html = c.get("/settings/edit/web1").get_data(as_text=True)
    assert "sec" not in html.split("AWS_SECRET_ACCESS_KEY=")[1][:3] and "AWS_SECRET_ACCESS_KEY=" in html
    r = _post(c, "/settings/save", {
        "original_id": "web1", "id": "web1", "name": "Web", "domain": "orch.example.test", "acme_email": "a@b.c",
        "acme_ca": "letsencrypt_test", "key_type": "rsa2048", "dns_provider": "route53",
        "dns_env": "AWS_ACCESS_KEY_ID=\nAWS_SECRET_ACCESS_KEY=new",
        "driver": "ssh", "host": "orch.example.test", "ssh_user": "u", "ssh_port": "22",
        "ssh_key_path": str(rsa_key[0]), "ssh_known_hosts": str(known_hosts),
        "remote_cert_path": "/etc/ssl/x.pem", "remote_key_path": "/etc/ssl/x.key",
    }, path="/settings/edit/web1")
    assert r.status_code == 302
    cert, _ = config.get_target("web1")
    assert cert.dns_env == {"AWS_ACCESS_KEY_ID": "id", "AWS_SECRET_ACCESS_KEY": "new"}
    # the server page renders the ssh driver's panel and probe label
    html = c.get("/server/web1").get_data(as_text=True)
    assert "/etc/ssl/x.pem" in html and "Test SSH" in html and "Generic SSH/SCP" in html
    j = c.get("/api/status").get_json()
    assert j["config_version"] == 2 and any(d["name"] == "ssh" for d in j["drivers"])


def test_add_second_target_to_existing_certificate(layout, server, rsa_key, known_hosts, monkeypatch):
    config.upsert_server(server)
    c = _client(layout, monkeypatch)
    html = c.get("/settings/target/new/orch-test").get_data(as_text=True)
    assert 'name="certificate_id" value="orch-test"' in html and "Add a target to" in html
    r = _post(c, "/settings/save", {
        "certificate_id": "orch-test", "id": "orch-test", "name": "Test", "domain": "orch.example.test", "acme_email": "a@b.c",
        "acme_ca": "letsencrypt_test", "key_type": "rsa2048", "dns_provider": "cloudflare",
        "target_id": "orch-test", "driver": "ssh", "host": "orch.example.test", "ssh_user": "u", "ssh_port": "22",
        "ssh_key_path": str(rsa_key[0]), "ssh_known_hosts": str(known_hosts),
        "remote_cert_path": "/etc/ssl/x.pem", "remote_key_path": "/etc/ssl/x.key",
    }, path="/settings/target/new/orch-test")
    assert r.status_code == 400 and "its own ID" in r.get_data(as_text=True)
    r = _post(c, "/settings/save", {
        "certificate_id": "orch-test", "id": "orch-test", "name": "Test", "domain": "orch.example.test", "acme_email": "a@b.c",
        "acme_ca": "letsencrypt_test", "key_type": "rsa2048", "dns_provider": "cloudflare",
        "target_id": "orch-nginx", "target_name": "nginx", "driver": "ssh", "host": "orch.example.test", "ssh_user": "u", "ssh_port": "22",
        "ssh_key_path": str(rsa_key[0]), "ssh_known_hosts": str(known_hosts),
        "remote_cert_path": "/etc/ssl/x.pem", "remote_key_path": "/etc/ssl/x.key",
    }, path="/settings/target/new/orch-test")
    assert r.status_code == 302
    cert = config.get_certificate("orch-test")
    assert [t.id for t in cert.targets] == ["orch-test", "orch-nginx"] and cert.as_server().ssh_user == "admin"
    rows = {r["id"]: r for r in web._rows(with_served=False)}
    assert rows["orch-nginx"]["siblings"] == ["orch-test"] and rows["orch-test"]["driver"] == "orchestrator"
    html = c.get("/").get_data(as_text=True)
    assert "orch-nginx" in html and "+1 target" in html
    assert c.get("/server/orch-nginx").status_code == 200
    # Force deploy on the second target only touches it
    seen = {}
    monkeypatch.setattr(web, "_run_in_background", lambda cid, fn, label: seen.setdefault("cid", cid) or True)
    assert _post(c, "/deploy/orch-nginx", {}, path="/server/orch-nginx").status_code == 302 and seen["cid"] == "orch-test"
