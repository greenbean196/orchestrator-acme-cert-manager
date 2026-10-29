"""System page, /api/status snapshot, CLI-dependency indicators and sysinfo helpers."""
from __future__ import annotations

import datetime as dt

from app import config, store, sysinfo
from app.models import RenewalRecord
from tests.conftest import make_server
from tests.test_config_persistence import _lab_pki
from tests.test_webui import _client, _post


def test_system_page_renders_and_marks_host_configuration(layout, server, monkeypatch):
    config.upsert_server(server)
    c = _client(layout, monkeypatch)
    html = c.get("/system").get_data(as_text=True)
    assert "Configured on the Docker host" in html
    assert "./upgrade-check.sh" in html and "./setup.sh --with-ca" in html
    assert 'class="info"' in html                      # the indicator macro is in use
    assert "Lab CA not configured" in html or "not configured" in html
    assert "ssh-rsa" in html and "SHA256:" in html      # key material summarised
    assert "pinned" in html


def test_secrets_are_reported_as_present_but_never_echoed(layout, monkeypatch):
    monkeypatch.setenv("CF_DNS_API_TOKEN", "cf-SECRET-VALUE-9f8e7d")
    monkeypatch.setenv("ORCH_API_KEY", "orch-SECRET-VALUE-1a2b3c")
    c = _client(layout, monkeypatch)
    html = c.get("/system").get_data(as_text=True)
    assert "SECRET-VALUE" not in html
    j = c.get("/api/status").get_json()
    assert "SECRET-VALUE" not in str(j)
    env = {e["name"]: e for e in j["environment"]}
    assert env["CF_DNS_API_TOKEN"]["state"] == "set" and env["CF_DNS_API_TOKEN"]["value"] == ""
    assert env["ORCH_API_KEY"]["state"] == "set"
    assert env["RENEW_WINDOW_DAYS"]["state"] == "default" and env["RENEW_WINDOW_DAYS"]["value"] == "1/3 of lifetime"
    for key in ("version", "scheduler", "ssh", "lab_ca", "host_operations", "findings", "paths"):
        assert key in j
    assert all(e["via"] for e in j["environment"])     # every variable says where it is set


def test_root_download_404_without_lab_ca_then_serves_pem(layout, monkeypatch):
    c = _client(layout, monkeypatch)
    assert c.get("/ca/root.pem").status_code == 404
    assert c.get("/ca/intermediate.pem").status_code == 404
    root, inter = _lab_pki(layout, monkeypatch)
    monkeypatch.setattr(sysinfo, "_probe_ca", lambda base: {"ok": True, "status": 200, "error": None})
    r = c.get("/ca/root.pem")
    assert r.status_code == 200 and b"BEGIN CERTIFICATE" in r.data
    assert "attachment" in r.headers["Content-Disposition"]
    html = c.get("/system").get_data(as_text=True)
    assert config.lab_ca_root_fingerprint() in html
    assert "Download root" in html and "healthy" in html
    assert "step ca revoke" in html                     # host-only PKI operations are listed, not hidden


def test_scheduler_parses_crontab_and_last_scheduled_run(layout, tmp_path, monkeypatch):
    cron = tmp_path / "crontab"
    cron.write_text("# comment\n0 2  * * * cd /app && python -m app.cli renew-all\n0 14 * * * cd /app && python -m app.cli renew-all\n")
    monkeypatch.setattr(sysinfo, "CRONTAB", cron)
    store.add_record(RenewalRecord(server_id="orch-test", timestamp=dt.datetime.now(dt.timezone.utc).isoformat(),
                                   outcome="success", kind="scheduled"))
    store.add_record(RenewalRecord(server_id="orch-test", timestamp=dt.datetime.now(dt.timezone.utc).isoformat(),
                                   outcome="failed", kind="renew"))
    sc = sysinfo.scheduler()
    assert [e["expr"] for e in sc["entries"]] == ["0 2 * * *", "0 14 * * *"]
    assert sc["next_run"] and dt.datetime.fromisoformat(sc["next_run"]) > dt.datetime.now().astimezone() - dt.timedelta(minutes=1)
    assert sc["last_scheduled"]["outcome"] == "success"   # the forced run is not a scheduled one


def test_ssh_material_reports_key_and_pin_state(layout, server, monkeypatch):
    config.upsert_server(server)
    config.upsert_server(make_server(id="unpinned", orchestrator_host="other.example.test",
                                     ssh_key_path=server.ssh_key_path, ssh_known_hosts=server.ssh_known_hosts))
    m = sysinfo.ssh_material()
    k = next(x for x in m["key_files"] if x["path"] == server.ssh_key_path)
    assert k["exists"] and k["type"] == "ssh-rsa" and k["bits"] == 2048 and k["fingerprint"].startswith("SHA256:")
    by_id = {s["id"]: s for s in m["servers"]}
    assert by_id["orch-test"]["pinned"] is True and by_id["unpinned"]["pinned"] is False
    assert any("known_hosts" in p for p in by_id["unpinned"]["problems"])
    assert "setup.sh" in m["via_key"] and "setup.sh" in m["via_known_hosts"]


def test_form_shows_lab_ca_state_and_persists_bundle_mode(layout, rsa_key, known_hosts, monkeypatch):
    monkeypatch.setattr(config, "LAB_CA_HOST", "")
    c = _client(layout, monkeypatch)
    html = c.get("/settings/new").get_data(as_text=True)
    assert "not initialised on this host" in html
    assert 'name="ca_bundle_mode"' in html
    assert "./setup.sh --with-ca" in html               # the CA field points at the host step
    r = _post(c, "/settings/save", {
        "id": "m1", "orchestrator_host": "orch.example.test", "acme_email": "a@b.c",
        "acme_ca": "letsencrypt_test", "key_type": "rsa2048", "ssh_user": "admin",
        "ssh_key_path": str(rsa_key[0]), "ssh_known_hosts": str(known_hosts), "ssh_port": "22",
        "restart_command": "sudo /bin/systemctl restart --no-block gms.service",
        "nginx_reload_command": "sudo /bin/systemctl reload nginx", "ca_bundle_mode": "additive",
    })
    assert r.status_code == 302
    assert config.get_server("m1").ca_bundle_mode == "additive"
    _lab_pki(layout, monkeypatch)
    html = c.get("/settings/edit/m1").get_data(as_text=True)
    assert "Lab CA ready at" in html and 'selected>additive' in html.replace('" selected', ' selected')


def test_server_page_points_cli_dependencies_at_setup(layout, server, monkeypatch):
    config.upsert_server(server)
    c = _client(layout, monkeypatch)
    html = c.get("/server/orch-test").get_data(as_text=True)
    assert "--install-sudoers" in html and "--ssh-port 22" in html
    assert html.count('class="info"') >= 5
    fleet = c.get("/").get_data(as_text=True)
    assert "/system" in fleet and "version" in fleet
