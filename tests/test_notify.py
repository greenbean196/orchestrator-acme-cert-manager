"""app.notify: webhook alerts for renewal outcomes.

Everything here is offline. ``requests.post`` is replaced on the module
notify imported (a recorder or a raiser), and NOTIFY_WEBHOOK_URL / NOTIFY_ON
are set per test through monkeypatch, which also exercises the per-call
settings read. The webhook URL carries a secret in its path, userinfo and
query string so the redaction checks have something concrete to look for.
"""
from __future__ import annotations

import logging

import pytest
import requests

from app import notify
from app.models import RenewalRecord

HOOK = "https://svc:PWSECRET@hooks.example.test:8443/services/T000/B000/PATHSECRET?token=QSSECRET"
REDACTED = "https://hooks.example.test"
SECRETS = ("PWSECRET", "PATHSECRET", "QSSECRET", "/services/", ":8443")


def rec(outcome: str = "failed", **overrides) -> RenewalRecord:
    base = dict(
        server_id="cert-a", timestamp="2026-10-22T10:00:00+00:00", outcome=outcome,
        actor="alice", source="web", targets=["orch-1", "cppm-2"],
        steps=[{"step": "issue", "ok": True, "message": "issued"},
               {"step": "deploy", "ok": False, "target": "cppm-2", "message": "HTTP 500 from CPPM"}],
        not_after="2027-01-20T10:00:00+00:00", serial="0AB12C",
    )
    base.update(overrides)
    return RenewalRecord(**base)


class _Resp:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("NOTIFY_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("NOTIFY_ON", raising=False)


@pytest.fixture
def posts(monkeypatch):
    """Record every requests.post call as (url, kwargs); answers HTTP 200."""
    calls: list[tuple[str, dict]] = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return _Resp(200)

    monkeypatch.setattr(notify.requests, "post", fake_post)
    return calls


@pytest.fixture
def posts_status(monkeypatch):
    """Like ``posts`` but the caller picks the status code: posts_status(404) -> calls list."""
    def install(status_code: int):
        calls: list[tuple[str, dict]] = []

        def fake_post(url, **kwargs):
            calls.append((url, kwargs))
            return _Resp(status_code)

        monkeypatch.setattr(notify.requests, "post", fake_post)
        return calls
    return install


def text_of(calls) -> str:
    assert len(calls) == 1, calls
    return calls[0][1]["json"]["text"]


# ---- enable / disable -------------------------------------------------------

def test_send_is_a_noop_without_webhook_url(posts, caplog):
    with caplog.at_level(logging.DEBUG, logger="notify"):
        assert notify.send(rec("failed")) is None
    assert posts == []
    assert "no webhook configured" in caplog.text


def test_blank_webhook_url_counts_as_unset(posts, monkeypatch):
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "   ")
    notify.send(rec("failed"))
    assert posts == []


def test_settings_are_read_on_every_call(posts, monkeypatch):
    notify.send(rec("failed"))
    assert posts == []

    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", HOOK)
    notify.send(rec("failed"))
    assert len(posts) == 1

    notify.send(rec("success"))                     # NOTIFY_ON still at its default
    assert len(posts) == 1

    monkeypatch.setenv("NOTIFY_ON", "all")
    notify.send(rec("success"))
    assert len(posts) == 2

    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "")    # switched off again without a restart
    notify.send(rec("failed"))
    assert len(posts) == 2


@pytest.mark.parametrize("outcome, notify_on, expected", [
    ("failed", None, True),
    ("failed", "all", True),
    ("failed", "FAILED", True),
    ("success", None, False),
    ("success", "failed", False),
    ("success", "all", True),
    ("success", " ALL ", True),      # trimmed and case-folded
    ("skipped", None, False),
    ("skipped", "all", False),       # nothing happened: never alerted
])
def test_outcome_gating(posts, monkeypatch, outcome, notify_on, expected):
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", HOOK)
    if notify_on is not None:
        monkeypatch.setenv("NOTIFY_ON", notify_on)
    notify.send(rec(outcome))
    assert (len(posts) == 1) is expected


# ---- the request ------------------------------------------------------------

def test_post_shape(posts, monkeypatch):
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", HOOK)
    notify.send(rec("failed"))
    url, kwargs = posts[0]
    assert url == HOOK                                   # the webhook itself needs the full URL
    assert kwargs["allow_redirects"] is False
    assert kwargs["timeout"] == notify._TIMEOUT
    assert 0 < kwargs["timeout"] <= 30
    assert set(kwargs) == {"json", "timeout", "allow_redirects"}
    assert isinstance(kwargs["json"]["text"], str) and kwargs["json"]["text"]


def test_webhook_url_is_trimmed(posts, monkeypatch):
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", f"  {HOOK}\n")
    notify.send(rec("failed"))
    assert posts[0][0] == HOOK


# ---- the message ------------------------------------------------------------

def test_failure_message_names_outcome_id_actor_source_and_failing_target(posts, monkeypatch):
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", HOOK)
    notify.send(rec("failed"))
    text = text_of(posts)
    lines = text.splitlines()
    assert lines[0] == "Certificate renewal FAILED: cert-a"
    assert "time: 2026-10-22T10:00:00+00:00" in lines
    assert "started by: alice via web" in lines
    assert "failed at: deploy on target cppm-2 — HTTP 500 from CPPM" in lines
    assert "new expiry" not in text and "serial" not in text


def test_success_message_names_outcome_id_actor_source_expiry_and_serial(posts, monkeypatch):
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", HOOK)
    monkeypatch.setenv("NOTIFY_ON", "all")
    notify.send(rec("success", actor="scheduler", source="cron"))
    text = text_of(posts)
    lines = text.splitlines()
    assert lines[0] == "Certificate renewed: cert-a"
    assert "started by: scheduler via cron" in lines
    assert "new expiry: 2027-01-20T10:00:00+00:00" in lines
    assert "serial: 0AB12C" in lines
    assert "failed at" not in text


def test_started_by_line_is_omitted_without_actor_or_source():
    text = notify._format(rec("failed", actor="", source=""))
    assert "started by" not in text
    assert notify._format(rec("failed", actor="bob", source="")).splitlines()[2] == "started by: bob via ?"
    assert notify._format(rec("failed", actor="", source="cli")).splitlines()[2] == "started by: ? via cli"


def test_failure_line_uses_first_failing_step_and_tolerates_missing_target():
    steps = [{"step": "issue", "ok": True},
             {"step": "deploy", "ok": False, "target": "orch-1", "message": "first"},
             {"step": "activate", "ok": False, "target": "cppm-2", "message": "second"}]
    text = notify._format(rec("failed", steps=steps))
    assert "failed at: deploy on target orch-1 — first" in text
    assert "second" not in text

    text = notify._format(rec("failed", steps=[{"step": "issue", "ok": False, "message": "DNS timeout"}]))
    assert "failed at: issue — DNS timeout" in text
    assert "on target" not in text

    text = notify._format(rec("failed", steps=[]))           # no step recorded: still a well-formed alert
    assert text.startswith("Certificate renewal FAILED: cert-a")
    assert "failed at" not in text


def test_success_message_omits_absent_expiry_and_serial():
    text = notify._format(rec("success", not_after=None, serial=None))
    assert "new expiry" not in text and "serial" not in text


def test_unknown_outcome_gets_a_generic_heading():
    assert notify._format(rec("locked", steps=[])).splitlines()[0] == "Renewal locked: cert-a"


def test_message_names_the_targets_of_the_run():
    text = notify._format(rec("success", targets=["orch-1", "cppm-2"]))
    assert "orch-1" in text and "cppm-2" in text


# ---- redaction and failure handling ------------------------------------------

def test_redacted_keeps_scheme_and_host_only():
    out = notify._redacted(HOOK)
    assert out == REDACTED
    for s in SECRETS:
        assert s not in out
    assert notify._redacted("https://discord.example/api/webhooks/123/abcTOKEN") == "https://discord.example"


def test_redacted_survives_an_unparseable_url():
    assert notify._redacted("http://[::1") == "<webhook>"      # urlsplit raises ValueError on a bad IPv6 literal


@pytest.mark.parametrize("status", [302, 404, 500])
def test_non_2xx_is_logged_with_redacted_url_and_never_raises(posts_status, monkeypatch, caplog, status):
    calls = posts_status(status)
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", HOOK)
    with caplog.at_level(logging.INFO, logger="notify"):
        assert notify.send(rec("failed")) is None
    assert len(calls) == 1
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    msg = warnings[0].getMessage()
    assert f"HTTP {status}" in msg and REDACTED in msg and "cert-a" in msg
    for s in SECRETS:
        assert s not in caplog.text


def test_2xx_is_logged_at_info(posts, monkeypatch, caplog):
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", HOOK)
    with caplog.at_level(logging.INFO, logger="notify"):
        notify.send(rec("failed"))
    assert "notify(cert-a): sent failed alert" in caplog.text
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    for s in SECRETS:
        assert s not in caplog.text


@pytest.mark.parametrize("exc_type", [requests.ConnectionError, requests.Timeout, requests.exceptions.SSLError])
def test_request_exception_is_logged_by_class_only_and_never_raises(monkeypatch, caplog, exc_type):
    # Real requests errors embed the full URL (and the pool/host) in their message; none of it may reach the log.
    def raising_post(url, **kwargs):
        raise exc_type(f"HTTPSConnectionPool: Max retries exceeded with url: {url} (Caused by NewConnectionError)")

    monkeypatch.setattr(notify.requests, "post", raising_post)
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", HOOK)
    with caplog.at_level(logging.DEBUG, logger="notify"):
        assert notify.send(rec("failed")) is None

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    msg = warnings[0].getMessage()
    assert msg == f"notify(cert-a): webhook post to {REDACTED} failed: {exc_type.__name__}"
    assert "Max retries" not in caplog.text and "HTTPSConnectionPool" not in caplog.text
    for s in SECRETS:
        assert s not in caplog.text
    assert warnings[0].exc_info is None        # no traceback (which would carry the URL) either
