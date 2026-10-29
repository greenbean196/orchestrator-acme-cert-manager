"""Web UI: fleet and target pages, renewal history, force-renew / force-deploy,
certificate and target management, driver probes, and a system/preflight panel.

Rows on the dashboard are *targets*; a certificate shared by several targets
shows the same Issued certificate on each row with per-target Served /
Activation state. Every state-changing route is a POST protected by a CSRF
token tied to the ``csrf`` cookie; a run started here holds the certificate's
lock, so the scheduler cannot touch it at the same time (and vice versa).
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import time
from urllib.parse import urlsplit

from flask import Flask, abort, jsonify, make_response, redirect, render_template, request, url_for

from .. import __version__, certs, config, drivers, locks, preflight, store, sysinfo
from ..models import Certificate, ServerConfig, Target
from . import auth

log = logging.getLogger("webui")
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024   # forms only; no uploads

# Endpoints reachable without a session: the auth pages, static assets, health.
_OPEN_ENDPOINTS = {"login", "setup", "logout", "healthz", "static"}
CSRF_COOKIE = "csrf"
CSRF_FIELD = "_csrf"
LOGIN_MAX_FAILURES = int(os.environ.get("LOGIN_MAX_FAILURES", "5"))
LOGIN_LOCKOUT_S = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "900"))

environment_of = certs.environment_of   # re-exported for callers and tests


# ============================= auth, CSRF, throttling ========================
def _current_user() -> str | None:
    return auth.read_token(request.cookies.get(auth.COOKIE_NAME, ""))


def _cookie_secure() -> bool:
    """Secure flag when the UI sits behind TLS (SESSION_COOKIE_SECURE=true) or the request is HTTPS."""
    return os.environ.get("SESSION_COOKIE_SECURE", "").lower() in ("1", "true", "yes") or request.is_secure


def _set_session(resp, username: str):
    resp.set_cookie(
        auth.COOKIE_NAME, auth.make_token(username),
        max_age=auth.SESSION_TTL, httponly=True, samesite="Strict", secure=_cookie_secure(),
    )
    return resp


def _safe_next(raw: str) -> str:
    """Only a same-site absolute path is an acceptable post-login destination."""
    nxt = (raw or "").replace("\\", "/").strip()
    parts = urlsplit(nxt)
    if not nxt.startswith("/") or nxt.startswith("//") or parts.scheme or parts.netloc:
        return url_for("index")
    return nxt


def _csrf_cookie_value() -> str:
    """The csrf cookie for this request (minted when absent; set on the response)."""
    val = request.cookies.get(CSRF_COOKIE, "")
    if not re.fullmatch(r"[0-9a-f]{32,64}", val or ""):
        val = getattr(request, "_new_csrf", None) or secrets.token_hex(32)
        request._new_csrf = val  # type: ignore[attr-defined]
    return val


def csrf_token() -> str:
    """Per-browser token: HMAC of the csrf cookie with the session signing key."""
    return hmac.new(auth._session_secret(), b"csrf|" + _csrf_cookie_value().encode(), hashlib.sha256).hexdigest()


def _csrf_valid() -> bool:
    supplied = request.form.get(CSRF_FIELD, "") or request.headers.get("X-CSRF-Token", "")
    if not supplied or not request.cookies.get(CSRF_COOKIE):
        return False
    return hmac.compare_digest(supplied, csrf_token())


@app.after_request
def _persist_csrf_cookie(resp):
    new = getattr(request, "_new_csrf", None)
    if new and request.cookies.get(CSRF_COOKIE) != new:      # absent OR not ours (another app's cookie on this host)
        resp.set_cookie(CSRF_COOKIE, new, httponly=True, samesite="Strict", max_age=30 * 86400, secure=_cookie_secure())
    return resp


@app.context_processor
def _inject_user():
    return {"current_user": _current_user(), "relative_time": relative_time, "csrf_token": csrf_token,
            "csrf_field": CSRF_FIELD}


@app.before_request
def _gate():
    """Require login on everything except the open endpoints; CSRF on every non-GET.

    If no admin exists yet, force the first-run Setup flow instead.
    """
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.endpoint != "static":
        if not _csrf_valid():
            log.warning("CSRF check failed for %s %s from %s", request.method, request.path, request.remote_addr)
            return render_template("error.html", status=403, title="Request rejected",
                                   message="The form token is missing or stale. Reload the page and try again.",
                                   now=_now()), 403
    if request.endpoint in _OPEN_ENDPOINTS:
        return None
    if auth.needs_setup():
        return redirect(url_for("setup"))
    if not _current_user():
        return redirect(url_for("login", next=request.path))
    return None


_FAILURES: dict[str, list[float]] = {}
_FAIL_LOCK = threading.Lock()


def _throttle_key(username: str) -> str:
    return f"{(username or '').lower()}|{request.remote_addr or '?'}"


def login_locked(username: str) -> int:
    """Seconds remaining in a lockout for this username+address, else 0."""
    now = time.time()
    with _FAIL_LOCK:
        fails = [t for t in _FAILURES.get(_throttle_key(username), []) if now - t < LOGIN_LOCKOUT_S]
        _FAILURES[_throttle_key(username)] = fails
        if len(fails) >= LOGIN_MAX_FAILURES:
            return int(LOGIN_LOCKOUT_S - (now - fails[-1])) + 1
    return 0


def _login_failed(username: str) -> None:
    with _FAIL_LOCK:
        _FAILURES.setdefault(_throttle_key(username), []).append(time.time())
        n = len(_FAILURES[_throttle_key(username)])
    log.warning("failed sign-in for %r from %s (%d/%d before lockout)", username, request.remote_addr, n, LOGIN_MAX_FAILURES)


def _login_succeeded(username: str) -> None:
    with _FAIL_LOCK:
        _FAILURES.pop(_throttle_key(username), None)


@app.route("/healthz")
def healthz():
    """200 while the web UI answers and the scheduler is not stale (issue #11)."""
    try:
        sc = sysinfo.scheduler()
    except Exception as exc:  # noqa: BLE001 - health must answer, never raise
        log.warning("healthz: scheduler state unavailable: %s", exc)
        return {"status": "ok", "scheduler": "unknown"}, 200
    body = {"status": "ok", "scheduler": {"last_started": sc["state"].get("started"),
                                          "last_finished": sc["state"].get("finished"),
                                          "interval_hours": sc["interval_hours"], "stale": sc["stale"]}}
    if sc["stale"]:
        body["status"] = "scheduler-stale"
        return body, 503
    return body, 200


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if not auth.needs_setup():
        return redirect(url_for("login"))
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        p2 = request.form.get("confirm", "")
        errors = []
        if not u:
            errors.append("A username is required.")
        elif not auth.valid_username(u):
            errors.append("Username may contain only letters, digits, '.', '_', '@' and '-' (1-64 characters).")
        if len(p) < auth.MIN_PASSWORD_LEN:
            errors.append(f"Password must be at least {auth.MIN_PASSWORD_LEN} characters.")
        if p != p2:
            errors.append("The two passwords don't match.")
        if errors:
            return render_template("setup.html", errors=errors, username=u, now=_now()), 400
        auth.create_admin(u, p)
        log.info("admin account %r created", u)
        return _set_session(make_response(redirect(url_for("index"))), u)
    return render_template("setup.html", errors=[], username="", now=_now())


@app.route("/login", methods=["GET", "POST"])
def login():
    if auth.needs_setup():
        return redirect(url_for("setup"))
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        wait = login_locked(u)
        if wait:
            log.warning("sign-in for %r from %s refused: locked out for %ds", u, request.remote_addr, wait)
            return render_template("login.html", error=f"Too many failed sign-in attempts. Try again in "
                                   f"{max(1, wait // 60)} minute(s).", next=request.form.get("next", ""), now=_now()), 429
        if auth.verify(u, p):
            _login_succeeded(u)
            return _set_session(make_response(redirect(_safe_next(request.form.get("next", "")))), u)
        _login_failed(u)
        return render_template("login.html", error="Incorrect username or password.",
                               next=request.form.get("next", ""), now=_now()), 401
    return render_template("login.html", error=None, next=request.args.get("next", ""), now=_now())


@app.route("/logout", methods=["POST"])
def logout():
    """Revokes every session token (single admin: logging out means everywhere), then clears the cookie."""
    if _current_user():
        auth.revoke_all()
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie(auth.COOKIE_NAME)
    return resp


@app.errorhandler(config.ConfigError)
def _config_error(exc):
    """A hand-edited servers.json that does not load must not turn every page into a bare 500."""
    log.error("configuration error: %s", exc)
    return render_template("error.html", status=500, title="Configuration cannot be loaded",
                           message=f"{exc}. Fix {config.SERVERS_FILE} on the host (config/servers.json; the previous "
                                   f"version is in servers.json.bak), then reload.", now=_now()), 500


CA_CHOICES = [
    ("letsencrypt", "Let's Encrypt (production)"),
    ("letsencrypt_test", "Let's Encrypt (staging)"),
    (config.LAB_CA_ID, "Lab CA (bundled step-ca)"),
]
KEY_CHOICES = ["rsa2048", "rsa3072", "rsa4096", "ec256", "ec384"]
_ALLOWED_CA = {v for v, _ in CA_CHOICES}
_ALLOWED_KEY = set(KEY_CHOICES)
_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
_ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")
_SECRET_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]*(API_KEY|_KEY|_TOKEN|_SECRET|_PASSWORD)(_[A-Z0-9]+)*$")   # ORCH_API_KEY_LAB is fine
_SECRET_ENV_DENY = {"CF_DNS_API_TOKEN", "NOTIFY_WEBHOOK_URL", "BACKUP_PASSPHRASE", "SESSION_COOKIE_SECURE"}
_HOST_FIELDS = ("orchestrator_host", "host", "appliance_host", "verify_host", "callback_host")
_CA_URL_RE = re.compile(r"^https?://[^\s/]+(/\S*)?$")

_PENDING: set[str] = set()          # certificate ids with a thread started but the lock not yet taken
_PENDING_LOCK = threading.Lock()
_NOTICES: dict[str, tuple[float, str]] = {}   # cert id -> (expires, message) shown on the pages
_NOTICE_TTL = 90

_SERVED_TTL = 60          # seconds to cache the certificate served by a target
_SERVED_CACHE: dict[str, tuple[float, dict]] = {}
_SERVED_LOCK = threading.Lock()


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")


def _is_renewing(cert_id: str) -> bool:
    with _PENDING_LOCK:
        if cert_id in _PENDING:
            return True
    return locks.is_locked(cert_id)


def _notice(cert_id: str, message: str) -> None:
    _NOTICES[cert_id] = (time.time() + _NOTICE_TTL, message)


def _take_notice(cert_id: str) -> str | None:
    item = _NOTICES.get(cert_id)
    if not item:
        return None
    if item[0] < time.time():
        _NOTICES.pop(cert_id, None)
        return None
    return item[1]


# ============================= certificate state =============================
def _parse_cert(pem: bytes) -> dict:
    return certs.parse_pem(pem)


def _cert_info(cert) -> dict:
    """The *issued* certificate: what is stored locally for this certificate."""
    return certs.leaf_info(config.leaf_path_for(cert))


def _served_info(drv, target, issued_serial: str | None = None) -> dict:
    # The issued serial is part of the key, so a scheduled run that changed the served
    # certificate is seen on the next page load instead of after the cache expires.
    key = f"{target.driver}:{target.id}:{drv.display_host(target)}:{issued_serial or ''}"
    now = time.monotonic()
    with _SERVED_LOCK:
        hit = _SERVED_CACHE.get(key)
        if hit and now - hit[0] < _SERVED_TTL:
            return hit[1]
    info = drv.served_info(target)
    with _SERVED_LOCK:
        _SERVED_CACHE[key] = (now, info)
    return info


def invalidate_served_cache() -> None:
    with _SERVED_LOCK:
        _SERVED_CACHE.clear()


def lifecycle(cert, issued: dict, served: dict, host: str | None = None) -> dict:
    """Activation state: does the target serve the certificate we issued?"""
    configured_env = config.ca_environment(cert.acme_ca)
    host = host or getattr(cert, "orchestrator_host", "") or "the target"
    if not issued.get("present"):
        return {"state": "none", "configured_env": configured_env,
                "message": "No certificate issued yet — run Force renew."}
    if served.get("error") or not served.get("present"):
        return {"state": "unknown", "configured_env": configured_env,
                "message": f"Could not read the certificate served by {host} "
                           f"({served.get('error') or 'no certificate'})."}
    if served.get("serial") == issued.get("serial"):
        msg = "The issued certificate is live on the target."
        ienv = issued.get("environment")
        if ienv and ienv != configured_env:
            msg += (f" It was issued by the {ienv.upper()} CA while the server is set to "
                    f"{configured_env} — run Force renew to issue from the configured CA.")
        return {"state": "live", "configured_env": configured_env, "message": msg}
    ienv = (issued.get("environment") or "unknown").capitalize()
    senv = served.get("environment") or "a different"
    return {"state": "pending", "configured_env": configured_env,
            "message": (f"{ienv} certificate issued (serial {issued.get('serial')}). "
                        f"{host} is still serving {senv} certificate "
                        f"(serial {served.get('serial')}). Deployment or activation is pending — "
                        f"use Force deploy (no CA contact).")}


def _parse_ts(ts: str | None):
    if not ts:
        return None
    try:
        d = datetime.datetime.fromisoformat(ts)
        if d.tzinfo is None:
            d = d.replace(tzinfo=datetime.timezone.utc)
        return d
    except ValueError:
        return None


def relative_time(ts: str | None) -> str:
    d = _parse_ts(ts)
    if d is None:
        return "—"
    secs = int((datetime.datetime.now(datetime.timezone.utc) - d).total_seconds())
    if secs < 0:
        return "just now"
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            return f"{secs // size}{unit} ago"
    return f"{secs}s ago"


def health(row: dict) -> dict:
    """One roll-up state per target, with the reasons behind it.

    States, worst first: working, critical, warning, ok, unknown, none.
    Status colors never carry meaning alone: the template pairs each state
    with a glyph and the label.
    """
    reasons: list[str] = []
    cert, lc, last = row["cert"], row["lifecycle"], row["last"]
    served = row.get("served") or {}
    if row["renewing"]:
        return {"state": "working", "label": "working", "reasons": ["a run is in progress"]}
    if row["ssh_problems"]:
        reasons.append("SSH configuration invalid" if row.get("driver", "orchestrator") in ("orchestrator", "ssh")
                       else "target configuration invalid")
    if cert.get("present") and cert.get("days_left") is not None and cert["days_left"] <= 0:
        reasons.append("certificate expired")
    if last and last.get("outcome") == "failed":
        reasons.append("last run failed")
    if reasons:
        return {"state": "critical", "label": "attention", "reasons": reasons}
    if lc["state"] == "pending":
        reasons.append("issued certificate not yet served")
    if cert.get("present") and cert.get("days_left") is not None:
        due, _ = certs.due_for_renewal(cert)
        if due:
            reasons.append(f"expires in {cert['days_left']} days")
    if cert.get("environment") and cert["environment"] != lc["configured_env"]:
        reasons.append(f"{cert['environment']} certificate while configured for {lc['configured_env']}")
    if cert.get("environment") == "staging" and lc["state"] == "live":
        reasons.append("serving a staging certificate")
    if row.get("verify_ssl") and (cert.get("environment") == "staging" or served.get("environment") == "staging"
                                  or served.get("self_signed")):
        reasons.append("API TLS verification is on while a staging or self-signed certificate is in play")
    if row.get("warnings"):
        reasons.append(row["warnings"][0])
    if reasons:
        return {"state": "warning", "label": "warning", "reasons": reasons}
    if not cert.get("present"):
        return {"state": "none", "label": "no certificate", "reasons": ["nothing issued yet"]}
    if lc["state"] == "unknown":
        return {"state": "unknown", "label": "unverified", "reasons": [lc["message"]]}
    return {"state": "ok", "label": "healthy", "reasons": ["issued certificate is live"]}


def _summarize(record: dict | None, target_id: str | None = None) -> dict | None:
    if not record:
        return None
    steps = record.get("steps", []) or []
    outcome = record.get("outcome")
    rolled_back = any((s.get("detail") or {}).get("rolled_back") for s in steps)
    failed_step = None
    if outcome == "failed":
        bad = next((s for s in steps if not s.get("ok", True)), None)
        message = (bad or {}).get("message", "")
        if bad:
            failed_step = {"step": bad.get("step"), "target": bad.get("target"), "detail": bad.get("detail") or {}}
    elif steps:
        message = steps[-1].get("message", "")
    else:
        message = ""
    return {
        "server_id": record.get("server_id"), "outcome": outcome,
        "timestamp": record.get("timestamp"), "ago": relative_time(record.get("timestamp")),
        "steps": steps, "message": message,
        "rolled_back": rolled_back, "not_after": record.get("not_after"),
        "serial": record.get("serial"), "failed_step": failed_step,
        "kind": record.get("kind") or "renew", "elapsed_s": record.get("elapsed_s"),
        "actor": record.get("actor") or "", "source": record.get("source") or "",
        "targets": record.get("targets") or [], "target_id": target_id,
    }


def _row_for(cert, target=None, with_served: bool = True) -> dict:
    """One dashboard row. Accepts (Certificate, Target) or a legacy ServerConfig."""
    if target is None:
        if isinstance(cert, ServerConfig):
            c = cert.to_certificate()
            cert, target = c, c.targets[0]
        else:
            target = cert.targets[0]
    drv = drivers.get(target.driver)
    issued = _cert_info(cert)
    served = _served_info(drv, target, issued.get("serial")) if with_served else {**certs.ABSENT, "error": "not checked"}
    host = drv.display_host(target)
    settings = target.settings
    holder = locks.holder(cert.id)
    row = {
        "id": target.id, "target_id": target.id, "cert_id": cert.id,
        "name": cert.name if target.id == cert.id else (target.name or f"{cert.name} · {target.id}"),
        "cert_name": cert.name, "target_name": target.name,
        "domain": cert.domain, "host": host, "driver": target.driver, "driver_label": drv.label,
        "steps": list(drv.steps), "probe_label": drv.probe_label, "probe_help": drv.probe_help,
        "served_label": drv.served_label, "activation_label": drv.activation_label,
        "ca": cert.acme_ca, "ca_env": config.ca_environment(cert.acme_ca),
        "verify_ssl": bool(settings.get("verify_ssl", False)), "ca_bundle": settings.get("ca_bundle", ""),
        "key_type": cert.key_type, "acme_email": cert.acme_email, "dns_provider": cert.dns_provider,
        "secrets": {"cf_inline": bool(cert.dns_api_token), "api_inline": bool(settings.get("api_key")),
                    "api_key_env": settings.get("api_key_env", "ORCH_API_KEY"), "dns_env_keys": sorted(cert.dns_env)},
        "summary": drv.summary(target),
        "siblings": [t.id for t in cert.targets if t.id != target.id],
        "cert": issued, "served": served, "lifecycle": lifecycle(cert, issued, served, host=host),
        "ssh_problems": drv.preflight(target), "warnings": drv.warnings(target),
        "last": _summarize(store.latest_for(cert.id), target_id=target.id),
        "renewing": holder is not None or _is_renewing(cert.id), "run": holder,
        "notice": _take_notice(cert.id),
    }
    row["health"] = health(row)
    return row


def _rows(with_served: bool = True) -> list[dict]:
    return [_row_for(c, t, with_served) for c, t in config.all_targets()]


_HEALTH_ORDER = {"working": 0, "critical": 1, "warning": 2, "unknown": 3, "none": 4, "ok": 5}


def fleet_summary(rows: list[dict]) -> dict:
    """Counts for the overview tiles."""
    def expiring(r):
        c = r["cert"]
        return c.get("present") and c.get("days_left") is not None and certs.due_for_renewal(c)[0]
    return {
        "servers": len(rows),
        "healthy": sum(1 for r in rows if r["health"]["state"] == "ok"),
        "attention": sum(1 for r in rows if r["health"]["state"] in ("critical", "warning")),
        "expiring": sum(1 for r in rows if expiring(r)),
        "working": sum(1 for r in rows if r["renewing"]),
        "min_days": min((r["cert"]["days_left"] for r in rows
                         if r["cert"].get("present") and r["cert"].get("days_left") is not None),
                        default=None),
    }


def _system() -> dict:
    """The light system summary every page carries (preflight, lab CA, schedule).

    The System page and /api/status use sysinfo.snapshot() for the full picture.
    """
    rep = preflight.run(strict=False)
    d = rep.as_dict()
    d["version"] = __version__
    d["problems"] = [f.as_dict() for f in rep.findings if f.level in ("fatal", "warn")]
    d["lab_ca"] = {"configured": config.lab_ca_available(), "host": config.LAB_CA_HOST,
                   "url": config.lab_ca_base_url(),
                   "fingerprint": config.lab_ca_root_fingerprint() if config.LAB_CA_ROOT.is_file() else ""}
    d["scheduler"] = sysinfo.scheduler()
    return d


# ============================= system page ===================================
@app.route("/system")
def system_page():
    """Everything an operator needs to know about this deployment, read-only.

    Items that are configured on the host (setup.sh, .env, docker compose) are
    marked as such, with the command that changes them.
    """
    rep = preflight.run(strict=False)
    snap = sysinfo.snapshot(rep, probe_ca=True)
    return render_template("system.html", sys=snap, now=_now())


def _send_pem(path, filename: str):
    if not path.is_file():
        abort(404)
    resp = make_response(path.read_bytes())
    resp.headers["Content-Type"] = "application/x-pem-file"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


@app.route("/ca/root.pem")
def ca_root_pem():
    """The lab CA root certificate (public). Confirm the fingerprint out of band before trusting it."""
    return _send_pem(config.LAB_CA_ROOT, "lab-root-ca.pem")


@app.route("/ca/intermediate.pem")
def ca_intermediate_pem():
    return _send_pem(config.LAB_CA_INTERMEDIATE, "lab-intermediate-ca.pem")


# ============================= dashboard =====================================
def _fleet_context() -> dict:
    rows = sorted(_rows(), key=lambda r: (_HEALTH_ORDER.get(r["health"]["state"], 9), r["name"].lower()))
    history = [_summarize(r) for r in store.all_records()[:20]]
    return {"rows": rows, "summary": fleet_summary(rows), "history": history,
            "system": _system(), "busy": any(r["renewing"] for r in rows), "now": _now(),
            "updated": datetime.datetime.now().strftime("%H:%M:%S")}


@app.route("/")
def index():
    return render_template("index.html", **_fleet_context())


@app.route("/partials/fleet")
def partial_fleet():
    """Live-refresh fragment for the overview (swapped in by app.js)."""
    return render_template("_fleet.html", **_fleet_context())


def _target_or_404(target_id: str) -> tuple[Certificate, Target]:
    try:
        return config.get_target(target_id)
    except config.ConfigError:
        abort(404)


def _server_context(target_id: str) -> dict:
    cert, target = _target_or_404(target_id)
    row = _row_for(cert, target)
    history = [_summarize(r, target_id=target.id) for r in store.all_records() if r.get("server_id") == cert.id][:30]
    return {"r": row, "history": history, "system": _system(), "busy": row["renewing"],
            "now": _now(), "updated": datetime.datetime.now().strftime("%H:%M:%S")}


@app.route("/server/<server_id>")
def server_detail(server_id: str):
    return render_template("server.html", test_result=None, **_server_context(server_id))


@app.route("/partials/server/<server_id>")
def partial_server(server_id: str):
    return render_template("_server.html", test_result=None, **_server_context(server_id))


@app.route("/server/<server_id>/test-ssh", methods=["POST"])
@app.route("/server/<server_id>/probe", methods=["POST"])
def server_test_ssh(server_id: str):
    """The driver's live, non-disruptive check (SSH auth + sudo for Orchestrator targets)."""
    cert, target = _target_or_404(server_id)
    drv = drivers.get(target.driver)
    res = drv.probe(target)
    log.info("probe %s (%s) via web UI by %s: %s", target.id, drv.name, _current_user(), "ok" if res.ok else res.message)
    return render_template("server.html", test_result=res.as_dict(), **_server_context(server_id))


@app.route("/api/servers")
def api_servers():
    return jsonify(_rows())


@app.route("/api/server/<server_id>")
def api_server(server_id: str):
    ctx = _server_context(server_id)
    return jsonify({"server": ctx["r"], "history": ctx["history"]})


@app.route("/api/history")
def api_history():
    return jsonify([_summarize(r) for r in store.all_records()])


@app.route("/api/status")
def api_status():
    """Full system snapshot (what the System page shows). Secrets are reported as set/unset only."""
    probe = request.args.get("probe", "0") in ("1", "true", "yes")
    return jsonify(sysinfo.snapshot(preflight.run(strict=False), probe_ca=probe))


def _run_in_background(cert_id: str, fn, label: str):
    """Start fn() on a thread; the runner takes the certificate lock itself."""
    if _is_renewing(cert_id):
        h = locks.holder(cert_id) or {}
        _notice(cert_id, f"{label} not started: a {h.get('kind', 'run')} is already in progress "
                         f"(started {relative_time(h.get('started'))} by {h.get('actor') or h.get('source') or 'unknown'}).")
        return False
    with _PENDING_LOCK:
        _PENDING.add(cert_id)

    def _run():
        try:
            fn()
        except locks.RunLocked as exc:
            log.warning("%s for %s refused: %s", label, cert_id, exc)
            _notice(cert_id, f"{label} not started: {exc}")
        except Exception as exc:  # noqa: BLE001
            log.error("%s failed for %s: %s", label, cert_id, exc)
            _notice(cert_id, f"{label} failed: {exc}")
        finally:
            invalidate_served_cache()
            with _PENDING_LOCK:
                _PENDING.discard(cert_id)

    threading.Thread(target=_run, daemon=True).start()
    return True


@app.route("/renew/<server_id>", methods=["POST"])
def renew(server_id: str):
    """Force renew: full pipeline for the certificate (every target), contacts the ACME CA."""
    from .. import renew as renew_mod
    cert, target = _target_or_404(server_id)
    user = _current_user() or "web"
    _run_in_background(cert.id, lambda: renew_mod.renew_certificate(cert, force=True, actor=user, source="web"),
                       "Force renew")
    return redirect(_back(server_id))


@app.route("/deploy/<server_id>", methods=["POST"])
def force_deploy(server_id: str):
    """Force deploy: re-push the on-disk cert to this target (deploy -> activate). No CA contact."""
    from .. import renew as renew_mod
    cert, target = _target_or_404(server_id)
    user = _current_user() or "web"
    _run_in_background(cert.id, lambda: renew_mod.redeploy_certificate(cert, actor=user, source="web", targets=[target]),
                       "Force deploy")
    return redirect(_back(server_id))


def _back(server_id: str) -> str:
    """Return to the server page when the action came from it, else the overview."""
    ref = request.form.get("return", "")
    if ref == "server":
        return url_for("server_detail", server_id=server_id)
    return url_for("index")


# ============================= settings ======================================
CERT_FIELDS = ("id", "name", "domain", "acme_ca", "acme_email", "key_type", "dns_provider", "dns_api_token", "dns_env")


def _flat_cert(cert: Certificate | None) -> dict:
    if cert is None:
        return {"id": "", "name": "", "domain": "", "acme_ca": "letsencrypt_test", "acme_email": "",
                "key_type": "rsa2048", "dns_provider": "cloudflare", "dns_api_token": "", "dns_env": ""}
    return {"id": cert.id, "name": cert.name, "domain": cert.domain, "acme_ca": cert.acme_ca,
            "acme_email": cert.acme_email, "key_type": cert.key_type, "dns_provider": cert.dns_provider,
            "dns_api_token": "", "dns_env": "\n".join(f"{k}=" for k in sorted(cert.dns_env))}


def _flat_from_server(s: ServerConfig) -> dict:
    """The form view of a legacy entry (secrets blank: a stored secret is NEVER echoed back)."""
    c = s.to_certificate()
    return _flat_from_target(c, c.targets[0])


def _flat_from_target(cert: Certificate, target: Target) -> dict:
    flat = _flat_cert(cert)
    drv = drivers.get(target.driver)
    flat.update(drv.flat(target) if hasattr(drv, "flat") else dict(target.settings))
    flat["driver"] = target.driver
    flat["target_id"] = target.id
    flat["target_name"] = target.name
    for f in drv.schema():
        if f.secret:
            flat[f.name] = ""
    return flat


def _flat_blank(driver: str = "orchestrator") -> dict:
    flat = _flat_cert(None)
    if driver not in drivers.names():
        driver = "orchestrator"          # a stale ?driver= bookmark is not a broken configuration
    drv = drivers.get(driver)
    for f in drv.schema():
        flat[f.name] = f.default
    flat["driver"] = driver
    flat["target_id"] = ""
    flat["target_name"] = ""
    return flat


def _flat_from_request(f) -> dict:
    driver = (f.get("driver", "orchestrator") or "orchestrator").strip()
    try:
        drv = drivers.get(driver)
    except config.ConfigError:
        drv = drivers.get("orchestrator")
        driver = "orchestrator"
    flat = {
        "id": f.get("id", "").strip(),
        "name": f.get("name", "").strip(),
        "domain": f.get("domain", "").strip(),
        "acme_ca": (f.get("acme_ca_url", "") or "").strip() or f.get("acme_ca", "letsencrypt").strip(),
        "acme_email": f.get("acme_email", "").strip(),
        "key_type": f.get("key_type", "rsa2048").strip(),
        "dns_provider": (f.get("dns_provider", "cloudflare") or "cloudflare").strip().lower(),
        "dns_api_token": f.get("dns_api_token", "").strip(),
        "dns_env": f.get("dns_env", ""),
        "driver": driver,
        "target_id": f.get("target_id", "").strip(),
        "target_name": f.get("target_name", "").strip(),
    }
    for fld in drv.schema():
        if fld.kind == "checkbox":
            flat[fld.name] = f.get(fld.name) in ("on", "true", "1")
        else:
            raw = f.get(fld.name)
            flat[fld.name] = (raw if raw is not None else fld.default)
            if isinstance(flat[fld.name], str):
                flat[fld.name] = flat[fld.name].strip()
    host = flat.get("orchestrator_host") or flat.get("host") or ""
    flat["domain"] = flat["domain"] or host
    if driver == "orchestrator":
        flat["ssh_known_hosts"] = flat.get("ssh_known_hosts") or config.DEFAULT_KNOWN_HOSTS
        flat["ssh_port"] = flat.get("ssh_port") or "22"
        flat["api_key_env"] = flat.get("api_key_env") or "ORCH_API_KEY"
        flat["ca_bundle_mode"] = flat.get("ca_bundle_mode") or "exclusive"
    return flat


def _parse_dns_env(text: str) -> tuple[dict[str, str], list[str]]:
    """KEY=VALUE lines -> dict; an empty value means 'keep what is stored'."""
    out: dict[str, str] = {}
    errors: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            errors.append(f"DNS variable line {line!r} is not KEY=VALUE.")
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        if not _ENV_KEY_RE.match(k):
            errors.append(f"DNS variable name {k!r} must be UPPER_CASE.")
            continue
        out[k] = v.strip()
    return out, errors


def _nest(flat: dict) -> dict:
    """Legacy helper: the v1 entry shape for an Orchestrator form."""
    return config._to_dict(_build(flat)[0].as_server())


def _build(flat: dict, existing_cert: Certificate | None = None, existing_target: Target | None = None):
    """(Certificate, Target) from a validated form; keeps stored secrets when fields are blank."""
    drv = drivers.get(flat["driver"])
    settings = drv.normalize({k: flat.get(k) for k in [f.name for f in drv.schema()]})
    if existing_target is not None:
        old = existing_target.settings
        for name in drv.secret_fields():
            if not flat.get(name):
                _set_nested(settings, name, _get_nested(old, name))
    dns_env, _ = _parse_dns_env(flat.get("dns_env", ""))
    if existing_cert is not None:
        for k, v in list(dns_env.items()):
            if v == "" and k in existing_cert.dns_env:
                dns_env[k] = existing_cert.dns_env[k]
    dns_env = {k: v for k, v in dns_env.items() if v}
    target_id = flat.get("target_id") or flat["id"]
    target = Target(id=target_id, driver=flat["driver"], name=flat.get("target_name", ""), settings=settings)
    cert = Certificate(
        id=flat["id"], name=flat["name"] or flat["id"], domain=flat["domain"],
        acme_ca=flat["acme_ca"], acme_email=flat["acme_email"], key_type=flat["key_type"],
        dns_provider=flat["dns_provider"],
        dns_api_token=flat["dns_api_token"] or (existing_cert.dns_api_token if existing_cert else ""),
        dns_env=dns_env, targets=[target],
    )
    return cert, target


def _get_nested(d: dict, name: str):
    if name in d:
        return d[name]
    return (d.get("ssh") or {}).get(name)


def _set_nested(d: dict, name: str, value) -> None:
    if name in d or "ssh" not in d:
        d[name] = value
    else:
        d["ssh"][name] = value


def _validate(flat: dict, is_new: bool, existing_cert: Certificate | None = None,
              existing_target: Target | None = None, new_target_only: bool = False) -> list[str]:
    errors = []
    sid = flat["id"]
    if not sid:
        errors.append("ID is required.")
    elif not _ID_RE.match(sid):
        errors.append("ID may contain only letters, numbers, hyphens, and underscores.")
    elif is_new and not new_target_only and config.server_exists(sid):
        errors.append(f"A server with ID '{sid}' already exists.")
    if flat.get("domain") and any(c.domain.lower() == flat["domain"].lower() and c.id != sid
                                             for c in config.load_certificates()):
        errors.append(f"Another certificate already covers {flat['domain']}; add this system as a target of that "
                      f"certificate instead (Settings → + Target).")
    tid = flat.get("target_id") or sid
    if not _ID_RE.match(tid or ""):
        errors.append("Target ID may contain only letters, numbers, hyphens, and underscores.")
    elif (is_new or new_target_only) and tid != sid and config.target_exists(tid):
        errors.append(f"A target with ID '{tid}' already exists.")
    elif new_target_only and tid == sid:
        errors.append("Give the additional target its own ID.")
    try:
        drv = drivers.get(flat.get("driver", "orchestrator"))
    except config.ConfigError as exc:
        return errors + [str(exc)]
    host = flat.get("orchestrator_host") or flat.get("host") or ""
    if not host:
        errors.append("Orchestrator host is required." if drv.name == "orchestrator" else "Host is required.")
    flat["domain"] = flat.get("domain") or host          # the certificate name defaults to the target host
    if not flat["domain"]:
        errors.append("Certificate domain is required.")
    if not flat["acme_email"]:
        errors.append("ACME email is required — Let's Encrypt needs it for registration.")
    for name in _HOST_FIELDS:
        val = flat.get(name)
        if val and not _HOST_RE.match(str(val)):
            errors.append(f"{name.replace('_', ' ')} must be a hostname or IP address (no scheme, port or path): {val!r}.")
    if flat["domain"] and not _HOST_RE.match(flat["domain"]):
        errors.append(f"Certificate domain must be a hostname: {flat['domain']!r}.")
    if flat["acme_email"] and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", flat["acme_email"]):
        errors.append("ACME email does not look like an email address.")
    for name, val in flat.items():
        if name.endswith("_env") and name != "dns_env" and val:
            if not _SECRET_ENV_RE.match(str(val)) or str(val) in _SECRET_ENV_DENY:
                errors.append(f"{name.replace('_', ' ')} must name a dedicated secret variable (ending in _API_KEY, _KEY, "
                              f"_TOKEN, _SECRET or _PASSWORD), not {val!r}.")
    if flat["acme_ca"] not in _ALLOWED_CA and not _CA_URL_RE.match(flat["acme_ca"]):
        errors.append("Invalid certificate authority selection (pick a preset or give an https:// ACME directory URL).")
    elif config.is_lab_ca(flat["acme_ca"]) and not config.lab_ca_available():
        errors.append("The bundled lab CA is not configured on this host: run ./setup.sh --with-ca "
                      "--lab-domain <zone>, then select it.")
    if flat["key_type"] not in _ALLOWED_KEY:
        errors.append("Invalid key type.")
    _, env_errors = _parse_dns_env(flat.get("dns_env", ""))
    errors.extend(env_errors)
    if drv.name == "orchestrator":
        try:
            port = int(flat["ssh_port"])
            if not (1 <= port <= 65535):
                errors.append("SSH port must be between 1 and 65535.")
        except (TypeError, ValueError):
            errors.append("SSH port must be a number.")
            return errors
        if flat.get("ca_bundle"):
            from pathlib import Path
            if not Path(flat["ca_bundle"]).is_file():
                errors.append(f"CA bundle not found at {flat['ca_bundle']} (path inside the container).")
        if flat.get("ca_bundle_mode") not in config.CA_BUNDLE_MODES:
            errors.append("CA bundle mode must be 'exclusive' or 'additive'.")
    if host and flat["domain"]:
        try:
            cert, target = _build(flat, existing_cert, existing_target)
        except config.ConfigError as exc:
            errors.append(str(exc))
        else:
            prefix = "SSH" if drv.name in ("orchestrator", "ssh") else "Target"
            errors.extend(f"{prefix}: {p}" for p in drv.preflight(target))
    return errors


def _render_form(flat, errors, is_new, existing=None, existing_cert=None, status=200, new_target_only=False):
    try:
        drv = drivers.get(flat.get("driver", "orchestrator"))
    except config.ConfigError:
        drv = drivers.get("orchestrator")
    stored = {}
    if existing is not None:
        for name in drv.secret_fields():
            stored[name] = bool(_get_nested(existing.settings, name))
    return render_template(
        "server_form.html", form=flat, errors=errors, is_new=is_new, new_target_only=new_target_only,
        ca_choices=CA_CHOICES, key_choices=KEY_CHOICES,
        drivers=[{"name": d.name, "label": d.label, "fields": [f.as_dict() for f in d.schema()],
                  "groups": _groups(d)} for d in drivers.all_drivers()],
        driver=drv.name, stored_secrets=stored,
        cf_token_set=bool(existing_cert and existing_cert.dns_api_token),
        api_key_set=bool(existing and _get_nested(existing.settings, "api_key")),
        cf_env_set=bool(os.environ.get(config.CF_TOKEN_ENV)),
        api_env_set=bool(os.environ.get((flat.get("api_key_env") or "ORCH_API_KEY"))),
        default_key=config.DEFAULT_SSH_KEY, default_known_hosts=config.DEFAULT_KNOWN_HOSTS,
        ca_bundle_modes=config.CA_BUNDLE_MODES,
        sibling_count=(len(existing_cert.targets) if existing_cert else 0),
        lab_ca={"available": config.lab_ca_available(), "configured": bool(config.LAB_CA_HOST),
                "url": config.lab_ca_base_url(), "root_present": config.LAB_CA_ROOT.is_file()},
        now=_now(),
    ), status


def _groups(drv) -> list[tuple[str, list[dict]]]:
    out: dict[str, list[dict]] = {}
    for f in drv.schema():
        out.setdefault(f.group or drv.label, []).append(f.as_dict())
    return list(out.items())


def _render_settings(test_result=None, test_server=None, status=200):
    certs_list = config.load_certificates()
    labels = {d.name: d.label for d in drivers.all_drivers()}
    hosts = {t.id: drivers.get(t.driver).display_host(t) for c in certs_list for t in c.targets}
    envs = {c.id: config.ca_environment(c.acme_ca) for c in certs_list}
    return render_template("settings.html", certificates=certs_list, driver_labels=labels, hosts=hosts, envs=envs,
                           ca_labels=dict(CA_CHOICES), system=_system(),
                           test_result=test_result, test_server=test_server, now=_now()), status


@app.route("/settings")
def settings():
    return _render_settings()[0]


@app.route("/settings/test-ssh/<server_id>", methods=["POST"])
def settings_test_ssh(server_id: str):
    """The driver's live check from the settings list. Restarts nothing."""
    try:
        cert, target = config.get_target(server_id)
    except config.ConfigError:
        return redirect(url_for("settings"))
    drv = drivers.get(target.driver)
    res = drv.probe(target)
    log.info("probe %s (%s) via settings by %s: %s", target.id, drv.name, _current_user(), "ok" if res.ok else res.message)
    return _render_settings(test_result=res.as_dict(), test_server={"name": target.name or target.id, "id": target.id})[0]


@app.route("/settings/new")
def settings_new():
    return _render_form(_flat_blank(request.args.get("driver", "orchestrator")), [], is_new=True)[0]


@app.route("/settings/target/new/<cert_id>")
def settings_target_new(cert_id: str):
    try:
        cert = config.get_certificate(cert_id)
    except config.ConfigError:
        return redirect(url_for("settings"))
    flat = _flat_blank(request.args.get("driver", "ssh"))
    flat.update(_flat_cert(cert))
    return _render_form(flat, [], is_new=True, existing_cert=cert, new_target_only=True)[0]


@app.route("/settings/edit/<server_id>")
def settings_edit(server_id: str):
    try:
        cert, target = config.get_target(server_id)
    except config.ConfigError:
        return redirect(url_for("settings"))
    return _render_form(_flat_from_target(cert, target), [], is_new=False, existing=target, existing_cert=cert)[0]


@app.route("/settings/save", methods=["POST"])
def settings_save():
    original_id = request.form.get("original_id", "").strip()      # target id when editing
    add_to_cert = request.form.get("certificate_id", "").strip()   # cert id when adding a target
    is_new = original_id == ""
    flat = _flat_from_request(request.form)

    existing_target = existing_cert = None
    if not is_new:
        try:
            existing_cert, existing_target = config.get_target(original_id)
        except config.ConfigError:
            abort(404)
        flat["id"] = existing_cert.id          # ids are create-only; never renamed on edit
        flat["target_id"] = existing_target.id
        flat["driver"] = existing_target.driver
        if "target_name" not in request.form:    # the primary target's form has no name field: keep the stored one
            flat["target_name"] = existing_target.name
    elif add_to_cert:
        try:
            existing_cert = config.get_certificate(add_to_cert)
        except config.ConfigError:
            abort(404)
        flat["id"] = existing_cert.id

    errors = _validate(flat, is_new, existing_cert, existing_target, new_target_only=bool(add_to_cert))
    if errors:
        return _render_form(flat, errors, is_new, existing=existing_target, existing_cert=existing_cert,
                            status=400, new_target_only=bool(add_to_cert))

    cert, target = _build(flat, existing_cert, existing_target)
    if existing_cert is not None:
        # Keep the certificate's other targets; replace (or add) this one.
        if existing_target is not None:
            cert.targets = [target if t.id == target.id else t for t in existing_cert.targets]   # in place: order is deploy order
        else:
            cert.targets = [t for t in existing_cert.targets if t.id != target.id] + [target]
        cert.attach()
    config.upsert_certificate(cert)
    invalidate_served_cache()
    log.info("certificate %s / target %s (%s) saved via web UI by %s to %s",
             cert.id, target.id, target.driver, _current_user(), config.SERVERS_FILE)
    return redirect(url_for("settings"))


@app.route("/settings/delete/<server_id>", methods=["POST"])
def settings_delete(server_id: str):
    """Delete a target; the certificate goes with its last target."""
    if config.delete_target(server_id):
        invalidate_served_cache()
        log.info("target %s deleted via web UI by %s", server_id, _current_user())
    return redirect(url_for("settings"))


def main() -> None:
    os.umask(0o077)            # every file this process creates starts owner-only
    logging.basicConfig(level="INFO", format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    log.info("web UI starting; configuration file: %s", config.SERVERS_FILE)
    app.run(host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
