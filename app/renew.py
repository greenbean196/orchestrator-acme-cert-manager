"""Orchestrate issue -> (deploy -> activate per target) and record the outcome.

One certificate is issued once and then deployed to each of its targets by
the target's driver. A run holds the certificate's lock (app/locks.py) so the
scheduler and the web UI never work on the same certificate at once; the
record carries who started it (actor) and from where (source).

``renew_server`` / ``redeploy_server`` keep the original one-Orchestrator
signatures: they wrap the certificate that server entry represents.
"""
from __future__ import annotations

import datetime
import logging
import time
from pathlib import Path

from cryptography import x509

from . import certs, config, deploy, drivers, issue, locks, notify, restart, store  # noqa: F401 (deploy/restart patched by tests)
from .drivers.base import CertBundle
from .models import Certificate, RenewalRecord, ServerConfig, StepResult, Target

log = logging.getLogger("renew")


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _timed(fn, arg, step: str = "step") -> dict:
    """Run a pipeline step and return its dict with elapsed_s added.

    An exception out of a step becomes a failed step (traceback tail in the
    detail) so the record and the alert are still produced.
    """
    import traceback
    t0 = time.monotonic()
    try:
        res = fn(arg)
    except Exception as exc:  # noqa: BLE001 - a step must never take the run down silently
        log.exception("%s step raised", step)
        res = StepResult(step, ok=False, message=f"{step} failed unexpectedly: {exc.__class__.__name__}: {exc}",
                         detail={"phase": "exception", "kind": "internal",
                                 "traceback": traceback.format_exc()[-2000:]})
    d = res.as_dict()
    d["elapsed_s"] = round(time.monotonic() - t0, 1)
    return d


def _leaf_meta(leaf: Path) -> tuple[str | None, str | None]:
    """(expiry_iso, serial_hex) for a leaf cert on disk, or (None, None)."""
    if not leaf.exists():
        return None, None
    try:
        cert = x509.load_pem_x509_certificate(leaf.read_bytes())
        na = getattr(cert, "not_valid_after_utc", None)
        return na.isoformat(), format(cert.serial_number, "x")
    except Exception as exc:  # noqa: BLE001
        log.warning("could not read leaf cert %s: %s", leaf, exc)
        return None, None


def _served_serial(info: dict) -> int | None:
    """The serial a driver's served_info() reports, as an int (drivers report hex strings)."""
    raw = info.get("serial") if info.get("present") else None
    if raw in (None, ""):
        return None
    try:
        return int(str(raw), 16)
    except ValueError:
        return None


def _deploy_targets(cert: Certificate, targets: list[Target], steps: list[dict]) -> str:
    """deploy -> activate for each target in turn.

    A failure on one target is recorded and the next target is still attempted:
    once the certificate is issued the targets are independent, and one broken
    or monitor-only target must not let the others expire. The outcome is
    "failed" when any target failed.
    """
    bundle = CertBundle.for_certificate(cert)
    outcome = "success"
    for t in targets:
        drv = drivers.get(t.driver)
        reason = drv.deploy_disabled(t)
        if reason:
            steps.append({"step": "deploy", "ok": True, "skipped": True, "target": t.id,
                          "message": f"skipped {t.id}: {reason}", "detail": {"phase": "prepare", "kind": "config"}})
            log.info("renew(%s): skipped %s (%s)", cert.id, t.id, reason)
            continue
        s_deploy = _timed(lambda _t, _d=drv: _d.deploy(_t, bundle), t, "deploy")
        s_deploy["target"] = t.id
        steps.append(s_deploy)
        if not s_deploy["ok"]:
            outcome = "failed"
            continue
        s_act = _timed(lambda _t, _d=drv: _d.activate_step(_t, bundle), t, drv.steps[-1])
        s_act["target"] = t.id
        steps.append(s_act)
        if not s_act["ok"]:
            outcome = "failed"
    return outcome


def pending_targets(cert: Certificate, targets: list[Target]) -> list[Target]:
    """Targets whose last verified activation is not the certificate on disk.

    This is how a scheduled run finishes a renewal whose activation failed on
    one target, or picks up a target added after the last issuance. Before a
    target is touched its served certificate is read: one that already
    presents the issued serial (deployed by hand, or by a run that died before
    taking its snapshot) is left alone, and a target that was never activated
    from here and cannot be read at all is not deployed to from a scheduled
    run - that stays an explicit operator action.
    """
    bundle = CertBundle.for_certificate(cert)
    if not bundle.present or not bundle.serial:
        return []
    out = []
    for t in targets:
        drv = drivers.get(t.driver)
        if drv.deploy_disabled(t):
            continue
        try:
            snap = drv.snapshot_bundle(t)
        except (config.ConfigError, OSError):
            snap = None
        if snap is not None and snap.serial == bundle.serial:
            continue
        try:
            served = drv.served_info(t)
        except Exception as exc:    # a driver bug must not take the whole scheduled run down
            log.warning("renew(%s): could not read the served certificate on %s: %s: %s",
                        cert.id, t.id, exc.__class__.__name__, exc)
            served = dict(certs.ABSENT, error=str(exc))
        if _served_serial(served) == bundle.serial:
            log.info("renew(%s): %s already serves %s; no deploy needed", cert.id, t.id, bundle.serial_hex)
            continue
        if snap is None and not served.get("present"):
            log.warning("renew(%s): %s has never been activated from here and its served certificate is "
                        "unreadable (%s); not deploying from a scheduled run - use Force deploy", cert.id, t.id,
                        served.get("error") or "absent")
            continue
        out.append(t)
    return out


def _finish(cert: Certificate, targets: list[Target], steps: list[dict], outcome: str, kind: str,
            not_after, serial, t_start: float, actor: str, source: str) -> RenewalRecord:
    record = RenewalRecord(
        server_id=cert.id, timestamp=_now(), outcome=outcome, steps=steps,
        not_after=not_after, serial=serial, kind=kind,
        elapsed_s=round(time.monotonic() - t_start, 1),
        actor=actor, source=source, targets=[t.id for t in targets],
    )
    try:
        store.add_record(record)
    except OSError as exc:
        log.error("renew(%s): could not write the history record: %s (the run outcome is %s)", cert.id, exc, outcome)
    notify.send(record)
    return record


def renew_certificate(cert: Certificate, force: bool = False, actor: str = "", source: str = "",
                      targets: list[Target] | None = None) -> RenewalRecord:
    """Run the full pipeline for one certificate, short-circuiting on the first failure.

    Skips deploy+activate when issuance reports the cert was not actually renewed
    (and we are not forcing): targets are only touched when the cert changed.
    Raises locks.RunLocked when another run holds this certificate.
    """
    kind = "renew" if force else ("scheduled" if source == "cron" else "check")
    targets = list(targets if targets is not None else cert.targets)
    with locks.run_lock(cert.id, kind, actor, source):
        steps: list[dict] = []
        outcome = "success"
        t_start = time.monotonic()

        s_issue = _timed(lambda c: issue.issue_or_renew(c, force=force), cert, "issue")
        steps.append(s_issue)
        not_after = s_issue["detail"].get("expiry")
        serial = s_issue["detail"].get("serial")

        if not s_issue["ok"]:
            outcome = "failed"
        elif not force and not s_issue["detail"].get("renewed", True):
            pending = pending_targets(cert, targets)
            if pending:
                log.info("renew(%s): certificate still valid but %s not yet activated: deploying",
                         cert.id, ", ".join(t.id for t in pending))
                steps[-1]["message"] += f" Pending activation on {', '.join(t.id for t in pending)}."
                targets = pending
            else:
                outcome = "skipped"
                log.info("renew(%s): skipped (cert still valid)", cert.id)

        if outcome == "success":
            outcome = _deploy_targets(cert, targets, steps)

        record = _finish(cert, targets, steps, outcome, kind, not_after, serial, t_start, actor, source)
    log.info("renew(%s): %s", cert.id, outcome)
    return record


def redeploy_certificate(cert: Certificate, actor: str = "", source: str = "",
                         targets: list[Target] | None = None) -> RenewalRecord:
    """Re-deploy the certificate already on disk (deploy -> activate), skipping issuance.

    Never contacts the ACME CA, so it is immune to Let's Encrypt rate limits. Use
    it to re-push a known-good cert to a target (e.g. after an appliance was
    rebuilt) or to re-run activation without spending an issuance. Records to
    history and alerts on failure exactly like renew_certificate.
    """
    targets = list(targets if targets is not None else cert.targets)
    leaf = config.cert_dir_for(cert) / f"{cert.domain}.cer"
    not_after, serial = _leaf_meta(leaf)
    with locks.run_lock(cert.id, "redeploy", actor, source):
        t_start = time.monotonic()
        if not leaf.exists():
            r = StepResult("deploy", ok=False, message="no certificate on disk yet -- run Force renew first")
            record = _finish(cert, targets, [r.as_dict()], "failed", "redeploy", None, None, t_start, actor, source)
            log.info("redeploy(%s): no cert on disk", cert.id)
            return record
        steps: list[dict] = []
        outcome = _deploy_targets(cert, targets, steps)
        record = _finish(cert, targets, steps, outcome, "redeploy", not_after, serial, t_start, actor, source)
    log.info("redeploy(%s): %s", cert.id, outcome)
    return record


# --------------------------------------------------------------------------- legacy entry points

def renew_server(server: ServerConfig, force: bool = False, actor: str = "", source: str = "") -> RenewalRecord:
    """Full pipeline for the certificate this Orchestrator entry represents."""
    return renew_certificate(server.to_certificate(), force=force, actor=actor, source=source)


def redeploy_server(server: ServerConfig, actor: str = "", source: str = "") -> RenewalRecord:
    """deploy -> activate from the certificate on disk for this Orchestrator entry."""
    return redeploy_certificate(server.to_certificate(), actor=actor, source=source)


def renew_all(force: bool = False, actor: str = "scheduler", source: str = "cron") -> list[RenewalRecord]:
    """What the scheduler runs: every certificate, each under its own lock.

    A certificate whose lock is held (a Force renew from the UI, say) is skipped
    with a warning rather than queued: the next scheduled run picks it up.
    """
    certs = config.load_certificates()
    if source == "cron":
        store.scheduler_started(source)
    if not certs:
        log.warning("no certificates configured")
        if source == "cron":
            store.scheduler_finished({})
        return []
    records: list[RenewalRecord] = []
    outcomes: dict[str, str] = {}
    for c in certs:
        try:
            rec = renew_certificate(c, force=force, actor=actor, source=source)
        except locks.RunLocked as exc:
            log.warning("renew-all: %s", exc)
            outcomes[c.id] = "locked"
            continue
        except Exception as exc:  # noqa: BLE001 - one certificate must not stop the others
            log.exception("renew-all: %s failed outside the pipeline", c.id)
            outcomes[c.id] = f"error: {exc.__class__.__name__}"
            continue
        records.append(rec)
        outcomes[c.id] = rec.outcome
    if source == "cron":
        store.scheduler_finished(outcomes)
    return records
