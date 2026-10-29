"""Notifications for renewal outcomes (generic webhook, Slack-compatible).

renew.py calls send() after every run. This alerts on failures by default —
the important case for an unattended, scheduled tool where nobody is watching.
Set NOTIFY_ON=all to also announce successful renewals; 'skipped' outcomes are
never alerted (nothing happened). send() never raises: a notification problem
must not break the pipeline.

Config (environment):
  NOTIFY_WEBHOOK_URL   incoming-webhook URL (Slack/Discord/Teams/generic). Empty = disabled.
  NOTIFY_ON            "failed" (default) or "all"
"""
from __future__ import annotations

import logging
import os

import requests

from .models import RenewalRecord

log = logging.getLogger("notify")

_TIMEOUT = 10


def _settings() -> tuple[str, str]:
    return (os.environ.get("NOTIFY_WEBHOOK_URL", "").strip(),
            os.environ.get("NOTIFY_ON", "failed").strip().lower())


def _redacted(url: str) -> str:
    """scheme://host only: the path of a webhook URL is the credential."""
    from urllib.parse import urlsplit
    try:
        u = urlsplit(url)
        return f"{u.scheme}://{u.hostname}"
    except ValueError:
        return "<webhook>"


def send(record: RenewalRecord) -> None:
    url, when = _settings()
    if not url:
        log.debug("notify(%s): no webhook configured", record.server_id)
        return

    if record.outcome == "skipped":
        return
    if record.outcome == "success" and when != "all":
        return

    text = _format(record)
    try:
        resp = requests.post(url, json={"text": text}, timeout=_TIMEOUT, allow_redirects=False)
        if resp.status_code >= 300:
            log.warning("notify(%s): webhook %s returned HTTP %s", record.server_id, _redacted(url), resp.status_code)
        else:
            log.info("notify(%s): sent %s alert", record.server_id, record.outcome)
    except requests.RequestException as exc:
        log.warning("notify(%s): webhook post to %s failed: %s", record.server_id, _redacted(url), exc.__class__.__name__)


def _format(record: RenewalRecord) -> str:
    head = {
        "failed": "Certificate renewal FAILED",
        "success": "Certificate renewed",
    }.get(record.outcome, f"Renewal {record.outcome}")

    lines = [f"{head}: {record.server_id}", f"time: {record.timestamp}"]
    if record.actor or record.source:
        lines.append(f"started by: {record.actor or '?'} via {record.source or '?'}")
    if record.targets:
        lines.append(f"targets: {', '.join(record.targets)}")

    if record.outcome == "failed":
        bad = next((s for s in record.steps if not s.get("ok", True)), None)
        if bad:
            where = f" on target {bad['target']}" if bad.get("target") else ""
            lines.append(f"failed at: {bad.get('step')}{where} — {bad.get('message')}")
    elif record.outcome == "success":
        if record.not_after:
            lines.append(f"new expiry: {record.not_after}")
        if record.serial:
            lines.append(f"serial: {record.serial}")

    return "\n".join(lines)
