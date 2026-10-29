"""Tiny JSON-backed history store for the web UI (SQLite is a future upgrade).

The history file lives next to servers.json in the persistent config
directory (HISTORY_FILE overrides). Earlier releases wrote it to
DATA_DIR/history.json, which is not covered by the documented bind mounts;
preflight copies that legacy file forward once if the new one is absent.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import datetime

from . import config
from .config import DATA_DIR, SERVERS_FILE
from .models import RenewalRecord

HISTORY_FILE = Path(os.environ.get("HISTORY_FILE") or (SERVERS_FILE.parent / "history.json"))
LEGACY_HISTORY_FILE = DATA_DIR / "history.json"
_LOCK = threading.Lock()
_MAX = 500
SCHEDULER_FILENAME = "scheduler.json"


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def scheduler_file() -> Path:
    """Where the scheduled runner records its progress (read by /healthz and the System page)."""
    return Path(config.SERVERS_FILE).parent / SCHEDULER_FILENAME


def scheduler_state() -> dict:
    try:
        data = json.loads(scheduler_file().read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_scheduler(state: dict) -> None:
    p = scheduler_file()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(state, indent=2))
        os.replace(tmp, p)
    except OSError as exc:  # the health signal must never break a run
        import logging
        logging.getLogger("store").warning("could not write %s: %s", p, exc)


def scheduler_started(source: str = "cron") -> None:
    state = scheduler_state()
    state.update({"started": _utcnow(), "finished": None, "pid": os.getpid(), "source": source})
    _write_scheduler(state)


def scheduler_finished(outcomes: dict[str, str]) -> None:
    state = scheduler_state()
    state.update({"finished": _utcnow(), "outcomes": outcomes,
                  "failed": sorted(k for k, v in outcomes.items() if v == "failed")})
    _write_scheduler(state)


def _read() -> list[dict]:
    if not HISTORY_FILE.exists():
        return []
    try:
        data = json.loads(HISTORY_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    return data if isinstance(data, list) else []


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text)
    try:
        os.replace(tmp, path)
    except OSError:            # a single-file bind mount cannot be replaced; write in place
        path.write_text(text)
        tmp.unlink(missing_ok=True)


def add_record(record: RenewalRecord) -> None:
    """Append one record; the scheduler process and the web UI share the file, so take a cross-process lock."""
    import fcntl
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    lock_path = HISTORY_FILE.with_name(f".{HISTORY_FILE.name}.lock")
    with _LOCK:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            if HISTORY_FILE.exists() and HISTORY_FILE.stat().st_size:
                try:
                    data = json.loads(HISTORY_FILE.read_text())
                    items = data if isinstance(data, list) else []
                    if not isinstance(data, list):
                        raise ValueError("history is not a list")
                except (json.JSONDecodeError, ValueError, OSError):
                    # Never overwrite an audit trail we could not read: set it aside instead.
                    aside = HISTORY_FILE.with_name(f"{HISTORY_FILE.name}.corrupt-{datetime.datetime.now():%Y%m%d%H%M%S}")
                    try:
                        os.replace(HISTORY_FILE, aside)
                    except OSError:
                        pass
                    items = []
            else:
                items = []
            items.append(record.as_dict())
            items = items[-_MAX:]
            _write_atomic(HISTORY_FILE, json.dumps(items, indent=2))
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def all_records() -> list[dict]:
    return list(reversed(_read()))


def latest_for(server_id: str) -> dict | None:
    for rec in reversed(_read()):
        if rec.get("server_id") == server_id:
            return rec
    return None
