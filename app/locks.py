"""Per-certificate run lock shared by the scheduler and the web UI.

supercronic runs ``renew-all`` in one process; the web UI runs Force renew /
Force deploy in threads of another. Both write ``data/certs/<domain>/``, both
upload to the appliance and both restart it, so only one run per certificate
may be in flight. The lock is an ``fcntl.flock`` on a file under the config
directory: the kernel releases it when the holder dies, so a crashed run never
leaves a stale lock, and the file content (pid, start, kind, actor) lets the
other process say who holds it.
"""
from __future__ import annotations

import contextlib
import datetime
import fcntl
import json
import logging
import os
from pathlib import Path

from . import config

log = logging.getLogger("locks")

LOCK_DIRNAME = "locks"


class RunLocked(Exception):
    """Another run holds the lock for this certificate."""

    def __init__(self, cert_id: str, holder: dict):
        self.cert_id = cert_id
        self.holder = holder
        since = holder.get("started", "?")
        who = holder.get("actor") or holder.get("source") or "unknown"
        super().__init__(f"{cert_id}: a {holder.get('kind', 'run')} is already running "
                         f"(pid {holder.get('pid', '?')}, since {since}, started by {who})")


def _dir() -> Path:
    d = Path(config.CONFIG_DIR) / LOCK_DIRNAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path(cert_id: str) -> Path:
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in cert_id)
    return _dir() / f"{safe}.lock"


def _read_holder(path: Path) -> dict:
    try:
        return json.loads(path.read_text() or "{}")
    except (OSError, ValueError):
        return {}


@contextlib.contextmanager
def run_lock(cert_id: str, kind: str = "run", actor: str = "", source: str = ""):
    """Hold the certificate's run lock for the duration of the block.

    Raises RunLocked immediately (never blocks) when another process or thread
    holds it.
    """
    path = _path(cert_id)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RunLocked(cert_id, _read_holder(path)) from None
        holder = {
            "pid": os.getpid(), "kind": kind, "actor": actor, "source": source,
            "started": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        }
        os.ftruncate(fd, 0)
        os.write(fd, json.dumps(holder).encode())
        os.fsync(fd)
        try:
            yield holder
        finally:
            # Clear the content before releasing so a reader never sees a stale holder.
            try:
                os.ftruncate(fd, 0)
            except OSError:
                pass
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def holder(cert_id: str) -> dict | None:
    """The lock holder's record when a run is in progress, else None.

    Probes with a non-blocking flock on a separate descriptor; on Linux flock
    locks are per open file description, so this never interferes with a
    holder in the same process.
    """
    path = _path(cert_id)
    if not path.exists():
        return None
    fd = os.open(path, os.O_RDONLY)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError:
            return _read_holder(path) or {"kind": "run"}
        fcntl.flock(fd, fcntl.LOCK_UN)
        return None
    finally:
        os.close(fd)


def is_locked(cert_id: str) -> bool:
    return holder(cert_id) is not None


def active() -> dict[str, dict]:
    """Every certificate currently locked, with its holder."""
    out: dict[str, dict] = {}
    d = Path(config.CONFIG_DIR) / LOCK_DIRNAME
    if not d.is_dir():
        return out
    for p in d.glob("*.lock"):
        cid = p.name[:-5]
        h = holder(cid)
        if h is not None:
            out[cid] = h
    return out
