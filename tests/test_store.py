"""app.store: the JSON renewal history and the scheduler progress file.

The ``layout`` fixture points store.HISTORY_FILE (and config.SERVERS_FILE, which
scheduler_file() derives from) at a fresh tmp dir, so every test starts with
no history and no scheduler state on disk.
"""
from __future__ import annotations

import datetime as dt
import errno
import fcntl
import json
import logging
import os
import re
import threading
from pathlib import Path

import pytest

from app import store
from app.models import RenewalRecord


def ts(i: int) -> str:
    return (dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(minutes=i)).isoformat(timespec="seconds")


def rec(server_id: str = "cert-a", i: int = 0, outcome: str = "success", **overrides) -> RenewalRecord:
    base = dict(server_id=server_id, timestamp=ts(i), outcome=outcome, actor="alice", source="web",
                targets=["orch-1"], steps=[{"step": "issue", "ok": True}], serial=f"S{i:04d}")
    base.update(overrides)
    return RenewalRecord(**base)


def on_disk() -> list[dict]:
    return json.loads(store.HISTORY_FILE.read_text())


def stray_files(cfg: Path) -> list[str]:
    """Anything next to history.json other than the file itself and its lock."""
    return sorted(p.name for p in cfg.iterdir() if p.name not in ("history.json", ".history.json.lock"))


def fail_replace_for(monkeypatch, target: Path, err: int = errno.EBUSY):
    """os.replace raises OSError when the destination is ``target``; every other call is passed through."""
    real = os.replace

    def fake_replace(src, dst, *a, **kw):
        if Path(dst) == target:
            raise OSError(err, os.strerror(err), str(dst))
        return real(src, dst, *a, **kw)

    monkeypatch.setattr(os, "replace", fake_replace)


# ---- reading --------------------------------------------------------------------

def test_missing_history_reads_as_empty(layout):
    assert not store.HISTORY_FILE.exists()
    assert store._read() == []
    assert store.all_records() == []
    assert store.latest_for("cert-a") is None
    assert not store.HISTORY_FILE.exists()          # reading never creates the file


@pytest.mark.parametrize("text", ["{not json", '{"a": 1}', "", "42"])
def test_read_treats_unusable_history_as_empty_without_touching_it(layout, text):
    store.HISTORY_FILE.write_text(text)
    assert store._read() == []
    assert store.HISTORY_FILE.read_text() == text
    assert stray_files(layout["cfg"]) == []         # only add_record sets a corrupt file aside


# ---- add_record ---------------------------------------------------------------

def test_add_record_creates_history_and_round_trips(layout):
    r = rec()
    store.add_record(r)
    assert on_disk() == [r.as_dict()]
    assert store.all_records() == [r.as_dict()]
    assert store.latest_for("cert-a") == r.as_dict()
    assert (layout["cfg"] / ".history.json.lock").is_file()
    assert stray_files(layout["cfg"]) == []         # no temp file left behind


def test_add_record_creates_a_missing_parent_directory(layout, monkeypatch):
    nested = layout["cfg"] / "deeper" / "still" / "history.json"
    monkeypatch.setattr(store, "HISTORY_FILE", nested)
    store.add_record(rec())
    assert on_disk() == [rec().as_dict()]


def test_records_are_served_newest_first(layout):
    for i, sid in enumerate(["cert-a", "cert-b", "cert-a", "cert-b"]):
        store.add_record(rec(sid, i))

    assert [r["timestamp"] for r in on_disk()] == [ts(0), ts(1), ts(2), ts(3)]       # file: append order
    newest_first = store.all_records()
    assert [r["timestamp"] for r in newest_first] == [ts(3), ts(2), ts(1), ts(0)]
    assert [r["server_id"] for r in newest_first] == ["cert-b", "cert-a", "cert-b", "cert-a"]
    assert store.latest_for("cert-a")["timestamp"] == ts(2)
    assert store.latest_for("cert-b")["timestamp"] == ts(3)
    assert store.latest_for("cert-c") is None


def test_history_is_bounded_and_drops_the_oldest(layout):
    cap = store._MAX
    assert cap > 0
    seed = [rec(f"s{i}", i).as_dict() for i in range(cap + 10)]      # an over-full file from an older build
    store.HISTORY_FILE.write_text(json.dumps(seed))

    store.add_record(rec("new", cap + 10))

    kept = on_disk()
    assert len(kept) == cap
    assert kept[-1]["server_id"] == "new"
    assert kept[0]["server_id"] == "s11"             # s0..s10 fell off the front
    assert store.all_records()[0]["server_id"] == "new"
    assert store.latest_for("s0") is None and store.latest_for("s11") is not None

    store.add_record(rec("newer", cap + 11))
    assert len(on_disk()) == cap
    assert on_disk()[0]["server_id"] == "s12"


def test_add_record_survives_a_failing_replace_and_keeps_every_record(layout, monkeypatch):
    first = rec("cert-a", 0)
    store.add_record(first)
    fail_replace_for(monkeypatch, store.HISTORY_FILE)       # e.g. history.json is a single-file bind mount

    second = rec("cert-b", 1)
    store.add_record(second)                                 # must not raise: in-place fallback

    assert on_disk() == [first.as_dict(), second.as_dict()]  # complete JSON: the original record is intact
    assert stray_files(layout["cfg"]) == []                  # the temp file was removed after the fallback


def test_tmp_write_failure_leaves_the_original_untouched(layout, monkeypatch):
    first = rec("cert-a", 0)
    store.add_record(first)
    original = store.HISTORY_FILE.read_bytes()
    original_stat = store.HISTORY_FILE.stat()
    real_write_text = Path.write_text

    def fake_write_text(self, data, *a, **kw):
        if self.name.endswith(".tmp"):
            raise OSError(errno.ENOSPC, "No space left on device", str(self))
        return real_write_text(self, data, *a, **kw)

    monkeypatch.setattr(Path, "write_text", fake_write_text)
    with pytest.raises(OSError) as info:
        store.add_record(rec("cert-b", 1))
    assert info.value.errno == errno.ENOSPC

    assert store.HISTORY_FILE.read_bytes() == original               # byte-for-byte: never partially written
    assert store.HISTORY_FILE.stat().st_mtime_ns == original_stat.st_mtime_ns
    assert stray_files(layout["cfg"]) == []                           # and no corrupt-* copy was taken
    # both locks were released on the way out
    assert store._LOCK.acquire(blocking=False)
    store._LOCK.release()
    fd = os.open(layout["cfg"] / ".history.json.lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def test_add_record_takes_an_exclusive_flock_on_the_lock_file(layout, monkeypatch):
    real_flock = fcntl.flock
    calls: list[tuple[int, int]] = []

    def recording_flock(fd, op):
        calls.append((os.fstat(fd).st_ino, op))
        return real_flock(fd, op)

    monkeypatch.setattr(fcntl, "flock", recording_flock)
    store.add_record(rec())

    lock_path = store.HISTORY_FILE.with_name(".history.json.lock")
    assert lock_path.is_file()
    assert [op for _, op in calls] == [fcntl.LOCK_EX, fcntl.LOCK_UN]
    assert {ino for ino, _ in calls} == {lock_path.stat().st_ino}
    assert (lock_path.stat().st_mode & 0o777) == 0o600


def test_add_record_waits_for_a_lock_held_elsewhere(layout):
    lock_path = store.HISTORY_FILE.with_name(".history.json.lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)       # a second open file description: flock conflicts
    fcntl.flock(fd, fcntl.LOCK_EX)
    worker = threading.Thread(target=store.add_record, args=(rec(),), daemon=True)
    try:
        worker.start()
        worker.join(0.15)
        assert worker.is_alive()                                  # blocked on the flock
        assert not store.HISTORY_FILE.exists()
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    worker.join(5)
    assert not worker.is_alive()
    assert on_disk() == [rec().as_dict()]


@pytest.mark.parametrize("garbage", ["{not json", '{"a": 1}', "[1, 2", "null"])
def test_corrupt_history_is_set_aside_and_a_fresh_file_written(layout, garbage):
    store.HISTORY_FILE.write_text(garbage)
    r = rec()

    store.add_record(r)

    assert on_disk() == [r.as_dict()]
    aside = stray_files(layout["cfg"])
    assert len(aside) == 1
    assert re.fullmatch(r"history\.json\.corrupt-\d{14}", aside[0]), aside
    assert (layout["cfg"] / aside[0]).read_text() == garbage     # the unreadable audit trail is preserved verbatim


def test_corrupt_history_set_aside_name_is_a_timestamp(layout, monkeypatch):
    class FrozenDateTime(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 22, 13, 14, 15, tzinfo=tz)

    monkeypatch.setattr(store.datetime, "datetime", FrozenDateTime)
    store.HISTORY_FILE.write_text("{broken")
    store.add_record(rec())
    assert stray_files(layout["cfg"]) == ["history.json.corrupt-20261022131415"]


def test_empty_history_file_is_not_treated_as_corrupt(layout):
    store.HISTORY_FILE.write_text("")
    store.add_record(rec())
    assert on_disk() == [rec().as_dict()]
    assert stray_files(layout["cfg"]) == []


def test_corrupt_history_that_cannot_be_moved_is_still_replaced(layout, monkeypatch):
    store.HISTORY_FILE.write_text("{broken")
    real = os.replace

    def fake_replace(src, dst, *a, **kw):
        if Path(src) == store.HISTORY_FILE:          # the move-aside only; the tmp -> history.json rename works
            raise OSError(errno.EPERM, "Operation not permitted", str(src))
        return real(src, dst, *a, **kw)

    monkeypatch.setattr(os, "replace", fake_replace)
    store.add_record(rec())
    assert on_disk() == [rec().as_dict()]
    assert stray_files(layout["cfg"]) == []


# ---- scheduler state -------------------------------------------------------------

def test_scheduler_file_lives_next_to_servers_json(layout):
    assert store.scheduler_file() == layout["cfg"] / "scheduler.json"


@pytest.mark.parametrize("text", [None, "garbage", "{", ""])
def test_scheduler_state_is_empty_when_missing_or_unreadable(layout, text):
    if text is not None:
        store.scheduler_file().write_text(text)
    assert store.scheduler_state() == {}


@pytest.mark.parametrize("text", ["[1]", '"str"', "42"])
def test_scheduler_state_that_is_not_an_object_is_discarded(layout, text):
    store.scheduler_file().write_text(text)
    store.scheduler_started()
    assert store.scheduler_state()["source"] == "cron"


def test_scheduler_started_and_finished_round_trip(layout):
    before = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    store.scheduler_started()

    started = store.scheduler_state()
    assert set(started) == {"started", "finished", "pid", "source"}
    assert started["finished"] is None
    assert started["pid"] == os.getpid()
    assert started["source"] == "cron"
    t0 = dt.datetime.fromisoformat(started["started"])
    assert t0.tzinfo is not None and t0.utcoffset() == dt.timedelta(0)
    assert before <= t0 <= dt.datetime.now(dt.timezone.utc)
    assert started == json.loads(store.scheduler_file().read_text())

    outcomes = {"cert-a": "success", "cert-c": "failed", "cert-b": "failed", "cert-d": "skipped"}
    store.scheduler_finished(outcomes)

    finished = store.scheduler_state()
    assert finished["started"] == started["started"]
    assert finished["pid"] == os.getpid() and finished["source"] == "cron"
    assert finished["outcomes"] == outcomes
    assert finished["failed"] == ["cert-b", "cert-c"]                      # sorted ids with outcome == failed
    t1 = dt.datetime.fromisoformat(finished["finished"])
    assert t1.utcoffset() == dt.timedelta(0) and t1 >= t0
    assert sorted(p.name for p in layout["cfg"].iterdir()) == ["scheduler.json"]   # no temp file left


def test_scheduler_started_again_resets_finished_and_records_the_source(layout):
    store.scheduler_started("cron")
    store.scheduler_finished({"cert-a": "failed"})
    store.scheduler_started("web")

    state = store.scheduler_state()
    assert state["finished"] is None
    assert state["source"] == "web"
    assert state["failed"] == ["cert-a"]           # the previous run's result stays until this run finishes


def test_scheduler_finished_with_no_failures(layout):
    store.scheduler_started()
    store.scheduler_finished({})
    state = store.scheduler_state()
    assert state["outcomes"] == {} and state["failed"] == []
    assert state["finished"] is not None


def test_scheduler_write_failure_is_logged_not_raised(layout, monkeypatch, caplog):
    fail_replace_for(monkeypatch, store.scheduler_file(), errno.EROFS)
    with caplog.at_level(logging.WARNING, logger="store"):
        assert store.scheduler_started() is None
        assert store.scheduler_finished({"cert-a": "failed"}) is None
    assert store.scheduler_state() == {}
    msgs = [r.getMessage() for r in caplog.records if r.name == "store"]
    assert len(msgs) == 2
    assert all("could not write" in m and "scheduler.json" in m for m in msgs)
