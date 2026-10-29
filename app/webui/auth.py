"""Single-admin authentication for the web UI.

Everything lives next to servers.json in the writable /config mount, so it
persists across container rebuilds:

    <config>/admin.json       the admin credential (PBKDF2-SHA256, mode 600)
    <config>/session.secret   HMAC key for signing session cookies (mode 600)
    <config>/session.revoked  timestamp before which every token is invalid (logout)

No external dependencies: password hashing and cookie signing use hashlib/hmac
from the standard library. A token carries the username, its issue time and a
fingerprint of the credential file, so a password change or an admin reset
invalidates it; logout revokes every token issued so far (one admin, so
"log out everywhere" is the right semantics).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from pathlib import Path

from .. import config

log = logging.getLogger("auth")

PBKDF2_ITERATIONS = 240_000
SESSION_TTL = 8 * 3600  # seconds
COOKIE_NAME = "session"
MIN_PASSWORD_LEN = 8
MIN_SECRET_LEN = 32
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
_DUMMY_SALT = bytes.fromhex("00" * 16)


def _auth_dir() -> Path:
    d = config.SERVERS_FILE.parent
    d.mkdir(parents=True, exist_ok=True)
    return d


def _admin_path() -> Path:
    return _auth_dir() / "admin.json"


def _revoked_path() -> Path:
    return _auth_dir() / "session.revoked"


def _write_private(path: Path, data: bytes, exclusive: bool = False) -> None:
    """Create a mode-600 file atomically (temp file in the same directory, then rename)."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if exclusive and path.exists():
            raise FileExistsError(path)
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def valid_username(username: str) -> bool:
    return bool(USERNAME_RE.match(username or ""))


# --------------------------------------------------------------------------- #
# admin credential
# --------------------------------------------------------------------------- #
def needs_setup() -> bool:
    """True until an admin account exists (drives the first-run Setup flow)."""
    return not _admin_path().exists()


def create_admin(username: str, password: str) -> None:
    if not valid_username(username):
        raise ValueError("username may contain only letters, digits, '.', '_', '@' and '-' (1-64 characters)")
    rec = {
        "username": username,
        "algo": "pbkdf2_sha256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": secrets.token_hex(16),
        "hash": "",
    }
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(rec["salt"]), rec["iterations"])
    rec["hash"] = dk.hex()
    _write_private(_admin_path(), (json.dumps(rec, indent=2) + "\n").encode())


def _record() -> dict | None:
    p = _admin_path()
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def credential_fingerprint() -> str:
    """Changes whenever admin.json changes (password change, reset); bound into every token."""
    try:
        return hashlib.sha256(_admin_path().read_bytes()).hexdigest()[:16]
    except OSError:
        return ""


def verify(username: str, password: str) -> bool:
    rec = _record()
    if not rec:
        return False
    try:
        salt = bytes.fromhex(rec["salt"])
        iterations = int(rec["iterations"])
    except (KeyError, ValueError, TypeError):
        return False
    # Always run the derivation so a wrong username costs the same as a wrong password.
    user_ok = hmac.compare_digest(str(rec.get("username", "")).encode(), (username or "").encode())
    dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode(), salt if user_ok else _DUMMY_SALT, iterations)
    pw_ok = hmac.compare_digest(dk.hex().encode(), str(rec.get("hash", "")).encode())
    return user_ok and pw_ok


# --------------------------------------------------------------------------- #
# signed session tokens
# --------------------------------------------------------------------------- #
def _session_secret() -> bytes:
    p = _auth_dir() / "session.secret"
    if p.exists():
        data = p.read_bytes()
        if len(data) >= MIN_SECRET_LEN:
            return data
        log.error("%s is only %d bytes (truncated or empty); regenerating it, every session is invalidated", p, len(data))
    sec = secrets.token_bytes(32)
    try:
        _write_private(p, sec, exclusive=not p.exists())
    except FileExistsError:
        return p.read_bytes()      # another process created it first
    return sec


def _revocation() -> tuple[int, int]:
    """(generation, timestamp) of the last revoke_all(); a pre-1.3 file holds the bare timestamp."""
    try:
        raw = _revoked_path().read_text().strip()
    except OSError:
        return 0, 0
    if not raw:
        return 0, 0
    try:
        data = json.loads(raw)
    except ValueError:
        return 0, 0
    if isinstance(data, dict):
        return int(data.get("gen", 0)), int(data.get("at", 0))
    return 0, int(data) if isinstance(data, (int, float)) else 0


def _revoked_before() -> int:
    return _revocation()[1]


def revoke_all() -> None:
    """Invalidate every token issued so far (logout).

    Tokens carry the revocation generation they were minted under; bumping it
    rejects every earlier token even when the logout and a fresh login share
    the same wall-clock second.
    """
    gen, _ = _revocation()
    _write_private(_revoked_path(), json.dumps({"gen": gen + 1, "at": int(time.time())}).encode())


def make_token(username: str) -> str:
    payload = json.dumps({"u": username, "t": int(time.time()), "c": credential_fingerprint(), "g": _revocation()[0]},
                         separators=(",", ":"))
    sig = hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
    b64 = base64.urlsafe_b64encode(payload.encode()).decode()
    return f"{b64}.{sig}"


def read_token(token: str) -> str | None:
    """Return the username if the token is valid, unexpired, unrevoked and bound to the current credential."""
    if not token or "." not in token:
        return None
    try:
        b64, sig = token.rsplit(".", 1)
        payload = base64.urlsafe_b64decode(b64.encode()).decode()
        expected = hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(payload)
        username, ts, fp = str(data["u"]), int(data["t"]), str(data.get("c", ""))
        now = int(time.time())
        if now - ts > SESSION_TTL or ts > now + 60:
            return None
        gen, at = _revocation()
        if int(data.get("g", 0)) < gen or ts < at:
            return None
        if not hmac.compare_digest(fp, credential_fingerprint()):
            return None
        return username
    except Exception:  # noqa: BLE001 - any malformed token is simply not a session
        return None
