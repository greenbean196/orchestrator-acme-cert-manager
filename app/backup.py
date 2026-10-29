"""Backup and restore of the configuration and runtime state (issue #13).

What goes in (relative paths inside the archive):

    config/   servers.json, history.json, admin.json, session.secret, scheduler.json
              (never trust/ or locks/: both are regenerated)
    data/certs/   issued certificates, Lego accounts, rollback snapshots
    data/ssh/     the activation key pair and the pinned host keys
    data/pki/     lab CA ONLINE state when it is visible to this process
    data/pki-root/ the lab CA OFFLINE root, only with include_root=True
    backup.json   manifest: version, timestamp, what was included and skipped

Logs are never included. Permissions and ownership bits are preserved by tar;
restore() re-applies the owner-only modes the app relies on. An encrypted
archive is AES-256-GCM over the .tar.gz with a scrypt-derived key (header
``OACMB1`` + 16-byte salt + 12-byte nonce).

From inside the container only the mounted directories are visible, so the
lab CA online state is skipped there (the manifest says so); ``setup.sh
--backup`` on the host sees everything.
"""
from __future__ import annotations

import datetime
import io
import json
import os
import stat
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__, config

MAGIC = b"OACMB1"
TOOL = "orchestrator-acme-cert-manager"
FORMAT = 1
MANIFEST = "backup.json"
_SECRET_MODES = {"config/servers.json": 0o600, "config/admin.json": 0o600, "config/session.secret": 0o600}


class BackupError(Exception):
    pass


@dataclass
class Result:
    path: Path
    entries: int
    size: int = 0
    encrypted: bool = False
    destination: str = ""
    skipped: list = field(default_factory=list)


def _parts(include_root: bool) -> list[tuple[str, Path, list[str]]]:
    """(archive prefix, source directory, excluded top-level names)."""
    data = Path(config.DATA_DIR)
    parts = [
        ("config", Path(config.CONFIG_DIR), ["trust", "locks"]),
        ("data/certs", data / "certs", []),
        ("data/ssh", data / "ssh", []),
        ("data/pki", data / "pki", []),
    ]
    if include_root:
        parts.append(("data/pki-root", data / "pki-root", []))
    return parts


def create(path: str | os.PathLike, include_root: bool = False, passphrase: str = "") -> Result:
    out = Path(path)
    if out.exists() and out.is_dir():
        raise BackupError(f"{out} is a directory")
    included, skipped = [], []
    buf = io.BytesIO()
    count = 0
    out_resolved = out.resolve()
    archive_suffixes = (".tgz", ".tar.gz", ".enc", ".tar")
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for prefix, src, excluded in _parts(include_root):
            if not src.is_dir() or not os.access(src, os.R_OK):
                skipped.append({"part": prefix, "reason": "not present or not readable from this process"})
                continue
            if prefix == "data/pki" and not any(src.iterdir()):
                skipped.append({"part": prefix, "reason": "empty (lab CA not initialised or only certs/ mounted)"})
                continue
            included.append(prefix)
            for root, dirs, files in os.walk(src):
                rel_root = Path(root).relative_to(src)
                if root == str(src):
                    dirs[:] = [d for d in dirs if d not in excluded]
                    files = [f for f in files if f not in excluded]
                dirs[:] = [d for d in dirs if d != "logs"]
                for name in files:
                    full = Path(root) / name
                    if full.is_symlink():
                        continue
                    if full.resolve() == out_resolved or name.endswith(archive_suffixes) or name.endswith((".lock", ".tmp")) \
                            or name.startswith(".") and (".restore-tmp" in name or name.endswith(".tmp")):
                        continue          # never nest earlier backups, the one being written, or scratch files
                    arc = str(Path(prefix) / rel_root / name)
                    try:
                        tar.add(full, arcname=arc, recursive=False)
                        count += 1
                    except OSError as exc:
                        skipped.append({"part": arc, "reason": str(exc)})
        manifest = {
            "tool": TOOL, "format": FORMAT, "app_version": __version__,
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "uid": os.getuid(), "included": included, "skipped": skipped, "include_root": include_root,
            "servers_file": str(config.SERVERS_FILE),
        }
        data = json.dumps(manifest, indent=2).encode()
        info = tarfile.TarInfo(MANIFEST)
        info.size = len(data)
        info.mtime = int(datetime.datetime.now().timestamp())
        info.mode = 0o600
        tar.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    if passphrase:
        raw = _encrypt(raw, passphrase)
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(raw)
    return Result(path=out, entries=count, size=len(raw), encrypted=bool(passphrase))


def read_manifest(path: str | os.PathLike, passphrase: str = "") -> dict:
    raw = _load(Path(path), passphrase)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        try:
            m = tar.extractfile(MANIFEST)
        except KeyError:
            raise BackupError(f"{path} has no {MANIFEST}; not a backup made by this tool") from None
        return json.loads(m.read()) if m else {}


def restore(path: str | os.PathLike, force: bool = False, passphrase: str = "") -> Result:
    src = Path(path)
    raw = _load(src, passphrase)
    roots = {"config": Path(config.CONFIG_DIR), "data": Path(config.DATA_DIR)}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        members = tar.getmembers()
        names = [m.name for m in members]
        if MANIFEST not in names:
            raise BackupError(f"{src} has no {MANIFEST}; not a backup made by this tool")
        # Safety: only plain files/dirs, relative paths under the two roots, no traversal.
        for m in members:
            if m.name == MANIFEST:
                continue
            p = Path(m.name)
            if p.is_absolute() or ".." in p.parts or p.parts[0] not in roots or len(p.parts) < 2:
                raise BackupError(f"refusing archive member outside config/ or data/: {m.name}")
            if not (m.isfile() or m.isdir()):
                raise BackupError(f"refusing non-regular archive member: {m.name}")
        manifest = json.loads(tar.extractfile(MANIFEST).read())
        if not isinstance(manifest, dict) or manifest.get("tool") != TOOL:
            raise BackupError(f"{src}: manifest was not written by {TOOL}")
        try:
            fmt = int(manifest.get("format", 1))
        except (TypeError, ValueError):
            raise BackupError(f"{src}: manifest has no readable format number") from None
        if fmt > FORMAT:
            raise BackupError(f"{src}: backup format {fmt} is newer than this version understands ({FORMAT})")
        src_resolved = src.resolve()
        writable = {name: os.access(root, os.W_OK) if root.is_dir() else os.access(root.parent, os.W_OK) for name, root in roots.items()}
        # Sub-mounts that are read-only inside the container (data/ssh, data/pki/certs in docker-compose.yml)
        ro_prefixes = [p for p in ("data/ssh", "data/pki/certs", "data/pki", "data/certs", "config")
                       if (lambda d: d.is_dir() and not os.access(d, os.W_OK))(roots[p.split("/")[0]].joinpath(*p.split("/")[1:]))]
        current = Path(config.SERVERS_FILE)
        archived = next((m for m in members if m.name == "config/servers.json"), None)
        if archived is not None and current.exists() and not force:
            if current.stat().st_mtime > archived.mtime + 1:
                raise BackupError(
                    f"{current} on this host is newer ({_ts(current.stat().st_mtime)}) than the archived copy "
                    f"({_ts(archived.mtime)}); pass --force to overwrite it")
        count = 0
        skipped: list[dict] = []
        for m in members:
            if m.name == MANIFEST:
                continue
            p = Path(m.name)
            if not writable.get(p.parts[0], False):
                raise BackupError(f"{roots[p.parts[0]]} is not writable from this process; nothing was restored")
            dest = roots[p.parts[0]].joinpath(*p.parts[1:])
            ro = next((pre for pre in ro_prefixes if m.name == pre or m.name.startswith(pre + "/")), None)
            if ro:
                skipped.append({"member": m.name, "reason": f"{ro} is mounted read-only here; restore it on the host (setup.sh --restore)"})
                continue
            if dest.resolve() == src_resolved:
                skipped.append({"member": m.name, "reason": "is the archive being restored"})
                continue
            try:
                if m.isdir():
                    dest.mkdir(parents=True, exist_ok=True)
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                fh = tar.extractfile(m)
                if fh is None:
                    continue
                tmp = dest.with_name(f".{dest.name}.restore-tmp")
                with open(tmp, "wb") as out:
                    out.write(fh.read())
                mode = _SECRET_MODES.get(m.name, stat.S_IMODE(m.mode) or 0o644)
                if p.parts[-1].endswith(".key") or "ssh" in p.parts and not p.parts[-1].endswith(".pub") and p.parts[-1] != "known_hosts":
                    mode = 0o600
                os.chmod(tmp, mode)
                os.replace(tmp, dest)
            except OSError as exc:
                raise BackupError(f"cannot restore {m.name}: {exc} ({count} file(s) were already replaced; run the restore again "
                                  f"once the cause is fixed)") from exc
            count += 1
    return Result(path=src, entries=count, destination=f"{roots['config']} and {roots['data']}",
                  encrypted=bool(passphrase), skipped=skipped)


# --------------------------------------------------------------------------- crypto / io

def _ts(epoch: float) -> str:
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat(timespec="seconds")


def _load(path: Path, passphrase: str) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise BackupError(f"cannot read {path}: {exc}") from exc
    if raw.startswith(MAGIC):
        if not passphrase:
            raise BackupError(f"{path} is encrypted; set the passphrase (BACKUP_PASSPHRASE or --passphrase-env)")
        return _decrypt(raw, passphrase)
    if passphrase:
        raise BackupError(f"{path} is not encrypted but a passphrase was given; refusing to guess")
    if raw[:2] != b"\x1f\x8b":
        raise BackupError(f"{path} is neither a gzip archive nor an encrypted backup")
    return raw


def _kdf(passphrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())


def _encrypt(raw: bytes, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_kdf(passphrase, salt)).encrypt(nonce, raw, MAGIC)
    return MAGIC + salt + nonce + ct


def _decrypt(blob: bytes, passphrase: str) -> bytes:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce, ct = blob[6:22], blob[22:34], blob[34:]
    try:
        return AESGCM(_kdf(passphrase, salt)).decrypt(nonce, ct, MAGIC)
    except InvalidTag:
        raise BackupError("wrong passphrase or corrupted archive") from None
