"""Load, validate, and persist server configuration in JSON.

Path resolution (all overridable through the environment):

    CONFIG_DIR     persistent, writable directory (default /config). Holds
                   servers.json, admin.json, session.secret and history.json.
    DATA_DIR       runtime data root (default /data). Holds certs/, logs/, ssh/.
    SERVERS_FILE   explicit path to the server list (default CONFIG_DIR/servers.json).

Earlier releases defaulted SERVERS_FILE to DATA_DIR/servers.json, which is
*not* covered by the documented bind mounts, so UI edits were lost when the
container was recreated. LEGACY_SERVERS_FILE is kept only so preflight can
detect that situation and tell the operator how to migrate.

File shapes
-----------
``{"servers": [...]}`` (1.0 - 1.2) holds one Orchestrator per entry.
``{"version": 2, "certificates": [...]}`` (1.3+) holds certificates, each with
a ``targets`` list (driver + settings). A v1 file is migrated in memory on every
load (one certificate + one Orchestrator target per entry, same id for both)
and is written back in the v2 shape only when something is saved.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .models import ORCHESTRATOR_DRIVER, Certificate, ServerConfig, Target

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CONFIG_DIR = Path(os.environ.get("CONFIG_DIR", "/config"))
SERVERS_FILE = Path(os.environ.get("SERVERS_FILE") or (CONFIG_DIR / "servers.json"))
LEGACY_SERVERS_FILE = DATA_DIR / "servers.json"
CERTS_DIR = DATA_DIR / "certs"
LOGS_DIR = DATA_DIR / "logs"
SSH_DIR = DATA_DIR / "ssh"

DEFAULT_SSH_KEY = str(SSH_DIR / "orch_restart")
DEFAULT_KNOWN_HOSTS = str(SSH_DIR / "known_hosts")
DEFAULT_RESTART_COMMAND = "sudo /bin/systemctl restart --no-block gms.service"
DEFAULT_NGINX_RELOAD_COMMAND = "sudo /bin/systemctl reload nginx"

CF_TOKEN_ENV = "CF_DNS_API_TOKEN"  # env var Lego reads for the Cloudflare DNS-01 challenge

# Bundled lab CA (step-ca), optional. See README "Bundled lab CA".
LAB_CA_ID = "lab"                                  # acme.ca value that selects it
LAB_CA_HOST = os.environ.get("LAB_CA_HOST", "")
LAB_CA_PORT = int(os.environ.get("LAB_CA_PORT", "9000") or 9000)   # step-ca listens on this port inside and outside
LAB_CA_PROVISIONER = "lab"   # fixed: created by pki/lab-ca-init.sh; not configurable (see README)
LAB_CA_CERTS_DIR = Path(os.environ.get("LAB_CA_CERTS_DIR", str(DATA_DIR / "pki" / "certs")))
LAB_CA_ROOT = LAB_CA_CERTS_DIR / "root_ca.crt"
LAB_CA_INTERMEDIATE = LAB_CA_CERTS_DIR / "intermediate_ca.crt"
LAB_CA_OFFLINE_MARKER = LAB_CA_CERTS_DIR / "root-key-offline"   # written by lab-ca-init.sh
LAB_CA_RETIRED_DIR = LAB_CA_CERTS_DIR / "retired"   # previous roots kept in API trust during a root rollover


class ConfigError(Exception):
    pass


def _one(s: dict) -> ServerConfig:
    try:
        acme = s.get("acme", {}) or {}
        dns = s.get("dns", {}) or {}
        ssh = s.get("ssh", {}) or {}
        return ServerConfig(
            id=s["id"],
            name=s.get("name", s["id"]),
            orchestrator_host=s["orchestrator_host"],
            domain=s.get("domain") or s["orchestrator_host"],
            acme_ca=acme.get("ca", "letsencrypt"),
            acme_email=acme.get("email", ""),
            key_type=acme.get("key_type", "rsa2048"),
            dns_provider=dns.get("provider", "cloudflare"),
            dns_api_token=dns.get("api_token", ""),
            ssh_user=(ssh.get("user") or "").strip(),
            ssh_key_path=(ssh.get("key_path") or "").strip(),
            ssh_known_hosts=(ssh.get("known_hosts") or DEFAULT_KNOWN_HOSTS).strip(),
            ssh_port=int(ssh.get("port") or 22),
            restart_command=ssh.get("restart_command", DEFAULT_RESTART_COMMAND),
            nginx_reload_command=ssh.get("nginx_reload_command", DEFAULT_NGINX_RELOAD_COMMAND),
            api_key_env=s.get("api_key_env", "ORCH_API_KEY"),
            api_key=s.get("api_key", ""),
            verify_ssl=bool(s.get("verify_ssl", False)),
            ca_bundle=(s.get("ca_bundle") or "").strip(),
            ca_bundle_mode=(s.get("ca_bundle_mode") or "exclusive").strip().lower(),
            allow_cross_env_rollback=bool(s.get("allow_cross_env_rollback", False)),
            dns_env={str(k): str(v) for k, v in (dns.get("env") or {}).items()},
        )
    except KeyError as exc:
        raise ConfigError(f"server entry missing required field: {exc}") from exc
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"server entry {s.get('id', '?')!r} has an invalid value: {exc}") from exc


def _to_dict(s: ServerConfig) -> dict:
    """Inverse of _one(): a ServerConfig back into the nested JSON shape."""
    return {
        "id": s.id,
        "name": s.name,
        "orchestrator_host": s.orchestrator_host,
        "domain": s.domain,
        "api_key_env": s.api_key_env,
        "api_key": s.api_key,
        "verify_ssl": s.verify_ssl,
        "ca_bundle": s.ca_bundle,
        "ca_bundle_mode": s.ca_bundle_mode,
        "allow_cross_env_rollback": s.allow_cross_env_rollback,
        "acme": {"ca": s.acme_ca, "email": s.acme_email, "key_type": s.key_type},
        "dns": {"provider": s.dns_provider, "api_token": s.dns_api_token, "env": dict(s.dns_env)},
        "ssh": {
            "user": s.ssh_user,
            "key_path": s.ssh_key_path,
            "known_hosts": s.ssh_known_hosts,
            "port": s.ssh_port,
            "restart_command": s.restart_command,
            "nginx_reload_command": s.nginx_reload_command,
        },
    }


def server_from_dict(s: dict) -> ServerConfig:
    """Public wrapper around _one() for building a ServerConfig from form data."""
    return _one(s)


CONFIG_VERSION = 2


def _parse_servers_file(path: Path) -> list[dict]:
    """Legacy accessor: the raw v1 entries (or v2 certificates flattened to v1 shape)."""
    return [_v1_entry(c, t) for c in _read_certificates(path) for t in c.orchestrator_targets()]


def _v1_entry(cert: Certificate, target: Target) -> dict:
    return _to_dict(ServerConfig.from_parts(cert, target))


def _read_raw(path: Path):
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path} is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    return raw


def file_version(path: Path | None = None) -> int | None:
    """1 for the legacy ``servers`` shape, 2 for ``certificates``, None when absent."""
    path = path or SERVERS_FILE
    if not path.exists():
        return None
    raw = _read_raw(path)
    if isinstance(raw, dict) and "certificates" in raw:
        return 2
    return 1


def _normalize_target(cert_id: str, t: dict) -> Target:
    if not isinstance(t, dict) or not t.get("id") or not t.get("driver"):
        raise ConfigError(f"certificate {cert_id!r}: every target needs an id and a driver")
    settings = dict(t.get("settings") or {})
    if t["driver"] == ORCHESTRATOR_DRIVER:
        # Same defaults the v1 loader applied, so a hand-edited v2 file behaves the same.
        ssh = dict(settings.get("ssh") or {})
        ssh.setdefault("known_hosts", DEFAULT_KNOWN_HOSTS)
        ssh.setdefault("restart_command", DEFAULT_RESTART_COMMAND)
        ssh.setdefault("nginx_reload_command", DEFAULT_NGINX_RELOAD_COMMAND)
        ssh["user"] = (ssh.get("user") or "").strip()
        ssh["key_path"] = (ssh.get("key_path") or "").strip()
        ssh["known_hosts"] = (ssh.get("known_hosts") or DEFAULT_KNOWN_HOSTS).strip()
        try:
            ssh["port"] = int(ssh.get("port") or 22)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"target {t['id']!r}: ssh.port is not a number: {exc}") from exc
        settings["ssh"] = ssh
        settings.setdefault("api_key_env", "ORCH_API_KEY")
        settings.setdefault("api_key", "")
        settings["verify_ssl"] = bool(settings.get("verify_ssl", False))
        settings["ca_bundle"] = (settings.get("ca_bundle") or "").strip()
        settings["ca_bundle_mode"] = (settings.get("ca_bundle_mode") or "exclusive").strip().lower()
        settings["allow_cross_env_rollback"] = bool(settings.get("allow_cross_env_rollback", False))
        if not settings.get("orchestrator_host"):
            raise ConfigError(f"target {t['id']!r}: orchestrator_host is required")
    return Target(id=str(t["id"]), driver=str(t["driver"]), name=str(t.get("name") or ""),
                  settings=settings, certificate_id=cert_id)


def _cert_from_v2(c: dict) -> Certificate:
    try:
        acme = c.get("acme", {}) or {}
        dns = c.get("dns", {}) or {}
        cert = Certificate(
            id=c["id"], name=c.get("name") or c["id"], domain=c["domain"],
            acme_ca=acme.get("ca", "letsencrypt"), acme_email=acme.get("email", ""),
            key_type=acme.get("key_type", "rsa2048"),
            dns_provider=dns.get("provider", "cloudflare"), dns_api_token=dns.get("api_token", ""),
            dns_env={str(k): str(v) for k, v in (dns.get("env") or {}).items()},
        )
    except KeyError as exc:
        raise ConfigError(f"certificate entry missing required field: {exc}") from exc
    cert.targets = [_normalize_target(cert.id, t) for t in (c.get("targets") or [])]
    return cert.attach()


def _read_certificates(path: Path) -> list[Certificate]:
    raw = _read_raw(path)
    if isinstance(raw, dict) and "certificates" in raw:
        entries = raw.get("certificates") or []
        if not isinstance(entries, list):
            raise ConfigError(f"{path}: expected a 'certificates' list")
        certs = [_cert_from_v2(c) for c in entries]
    else:
        entries = raw.get("servers", []) if isinstance(raw, dict) else raw
        if not isinstance(entries, list):
            raise ConfigError(f"{path}: expected a 'servers' list")
        certs = [_one(s).to_certificate() for s in entries]
    seen_c: set[str] = set()
    seen_t: set[str] = set()
    for c in certs:
        if c.id in seen_c:
            raise ConfigError(f"{path}: duplicate certificate id {c.id!r}")
        seen_c.add(c.id)
        for t in c.targets:
            if t.id in seen_t:
                raise ConfigError(f"{path}: duplicate target id {t.id!r} (target ids are global)")
            seen_t.add(t.id)
    return certs


def load_certificates(path: Path | None = None) -> list[Certificate]:
    """Every certificate with its targets; a v1 file is migrated in memory."""
    path = path or SERVERS_FILE
    if not path.exists():
        return []
    return _read_certificates(path)


def load_servers(path: Path | None = None) -> list[ServerConfig]:
    """The flattened legacy view: one entry per Orchestrator target."""
    return [c.as_server(t) for c in load_certificates(path) for t in c.orchestrator_targets()]


def get_certificate(cert_id: str) -> Certificate:
    for c in load_certificates():
        if c.id == cert_id:
            return c
    raise ConfigError(f"no certificate with id {cert_id!r}")


def all_targets() -> list[tuple[Certificate, Target]]:
    return [(c, t) for c in load_certificates() for t in c.targets]


def get_target(target_id: str) -> tuple[Certificate, Target]:
    for c, t in all_targets():
        if t.id == target_id:
            return c, t
    raise ConfigError(f"no target with id {target_id!r}")


def target_exists(target_id: str) -> bool:
    return any(t.id == target_id for _, t in all_targets())


def get_server(server_id: str) -> ServerConfig:
    """The Orchestrator target with this id, flattened with its certificate."""
    for s in load_servers():
        if s.id == server_id:
            return s
    raise ConfigError(f"no server with id {server_id!r}")


def server_exists(server_id: str) -> bool:
    """True when any certificate or target already uses this id."""
    certs = load_certificates()
    return any(c.id == server_id for c in certs) or any(t.id == server_id for c in certs for t in c.targets)


def _lock_down(path: Path) -> None:
    """Restrict a secret-bearing file to owner read/write (best effort)."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def save_certificates(certs: list[Certificate]) -> None:
    """Write the full configuration back to servers.json in the v2 shape.

    Writes in place rather than renaming a temp file over the target, because
    servers.json may be an individual Docker bind mount — os.replace() onto a
    mount point fails with EBUSY. A .bak copy is kept so a mid-write failure is
    still recoverable. Both files are chmod 600 because they hold secrets.
    """
    SERVERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": CONFIG_VERSION, "certificates": [c.as_dict() for c in certs]}
    text = json.dumps(payload, indent=2) + "\n"
    if SERVERS_FILE.exists():
        current = SERVERS_FILE.read_bytes()
        bak = SERVERS_FILE.with_suffix(".json.bak")
        _write_private(bak, current)
        v1_copy = SERVERS_FILE.with_suffix(".json.v1")
        if file_version() == 1 and not v1_copy.exists():
            _write_private(v1_copy, current)       # kept once: the pre-1.3 file a rollback needs, whatever .bak holds later
    _write_private(SERVERS_FILE, text.encode())


def _write_private(path: Path, data: bytes) -> None:
    """Mode-600 file written atomically; in place only when the target is a single-file bind mount (EBUSY)."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    try:
        os.replace(tmp, path)
    except OSError:
        with open(path, "wb") as fh:
            fh.write(data)
        _lock_down(path)
        try:
            tmp.unlink()
        except OSError:
            pass


class _config_lock:
    """Cross-process lock around load-modify-save of servers.json."""

    def __enter__(self):
        import fcntl
        SERVERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        self._fd = os.open(SERVERS_FILE.with_name(f".{SERVERS_FILE.name}.lock"), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self._fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        import fcntl
        fcntl.flock(self._fd, fcntl.LOCK_UN)
        os.close(self._fd)
        return False


def save_servers(servers: list[ServerConfig]) -> None:
    """Legacy writer: each entry becomes one certificate with one Orchestrator target."""
    save_certificates([s.to_certificate() for s in servers])


def upsert_certificate(cert: Certificate) -> None:
    """Insert a certificate or replace the one with the same id (preserving order)."""
    with _config_lock():
        certs = load_certificates()
        for i, c in enumerate(certs):
            if c.id == cert.id:
                certs[i] = cert
                break
        else:
            certs.append(cert)
        for t in cert.targets:
            t.certificate_id = cert.id
        save_certificates(certs)


def upsert_target(cert_id: str, target: Target) -> None:
    """Insert or replace one target of an existing certificate."""
    with _config_lock():
        _upsert_target(cert_id, target)


def _upsert_target(cert_id: str, target: Target) -> None:
    certs = load_certificates()
    cert = next((c for c in certs if c.id == cert_id), None)
    if cert is None:
        raise ConfigError(f"no certificate with id {cert_id!r}")
    for c in certs:
        for t in c.targets:
            if t.id == target.id and c.id != cert_id:
                raise ConfigError(f"target id {target.id!r} is already used by certificate {c.id!r}")
    target.certificate_id = cert_id
    for i, t in enumerate(cert.targets):
        if t.id == target.id:
            cert.targets[i] = target
            break
    else:
        cert.targets.append(target)
    cert.attach()
    save_certificates(certs)


def delete_target(target_id: str) -> bool:
    """Remove one target; a certificate left without targets is removed too."""
    with _config_lock():
        certs = load_certificates()
        emptied: set[str] = set()
        changed = False
        for c in certs:
            before = len(c.targets)
            c.targets = [t for t in c.targets if t.id != target_id]
            if len(c.targets) != before:
                changed = True
                if not c.targets:
                    emptied.add(c.id)
        if not changed:
            return False
        save_certificates([c for c in certs if c.id not in emptied])     # only the certificate this target emptied
        return True


def upsert_server(server: ServerConfig) -> None:
    """Insert a new Orchestrator entry or replace an existing one in place.

    The certificate's other targets (if any) are kept; only the Orchestrator
    target with this id and the certificate's own fields are replaced.
    """
    with _config_lock():
        certs = load_certificates()
        new = server.to_certificate()
        cert = next((c for c in certs if c.id == new.id), None)
        if cert is None:
            certs.append(new)
        else:
            others = [t for t in cert.targets if t.id != server.id]
            new.targets = new.targets + others
            new.attach()
            certs[certs.index(cert)] = new
        save_certificates(certs)


def delete_server(server_id: str) -> bool:
    """Remove a certificate (and all its targets) by id. Returns True if something was removed."""
    with _config_lock():
        certs = load_certificates()
        remaining = [c for c in certs if c.id != server_id]
        if len(remaining) == len(certs):
            return False
        save_certificates(remaining)
        return True


def api_key_for(server: ServerConfig) -> str:
    """Resolve the Orchestrator API key: inline value first, then the env var."""
    key = server.api_key or os.environ.get(server.api_key_env, "")
    if not key:
        raise ConfigError(
            f"no Orchestrator API key for {server.id!r}: set it in the server's "
            f"settings, or export {server.api_key_env}"
        )
    return key


def cf_token_for(cert) -> str:
    """Resolve the Cloudflare DNS token: inline value first, then the env var.

    Accepts a Certificate or the flattened ServerConfig (both carry dns_api_token).
    """
    return cert.dns_api_token or os.environ.get(CF_TOKEN_ENV, "")


def _domain_dir(domain: str) -> Path:
    """CERTS_DIR/<domain>, refusing anything that would escape CERTS_DIR."""
    name = (domain or "").strip()
    if not name or "/" in name or name in (".", "..") or name.startswith("."):
        raise ConfigError(f"invalid certificate domain {domain!r}")
    d = (CERTS_DIR / name)
    if d.resolve().parent != CERTS_DIR.resolve():
        raise ConfigError(f"certificate domain {domain!r} resolves outside {CERTS_DIR}")
    return d


def duplicate_domains(certs: list[Certificate]) -> list[str]:
    seen: dict[str, str] = {}
    dupes = []
    for c in certs:
        key = c.domain.lower()
        if key in seen:
            dupes.append(f"{c.id} and {seen[key]} both issue for {c.domain}")
        seen.setdefault(key, c.id)
    return dupes


def cert_dir_for(cert) -> Path:
    """Per-certificate directory (Lego state, flattened files, rollback snapshot)."""
    d = _domain_dir(cert.domain)
    d.mkdir(parents=True, exist_ok=True)
    return d


def leaf_path_for(cert) -> Path:
    """The flattened leaf certificate for this certificate (may not exist yet)."""
    return _domain_dir(cert.domain) / f"{cert.domain}.cer"


def is_staging_ca(acme_ca: str) -> bool:
    ca = (acme_ca or "").strip().lower()
    return ca == "letsencrypt_test" or "staging" in ca


def is_lab_ca(acme_ca: str) -> bool:
    return (acme_ca or "").strip().lower() == LAB_CA_ID


def ca_environment(acme_ca: str) -> str:
    """'lab' | 'staging' | 'production' for a configured acme.ca value."""
    if is_lab_ca(acme_ca):
        return "lab"
    return "staging" if is_staging_ca(acme_ca) else "production"


def lab_ca_base_url() -> str:
    return f"https://{LAB_CA_HOST}:{LAB_CA_PORT}" if LAB_CA_HOST else ""


def lab_ca_acme_url() -> str:
    """ACME directory of the bundled CA, or '' when it is not configured."""
    base = lab_ca_base_url()
    return f"{base}/acme/{LAB_CA_PROVISIONER}/directory" if base else ""


def lab_ca_available() -> bool:
    return bool(LAB_CA_HOST) and LAB_CA_ROOT.is_file()


_LAB_ISSUERS: tuple[float, frozenset[str]] = (-1.0, frozenset())


def lab_ca_issuer_names() -> frozenset[str]:
    """RFC 4514 subject names of the lab root, intermediate and retired roots (cached by mtime).

    A certificate whose issuer is one of these was issued by the lab CA.
    """
    global _LAB_ISSUERS
    files = [f for f in (LAB_CA_ROOT, LAB_CA_INTERMEDIATE) if f.is_file()]
    if LAB_CA_RETIRED_DIR.is_dir():
        files.extend(sorted(f for f in LAB_CA_RETIRED_DIR.glob("*.crt") if f.is_file()))
    if not files:
        return frozenset()
    stamp = max(f.stat().st_mtime for f in files)
    if stamp == _LAB_ISSUERS[0]:
        return _LAB_ISSUERS[1]
    from cryptography import x509  # lazy import
    names = set()
    for f in files:
        try:
            names.add(x509.load_pem_x509_certificate(f.read_bytes()).subject.rfc4514_string())
        except (ValueError, OSError):
            continue
    _LAB_ISSUERS = (stamp, frozenset(names))
    return _LAB_ISSUERS[1]


TRUST_DIR = CONFIG_DIR / "trust"
CA_BUNDLE_MODES = ("exclusive", "additive")
_TRUST_LOCK = __import__("threading").Lock()


def api_trust_bundle(ca_bundle: str = "", mode: str = "exclusive") -> str | bool:
    """Trust material for verified Orchestrator API calls.

    * ca_bundle set, mode "exclusive" (default): that file is the ONLY trust, as
      before the lab CA existed. A missing file is a ConfigError, never a
      fallback to broader trust.
    * ca_bundle set, mode "additive": system (certifi) roots + lab root + the
      bundle, for operators who want a private CA *and* public/lab transitions.
    * no ca_bundle: system roots + the lab root when the lab CA is configured,
      so public<->lab migrations and rollback keep verifying; plain system trust
      (True) when the lab CA is not configured.

    Combined bundles are immutable files named by content digest and written
    atomically, so concurrent deployments with different inputs never share or
    truncate each other's file.
    """
    extras: list[Path] = []
    if ca_bundle:
        p = Path(ca_bundle)
        if not p.is_file():
            raise ConfigError(f"ca_bundle {ca_bundle} is not readable; refusing to fall back to broader trust")
        if mode not in CA_BUNDLE_MODES:
            raise ConfigError(f"ca_bundle_mode must be one of {CA_BUNDLE_MODES}, got {mode!r}")
        if mode == "exclusive":
            return str(p)
        extras.append(p)
    if LAB_CA_HOST:
        # Lab trust is configured: its root is a required anchor, never a
        # silently-dropped one. A missing/unreadable root fails closed.
        if not LAB_CA_ROOT.is_file() or not os.access(LAB_CA_ROOT, os.R_OK):
            raise ConfigError(
                f"LAB_CA_HOST is set but the lab root {LAB_CA_ROOT} is missing or unreadable; refusing "
                f"to fall back to public trust. Mount ./data/pki/certs (compose does) and run "
                f"./setup.sh --with-ca, or unset LAB_CA_HOST if the lab CA is not in use.")
        extras.append(LAB_CA_ROOT)
        # During a root rollover the appliances still serve leaves from the previous
        # root; keep those roots trusted until every target has been re-issued.
        if LAB_CA_RETIRED_DIR.is_dir():
            extras.extend(sorted(f for f in LAB_CA_RETIRED_DIR.glob("*.crt") if f.is_file()))
    if not extras:
        return True
    try:
        import certifi
        system = Path(certifi.where())
    except ImportError:  # pragma: no cover
        system = None
    parts = ([system] if system and system.is_file() else []) + extras
    data = b"".join(f.read_bytes().rstrip(b"\n") + b"\n" for f in parts)
    import hashlib
    digest = hashlib.sha256(data).hexdigest()[:24]
    out = TRUST_DIR / f"api-trust-{digest}.pem"
    if out.is_file():
        return str(out)
    with _TRUST_LOCK:
        if out.is_file():
            return str(out)
        TRUST_DIR.mkdir(parents=True, exist_ok=True)
        tmp = TRUST_DIR / f".{out.name}.{os.getpid()}.tmp"
        tmp.write_bytes(data)
        os.replace(tmp, out)          # atomic: readers see either nothing or the whole file
    return str(out)


def lab_ca_root_fingerprint() -> str:
    """SHA-256 of the root certificate in DER form (same value `step certificate fingerprint` prints)."""
    if not LAB_CA_ROOT.is_file():
        return ""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    cert = x509.load_pem_x509_certificate(LAB_CA_ROOT.read_bytes())
    return cert.fingerprint(hashes.SHA256()).hex()
