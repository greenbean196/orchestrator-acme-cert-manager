"""Startup / on-demand checks that turn silent misconfiguration into clear errors.

Covers the failure classes seen in the field:

  * the server list being read from a path that is not persistently mounted
    (UI edits silently lost on container recreate; two divergent configs),
  * target settings that look fine in the file but fail at activation time
    (each driver's preflight), and
  * a container user that cannot write where it must (non-root image).

run(strict=True) returns a Report; the entrypoint exits non-zero on fatal
findings unless STRICT_STARTUP=false.
"""
from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from . import certs, config, drivers, store

log = logging.getLogger("preflight")


@dataclass
class Finding:
    level: str          # "fatal" | "warn" | "info"
    code: str
    message: str

    def as_dict(self) -> dict:
        return {"level": self.level, "code": self.code, "message": self.message}


@dataclass
class Report:
    servers_file: str
    history_file: str
    in_container: bool
    config_mounted: bool | None
    findings: list[Finding] = field(default_factory=list)
    ssh_problems: dict[str, list[str]] = field(default_factory=dict)   # per target id: driver preflight problems

    @property
    def fatal(self) -> list[Finding]:
        return [f for f in self.findings if f.level == "fatal"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.level == "warn"]

    @property
    def ok(self) -> bool:
        return not self.fatal

    def as_dict(self) -> dict:
        return {
            "servers_file": self.servers_file,
            "history_file": self.history_file,
            "in_container": self.in_container,
            "config_mounted": self.config_mounted,
            "findings": [f.as_dict() for f in self.findings],
            "ssh_problems": self.ssh_problems,
        }


def in_container() -> bool:
    if os.environ.get("IN_CONTAINER", "").lower() in ("1", "true", "yes"):
        return True
    return Path("/.dockerenv").exists()


def is_persistently_mounted(path: Path) -> bool | None:
    """True if the nearest existing ancestor of `path` is on a mount point
    other than the container root. None if that cannot be determined.
    """
    try:
        mounts = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError:
        return None
    mount_points = set()
    for line in mounts:
        parts = line.split()
        if len(parts) > 4:
            mount_points.add(parts[4])
    p = path.resolve() if path.exists() else path.parent.resolve()
    while True:
        if str(p) in mount_points and str(p) != "/":
            return True
        if p.parent == p:
            return False
        p = p.parent


def _same_content(a: Path, b: Path) -> bool:
    try:
        return a.read_bytes() == b.read_bytes()
    except OSError:
        return False


def _migrate_history() -> Finding | None:
    """Copy a legacy /data/history.json forward once (copy, never move)."""
    legacy, new = store.LEGACY_HISTORY_FILE, store.HISTORY_FILE
    if legacy.exists() and not new.exists() and legacy != new:
        try:
            new.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(legacy, new)
            return Finding("info", "history-migrated",
                           f"copied renewal history from {legacy} to {new}")
        except OSError as exc:
            return Finding("warn", "history-migrate-failed",
                           f"could not copy {legacy} to {new}: {exc}")
    return None


def _chown_hint() -> str:
    uid, gid = os.getuid(), os.getgid()
    return (f"the container runs as uid {uid}:{gid}; on the host either set OACM_UID={uid}/OACM_GID={gid} "
            f"to your own ids in .env (./setup.sh does this) or `sudo chown -R {uid}:{gid} config data/certs data/logs`")


def check_permissions(strict: bool = True) -> list[Finding]:
    """The running user must be able to write config, certs and logs, and read the SSH material."""
    out: list[Finding] = []
    if not in_container():
        return out
    cfg = Path(config.CONFIG_DIR)
    if cfg.is_dir() and not os.access(cfg, os.W_OK):
        out.append(Finding("fatal" if strict else "warn", "perm-config-dir",
                           f"{cfg} is not writable by the service user: saves, run locks and the trust bundle "
                           f"cannot be written. {_chown_hint()}."))
    for name, d in (("perm-certs-dir", Path(config.CERTS_DIR)), ("perm-logs-dir", Path(config.LOGS_DIR))):
        if d.is_dir() and not os.access(d, os.W_OK):
            out.append(Finding("warn", name, f"{d} is not writable by the service user; issuance or logging will fail. {_chown_hint()}."))
    return out


def check_config_paths(strict: bool = True) -> list[Finding]:
    out: list[Finding] = []
    active, legacy = config.SERVERS_FILE, config.LEGACY_SERVERS_FILE
    container = in_container()
    out.append(Finding("info", "config-path", f"active server configuration: {active}"))

    if container:
        mounted = is_persistently_mounted(active)
        if mounted is False:
            out.append(Finding(
                "fatal" if strict else "warn", "config-not-mounted",
                f"{active} is not on a bind mount or volume: every change made in the web UI "
                f"would be lost when the container is recreated. Mount ./config:/config and set "
                f"SERVERS_FILE=/config/servers.json (set STRICT_STARTUP=false to override)."))

    if legacy != active and legacy.exists():
        if not active.exists():
            out.append(Finding(
                "fatal" if strict else "warn", "legacy-config-only",
                f"a server configuration exists at the legacy path {legacy} but nothing exists at "
                f"the active path {active}. Starting now would present an empty server list. "
                f"Migrate it first: copy {legacy} to {active} on the host (config/servers.json), "
                f"compare both files for differing secrets, then restart. "
                f"See README: 'Migrating from /data/servers.json'."))
        elif not _same_content(legacy, active):
            out.append(Finding(
                "warn", "legacy-config-conflict",
                f"both {legacy} and {active} exist and differ. Only {active} is used. Diff them, "
                f"merge anything newer from the legacy file by hand, then delete the legacy file "
                f"so operators cannot edit the wrong one."))
        else:
            out.append(Finding("info", "legacy-config-duplicate",
                               f"{legacy} is an identical copy of {active}; it can be deleted."))

    if active.exists():
        try:
            if not os.access(active, os.W_OK):
                out.append(Finding("warn", "config-readonly",
                                   f"{active} is not writable; saves from the web UI will fail."))
        except OSError:
            pass
        try:
            if config.file_version(active) == 1:
                out.append(Finding("info", "config-v1",
                                   f"{active} is in the pre-1.3 'servers' shape; it is read as one certificate "
                                   f"with one Orchestrator target per entry and rewritten in the 'certificates' "
                                   f"shape the next time something is saved."))
        except config.ConfigError:
            pass
    else:
        parent = active.parent
        if parent.exists() and not os.access(parent, os.W_OK):
            out.append(Finding("warn", "config-dir-readonly",
                               f"{parent} is not writable; the web UI cannot create {active.name}."))

    if config.LAB_CA_HOST and config.LAB_CA_RETIRED_DIR.is_dir():
        retired = sorted(config.LAB_CA_RETIRED_DIR.glob("*.crt"))
        if retired:
            out.append(Finding("warn", "lab-ca-rollover",
                               f"root rollover in progress: {len(retired)} retired root(s) still trusted for API "
                               f"calls ({config.LAB_CA_RETIRED_DIR}). Force renew every lab-CA server, then "
                               f"delete the retired roots."))
    mig = _migrate_history()
    if mig:
        out.append(mig)
    out.extend(check_permissions(strict=strict))
    return out


def check_servers() -> tuple[list[Finding], dict[str, list[str]]]:
    """Per-certificate and per-target checks: credentials, lab CA, driver preflight, TLS policy."""
    out: list[Finding] = []
    problems: dict[str, list[str]] = {}
    try:
        certificates = config.load_certificates()
    except config.ConfigError as exc:
        return [Finding("fatal", "config-invalid", str(exc))], problems
    if not certificates:
        out.append(Finding("info", "no-servers", "no servers configured yet (add one in the web UI)"))
        return out, problems
    for d in config.duplicate_domains(certificates):
        out.append(Finding("warn", "duplicate-domain", f"{d}: two certificates share one directory under "
                           f"{config.CERTS_DIR} and overwrite each other; keep one certificate and add the other "
                           f"system as a target of it."))
    for c in certificates:
        issued = certs.leaf_info(config.leaf_path_for(c))
        if config.is_lab_ca(c.acme_ca) and not config.lab_ca_available():
            out.append(Finding("warn", "lab-ca-missing",
                               f"{c.id}: the bundled lab CA is selected but LAB_CA_HOST is unset or "
                               f"{config.LAB_CA_ROOT} is missing; run ./setup.sh --with-ca."))
        elif config.is_lab_ca(c.acme_ca) and not config.LAB_CA_OFFLINE_MARKER.is_file():
            out.append(Finding("warn", "lab-ca-root-online",
                               f"{c.id}: {config.LAB_CA_OFFLINE_MARKER} is missing, so the lab CA root key may "
                               f"still be in the online volume; re-run ./setup.sh --with-ca and move "
                               f"data/pki-root off the host."))
        provider = (c.dns_provider or "cloudflare").lower()
        if provider == "cloudflare" and not config.cf_token_for(c):
            out.append(Finding("warn", "cf-token-missing",
                               f"{c.id}: no Cloudflare DNS token (inline or {config.CF_TOKEN_ENV})."))
        elif provider != "cloudflare" and not c.dns_env:
            out.append(Finding("warn", "dns-env-missing",
                               f"{c.id}: DNS provider {provider!r} has no variables configured; issuance will fail."))
        if not c.targets:
            out.append(Finding("warn", "no-targets", f"{c.id}: the certificate has no deploy targets."))
        for t in c.targets:
            try:
                drv = drivers.get(t.driver)
            except config.ConfigError as exc:
                out.append(Finding("fatal", "driver-unknown", f"{t.id}: {exc}"))
                continue
            probs = drv.preflight(t)
            if probs:
                problems[t.id] = probs
                code = "ssh-config" if t.driver in ("orchestrator", "ssh") else "target-config"
                out.append(Finding("warn", code,
                                   f"{t.id}: activation will fail until fixed: " + " | ".join(probs)))
            for w in drv.warnings(t):
                out.append(Finding("warn", "command-warning", f"{t.id}: {w}"))
            if t.driver == "orchestrator":
                s = t.settings
                if not s.get("verify_ssl"):
                    out.append(Finding("info", "tls-unverified",
                                       f"{t.id}: verify_ssl is off; Orchestrator API calls do not verify the "
                                       f"appliance certificate. Enable it once the production certificate is live."))
                elif issued.get("present") and issued.get("environment") in ("staging",):
                    out.append(Finding("warn", "tls-verify-vs-staging",
                                       f"{t.id}: verify_ssl is on but the issued certificate is a {issued['environment']} "
                                       f"one, which no system root trusts: API calls will fail TLS verification. Turn "
                                       f"verify_ssl off until production is live, or set ca_bundle."))
                if not (s.get("api_key") or os.environ.get(s.get("api_key_env") or "ORCH_API_KEY")):
                    out.append(Finding("warn", "api-key-missing",
                                       f"{t.id}: no Orchestrator API key (inline or {s.get('api_key_env') or 'ORCH_API_KEY'})."))
    return out, problems


def run(strict: bool | None = None) -> Report:
    if strict is None:
        strict = os.environ.get("STRICT_STARTUP", "true").lower() not in ("0", "false", "no")
    findings = check_config_paths(strict=strict)
    sfind, ssh_problems = check_servers()
    findings.extend(sfind)
    return Report(
        servers_file=str(config.SERVERS_FILE),
        history_file=str(store.HISTORY_FILE),
        in_container=in_container(),
        config_mounted=is_persistently_mounted(config.SERVERS_FILE) if in_container() else None,
        findings=findings,
        ssh_problems=ssh_problems,
    )


def log_report(report: Report) -> None:
    for f in report.findings:
        lvl = {"fatal": logging.ERROR, "warn": logging.WARNING}.get(f.level, logging.INFO)
        log.log(lvl, "[%s] %s", f.code, f.message)
