"""Activate the deployed cert (nginx reload) and verify it's actually served,
with rollback to the last-known-good certificate on failure.
(Phase 4/5 — pinned-key SSH, served-cert verification, rollback.)

Key facts learned in the lab:
  * The httpsCertificate API updates gms's keystore, but nginx terminates TLS on
    :443 and caches the cert in memory — it must be reloaded to serve the new file.
  * Because nginx never goes down during a gms restart, "is :443 answering" always
    passes. Readiness = the serial served on :443 matches the deployed serial.
  * On activation failure, we re-deploy the last-known-good cert (same validated
    API path) and reload again, so a bad run leaves the PREVIOUS working cert live.
"""
from __future__ import annotations

import logging
import socket
import ssl
import time
from pathlib import Path

import paramiko
from cryptography import x509

from . import config, deploy, sshcheck
from .drivers import base as drv
from .models import ServerConfig, StepResult

log = logging.getLogger("restart")

STEP = "restart"
_SSH_TIMEOUT = 20
_CMD_TIMEOUT = 180
_POLL_TIMEOUT = 300
_POLL_INTERVAL = 10
_ROLLBACK_POLL_TIMEOUT = 120


def restart(server: ServerConfig) -> StepResult:
    """Reload so the new cert is served; verify; roll back to last-good on failure."""
    pre = preflight(server)
    if pre is not None:
        return pre

    try:
        want_serial = _deployed_serial(server)
    except (FileNotFoundError, ValueError) as exc:
        return StepResult(STEP, ok=False,
                          message=f"cannot read deployed cert to verify against: {exc}")

    # Apply: optional gms restart + nginx reload.
    applied = _apply(server)
    if not applied.ok:
        # A failed nginx reload leaves the old cert running (safe), so no rollback needed.
        return applied

    # Verify the served cert is the one we deployed.
    ok, waited = _wait_for_served_serial(server, want_serial, _POLL_TIMEOUT)
    if ok:
        _promote_known_good(server)   # this cert is now the rollback target
        return StepResult(STEP, ok=True,
                          message=f"New certificate live on {server.orchestrator_host} "
                                  f"after ~{waited}s.",
                          detail={"serial": format(want_serial, "x"), "wait_seconds": waited})

    # Activation did not verify -> try to restore the last-known-good cert.
    return _attempt_rollback(server, want_serial)


# --------------------------------------------------------------------------- apply / ssh

def preflight(server: ServerConfig) -> StepResult | None:
    """Static SSH configuration check; None when everything looks usable."""
    problems = sshcheck.validate(server)
    if not problems:
        return None
    return StepResult(STEP, ok=False,
                      message=f"SSH configuration invalid for {server.id}: " + " | ".join(problems),
                      detail={"phase": "preflight", "problems": problems})


def _apply(server: ServerConfig) -> StepResult:
    client, err = _open(server)
    if err:
        return err
    try:
        for label, cmd in (("restart", server.restart_command),
                           ("nginx reload", server.nginx_reload_command)):
            if not cmd:
                continue
            try:
                rc, out, e = _run(client, cmd)
            except (paramiko.SSHException, socket.timeout, OSError) as exc:
                return StepResult(STEP, ok=False,
                                  message=f"{label} command could not be run over SSH: {exc}",
                                  detail={"phase": label, "command": cmd})
            if rc != 0:
                return StepResult(STEP, ok=False,
                                  message=f"{label} command exited {rc}: {_first_line(e or out)}",
                                  detail={"phase": label, "command": cmd, "exit": rc,
                                          "stderr": e[:2000], "stdout": out[:2000]})
    finally:
        client.close()
    return StepResult(STEP, ok=True, message="applied")


def _reload_nginx(server: ServerConfig) -> StepResult:
    if not server.nginx_reload_command:
        return StepResult(STEP, ok=True, message="no nginx reload configured")
    client, err = _open(server)
    if err:
        return err
    try:
        rc, out, e = _run(client, server.nginx_reload_command)
    except (paramiko.SSHException, socket.timeout, OSError) as exc:
        return StepResult(STEP, ok=False, message=f"nginx reload could not be run over SSH: {exc}")
    finally:
        client.close()
    if rc != 0:
        return StepResult(STEP, ok=False, message=f"nginx reload exited {rc}: {_first_line(e or out)}",
                          detail={"stderr": e[:2000]})
    return StepResult(STEP, ok=True, message="reloaded")


def _open(server: ServerConfig):
    """Return (client, None) or (None, StepResult-error) with an operator-facing message."""
    try:
        return sshcheck.open_client(server), None
    except sshcheck.SSHConfigError as exc:
        return None, StepResult(STEP, ok=False, message=str(exc), detail={"phase": "connect"})


def _run(client: paramiko.SSHClient, cmd: str):
    log.info("restart: running %r", cmd)
    return sshcheck.run(client, cmd, timeout=_CMD_TIMEOUT)


def _first_line(text: str) -> str:
    """The last non-empty line: wrappers such as `service` print 'Redirecting to ...' first
    and the real error last. The full output stays in the step detail."""
    lines = [ln for ln in (text or "").strip().splitlines() if ln.strip()]
    return lines[-1] if lines else "no output"


_last_line = _first_line


# --------------------------------------------------------------------------- rollback

def _rollback_dir(server: ServerConfig) -> Path:
    """rollback/ for the 1:1 entry; rollback/<target id>/ for an additional Orchestrator target on the same certificate."""
    d = config.cert_dir_for(server) / "rollback"
    if server.certificate_id and server.certificate_id != server.id:
        d = d / server.id
    return d


def _rollback_files(server: ServerConfig):
    d = _rollback_dir(server)
    return d / f"{server.domain}.cer", d / f"{server.domain}.key", d / "ca.cer"


def _promote_known_good(server: ServerConfig) -> None:
    """Copy the just-verified cert into rollback/ as the new last-known-good."""
    src = config.cert_dir_for(server)
    try:
        drv.promote_snapshot(_rollback_dir(server), drv.CertBundle.from_paths(
            src / f"{server.domain}.cer", src / f"{server.domain}.key", src / "ca.cer"))
    except (OSError, ValueError) as exc:
        log.warning("could not save known-good cert for %s: %s", server.id, exc)


def _attempt_rollback(server: ServerConfig, failed_serial: int) -> StepResult:
    cert, key, ca = _rollback_files(server)
    if not (cert.exists() and key.exists() and ca.exists()):
        return StepResult(STEP, ok=False,
                          message="activation failed and no previous certificate exists to roll back to",
                          detail={"rolled_back": False, "reason": "no known-good snapshot",
                                  "failed_serial": format(failed_serial, "x")})

    snap = drv.CertBundle.from_paths(cert, key, ca)
    failed = drv.CertBundle.for_certificate(server)
    if snap.serial and snap.serial == failed_serial:
        return StepResult(STEP, ok=False,
                          message=("activation did not verify; the certificate on disk is already the last-known-good "
                                   "one, so there is nothing to roll back to. Check the reload command and that "
                                   "orchestrator_host is the appliance you expect."),
                          detail={"rolled_back": False, "reason": "snapshot equals the failed certificate",
                                  "failed_serial": format(failed_serial, "x")})
    refusal = drv.cross_environment_refusal(server.to_target(), snap, failed)
    if refusal:
        log.error("restart(%s): %s", server.id, refusal)
        return StepResult(STEP, ok=False, message=refusal,
                          detail={"rolled_back": False, "reason": "cross-environment rollback refused",
                                  "failed_serial": format(failed_serial, "x"), "snapshot_serial": snap.serial_hex,
                                  "snapshot_environment": snap.environment, "failed_environment": failed.environment})

    log.warning("restart(%s): activation failed — rolling back to last-known-good", server.id)
    dres = deploy.deploy_paths(server, cert, key, ca)
    if not dres.ok:
        return StepResult(STEP, ok=False,
                          message=f"activation failed; rollback re-deploy failed: {dres.message}",
                          detail={"rolled_back": False})

    rel = _reload_nginx(server)
    if not rel.ok:
        return StepResult(STEP, ok=False,
                          message=f"activation failed; rollback reload failed: {rel.message}",
                          detail={"rolled_back": False})

    prev_serial = _deployed_serial_from(cert)
    ok, _ = _wait_for_served_serial(server, prev_serial, _ROLLBACK_POLL_TIMEOUT)
    crossed = bool(snap.environment and failed.environment and snap.environment != failed.environment)
    msg = ("activation verification failed — rolled back to previous certificate" if ok
           else "activation failed and rollback did not verify")
    if ok and crossed:
        msg += (f" (CROSS-ENVIRONMENT: restored a {snap.environment} certificate in place of a "
                f"{failed.environment} one, as allowed by this target's rollback policy)")
    return StepResult(STEP, ok=False,
                      message=msg,
                      detail={"rolled_back": ok,
                              "restored_serial": format(prev_serial, "x"),
                              "failed_serial": format(failed_serial, "x"),
                              "cross_environment": crossed,
                              "snapshot_environment": snap.environment})


# --------------------------------------------------------------------------- cert helpers

def _deployed_serial(server: ServerConfig) -> int:
    return _deployed_serial_from(config.cert_dir_for(server) / f"{server.domain}.cer")


def _deployed_serial_from(leaf_path: Path) -> int:
    return x509.load_pem_x509_certificate(Path(leaf_path).read_bytes()).serial_number


def _served_serial(host: str, port: int = 443, timeout: int = 10) -> int:
    pem = ssl.get_server_certificate((host, port), timeout=timeout)
    return x509.load_pem_x509_certificate(pem.encode()).serial_number


def _wait_for_served_serial(server: ServerConfig, want_serial: int, poll_timeout: int) -> tuple[bool, int]:
    deadline = time.time() + poll_timeout
    waited = 0
    while time.time() < deadline:
        try:
            if _served_serial(server.orchestrator_host) == want_serial:
                return True, waited
        except (ssl.SSLError, OSError):
            pass
        time.sleep(_POLL_INTERVAL)
        waited += _POLL_INTERVAL
    return False, waited
