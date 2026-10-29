"""SSH configuration validation and a non-disruptive connection test.

Everything the activation stage needs from SSH is checked here *before* a
Paramiko connection is attempted, so a misconfiguration surfaces as a short,
actionable message instead of a low-level traceback such as
"[Errno 2] No such file or directory: ''".

validate(server)      -> list of human-readable problems (empty == OK)
warnings(server)      -> list of non-fatal smells in the activation commands
load_private_key(p)   -> paramiko PKey, or raises SSHConfigError
test_connection(s)    -> StepResult: authenticates and checks sudo
                         authorization with `sudo -n -l` (never restarts anything)

The ``*_endpoint`` functions take the SSH parameters explicitly so the generic
SSH/SCP driver shares them; the ``server``-taking functions are the
Orchestrator view of the same checks.
"""
from __future__ import annotations

import logging
import os
import shlex
import socket
from dataclasses import dataclass
from pathlib import Path

import paramiko

from . import config
from .models import ServerConfig, StepResult

log = logging.getLogger("sshcheck")

STEP = "ssh-test"
_CONNECT_TIMEOUT = 20
_CMD_TIMEOUT = 30
_KEY_CLASSES = (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey)


class SSHConfigError(Exception):
    """A problem with the SSH settings that must be fixed by the operator."""


@dataclass
class Endpoint:
    """The SSH parameters of one target."""
    label: str
    host: str
    port: int
    user: str
    key_path: str
    known_hosts: str

    @classmethod
    def of(cls, server: ServerConfig) -> "Endpoint":
        return cls(server.id, server.orchestrator_host, int(server.ssh_port), server.ssh_user,
                   server.ssh_key_path, server.ssh_known_hosts)


# --------------------------------------------------------------------------- static checks

def known_hosts_entry_name(host: str, port: int) -> str:
    """The known_hosts key name Paramiko/OpenSSH use for host:port."""
    return host if int(port) == 22 else f"[{host}]:{port}"


def load_private_key(path: str) -> paramiko.PKey:
    """Parse an unencrypted private key file of any type Paramiko supports."""
    if not path:
        raise SSHConfigError("ssh.key_path is empty")
    p = Path(path)
    if not p.is_file():
        raise SSHConfigError(f"private key not found at {path}")
    if not os.access(p, os.R_OK):
        raise SSHConfigError(f"private key at {path} is not readable by the service user "
                             f"(uid {os.getuid()}) — fix the file's ownership/permissions")
    last: Exception | None = None
    for cls in _KEY_CLASSES:
        try:
            return cls.from_private_key_file(str(p))
        except paramiko.PasswordRequiredException as exc:
            raise SSHConfigError(
                f"private key at {path} is passphrase-protected; the unattended service "
                f"needs a key without a passphrase") from exc
        except (paramiko.SSHException, ValueError, OSError) as exc:
            last = exc
    raise SSHConfigError(
        f"private key at {path} could not be parsed as RSA, Ed25519 or ECDSA "
        f"(is it a *private* key in OpenSSH/PEM format?): {last}")


def validate_endpoint(ep: Endpoint) -> list[str]:
    """Every SSH configuration problem for one endpoint (empty list == OK)."""
    problems: list[str] = []

    if not ep.user:
        problems.append("ssh.user is empty — set the login the activation commands run as.")

    if not ep.key_path:
        problems.append(f"ssh.key_path is empty — configure a private key path, for example "
                        f"{config.DEFAULT_SSH_KEY}.")
    else:
        try:
            load_private_key(ep.key_path)
        except SSHConfigError as exc:
            problems.append(str(exc))

    if not (1 <= int(ep.port) <= 65535):
        problems.append(f"ssh.port {ep.port} is out of range.")

    if not ep.known_hosts:
        problems.append(f"ssh.known_hosts is empty — pin the host key, for example "
                        f"{config.DEFAULT_KNOWN_HOSTS}.")
    else:
        kh = Path(ep.known_hosts)
        if not kh.is_file():
            problems.append(f"known_hosts not found at {ep.known_hosts} — run setup.sh "
                            f"(or ssh-keyscan) and verify the fingerprint before trusting it.")
        elif not os.access(kh, os.R_OK):
            problems.append(f"known_hosts at {ep.known_hosts} is not readable by the service user.")
        else:
            try:
                hk = paramiko.HostKeys(str(kh))
            except (paramiko.SSHException, OSError, ValueError) as exc:
                problems.append(f"known_hosts at {ep.known_hosts} could not be parsed: {exc}")
            else:
                name = known_hosts_entry_name(ep.host, ep.port)
                if not hk.lookup(name):
                    problems.append(
                        f"known_hosts at {ep.known_hosts} has no entry for {name!r} — "
                        f"the entry must match the host (and port) the tool connects to.")
    return problems


def validate(server: ServerConfig) -> list[str]:
    """Return every SSH configuration problem for this server (empty list == OK)."""
    problems = validate_endpoint(Endpoint.of(server))
    if not server.restart_command and not server.nginx_reload_command:
        problems.append("no restart or nginx reload command is configured; nothing would activate the certificate.")
    return problems


def command_warnings(label: str, command: str, expect_no_block: bool = False) -> list[str]:
    """Non-fatal smells in an activation command (issue #15)."""
    out: list[str] = []
    cmd = (command or "").strip()
    if not cmd:
        return out
    try:
        parts = shlex.split(cmd)
    except ValueError:
        return [f"{label} could not be parsed as a shell command: {cmd!r}"]
    if parts and parts[0] != "sudo":
        out.append(f"{label} does not start with sudo — it will run unprivileged and the sudoers rule is not probed: {cmd!r}")
    base = [p for p in parts if p != "sudo" and not p.startswith("-")] or parts
    prog = os.path.basename(base[0]) if base else ""
    if prog == "service":
        out.append(f"{label} uses the 'service' wrapper, which prints 'Redirecting to ...' before the real error "
                   f"and cannot restart without blocking; prefer '/bin/systemctl restart --no-block <unit>': {cmd!r}")
    if expect_no_block and prog == "systemctl" and "restart" in parts and "--no-block" not in parts:
        out.append(f"{label} is a systemctl restart without --no-block: the SSH command blocks until GMS has "
                   f"restarted and can hit the command timeout: {cmd!r}")
    return out


def warnings(server: ServerConfig) -> list[str]:
    return (command_warnings("restart_command", server.restart_command, expect_no_block=True)
            + command_warnings("nginx_reload_command", server.nginx_reload_command))


# --------------------------------------------------------------------------- connection

def classify_connect_error(exc: Exception, ep: Endpoint) -> str:
    name = known_hosts_entry_name(ep.host, ep.port)
    if isinstance(exc, paramiko.BadHostKeyException):
        return (f"SSH host key for {name} does not match the pinned entry in "
                f"{ep.known_hosts}. If the appliance was rebuilt, re-pin it after "
                f"verifying the new fingerprint out of band; never disable host-key checking.")
    if isinstance(exc, paramiko.AuthenticationException):
        return (f"SSH authentication failed for {ep.user}@{name}: the public half of "
                f"{ep.key_path} is not in that account's authorized_keys, or the account "
                f"does not permit key authentication. With an RSA key it can also mean the server accepts only "
                f"SHA-1 (ssh-rsa) signatures, which this client no longer sends: enable rsa-sha2-256/512 there.")
    if isinstance(exc, paramiko.SSHException):
        msg = str(exc)
        if "not found in known_hosts" in msg or "Unknown server" in msg:
            return (f"SSH host key for {name} is not pinned in {ep.known_hosts}; "
                    f"add it after verifying the fingerprint.")
        if "no acceptable" in msg.lower() or "incompatible ssh peer" in msg.lower():
            return (f"SSH negotiation with {name} failed: {msg}. The server offers only algorithms this client no "
                    f"longer speaks (typically SHA-1: an ssh-rsa host key signature, diffie-hellman-*-sha1 key exchange "
                    f"or a DSS key). Enable rsa-sha2-256/512, ecdsa or ed25519 host keys and a SHA-2 key exchange on "
                    f"the server; this tool does not re-enable SHA-1.")
        return f"SSH negotiation with {name} failed: {msg}"
    if isinstance(exc, socket.timeout):
        return f"SSH connection to {name} timed out after {_CONNECT_TIMEOUT}s."
    if isinstance(exc, OSError):
        return f"SSH connection to {name} failed: {exc}"
    return f"SSH connection to {name} failed: {exc!r}"


def _classify_connect_error(exc: Exception, server: ServerConfig) -> str:
    return classify_connect_error(exc, Endpoint.of(server))


def connect(ep: Endpoint, extra_problems: list[str] | None = None) -> paramiko.SSHClient:
    """Validate the endpoint and return a connected client; SSHConfigError on any failure."""
    problems = validate_endpoint(ep) + list(extra_problems or [])
    if problems:
        raise SSHConfigError(
            f"SSH configuration invalid for {ep.label}:\n  - " + "\n  - ".join(problems))

    pkey = load_private_key(ep.key_path)
    client = paramiko.SSHClient()
    try:
        client.load_host_keys(ep.known_hosts)
    except (OSError, paramiko.SSHException) as exc:
        raise SSHConfigError(f"cannot load known_hosts {ep.known_hosts}: {exc}") from exc
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            hostname=ep.host,
            port=int(ep.port),
            username=ep.user,
            pkey=pkey,
            timeout=_CONNECT_TIMEOUT,
            banner_timeout=_CONNECT_TIMEOUT,
            auth_timeout=_CONNECT_TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
        )
    except (paramiko.SSHException, OSError) as exc:
        client.close()
        raise SSHConfigError(classify_connect_error(exc, ep)) from exc
    return client


def open_client(server: ServerConfig) -> paramiko.SSHClient:
    """Validate the SSH settings and return a connected client.

    Raises SSHConfigError with an operator-facing message on any failure.
    """
    extra = [] if (server.restart_command or server.nginx_reload_command) else \
        ["no restart or nginx reload command is configured; nothing would activate the certificate."]
    return connect(Endpoint.of(server), extra)


def command_timeout() -> int:
    return _CMD_TIMEOUT


def run(client: paramiko.SSHClient, cmd: str, timeout: int = _CMD_TIMEOUT) -> tuple[int, str, str]:
    """Run one command; returns (exit_status, stdout, stderr).

    The wait for the exit status is bounded by ``timeout`` (Paramiko's
    recv_exit_status() alone waits forever) and output is drained while
    waiting, so a chatty or hung command can neither block on a full pipe nor
    stall the pipeline past the deadline.
    """
    import time as _time
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    chan = stdout.channel
    out, err = bytearray(), bytearray()
    deadline = _time.monotonic() + timeout
    while True:
        while chan.recv_ready():
            out += chan.recv(65536)
        while chan.recv_stderr_ready():
            err += chan.recv_stderr(65536)
        if chan.exit_status_ready():
            break
        if _time.monotonic() >= deadline:
            chan.close()
            raise socket.timeout(f"command did not finish within {timeout}s: {cmd!r}")
        chan.status_event.wait(0.5)
    while chan.recv_ready():
        out += chan.recv(65536)
    while chan.recv_stderr_ready():
        err += chan.recv_stderr(65536)
    rc = chan.recv_exit_status()
    return rc, out.decode(errors="replace").strip(), err.decode(errors="replace").strip()


def authorization_probe(command: str) -> str | None:
    """Turn 'sudo <cmd>' into 'sudo -n -l <cmd>' (checks sudoers, runs nothing).

    Returns None when the command does not go through sudo (nothing to probe).
    """
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    if not parts or parts[0] != "sudo":
        return None
    rest = [p for p in parts[1:] if p not in ("-n", "--non-interactive")]
    if not rest:
        return None
    return "sudo -n -l " + " ".join(shlex.quote(p) for p in rest)


def probe_commands(client: paramiko.SSHClient, user: str, commands: list[tuple[str, str]]) -> tuple[bool, list[dict]]:
    """Run `sudo -n -l <command>` for each (label, command); (all_ok, checks)."""
    checks: list[dict] = []
    ok = True
    for label, cmd in commands:
        if not cmd:
            continue
        probe = authorization_probe(cmd)
        if probe is None:
            checks.append({"label": label, "command": cmd, "ok": True, "note": "not using sudo; authorization not probed"})
            continue
        try:
            rc, out, err = run(client, probe)
        except (paramiko.SSHException, socket.timeout, OSError) as exc:
            ok = False
            checks.append({"label": label, "command": cmd, "ok": False, "error": f"probe failed: {exc}"})
            continue
        passed = rc == 0
        ok = ok and passed
        entry = {"label": label, "command": cmd, "ok": passed, "probe": probe, "exit": rc,
                 "stdout": out[:500], "stderr": err[:500]}
        if not passed:
            if "password" in (err + out).lower():
                entry["hint"] = (f"sudo wants a password for {user}: add a NOPASSWD "
                                 f"sudoers rule scoped to exactly this command.")
            else:
                entry["hint"] = "sudoers does not permit this exact command for this user."
        checks.append(entry)
    return ok, checks


def test_connection(server: ServerConfig) -> StepResult:
    """Authenticate and verify sudo authorization for the activation commands.

    Runs `sudo -n -l <command>` for each configured command, which asks sudo
    whether the command would be permitted without a password. No service is
    restarted or reloaded.
    """
    try:
        client = open_client(server)
    except SSHConfigError as exc:
        return StepResult(STEP, ok=False, message=str(exc), detail={"phase": "connect"})

    try:
        ok, checks = probe_commands(client, server.ssh_user,
                                    [("restart_command", server.restart_command),
                                     ("nginx_reload_command", server.nginx_reload_command)])
    finally:
        client.close()

    if ok:
        msg = (f"SSH key authentication to {server.ssh_user}@{server.orchestrator_host} succeeded "
               f"and sudo permits the activation commands without a password.")
    else:
        bad = [c for c in checks if not c.get("ok")]
        msg = (f"SSH authentication to {server.ssh_user}@{server.orchestrator_host} succeeded, "
               f"but sudo authorization failed for: "
               + "; ".join(f"{c['command']!r} ({c.get('hint') or c.get('error')})" for c in bad))
    return StepResult(STEP, ok=ok, message=msg, detail={"phase": "authorize", "checks": checks})
