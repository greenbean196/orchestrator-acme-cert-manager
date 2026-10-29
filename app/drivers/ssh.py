"""Generic SSH/SCP driver: copy the files, run a command, verify on host:port.

Covers anything with an SSH management plane and no product API: the
certificate, key and chain are uploaded over SFTP to configured paths
(written to a temporary name and renamed, so a reader never sees a partial
file), an optional activation command is run, and the served certificate on
``verify_host:verify_port`` is compared to the deployed serial. The probe
authenticates, checks the remote directories are writable and, when the
activation command uses sudo, asks sudoers whether it is permitted.
"""
from __future__ import annotations

import posixpath
import shlex
import socket
import time
from typing import Any

import paramiko

from .. import certs, config, sshcheck
from ..models import StepResult, Target
from . import register
from .base import CertBundle, Driver, Field, snapshot_info

_CMD_TIMEOUT = 180
_POLL_INTERVAL = 10


def _replace(sftp, tmp: str, path: str) -> None:
    """Move ``tmp`` over ``path`` atomically where the server allows it (posix-rename@openssh.com), else remove+rename."""
    posix = getattr(sftp, "posix_rename", None)
    if posix is not None:
        try:
            posix(tmp, path)
            return
        except IOError:
            pass      # extension unsupported by this server: fall back
    try:
        sftp.remove(path)
    except IOError:
        pass
    sftp.rename(tmp, path)


class SSHDriver(Driver):
    name = "ssh"
    label = "Generic SSH/SCP"
    steps = ("deploy", "activate")
    probe_label = "Test SSH"
    probe_help = "Authenticate, check the remote directories are writable and probe sudo for the activation command. Changes nothing."
    served_label = "Served"
    activation_label = "Activation (SSH)"

    def schema(self) -> list[Field]:
        return [
            Field("host", "Host", required=True, group="Target", help="SSH host (and, unless overridden below, the host whose served certificate is verified)."),
            Field("ssh_port", "SSH port", kind="number", default=22, group="Target",
                  via="ssh-keyscan -p <port> <host> >> data/ssh/known_hosts",
                  via_text="A non-default port changes the known_hosts entry name to [host]:port; pin it with the same port."),
            Field("ssh_user", "SSH user", required=True, group="Target"),
            Field("ssh_key_path", "Private key path", default=config.DEFAULT_SSH_KEY, group="Target",
                  help="Path inside the container; ./data/ssh on the host is mounted read-only at /data/ssh.",
                  via="./setup.sh [--key-type ed25519]",
                  via_text="Generated on the host and mounted read-only; the container cannot create keys."),
            Field("ssh_known_hosts", "Known hosts path", default=config.DEFAULT_KNOWN_HOSTS, group="Target",
                  help="Pinned host key (strict checking). Must contain an entry for the host above.",
                  via="ssh-keyscan -t rsa,ecdsa,ed25519 <host> >> data/ssh/known_hosts",
                  via_text="Pin the host key on the Docker host after confirming its fingerprint; the container never trusts a host on first use."),
            Field("remote_cert_path", "Remote certificate path", required=True, group="Files",
                  help="Where the leaf certificate (PEM) is written on the target."),
            Field("remote_key_path", "Remote private key path", required=True, group="Files",
                  help="Where the private key (PEM, mode 600) is written on the target."),
            Field("remote_chain_path", "Remote chain path (optional)", group="Files",
                  help="Where the issuer chain is written. Leave blank if the target wants a full chain in the certificate file instead."),
            Field("fullchain", "Write leaf + chain into the certificate file", kind="checkbox", default=False, group="Files",
                  help="For daemons that expect one file with the whole chain (nginx, haproxy)."),
            Field("activate_command", "Activation command (optional)", group="Activation",
                  help="Run after the upload, e.g. 'sudo /bin/systemctl reload nginx'. Must be permitted by sudoers without a password when it uses sudo."),
            Field("verify_host", "Verify host (optional)", group="Verification",
                  help="Defaults to the SSH host. The served certificate on this host:port is compared to the deployed serial."),
            Field("verify_port", "Verify port", kind="number", default=443, group="Verification"),
            Field("allow_cross_env_rollback", "Allow rollback across CA environments", kind="checkbox", default=False,
                  group="Rollback policy", advanced=True,
                  help="Off (default): a failed production activation never restores a staging or lab certificate."),
        ]

    def normalize(self, settings: dict) -> dict:
        n = super().normalize(settings)
        if not n["host"]:
            raise config.ConfigError("Host is required.")
        if not (1 <= n["ssh_port"] <= 65535):
            raise config.ConfigError("SSH port must be between 1 and 65535.")
        if not (1 <= n["verify_port"] <= 65535):
            raise config.ConfigError("Verify port must be between 1 and 65535.")
        for key in ("remote_cert_path", "remote_key_path"):
            if not n[key]:
                raise config.ConfigError(f"{key.replace('_', ' ')} is required.")
            if not n[key].startswith("/"):
                raise config.ConfigError(f"{key.replace('_', ' ')} must be absolute.")
        if n["remote_chain_path"] and not n["remote_chain_path"].startswith("/"):
            raise config.ConfigError("remote chain path must be absolute.")
        n["ssh_known_hosts"] = n["ssh_known_hosts"] or config.DEFAULT_KNOWN_HOSTS
        return n

    def flat(self, target: Target) -> dict:
        return dict(target.settings)

    # ---- helpers ------------------------------------------------------------
    def endpoint(self, target: Target) -> sshcheck.Endpoint:
        s = target.settings
        return sshcheck.Endpoint(target.id, s.get("host", ""), int(s.get("ssh_port") or 22), s.get("ssh_user", ""),
                                 s.get("ssh_key_path", ""), s.get("ssh_known_hosts", ""))

    def display_host(self, target: Target) -> str:
        return str(target.settings.get("host") or "")

    def verify_endpoint(self, target: Target) -> tuple[str, int]:
        s = target.settings
        return (s.get("verify_host") or s.get("host") or ""), int(s.get("verify_port") or 443)

    def summary(self, target: Target) -> dict[str, Any]:
        s = target.settings
        cert = self.certificate_of(target)
        vh, vp = self.verify_endpoint(target)
        return {
            "host": s.get("host"), "ssh_user": s.get("ssh_user"), "ssh_port": s.get("ssh_port"),
            "ssh_key_path": s.get("ssh_key_path"), "ssh_known_hosts": s.get("ssh_known_hosts"),
            "remote_cert_path": s.get("remote_cert_path"), "remote_key_path": s.get("remote_key_path"),
            "remote_chain_path": s.get("remote_chain_path"), "fullchain": bool(s.get("fullchain")),
            "activate_command": s.get("activate_command"), "verify": f"{vh}:{vp}",
            "snapshot": snapshot_info(s, self.snapshot_dir(target), cert.domain),
            "ssh_warnings": sshcheck.command_warnings("activate_command", s.get("activate_command", "")),
        }

    # ---- checks -------------------------------------------------------------
    def preflight(self, target: Target) -> list[str]:
        return sshcheck.validate_endpoint(self.endpoint(target))

    def warnings(self, target: Target) -> list[str]:
        return sshcheck.command_warnings("activate_command", target.settings.get("activate_command", ""))

    def probe(self, target: Target) -> StepResult:
        ep = self.endpoint(target)
        s = target.settings
        try:
            client = sshcheck.connect(ep)
        except sshcheck.SSHConfigError as exc:
            return StepResult("probe", ok=False, message=str(exc), detail={"phase": "connect"})
        checks: list[dict] = []
        ok = True
        try:
            dirs = sorted({posixpath.dirname(s[k]) for k in ("remote_cert_path", "remote_key_path", "remote_chain_path") if s.get(k)})
            for d in dirs:
                try:
                    rc, _out, err = sshcheck.run(client, f"test -d {shlex.quote(d)} && test -w {shlex.quote(d)}")
                except (paramiko.SSHException, socket.timeout, OSError) as exc:
                    rc, err = 1, str(exc)
                passed = rc == 0
                ok = ok and passed
                checks.append({"command": f"writable {d}", "ok": passed, "exit": rc, "stderr": err[:300],
                               **({} if passed else {"hint": f"{d} is missing or not writable by {ep.user}; create it or fix its permissions."})})
            if s.get("activate_command"):
                sok, schecks = sshcheck.probe_commands(client, ep.user, [("activate_command", s["activate_command"])])
                ok = ok and sok
                checks.extend(schecks)
        finally:
            client.close()
        msg = (f"SSH key authentication to {ep.user}@{ep.host} succeeded; remote paths are writable"
               + (" and sudo permits the activation command." if s.get("activate_command") else ".")) if ok else \
              (f"SSH authentication to {ep.user}@{ep.host} succeeded, but: "
               + "; ".join(f"{c['command']!r} ({c.get('hint') or c.get('error')})" for c in checks if not c.get("ok")))
        return StepResult("probe", ok=ok, message=msg, detail={"phase": "authorize", "checks": checks})

    # ---- pipeline -----------------------------------------------------------
    def deploy(self, target: Target, bundle: CertBundle) -> StepResult:
        if not bundle.present:
            return StepResult("deploy", ok=False, message="missing certificate files to deploy",
                              detail={"phase": "prepare", "kind": "local"})
        s = target.settings
        ep = self.endpoint(target)
        try:
            client = sshcheck.connect(ep)
        except sshcheck.SSHConfigError as exc:
            return StepResult("deploy", ok=False, message=str(exc), detail={"phase": "connect", "kind": "transport"})
        cert_data = bundle.cert.read_bytes()
        if s.get("fullchain"):
            cert_data = cert_data.rstrip(b"\n") + b"\n" + bundle.chain.read_bytes()
        files = [(s["remote_cert_path"], cert_data, 0o644), (s["remote_key_path"], bundle.key.read_bytes(), 0o600)]
        if s.get("remote_chain_path"):
            files.append((s["remote_chain_path"], bundle.chain.read_bytes(), 0o644))
        written: list[str] = []
        staged: list[str] = []
        try:
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(30)
            sftp = client.open_sftp()
            sftp.get_channel().settimeout(sshcheck.command_timeout())   # a stalled peer must not hold the certificate lock
            try:
                # Stage every file first (the key is created private before a byte is written), then
                # swap them in: a failure while staging leaves the old set untouched.
                for path, data, mode in files:
                    tmp = f"{path}.oacm-tmp"
                    with sftp.open(tmp, "wb") as fh:
                        fh.chmod(mode)
                        fh.write(data)
                    sftp.chmod(tmp, mode)
                    staged.append(tmp)
                for path, _data, _mode in files:
                    _replace(sftp, f"{path}.oacm-tmp", path)
                    written.append(path)
            finally:
                sftp.close()
        except (paramiko.SSHException, socket.timeout, OSError, IOError) as exc:
            if written:
                what = (f"{len(written)} of {len(files)} file(s) replaced ({', '.join(written)}); the target now holds a mixed "
                        f"set, run Force deploy once it is reachable")
            else:
                what = "nothing on the target was replaced"
            return StepResult("deploy", ok=False,
                              message=f"upload to {ep.user}@{ep.host} failed: {exc}; {what}",
                              detail={"phase": "upload", "kind": "transport", "written": written, "staged": staged})
        finally:
            client.close()
        return StepResult("deploy", ok=True,
                          message=f"Certificate files uploaded to {ep.host} ({', '.join(p for p, _, _ in files)}).",
                          detail={"phase": "upload", "written": written})

    def activate(self, target: Target) -> StepResult:
        cmd = (target.settings.get("activate_command") or "").strip()
        if not cmd:
            return StepResult("activate", ok=True, message="no activation command configured")
        ep = self.endpoint(target)
        try:
            client = sshcheck.connect(ep)
        except sshcheck.SSHConfigError as exc:
            return StepResult("activate", ok=False, message=str(exc), detail={"phase": "connect"})
        try:
            rc, out, err = sshcheck.run(client, cmd, timeout=_CMD_TIMEOUT)
        except (paramiko.SSHException, socket.timeout, OSError) as exc:
            return StepResult("activate", ok=False, message=f"activation command could not be run over SSH: {exc}",
                              detail={"phase": "activate", "command": cmd})
        finally:
            client.close()
        if rc != 0:
            last = (err or out).strip().splitlines()
            return StepResult("activate", ok=False,
                              message=f"activation command exited {rc}: {last[-1] if last else 'no output'}",
                              detail={"phase": "activate", "command": cmd, "exit": rc, "stderr": err[:2000], "stdout": out[:2000]})
        return StepResult("activate", ok=True, message="activation command succeeded")

    def _sni(self, target: Target) -> str | None:
        return target.certificate.domain if target.certificate else None

    def verify(self, target: Target, serial: int, timeout: int) -> tuple[bool, int]:
        host, port = self.verify_endpoint(target)
        deadline = time.time() + timeout
        waited = 0
        while True:
            info = certs.fetch_served(host, port, sni=self._sni(target))
            if info.get("present") and info.get("serial") and int(info["serial"], 16) == serial:
                return True, waited
            if time.time() >= deadline:
                return False, waited
            time.sleep(_POLL_INTERVAL)
            waited += _POLL_INTERVAL

    def served_info(self, target: Target) -> dict[str, Any]:
        host, port = self.verify_endpoint(target)
        return certs.fetch_served(host, port, sni=self._sni(target))


register(SSHDriver())
