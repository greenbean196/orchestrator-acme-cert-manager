"""Orchestrator driver: the original pipeline behind the driver contract.

Deploy is the httpsCertificate REST API (deploy.py), activation is the SSH
restart + nginx reload with served-serial verification and rollback
(restart.py), the probe is the sudo authorization check (sshcheck.py). The
driver flattens the certificate and target into the ServerConfig those modules
take, so their behaviour and tests are unchanged.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import certs, config, deploy as deploy_mod, restart as restart_mod, sshcheck
from ..models import ServerConfig, StepResult, Target
from . import register
from .base import CertBundle, Driver, Field, snapshot_info

HOST_ENV = "edit .env on the Docker host, then: docker compose down && docker compose up -d"


class OrchestratorDriver(Driver):
    name = "orchestrator"
    label = "EdgeConnect Orchestrator"
    steps = ("deploy", "restart")
    probe_label = "Test SSH"
    probe_help = "Authenticate over SSH and check sudo authorization. Restarts nothing."
    served_label = "Served on :443"
    activation_label = "Activation (SSH)"

    def schema(self) -> list[Field]:
        return [
            Field("orchestrator_host", "Orchestrator host", required=True, group="Target",
                  help="Used for the API, SSH and the served-certificate check. Use the FQDN on the certificate when TLS verification is on."),
            Field("verify_ssl", "Verify the Orchestrator's TLS certificate on API calls", kind="checkbox", default=False, group="Target",
                  help="Leave off only while the appliance still serves its factory self-signed certificate. Turn on once the production certificate is live.",
                  via="lab root: ./setup.sh --with-ca on the host",
                  via_text="Without a CA bundle the trust is the system roots plus the lab root (when the lab CA is configured on the host), so public-to-lab migrations and rollback keep verifying."),
            Field("ca_bundle", "CA bundle (optional)", group="Target",
                  help="PEM bundle for API verification when the appliance chains to a private CA. Path inside the container.",
                  via="cp bundle.pem data/ssh/  →  /data/ssh/bundle.pem",
                  via_text="The file must live inside a directory that docker-compose.yml mounts (./data/ssh or ./config on the host) and the path is the one inside the container."),
            Field("ca_bundle_mode", "Bundle mode", kind="select", default="exclusive", group="Target",
                  choices=[(m, m) for m in config.CA_BUNDLE_MODES],
                  help="exclusive: the bundle is the only trust. additive: bundle + system roots + lab root."),
            Field("api_key", "Orchestrator API key", kind="password", secret=True, group="Secrets",
                  help="Read-Write key. Blank falls back to the env var on the right."),
            Field("api_key_env", "API key env var", default="ORCH_API_KEY", group="Secrets",
                  via="<NAME>=… in .env; docker compose down && docker compose up -d",
                  via_text="Name of a variable in .env on the Docker host. Its value is never shown here."),
            Field("ssh_user", "SSH user", required=True, group="SSH (activation)",
                  via="./setup.sh --host <orchestrator> --ssh-user <user> [--install-sudoers]",
                  via_text="This account on the appliance must hold the public key and the NOPASSWD sudoers rule for the two activation commands."),
            Field("ssh_port", "SSH port", kind="number", default=22, group="SSH (activation)",
                  via="./setup.sh --host <orchestrator> --ssh-port <port>",
                  via_text="A non-default port changes the known_hosts entry name to [host]:port; pin it with the same port."),
            Field("ssh_key_path", "Private key path", default=config.DEFAULT_SSH_KEY, group="SSH (activation)",
                  help="Path inside the container; ./data/ssh on the host is mounted read-only at /data/ssh.",
                  via="./setup.sh [--key-type ed25519]",
                  via_text="Generated on the host as data/ssh/orch_restart (RSA-4096, no passphrase) and mounted read-only; the container cannot create keys."),
            Field("ssh_known_hosts", "Known hosts path", default=config.DEFAULT_KNOWN_HOSTS, group="SSH (activation)",
                  help="Pinned Orchestrator host key (strict checking). Must contain an entry for the host above.",
                  via="./setup.sh --host <orchestrator> [--trust-host-key]",
                  via_text="The appliance host key is pinned on the host after you confirm its fingerprint; the container never trusts a host on first use."),
            Field("restart_command", "Restart command", default=config.DEFAULT_RESTART_COMMAND, group="SSH (activation)", advanced=True,
                  via="./setup.sh --host <orchestrator> --install-sudoers",
                  via_text="Both commands must match the NOPASSWD sudoers rule on the appliance word for word; setup.sh prints or installs that rule."),
            Field("nginx_reload_command", "Nginx reload command", default=config.DEFAULT_NGINX_RELOAD_COMMAND, group="SSH (activation)", advanced=True),
            Field("allow_cross_env_rollback", "Allow rollback across CA environments", kind="checkbox", default=False, group="Rollback policy", advanced=True,
                  help="Off (default): a failed production activation never restores a staging or lab certificate; the run fails loudly instead. On: the last-known-good is restored whatever CA issued it, and the message says so."),
        ]

    # ---- flat <-> nested settings ------------------------------------------
    def normalize(self, settings: dict) -> dict:
        """Accept either the flat form shape or the nested stored shape; return the nested one."""
        flat = dict(settings)
        ssh = flat.pop("ssh", None)
        if isinstance(ssh, dict):
            for k in ("user", "key_path", "known_hosts", "port", "restart_command", "nginx_reload_command"):
                flat.setdefault(f"ssh_{k}" if k in ("user", "key_path", "known_hosts", "port") else k, ssh.get(k))
        n = super().normalize(flat)
        if not n["orchestrator_host"]:
            raise config.ConfigError("Orchestrator host is required.")
        if not (1 <= n["ssh_port"] <= 65535):
            raise config.ConfigError("SSH port must be between 1 and 65535.")
        if n["ca_bundle_mode"] not in config.CA_BUNDLE_MODES:
            raise config.ConfigError("CA bundle mode must be 'exclusive' or 'additive'.")
        return {
            "orchestrator_host": n["orchestrator_host"], "verify_ssl": n["verify_ssl"],
            "ca_bundle": n["ca_bundle"], "ca_bundle_mode": n["ca_bundle_mode"],
            "api_key": n["api_key"], "api_key_env": n["api_key_env"] or "ORCH_API_KEY",
            "allow_cross_env_rollback": n["allow_cross_env_rollback"],
            "ssh": {"user": n["ssh_user"], "key_path": n["ssh_key_path"],
                    "known_hosts": n["ssh_known_hosts"] or config.DEFAULT_KNOWN_HOSTS, "port": n["ssh_port"],
                    "restart_command": n["restart_command"], "nginx_reload_command": n["nginx_reload_command"]},
        }

    def flat(self, target: Target) -> dict:
        """The form view of a target's settings (secrets blanked)."""
        s = target.settings
        ssh = s.get("ssh") or {}
        return {
            "orchestrator_host": s.get("orchestrator_host", ""), "verify_ssl": bool(s.get("verify_ssl")),
            "ca_bundle": s.get("ca_bundle", ""), "ca_bundle_mode": s.get("ca_bundle_mode", "exclusive"),
            "api_key": "", "api_key_env": s.get("api_key_env", "ORCH_API_KEY"),
            "allow_cross_env_rollback": bool(s.get("allow_cross_env_rollback")),
            "ssh_user": ssh.get("user", ""), "ssh_port": ssh.get("port", 22),
            "ssh_key_path": ssh.get("key_path", ""), "ssh_known_hosts": ssh.get("known_hosts", ""),
            "restart_command": ssh.get("restart_command", ""), "nginx_reload_command": ssh.get("nginx_reload_command", ""),
        }

    def server(self, target: Target) -> ServerConfig:
        return ServerConfig.from_parts(self.certificate_of(target), target)

    def display_host(self, target: Target) -> str:
        return str(target.settings.get("orchestrator_host") or "")

    def summary(self, target: Target) -> dict[str, Any]:
        s = self.server(target)
        return {
            "host": s.orchestrator_host, "verify_ssl": s.verify_ssl, "ca_bundle": s.ca_bundle,
            "ca_bundle_mode": s.ca_bundle_mode, "ssh_user": s.ssh_user, "ssh_port": s.ssh_port,
            "ssh_key_path": s.ssh_key_path, "ssh_known_hosts": s.ssh_known_hosts,
            "restart_command": s.restart_command, "nginx_reload_command": s.nginx_reload_command,
            "api_inline": bool(s.api_key), "api_key_env": s.api_key_env,
            "snapshot": snapshot_info(target.settings, restart_mod._rollback_dir(s), s.domain),
            "ssh_warnings": sshcheck.warnings(s),
        }

    # ---- checks -------------------------------------------------------------
    def preflight(self, target: Target) -> list[str]:
        return sshcheck.validate(self.server(target))

    def warnings(self, target: Target) -> list[str]:
        out = sshcheck.warnings(self.server(target))
        kt = (self.certificate_of(target).key_type or "rsa2048").lower()
        if not kt.startswith("rsa"):
            out.append(f"certificate key type {kt}: Orchestrator has been validated with RSA certificates only.")
        return out

    def probe(self, target: Target) -> StepResult:
        return sshcheck.test_connection(self.server(target))

    # ---- pipeline -----------------------------------------------------------
    def deploy(self, target: Target, bundle: CertBundle) -> StepResult:
        s = self.server(target)
        current = CertBundle.for_certificate(self.certificate_of(target))
        if (bundle.cert, bundle.key, bundle.chain) == (current.cert, current.key, current.chain):
            return deploy_mod.deploy(s)                      # the module-level entry point tests patch
        return deploy_mod.deploy_paths(s, bundle.cert, bundle.key, bundle.chain)

    def activate(self, target: Target) -> StepResult:
        return restart_mod._apply(self.server(target))

    def verify(self, target: Target, serial: int, timeout: int) -> tuple[bool, int]:
        return restart_mod._wait_for_served_serial(self.server(target), serial, timeout)

    def served_info(self, target: Target) -> dict[str, Any]:
        return certs.fetch_served(self.display_host(target))

    def snapshot_dir(self, target: Target) -> Path:
        return restart_mod._rollback_dir(self.server(target))

    def snapshot(self, target: Target, bundle: CertBundle) -> None:
        restart_mod._promote_known_good(self.server(target))

    def activate_step(self, target: Target, bundle: CertBundle) -> StepResult:
        """restart.restart() already does activate + verify + snapshot/rollback; keep it as one unit."""
        return restart_mod.restart(self.server(target))


register(OrchestratorDriver())
