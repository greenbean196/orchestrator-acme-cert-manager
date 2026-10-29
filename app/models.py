"""Shared data types.

Two layers coexist on purpose:

* ``Certificate`` + ``Target`` is the configuration model since 1.3: one
  certificate (what is issued) is deployed to any number of targets, each
  handled by a driver (app/drivers). ``servers.json`` is written in this
  shape (``version: 2``).
* ``ServerConfig`` is the flattened "one Orchestrator == one certificate ==
  one target" view that the original pipeline modules (issue/deploy/restart/
  sshcheck) take. The Orchestrator driver builds one from a certificate and
  its target, so those modules and their tests are unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

ORCHESTRATOR_DRIVER = "orchestrator"


@dataclass
class ServerConfig:
    """One Orchestrator target, flattened with its certificate.

    Secrets are optional inline: if api_key / dns_api_token are set they are
    used for this server; if blank the tool falls back to the environment
    (api_key_env and CF_DNS_API_TOKEN respectively).
    """
    id: str
    name: str
    orchestrator_host: str
    domain: str
    acme_ca: str = "letsencrypt"          # letsencrypt | letsencrypt_test | lab | directory URL
    acme_email: str = ""
    key_type: str = "rsa2048"             # Orchestrator serves a single RSA cert
    dns_provider: str = "cloudflare"
    dns_api_token: str = ""               # inline Cloudflare DNS token (else env CF_DNS_API_TOKEN)
    ssh_user: str = ""
    ssh_key_path: str = ""
    ssh_known_hosts: str = ""
    ssh_port: int = 22
    restart_command: str = "sudo systemctl restart --no-block gms.service"
    nginx_reload_command: str = "sudo systemctl reload nginx"
    api_key_env: str = "ORCH_API_KEY"     # env var name used when api_key is blank
    api_key: str = ""                     # inline Orchestrator API key (else api_key_env)
    verify_ssl: bool = False
    ca_bundle: str = ""                   # optional CA bundle (PEM) used when verify_ssl is on
    ca_bundle_mode: str = "exclusive"     # exclusive: ca_bundle is the ONLY trust; additive: + system + lab roots
    allow_cross_env_rollback: bool = False  # rollback may restore a cert from another CA environment
    dns_env: dict[str, str] = field(default_factory=dict)   # extra DNS provider variables (Lego env)
    certificate_id: str = ""              # the certificate this target belongs to (== id for 1:1 entries)
    target_name: str = ""                 # display name of the target when it differs from the certificate's

    @property
    def requests_verify(self):
        """Legacy view of the trust setting: a CA bundle path, True, or False.

        deploy.py uses config.api_trust_bundle(), which honours ca_bundle_mode and
        adds the lab root; this property keeps the exclusive semantics of ca_bundle.
        """
        if not self.verify_ssl:
            return False
        return self.ca_bundle or True

    @property
    def base_url(self) -> str:
        return f"https://{self.orchestrator_host}/gms/rest/gms/httpsCertificate"

    # ---- conversions to the certificate + target model ---------------------
    def to_certificate(self) -> "Certificate":
        """The certificate + one Orchestrator target this entry represents."""
        return Certificate(
            id=self.certificate_id or self.id, name=self.name, domain=self.domain,
            acme_ca=self.acme_ca, acme_email=self.acme_email, key_type=self.key_type,
            dns_provider=self.dns_provider, dns_api_token=self.dns_api_token,
            dns_env=dict(self.dns_env), targets=[self.to_target()],
        )

    def to_target(self) -> "Target":
        return Target(
            id=self.id, driver=ORCHESTRATOR_DRIVER, name=self.target_name or self.name,
            settings={
                "orchestrator_host": self.orchestrator_host,
                "api_key_env": self.api_key_env, "api_key": self.api_key,
                "verify_ssl": self.verify_ssl, "ca_bundle": self.ca_bundle,
                "ca_bundle_mode": self.ca_bundle_mode,
                "allow_cross_env_rollback": self.allow_cross_env_rollback,
                "ssh": {
                    "user": self.ssh_user, "key_path": self.ssh_key_path,
                    "known_hosts": self.ssh_known_hosts, "port": self.ssh_port,
                    "restart_command": self.restart_command,
                    "nginx_reload_command": self.nginx_reload_command,
                },
            },
            certificate_id=self.certificate_id or self.id,
        )

    @classmethod
    def from_parts(cls, cert: "Certificate", target: "Target") -> "ServerConfig":
        """Flatten a certificate and one of its Orchestrator targets."""
        s = target.settings
        ssh = s.get("ssh") or {}
        return cls(
            id=target.id, name=cert.name if target.id == cert.id else (target.name or cert.name),
            orchestrator_host=s.get("orchestrator_host", ""), domain=cert.domain,
            acme_ca=cert.acme_ca, acme_email=cert.acme_email, key_type=cert.key_type,
            dns_provider=cert.dns_provider, dns_api_token=cert.dns_api_token,
            ssh_user=(ssh.get("user") or "").strip(), ssh_key_path=(ssh.get("key_path") or "").strip(),
            ssh_known_hosts=(ssh.get("known_hosts") or "").strip(), ssh_port=int(ssh.get("port") or 22),
            restart_command=ssh.get("restart_command", ""), nginx_reload_command=ssh.get("nginx_reload_command", ""),
            api_key_env=s.get("api_key_env", "ORCH_API_KEY"), api_key=s.get("api_key", ""),
            verify_ssl=bool(s.get("verify_ssl", False)), ca_bundle=(s.get("ca_bundle") or "").strip(),
            ca_bundle_mode=(s.get("ca_bundle_mode") or "exclusive").strip().lower(),
            allow_cross_env_rollback=bool(s.get("allow_cross_env_rollback", False)),
            dns_env=dict(cert.dns_env), certificate_id=cert.id, target_name=target.name,
        )


@dataclass
class Target:
    """One deployment target of a certificate: a driver plus its settings.

    ``settings`` is driver-specific and validated by ``driver.normalize()``.
    ``certificate_id`` is filled in when the configuration is loaded.
    """
    id: str
    driver: str
    name: str = ""
    settings: dict[str, Any] = field(default_factory=dict)
    certificate_id: str = ""
    certificate: Optional["Certificate"] = field(default=None, repr=False, compare=False)

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "driver": self.driver, "name": self.name, "settings": self.settings}


@dataclass
class Certificate:
    """What is issued: one name (SAN support is a follow-up), from one ACME CA,
    proven by one DNS provider; deployed to ``targets``."""
    id: str
    name: str
    domain: str
    acme_ca: str = "letsencrypt"
    acme_email: str = ""
    key_type: str = "rsa2048"
    dns_provider: str = "cloudflare"
    dns_api_token: str = ""
    dns_env: dict[str, str] = field(default_factory=dict)   # provider variables passed to Lego, redacted everywhere
    targets: list[Target] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.attach()

    def attach(self) -> "Certificate":
        """Point every target back at this certificate (after loading or editing)."""
        for t in self.targets:
            t.certificate_id = self.id
            t.certificate = self
        return self

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "domain": self.domain,
            "acme": {"ca": self.acme_ca, "email": self.acme_email, "key_type": self.key_type},
            "dns": {"provider": self.dns_provider, "api_token": self.dns_api_token, "env": dict(self.dns_env)},
            "targets": [t.as_dict() for t in self.targets],
        }

    def target(self, target_id: str) -> Optional[Target]:
        return next((t for t in self.targets if t.id == target_id), None)

    def orchestrator_targets(self) -> list[Target]:
        return [t for t in self.targets if t.driver == ORCHESTRATOR_DRIVER]

    def as_server(self, target: Target | None = None) -> ServerConfig:
        """Flattened legacy view for one Orchestrator target (the first one by default)."""
        t = target or (self.orchestrator_targets()[0] if self.orchestrator_targets() else None)
        if t is None:
            raise ValueError(f"certificate {self.id!r} has no Orchestrator target")
        return ServerConfig.from_parts(self, t)


@dataclass
class StepResult:
    """Outcome of a single pipeline step (issue / deploy / restart|activate)."""
    step: str
    ok: bool
    message: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"step": self.step, "ok": self.ok, "message": self.message, "detail": self.detail}


@dataclass
class RenewalRecord:
    """A single renewal attempt, persisted for the web UI history.

    ``server_id`` is the certificate id (it was the server id when one entry
    was one Orchestrator; the ids are identical for migrated entries). Steps
    that act on a target carry ``target`` in their dict.
    """
    server_id: str
    timestamp: str
    outcome: str                          # success | failed | skipped
    steps: list[dict[str, Any]] = field(default_factory=list)
    not_after: Optional[str] = None
    serial: Optional[str] = None
    kind: str = "renew"                   # scheduled | renew (forced) | redeploy
    elapsed_s: Optional[float] = None
    actor: str = ""                       # who started it: scheduler | cli user | web username
    source: str = ""                      # where from: cron | cli | web
    targets: list[str] = field(default_factory=list)   # target ids this run touched

    def as_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "timestamp": self.timestamp,
            "outcome": self.outcome,
            "steps": self.steps,
            "not_after": self.not_after,
            "serial": self.serial,
            "kind": self.kind,
            "elapsed_s": self.elapsed_s,
            "actor": self.actor,
            "source": self.source,
            "targets": self.targets,
        }
