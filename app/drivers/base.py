"""The deploy-target driver contract.

A driver owns everything product-specific about putting a certificate on a
target and proving it is served. The core (issuance, the pipeline runner,
history, alerts, dashboard, lifecycle state) only ever calls these methods:

    schema()                     -> fields     driver-specific settings and their form section
    normalize(settings)          -> settings   defaults + types; raises ConfigError
    preflight(target)            -> problems   static config + credential checks, no side effects
    probe(target)                -> StepResult live, non-disruptive connectivity/authorization test
    deploy(target, bundle)       -> StepResult upload; safe to repeat
    activate(target)             -> StepResult the disruptive step
    verify(target, serial, t/o)  -> (ok, s)    what clients actually get
    served_info(target)          -> dict       the certificate currently served (dashboard "Served")
    snapshot(target, bundle)                   remember the bundle as last-known-good
    rollback(target)             -> StepResult re-deploy + re-activate the last-known-good
    activate_step(target, bundle)-> StepResult activate + verify + snapshot/rollback as one recorded
                                              step; the default composes the methods above

Every method takes the ``Target`` (driver name, settings, certificate id) and,
where it needs the certificate, the ``CertBundle`` (paths + serial +
environment). Drivers never touch the ACME CA.
"""
from __future__ import annotations

import datetime
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .. import certs, config
from ..models import Certificate, StepResult, Target

log = logging.getLogger("drivers")


@dataclass
class Field:
    """One driver setting as the form and the API describe it."""
    name: str
    label: str
    kind: str = "text"            # text | password | number | checkbox | select | textarea
    default: Any = ""
    help: str = ""
    required: bool = False
    choices: list[tuple[str, str]] = field(default_factory=list)
    secret: bool = False          # never echoed back; blank on edit keeps the stored value
    via: str = ""                 # host-side dependency: the command / .env key that provides it
    via_text: str = ""            # what that dependency is, for the info indicator
    group: str = ""               # fieldset title (defaults to the driver label)
    advanced: bool = False        # collapsed by default

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "label": self.label, "kind": self.kind, "default": self.default,
                "help": self.help, "required": self.required, "choices": self.choices,
                "secret": self.secret, "via": self.via, "via_text": self.via_text,
                "group": self.group, "advanced": self.advanced}


@dataclass
class CertBundle:
    """The flattened certificate files for one certificate, plus what they are."""
    cert: Path
    key: Path
    chain: Path
    serial: int = 0
    environment: str = ""         # lab | staging | production | '' when unknown
    issuer: str = ""
    not_after: str = ""

    @classmethod
    def for_certificate(cls, certificate: Certificate) -> "CertBundle":
        d = config.cert_dir_for(certificate)
        return cls.from_paths(d / f"{certificate.domain}.cer", d / f"{certificate.domain}.key", d / "ca.cer")

    @classmethod
    def from_paths(cls, cert: Path, key: Path, chain: Path) -> "CertBundle":
        b = cls(cert=Path(cert), key=Path(key), chain=Path(chain))
        info = certs.leaf_info(b.cert)
        if info.get("present") and info.get("serial"):
            b.serial = int(info["serial"], 16)
            b.environment = info.get("environment") or ""
            b.issuer = info.get("issuer") or ""
            b.not_after = info.get("not_after_iso") or ""
        return b

    @property
    def present(self) -> bool:
        return self.cert.exists() and self.key.exists() and self.chain.exists()

    @property
    def serial_hex(self) -> str:
        return format(self.serial, "x") if self.serial else ""


SNAPSHOT_META = "meta.json"


class Driver:
    """Base class: generic snapshot/rollback composition; subclasses fill in the product parts."""

    name = "base"
    label = "Base"
    steps: tuple[str, ...] = ("deploy", "activate")   # recorded step names after "issue"
    probe_label = "Test connection"
    probe_help = "Live, non-disruptive connectivity and authorization check."
    served_label = "Served"
    activation_label = "Activation"

    # ---- configuration ------------------------------------------------------
    def schema(self) -> list[Field]:
        return []

    def normalize(self, settings: dict) -> dict:
        """Apply defaults and coerce types; raise config.ConfigError on invalid input."""
        out = {}
        for f in self.schema():
            raw = settings.get(f.name, f.default)
            if f.kind == "checkbox":
                out[f.name] = raw in (True, "on", "true", "1", 1)
            elif f.kind == "number":
                try:
                    out[f.name] = int(raw) if raw not in ("", None) else int(f.default or 0)
                except (TypeError, ValueError) as exc:
                    raise config.ConfigError(f"{f.label} must be a number") from exc
            else:
                out[f.name] = (str(raw) if raw is not None else "").strip()
                if f.kind == "select" and f.choices:
                    allowed = [c[0] if isinstance(c, (tuple, list)) else c for c in f.choices]
                    if out[f.name] == "" and f.default is not None:
                        out[f.name] = str(f.default)
                    if out[f.name] not in allowed:
                        raise config.ConfigError(f"{f.label} must be one of {', '.join(map(str, allowed))}, not {out[f.name]!r}")
        return out

    def secret_fields(self) -> list[str]:
        return [f.name for f in self.schema() if f.secret]

    def display_host(self, target: Target) -> str:
        return str(target.settings.get("host") or "")

    def summary(self, target: Target) -> dict[str, Any]:
        """Driver-specific facts for the server page (never secrets)."""
        return {}

    # ---- checks -------------------------------------------------------------
    def preflight(self, target: Target) -> list[str]:
        return []

    def warnings(self, target: Target) -> list[str]:
        """Non-fatal configuration smells (shown, never blocking)."""
        return []

    def probe(self, target: Target) -> StepResult:
        return StepResult("probe", ok=True, message="nothing to probe for this driver")

    # ---- pipeline -----------------------------------------------------------
    def deploy_disabled(self, target: Target) -> str | None:
        """A reason when this target must not be written to (monitor-only); None when deploys are allowed.

        A run skips such a target with a recorded step instead of failing, so one
        monitor-only target never blocks the others.
        """
        return None

    def deploy(self, target: Target, bundle: CertBundle) -> StepResult:
        raise NotImplementedError

    def activate(self, target: Target) -> StepResult:
        return StepResult(self.steps[-1], ok=True, message="no activation needed")

    def verify(self, target: Target, serial: int, timeout: int) -> tuple[bool, int]:
        """Poll until the target serves ``serial``; (ok, seconds waited)."""
        raise NotImplementedError

    def served_info(self, target: Target) -> dict[str, Any]:
        info = dict(certs.ABSENT)
        info["error"] = "not supported by this driver"
        return info

    # ---- last-known-good ------------------------------------------------------
    @staticmethod
    def certificate_of(target: Target) -> Certificate:
        if target.certificate is None:
            target.certificate = config.get_certificate(target.certificate_id)
        return target.certificate

    def snapshot_dir(self, target: Target) -> Path:
        cert = self.certificate_of(target)
        d = config.cert_dir_for(cert) / "rollback"
        if target.id != cert.id:
            d = d / target.id
        return d

    def snapshot(self, target: Target, bundle: CertBundle) -> None:
        """Copy the just-verified bundle into the rollback directory with its metadata."""
        d = self.snapshot_dir(target)
        try:
            promote_snapshot(d, bundle)
        except (OSError, ValueError) as exc:
            log.warning("could not save known-good cert for %s: %s", target.id, exc)

    def snapshot_bundle(self, target: Target) -> Optional[CertBundle]:
        d = self.snapshot_dir(target)
        cert = self.certificate_of(target)
        b = CertBundle.from_paths(d / f"{cert.domain}.cer", d / f"{cert.domain}.key", d / "ca.cer")
        return b if b.present else None

    def rollback(self, target: Target, failed: CertBundle) -> StepResult:
        """Re-deploy and re-activate the snapshot; honours the cross-environment policy."""
        step = self.steps[-1]
        snap = self.snapshot_bundle(target)
        if snap is None:
            return StepResult(step, ok=False,
                              message="activation failed and no previous certificate exists to roll back to",
                              detail={"rolled_back": False, "reason": "no known-good snapshot",
                                      "failed_serial": failed.serial_hex})
        if snap.serial and snap.serial == failed.serial:
            return StepResult(step, ok=False,
                              message=("activation did not verify; the certificate is already the last-known-good one, "
                                       "so there is nothing to roll back to"),
                              detail={"rolled_back": False, "reason": "snapshot equals the failed certificate",
                                      "failed_serial": failed.serial_hex})
        refusal = cross_environment_refusal(target, snap, failed)
        if refusal:
            return StepResult(step, ok=False, message=refusal,
                              detail={"rolled_back": False, "reason": "cross-environment rollback refused",
                                      "failed_serial": failed.serial_hex, "snapshot_serial": snap.serial_hex,
                                      "snapshot_environment": snap.environment,
                                      "failed_environment": failed.environment})
        log.warning("%s(%s): activation failed — rolling back to last-known-good", self.name, target.id)
        d = self.deploy(target, snap)
        if not d.ok:
            return StepResult(step, ok=False, message=f"activation failed; rollback re-deploy failed: {d.message}",
                              detail={"rolled_back": False, "failed_serial": failed.serial_hex})
        a = self.activate(target)
        if not a.ok:
            return StepResult(step, ok=False, message=f"activation failed; rollback activation failed: {a.message}",
                              detail={"rolled_back": False, "failed_serial": failed.serial_hex})
        ok, _ = self.verify(target, snap.serial, rollback_timeout())
        crossed = bool(snap.environment and failed.environment and snap.environment != failed.environment)
        msg = ("activation verification failed — rolled back to previous certificate" if ok
               else "activation failed and rollback did not verify")
        if ok and crossed:
            msg += f" (CROSS-ENVIRONMENT: restored a {snap.environment} certificate in place of a {failed.environment} one)"
        return StepResult(step, ok=False, message=msg,
                          detail={"rolled_back": ok, "restored_serial": snap.serial_hex,
                                  "failed_serial": failed.serial_hex, "cross_environment": crossed,
                                  "snapshot_environment": snap.environment})

    def activate_step(self, target: Target, bundle: CertBundle) -> StepResult:
        """activate -> verify -> snapshot, or rollback; one recorded step."""
        step = self.steps[-1]
        a = self.activate(target)
        if not a.ok:
            a.step = step
            return a
        ok, waited = self.verify(target, bundle.serial, activation_timeout())
        if ok:
            self.snapshot(target, bundle)
            return StepResult(step, ok=True,
                              message=f"New certificate live on {self.display_host(target)} after ~{waited}s.",
                              detail={"serial": bundle.serial_hex, "wait_seconds": waited})
        return self.rollback(target, bundle)


# --------------------------------------------------------------------------- helpers

def activation_timeout() -> int:
    return int(os.environ.get("ACTIVATE_POLL_TIMEOUT", "300"))


def rollback_timeout() -> int:
    return int(os.environ.get("ROLLBACK_POLL_TIMEOUT", "120"))


def promote_snapshot(d: Path, bundle: CertBundle) -> None:
    """Copy cert/key/chain + metadata into ``d`` so a reader never sees a half-written set.

    The three files are staged under a temporary directory next to ``d`` and
    renamed into place one by one only after all copies succeeded and the key
    matches the certificate; an earlier snapshot stays intact until then.
    """
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization
    leaf = x509.load_pem_x509_certificate(bundle.cert.read_bytes())
    try:
        key = serialization.load_pem_private_key(bundle.key.read_bytes(), password=None)
    except UnsupportedAlgorithm as exc:
        raise ValueError(f"refusing to snapshot: unsupported private key algorithm ({exc})") from exc
    if leaf.public_key().public_numbers() != key.public_key().public_numbers():
        raise ValueError("refusing to snapshot: the private key does not match the certificate")
    d.parent.mkdir(parents=True, exist_ok=True)
    stage = d.parent / f".{d.name}.tmp-{os.getpid()}"
    if stage.exists():
        shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(mode=0o700)
    try:
        for src in (bundle.cert, bundle.key, bundle.chain):
            fd = os.open(stage / src.name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if src == bundle.key else 0o644)
            with os.fdopen(fd, "wb") as fh:
                fh.write(src.read_bytes())
        write_snapshot_meta(stage, bundle)
        d.mkdir(parents=True, exist_ok=True)
        for name in (bundle.cert.name, bundle.chain.name, SNAPSHOT_META, bundle.key.name):
            os.replace(stage / name, d / name)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def write_snapshot_meta(d: Path, bundle: CertBundle) -> None:
    meta = {"serial": bundle.serial_hex, "environment": bundle.environment, "issuer": bundle.issuer,
            "not_after": bundle.not_after,
            "taken_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}
    (d / SNAPSHOT_META).write_text(json.dumps(meta, indent=2) + "\n")


def read_snapshot_meta(d: Path) -> dict[str, Any]:
    p = d / SNAPSHOT_META
    try:
        return json.loads(p.read_text()) if p.is_file() else {}
    except (OSError, ValueError):
        return {}


def snapshot_info(target_settings: dict, d: Path, domain: str) -> dict[str, Any]:
    """What the server page shows about the rollback target."""
    leaf = d / f"{domain}.cer"
    info = {"present": leaf.exists(), "serial": None, "environment": None, "taken_at": None,
            "not_after": None, "allow_cross_env": bool(target_settings.get("allow_cross_env_rollback"))}
    if not info["present"]:
        return info
    meta = read_snapshot_meta(d)
    parsed = certs.leaf_info(leaf)
    info.update({"serial": parsed.get("serial"), "environment": parsed.get("environment") or meta.get("environment"),
                 "taken_at": meta.get("taken_at"), "not_after": parsed.get("not_after")})
    return info


def cross_environment_refusal(target: Target, snap: CertBundle, failed: CertBundle) -> str | None:
    """A message when policy forbids restoring a snapshot from another CA environment, else None."""
    if target.settings.get("allow_cross_env_rollback"):
        return None
    if not snap.environment or not failed.environment or snap.environment == failed.environment:
        return None
    return (f"activation of the {failed.environment} certificate (serial {failed.serial_hex}) failed and the "
            f"only rollback snapshot is a {snap.environment} certificate (serial {snap.serial_hex}); refusing to "
            f"roll back across CA environments. The appliance keeps whatever it serves now. Fix the cause and "
            f"press Force deploy, or allow cross-environment rollback for this target in Settings.")
