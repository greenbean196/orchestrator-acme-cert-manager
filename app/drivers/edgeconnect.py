"""EdgeConnect appliance driver through Orchestrator (issue #21).

What is documented (HPE Postman collections 9.3-9.6, developer hub):

* Orchestrator reports an appliance's HTTPS certificate with
  ``GET /gms/rest/httpsCertificate?nePk={nePk}`` and proxies appliance REST
  calls with ``/gms/rest/appliance/rest?nePk={nePk}&url=<appliance path>``.
* The appliance-level API (``/rest/json/httpsCertificate/validation`` and
  ``/rest/json/httpsCertificate/config`` with ``certificateData``, ``keyData``,
  ``chain``) installs a certificate but "must restart nodejs manually", and
  HPE documents that certificates uploaded directly to an appliance are
  overwritten by Orchestrator synchronization; the supported path is the
  HTTPS Certificate template (schema not public) or EST end-entity profiles
  (9.4.3+).

So this driver ships the read-only parts for real (preflight: Orchestrator
version and appliance state/reachability; probe; served_info and verify from
what Orchestrator reports) and keeps the write path behind
``experimental_passthrough_write``: off, deploy/activate fail with a message
that says what to confirm on hardware first; on, it validates then installs
through the passthrough and restarts the configured appliance process.
"""
from __future__ import annotations

import base64
import logging
import os
import re
import time
from typing import Any

import requests

from .. import certs, config
from ..deploy import redact
from ..models import StepResult, Target
from . import register
from .base import CertBundle, Driver, Field, snapshot_info

log = logging.getLogger("edgeconnect")
_TIMEOUT = 30
_POLL_INTERVAL = 10
_MIN_VERSION = (9, 3)


class EdgeConnectDriver(Driver):
    name = "edgeconnect"
    label = "EdgeConnect appliance (via Orchestrator)"
    steps = ("deploy", "activate")
    probe_label = "Test Orchestrator API"
    probe_help = "Read the Orchestrator version, the appliance record, its reachability and the certificate Orchestrator reports. Changes nothing."
    served_label = "Installed (Orchestrator-reported)"
    activation_label = "Activation (Orchestrator passthrough)"

    def schema(self) -> list[Field]:
        return [
            Field("orchestrator_host", "Orchestrator host", required=True, group="Orchestrator",
                  help="The Orchestrator that manages the appliance; same API key model as an Orchestrator target."),
            Field("api_key", "Orchestrator API key", kind="password", secret=True, group="Orchestrator",
                  help="Read-Write key whose RBAC role / appliance access group covers this appliance. Blank falls back to the env var."),
            Field("api_key_env", "API key env var", default="ORCH_API_KEY", group="Orchestrator",
                  via="<NAME>=… in .env; docker compose down && docker compose up -d", via_text="Name of a variable in .env on the Docker host."),
            Field("verify_ssl", "Verify the Orchestrator's TLS certificate", kind="checkbox", default=False, group="Orchestrator"),
            Field("ca_bundle", "CA bundle (optional)", group="Orchestrator"),
            Field("ca_bundle_mode", "Bundle mode", kind="select", default="exclusive", group="Orchestrator",
                  choices=[(m, m) for m in config.CA_BUNDLE_MODES]),
            Field("ne_pk", "Appliance nePk", required=True, group="Appliance",
                  help="Orchestrator's appliance id, e.g. 3.NE (GET /gms/rest/appliance → id)."),
            Field("appliance_host", "Appliance management host (optional)", group="Appliance",
                  help="If the runner can reach the appliance, its served certificate on :443 is checked too."),
            Field("experimental_passthrough_write", "Experimental: install through the Orchestrator passthrough", kind="checkbox",
                  default=False, group="Write path", advanced=True,
                  help="POST appliance/rest?url=httpsCertificate/validation then /config with certificateData/keyData/chain, then restart the "
                       "appliance process below. HPE documents direct uploads as overwritten by Orchestrator sync; confirm on a lab appliance first."),
            Field("restart_process", "Appliance process to restart after install", default="", group="Write path", advanced=True,
                  help="Name for POST appliance/rest?url=cnprocess/restart/<name> ('nodejs' is documented as needing a restart; the process name is not). Blank: no restart."),
            Field("allow_cross_env_rollback", "Allow rollback across CA environments", kind="checkbox", default=False, group="Rollback policy", advanced=True),
        ]

    def normalize(self, settings: dict) -> dict:
        n = super().normalize(settings)
        if not n["orchestrator_host"]:
            raise config.ConfigError("Orchestrator host is required.")
        if not re.fullmatch(r"\d+\.NE", n["ne_pk"] or ""):
            raise config.ConfigError("Appliance nePk must look like 3.NE.")
        if n["ca_bundle_mode"] not in config.CA_BUNDLE_MODES:
            raise config.ConfigError("CA bundle mode must be 'exclusive' or 'additive'.")
        n["api_key_env"] = n["api_key_env"] or "ORCH_API_KEY"
        return n

    def flat(self, target: Target) -> dict:
        d = dict(target.settings)
        d["api_key"] = ""
        return d

    def display_host(self, target: Target) -> str:
        return f"{target.settings.get('ne_pk', '?')} via {target.settings.get('orchestrator_host', '')}"

    def summary(self, target: Target) -> dict[str, Any]:
        s = target.settings
        cert = self.certificate_of(target)
        return {"orchestrator_host": s.get("orchestrator_host"), "ne_pk": s.get("ne_pk"), "appliance_host": s.get("appliance_host"),
                "verify_ssl": bool(s.get("verify_ssl")), "api_inline": bool(s.get("api_key")), "api_key_env": s.get("api_key_env"),
                "write_path": "experimental passthrough" if s.get("experimental_passthrough_write") else "read-only (confirm on hardware)",
                "restart_process": s.get("restart_process") or "none",
                "snapshot": snapshot_info(s, self.snapshot_dir(target), cert.domain), "ssh_warnings": []}

    # ---- http ---------------------------------------------------------------
    def _key(self, target: Target) -> str:
        s = target.settings
        return s.get("api_key") or os.environ.get(s.get("api_key_env") or "ORCH_API_KEY", "")

    def _verify(self, target: Target):
        s = target.settings
        return config.api_trust_bundle(s.get("ca_bundle", ""), s.get("ca_bundle_mode", "exclusive")) if s.get("verify_ssl") else False

    def _req(self, target: Target, method: str, path: str, phase: str, **kw) -> Any:
        base = f"https://{target.settings['orchestrator_host']}/gms/rest"
        key = self._key(target)
        if not key:
            raise EdgeConnectError(phase, f"no Orchestrator API key (inline or {target.settings.get('api_key_env') or 'ORCH_API_KEY'})", kind="config")
        headers = {"X-Auth-Token": key, "Accept": "application/json"}
        try:
            r = requests.request(method, f"{base}/{path}", headers=headers, verify=self._verify(target), timeout=_TIMEOUT, **kw)
        except requests.exceptions.SSLError as exc:
            raise EdgeConnectError(phase, f"TLS verification of the Orchestrator failed: {redact(str(exc))}", kind="tls") from exc
        except requests.RequestException as exc:
            raise EdgeConnectError(phase, f"{method} /gms/rest/{path.split('?')[0]} failed: {redact(str(exc))}", kind="transport") from exc
        if not r.ok:
            raise EdgeConnectError(phase, f"{method} /gms/rest/{path.split('?')[0]} returned HTTP {r.status_code}: {redact(r.text)}",
                                   status=r.status_code, kind="rejected" if r.status_code < 500 else "http")
        if not r.text.strip():
            return None
        try:
            return r.json()
        except ValueError:
            return r.text

    def version(self, target: Target) -> tuple[int, int] | None:
        v = self._req(target, "GET", "gms/versions", "version")
        cur = (v or {}).get("current") if isinstance(v, dict) else None
        m = re.match(r"(\d+)\.(\d+)", str(cur or ""))
        return (int(m.group(1)), int(m.group(2))) if m else None

    def appliance(self, target: Target) -> dict:
        ne = target.settings["ne_pk"]
        data = self._req(target, "GET", f"appliance?nePk={ne}", "appliance")
        if isinstance(data, list):
            data = next((a for a in data if str(a.get("id") or a.get("nePk")) == ne), None)
        if not isinstance(data, dict):
            raise EdgeConnectError("appliance", f"appliance {ne} not found in GET /gms/rest/appliance")
        return data

    def reported_certificate(self, target: Target) -> dict:
        """What Orchestrator says the appliance serves (freshness undocumented)."""
        ne = target.settings["ne_pk"]
        data = self._req(target, "GET", f"httpsCertificate?nePk={ne}", "certificate")
        pem = ""
        if isinstance(data, dict):
            pem = data.get("cert") or data.get("certificateData") or data.get("certificate") or ""
            if isinstance(pem, str) and pem.startswith("data:"):
                pem = base64.b64decode(pem.split(",", 1)[1]).decode(errors="replace")
        if isinstance(pem, str) and "BEGIN CERTIFICATE" in pem:
            info = certs.parse_pem(pem.encode())
            info["error"] = None
            info["raw"] = None
            return info
        info = dict(certs.ABSENT)
        info["error"] = "Orchestrator returned no PEM certificate for the appliance (response shape unknown on this version)"
        info["raw"] = redact(str(data))[:300]
        if isinstance(data, dict) and data.get("serial"):
            info["serial"] = str(data["serial"]).upper().replace(":", "")
            info["present"] = True
            info["error"] = None
        return info

    # ---- checks -------------------------------------------------------------
    def preflight(self, target: Target) -> list[str]:
        problems = []
        if not self._key(target):
            problems.append(f"no Orchestrator API key (inline or {target.settings.get('api_key_env') or 'ORCH_API_KEY'}).")
        if target.settings.get("experimental_passthrough_write") and not target.settings.get("restart_process"):
            problems.append("experimental passthrough write is on but no appliance process to restart is set; the installed "
                            "certificate would not be served until nodejs restarts.")
        return problems

    def warnings(self, target: Target) -> list[str]:
        out = []
        if not target.settings.get("experimental_passthrough_write"):
            out.append("write path not enabled: this target is monitor-only until the passthrough install is confirmed on a lab appliance.")
        else:
            out.append("experimental passthrough write: HPE documents direct appliance uploads as overwritten by Orchestrator sync.")
        return out

    def probe(self, target: Target) -> StepResult:
        checks = []
        try:
            ver = self.version(target)
            checks.append({"command": "GET /gms/rest/gms/versions", "ok": bool(ver and ver >= _MIN_VERSION),
                           "note": f"Orchestrator {'.'.join(map(str, ver)) if ver else '?'}",
                           **({} if ver and ver >= _MIN_VERSION else {"hint": "Orchestrator 9.3+ is required (query-parameter endpoints)"})})
            app = self.appliance(target)
            state = app.get("state")
            checks.append({"command": f"GET /gms/rest/appliance?nePk={target.settings['ne_pk']}", "ok": state in (1, "1", None),
                           "note": f"{app.get('hostName') or '?'} · {app.get('model') or ''} · ECOS {app.get('softwareVersion') or '?'} · state {state}",
                           **({} if state in (1, "1", None) else {"hint": "appliance state is not 'normal' (1): unreachable or out of sync"})})
            reach = self._req(target, "GET", f"reachability/appliance?nePk={target.settings['ne_pk']}", "reachability")
            checks.append({"command": "GET /gms/rest/reachability/appliance", "ok": True, "note": redact(str(reach))[:200]})
            rep = self.reported_certificate(target)
            checks.append({"command": "GET /gms/rest/httpsCertificate", "ok": bool(rep.get("present")),
                           "note": f"serial {rep.get('serial') or '?'} · issuer {rep.get('issuer') or '?'}" if rep.get("present") else rep.get("error")})
        except EdgeConnectError as exc:
            checks.append({"command": exc.phase, "ok": False, "error": str(exc)})
            return StepResult("probe", ok=False, message=str(exc), detail={"phase": exc.phase, "kind": exc.kind, "checks": checks})
        ok = all(c["ok"] for c in checks)
        return StepResult("probe", ok=ok, message=("Orchestrator answers, the appliance is known and reports a certificate." if ok
                                                   else "Orchestrator answers but a check failed (see details)."),
                          detail={"phase": "authorize", "checks": checks})

    # ---- pipeline -----------------------------------------------------------
    def deploy_disabled(self, target: Target) -> str | None:
        if target.settings.get("experimental_passthrough_write"):
            return None
        return ("monitor-only: the EdgeConnect write path is not enabled on this target (the HTTPS Certificate template "
                "schema is not public and direct appliance uploads are documented as overwritten by Orchestrator sync); "
                "enable 'experimental passthrough write' after confirming it on a lab appliance")

    def deploy(self, target: Target, bundle: CertBundle) -> StepResult:
        s = target.settings
        if not s.get("experimental_passthrough_write"):
            return StepResult("deploy", ok=False,
                              message=("EdgeConnect write path is not enabled: the HTTPS Certificate template schema is not public and "
                                       "direct appliance uploads are documented as overwritten by Orchestrator sync. Confirm the passthrough "
                                       "install on a lab appliance, then enable 'experimental passthrough write' on this target."),
                              detail={"phase": "prepare", "kind": "config"})
        if not bundle.present:
            return StepResult("deploy", ok=False, message="missing certificate files to deploy", detail={"phase": "prepare", "kind": "local"})
        payload = {"certificateData": bundle.cert.read_text(), "keyData": bundle.key.read_text(), "chain": bundle.chain.read_text(),
                   "keyPassPhrase": "", "srvr_cert_label": (target.certificate.domain if target.certificate else target.id)}
        ne = s["ne_pk"]
        try:
            self._req(target, "POST", f"appliance/rest?nePk={ne}&url=httpsCertificate/validation", "validation", json=payload)
            self._req(target, "POST", f"appliance/rest?nePk={ne}&url=httpsCertificate/config", "install", json=payload)
        except EdgeConnectError as exc:
            return StepResult("deploy", ok=False, message=str(exc), detail={"phase": exc.phase, "kind": exc.kind, "status": exc.status})
        return StepResult("deploy", ok=True, message=f"Certificate validated and installed on appliance {ne} through the Orchestrator passthrough.",
                          detail={"phase": "install"})

    def activate(self, target: Target) -> StepResult:
        s = target.settings
        proc = (s.get("restart_process") or "").strip()
        if not proc:
            return StepResult("activate", ok=True, message="no appliance process restart configured")
        try:
            self._req(target, "POST", f"appliance/rest?nePk={s['ne_pk']}&url=cnprocess/restart/{proc}", "restart", json={"onlyIfRequired": False})
        except EdgeConnectError as exc:
            return StepResult("activate", ok=False, message=str(exc), detail={"phase": exc.phase, "kind": exc.kind, "status": exc.status})
        return StepResult("activate", ok=True, message=f"restart of {proc} requested on {s['ne_pk']}")

    def verify(self, target: Target, serial: int, timeout: int) -> tuple[bool, int]:
        deadline = time.time() + timeout
        waited = 0
        host = (target.settings.get("appliance_host") or "").strip()
        while True:
            try:
                rep = self.reported_certificate(target)
            except EdgeConnectError:
                rep = {}
            api_ok = bool(rep.get("serial")) and int(rep["serial"], 16) == serial
            served_ok = True
            if host:
                got = certs.fetch_served(host, 443)
                served_ok = bool(got.get("serial")) and int(got["serial"], 16) == serial
            if api_ok and served_ok:
                return True, waited
            if time.time() >= deadline:
                return False, waited
            time.sleep(_POLL_INTERVAL)
            waited += _POLL_INTERVAL

    def served_info(self, target: Target) -> dict[str, Any]:
        try:
            info = self.reported_certificate(target)
            info.pop("raw", None)
            return info
        except EdgeConnectError as exc:
            info = dict(certs.ABSENT)
            info["error"] = str(exc)[:200]
            return info


class EdgeConnectError(Exception):
    def __init__(self, phase: str, message: str, status: int | None = None, kind: str = "http"):
        super().__init__(message)
        self.phase, self.status, self.kind = phase, status, kind


register(EdgeConnectDriver())
