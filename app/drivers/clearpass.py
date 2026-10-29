"""ClearPass Policy Manager driver (issue #20).

How ClearPass takes a server certificate (REST API, identical schema in
6.11 / 6.12 / 6.14): ``PUT /api/server-cert/name/{server_uuid}/{service_name}``
with ``{"pkcs12_file_url": ..., "pkcs12_passphrase": ...}``. There is no inline
upload: ClearPass fetches the PKCS#12 from the URL itself, so this driver runs
a short-lived HTTP listener (``callback_host``:``callback_port``, published by
Compose) that serves exactly one random path to the cluster's addresses and
nothing else. Installing is the activation: ClearPass restarts the service on
that node when the PUT lands. Private keys never come back out of ClearPass,
so rollback uses this tool's own last-known-good snapshot.

Cluster model: one entry host (publisher or cluster name); node UUIDs come
from ``GET /api/cluster/server``; writes are proxied to the publisher by
ClearPass. Subscribers are updated first and the entry node last, one node at
a time, each verified (API-reported certificate and, optionally, the
certificate served on the node's :443) before the next. HTTPS has two slots
since 6.10, HTTPS(RSA) and HTTPS(ECC); ECC-capable clients get the ECC
certificate, so a target that only updates one slot checks the other.

Unverified on hardware (confirm before trusting the first run): the PUT
response timing, FIPS-mode PKCS#12 acceptance, whether an http:// callback is
accepted on your release. Each is reported in the step diagnostics.
"""
from __future__ import annotations

import http.server
import ipaddress
import logging
import secrets
import socket
import ssl
import threading
import time
from typing import Any

import requests

from .. import certs, config
from ..deploy import redact
from ..models import StepResult, Target
from . import register
from .base import CertBundle, Driver, Field, activation_timeout, rollback_timeout, snapshot_info, \
    cross_environment_refusal

log = logging.getLogger("clearpass")

SERVICE_ORDER = ("RADIUS", "RadSec", "HTTPS(ECC)", "HTTPS(RSA)")   # HTTPS last: it restarts the web service
_TIMEOUT = 60
_POLL_INTERVAL = 10
_REPLICATION_RETRIES = 3
_REPLICATION_DELAY = 5


class ClearPassDriver(Driver):
    name = "clearpass"
    label = "ClearPass Policy Manager"
    steps = ("deploy", "activate")
    probe_label = "Test API"
    probe_help = "Authenticate (OAuth2 client credentials), list the cluster nodes and the certificate slots. Changes nothing."
    served_label = "Served (API-reported)"
    activation_label = "Activation (REST)"

    def __init__(self):
        self._prepared: dict[str, dict] = {}

    def schema(self) -> list[Field]:
        return [
            Field("host", "ClearPass host (publisher or cluster FQDN)", required=True, group="Target",
                  help="All API calls go here; ClearPass proxies writes to the publisher and addresses nodes by UUID."),
            Field("client_id", "API client ID", required=True, group="Secrets",
                  help="Administration → API Services → API Clients: grant type client_credentials, operator profile with API access and Certificates read/write (Server Manager read for the node list)."),
            Field("client_secret", "API client secret", kind="password", secret=True, group="Secrets",
                  help="Blank falls back to the env var below."),
            Field("client_secret_env", "Client secret env var", default="CPPM_CLIENT_SECRET", group="Secrets",
                  via="<NAME>=… in .env; docker compose down && docker compose up -d",
                  via_text="Name of a variable in .env on the Docker host. Its value is never shown here."),
            Field("verify_ssl", "Verify the ClearPass TLS certificate on API calls", kind="checkbox", default=False, group="Target",
                  help="Leave off while the cluster still serves its factory certificate; turn on once the production certificate is live."),
            Field("ca_bundle", "CA bundle (optional)", group="Target", help="PEM bundle (path inside the container) when the cluster chains to a private CA."),
            Field("ca_bundle_mode", "Bundle mode", kind="select", default="exclusive", group="Target",
                  choices=[(m, m) for m in config.CA_BUNDLE_MODES]),
            Field("service_https_rsa", "HTTPS(RSA)", kind="checkbox", default=True, group="Services (slots to replace)",
                  help="Needs an RSA certificate. The web UI and guest portal restart on each node."),
            Field("service_https_ecc", "HTTPS(ECC)", kind="checkbox", default=False, group="Services (slots to replace)",
                  help="Needs an EC certificate (key type ec256/ec384): the slot rejects RSA keys. ECC-capable clients prefer this slot when it is enabled."),
            Field("service_radius", "RADIUS", kind="checkbox", default=False, group="Services (slots to replace)",
                  help="RSA certificate. RADIUS restarts on each node (brief authentication failures)."),
            Field("service_radsec", "RadSec", kind="checkbox", default=False, group="Services (slots to replace)",
                  help="RSA certificate. Skipped on nodes without a RadSec slot."),
            Field("other_slot_policy", "When the other HTTPS slot is enabled with a different key type", kind="select", default="block",
                  group="Services (slots to replace)", choices=[("block", "block: refuse to activate (default)"),
                                                                 ("warn", "warn and continue"),
                                                                 ("ignore", "ignore")],
                  help="Only one of HTTPS(RSA)/HTTPS(ECC) updated while the other stays enabled with an old certificate means some clients keep seeing the old one."),
            Field("nodes", "Nodes", default="all", group="Cluster",
                  help="'all', or a comma-separated list of node names, FQDNs or UUIDs from GET /api/cluster/server."),
            Field("verify_served", "Also verify the certificate served on each node's :443", kind="checkbox", default=True, group="Cluster",
                  help="TLS probe to the node (management IP, else FQDN) with the certificate name as SNI, restricted to the slot's key type. Turn off when nodes are not reachable from the runner."),
            Field("callback_host", "Callback host", required=True, group="PKCS#12 callback",
                  help="IP or FQDN of this Docker host that every ClearPass node can reach; ClearPass downloads the PKCS#12 from http://<callback_host>:<port>/<random>/<name>.p12.",
                  via="ports: - \"8765:8765\" on the cert manager service (docker-compose.override.yml)",
                  via_text="The callback port must be published by Compose and allowed by the host firewall from the ClearPass nodes."),
            Field("callback_port", "Callback port", kind="number", default=8765, group="PKCS#12 callback"),
            Field("callback_bind", "Callback bind address", default="0.0.0.0", group="PKCS#12 callback", advanced=True),
            Field("callback_ttl", "Callback lifetime (seconds)", kind="number", default=300, group="PKCS#12 callback", advanced=True,
                  help="The listener stops after the last PUT or when this expires; it serves one path, to the cluster's addresses only."),
            Field("allow_cross_env_rollback", "Allow rollback across CA environments", kind="checkbox", default=False, group="Rollback policy", advanced=True),
        ]

    def normalize(self, settings: dict) -> dict:
        n = super().normalize(settings)
        if not n["host"]:
            raise config.ConfigError("ClearPass host is required.")
        if not n["client_id"]:
            raise config.ConfigError("API client ID is required.")
        if not n["callback_host"] or n["callback_host"] in ("0.0.0.0", "localhost", "::", "::1"):
            raise config.ConfigError("Callback host must be an address the ClearPass nodes can reach (not localhost).")
        if not (1 <= n["callback_port"] <= 65535):
            raise config.ConfigError("Callback port must be between 1 and 65535.")
        if n["callback_port"] == 8080:
            raise config.ConfigError("Callback port 8080 is the web UI's port inside the container.")
        if not any(n[k] for k in ("service_https_rsa", "service_https_ecc", "service_radius", "service_radsec")):
            raise config.ConfigError("Select at least one service slot.")
        if n["ca_bundle_mode"] not in config.CA_BUNDLE_MODES:
            raise config.ConfigError("CA bundle mode must be 'exclusive' or 'additive'.")
        n["client_secret_env"] = n["client_secret_env"] or "CPPM_CLIENT_SECRET"
        n["nodes"] = n["nodes"] or "all"
        return n

    def flat(self, target: Target) -> dict:
        d = dict(target.settings)
        d["client_secret"] = ""
        return d

    # ---- helpers ------------------------------------------------------------
    def display_host(self, target: Target) -> str:
        return str(target.settings.get("host") or "")

    def services(self, target: Target) -> list[str]:
        s = target.settings
        chosen = {"HTTPS(RSA)": s.get("service_https_rsa"), "HTTPS(ECC)": s.get("service_https_ecc"),
                  "RADIUS": s.get("service_radius"), "RadSec": s.get("service_radsec")}
        return [name for name in SERVICE_ORDER if chosen.get(name)]

    def _secret(self, target: Target) -> str:
        s = target.settings
        import os
        return s.get("client_secret") or os.environ.get(s.get("client_secret_env") or "CPPM_CLIENT_SECRET", "")

    def _verify(self, target: Target):
        s = target.settings
        if not s.get("verify_ssl"):
            return False
        return config.api_trust_bundle(s.get("ca_bundle", ""), s.get("ca_bundle_mode", "exclusive"))

    def summary(self, target: Target) -> dict[str, Any]:
        s = target.settings
        cert = self.certificate_of(target)
        return {
            "host": s.get("host"), "client_id": s.get("client_id"), "secret_inline": bool(s.get("client_secret")),
            "secret_env": s.get("client_secret_env"), "verify_ssl": bool(s.get("verify_ssl")),
            "services": ", ".join(self.services(target)), "nodes": s.get("nodes"),
            "callback": f"http://{s.get('callback_host')}:{s.get('callback_port')}/<random>/<name>.p12",
            "other_slot_policy": s.get("other_slot_policy"),
            "snapshot": snapshot_info(s, self.snapshot_dir(target), cert.domain),
            "ssh_warnings": [],
        }

    # ---- checks -------------------------------------------------------------
    def preflight(self, target: Target) -> list[str]:
        problems: list[str] = []
        s = target.settings
        if not self._secret(target):
            problems.append(f"no API client secret (inline or {s.get('client_secret_env') or 'CPPM_CLIENT_SECRET'}).")
        cert = self.certificate_of(target)
        kt = (cert.key_type or "rsa2048").lower()
        svc = self.services(target)
        if "HTTPS(ECC)" in svc and not kt.startswith("ec"):
            problems.append(f"HTTPS(ECC) needs an EC certificate; this certificate's key type is {kt} (the slot rejects RSA keys).")
        if any(x in svc for x in ("HTTPS(RSA)", "RADIUS", "RadSec")) and kt.startswith("ec"):
            problems.append(f"HTTPS(RSA)/RADIUS/RadSec need an RSA certificate; this certificate's key type is {kt}.")
        return problems

    def warnings(self, target: Target) -> list[str]:
        out = []
        if not target.settings.get("verify_ssl"):
            out.append("verify_ssl is off: API calls do not verify the ClearPass certificate.")
        if str(target.settings.get("callback_host", "")).startswith("127."):
            out.append("callback_host is a loopback address: ClearPass nodes cannot fetch the PKCS#12 from it unless they run on this host.")
        return out

    def _session(self, target: Target) -> tuple[requests.Session, str]:
        """Authenticated session and base URL; raises ClearPassError."""
        s = target.settings
        base = f"https://{s['host']}/api"
        sess = requests.Session()
        sess.verify = self._verify(target)
        secret = self._secret(target)
        if not secret:
            raise ClearPassError("auth", "no API client secret configured")
        data = {"grant_type": "client_credentials", "client_id": s["client_id"], "client_secret": secret}
        try:
            r = sess.post(f"{base}/oauth", data=data, timeout=_TIMEOUT)
            if r.status_code in (400, 415):
                r = sess.post(f"{base}/oauth", json=data, timeout=_TIMEOUT)
        except requests.exceptions.SSLError as exc:
            raise ClearPassError("auth", f"TLS verification of {s['host']} failed: {redact(str(exc))}; turn off verify_ssl "
                                         f"until the production certificate is live, or set ca_bundle", kind="tls") from exc
        except requests.RequestException as exc:
            raise ClearPassError("auth", f"could not reach {base}/oauth: {redact(str(exc))}", kind="transport") from exc
        if r.status_code != 200:
            raise ClearPassError("auth", f"POST /api/oauth returned HTTP {r.status_code}: {redact(r.text)} (wrong id/secret, "
                                         f"client disabled, public client, or grant type not client_credentials)",
                                 status=r.status_code, kind="rejected")
        tok = (r.json() or {}).get("access_token") if r.headers.get("Content-Type", "").startswith("application/json") else None
        if not tok:
            raise ClearPassError("auth", "POST /api/oauth succeeded but returned no access_token", kind="rejected")
        sess.headers.update({"Authorization": f"Bearer {tok}", "Accept": "application/json"})
        return sess, base

    def _get(self, sess: requests.Session, url: str, phase: str) -> Any:
        try:
            r = sess.get(url, timeout=_TIMEOUT)
        except requests.RequestException as exc:
            raise ClearPassError(phase, f"GET {url.split('/api')[-1]} failed: {redact(str(exc))}", kind="transport") from exc
        if r.status_code != 200:
            raise ClearPassError(phase, f"GET {url.split('/api')[-1]} returned HTTP {r.status_code}: {redact(r.text)}",
                                 status=r.status_code, kind="rejected" if r.status_code < 500 else "http")
        try:
            return r.json()
        except ValueError as exc:
            raise ClearPassError(phase, f"GET {url.split('/api')[-1]} did not return JSON") from exc

    @staticmethod
    def _items(data: Any) -> list[dict]:
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            emb = data.get("_embedded")
            if isinstance(emb, dict) and isinstance(emb.get("items"), list):
                return [x for x in emb["items"] if isinstance(x, dict)]
            if isinstance(data.get("items"), list):
                return [x for x in data["items"] if isinstance(x, dict)]
            return [data] if data.get("server_uuid") or data.get("service_name") else []
        return []

    def nodes(self, sess: requests.Session, base: str, target: Target) -> list[dict]:
        """Cluster nodes in update order: subscribers first, the entry/publisher node last."""
        raw = self._get(sess, f"{base}/cluster/server", "nodes")
        items = self._items(raw)
        want = (target.settings.get("nodes") or "all").strip().lower()
        wanted = {x.strip().lower() for x in want.split(",")} if want != "all" else None
        nodes = []
        for it in items:
            uuid = it.get("server_uuid") or it.get("uuid")
            if not uuid:
                continue
            node = {"uuid": str(uuid), "name": str(it.get("name") or ""), "fqdn": str(it.get("fqdn") or it.get("server_dns_name") or ""),
                    "management_ip": it.get("management_ip") or "", "server_ip": it.get("server_ip") or "",
                    "is_publisher": bool(it.get("is_publisher")), "local": bool(it.get("local_server")),
                    "replication": it.get("replication_status")}
            if wanted and not ({node["uuid"].lower(), node["name"].lower(), node["fqdn"].lower()} & wanted):
                continue
            nodes.append(node)
        if not nodes:
            raise ClearPassError("nodes", f"GET /api/cluster/server returned no matching node (nodes={want!r})")
        nodes.sort(key=lambda n: (n["local"] or n["is_publisher"], n["name"]))
        return nodes

    def slots(self, sess: requests.Session, base: str, node: dict, service: str) -> dict | None:
        try:
            raw = self._get(sess, f"{base}/server-cert/name/{node['uuid']}/{service}", "slots")
        except ClearPassError as exc:
            if exc.status == 404:
                return None
            raise
        items = self._items(raw)
        return items[0] if items else (raw if isinstance(raw, dict) else None)

    def probe(self, target: Target) -> StepResult:
        checks: list[dict] = []
        try:
            sess, base = self._session(target)
            checks.append({"command": "POST /api/oauth (client_credentials)", "ok": True})
            nodes = self.nodes(sess, base, target)
            checks.append({"command": "GET /api/cluster/server", "ok": True,
                           "note": ", ".join(f"{n['name'] or n['uuid']}{' (publisher)' if n['is_publisher'] else ''}" for n in nodes)})
            ok = True
            for n in nodes:
                for svc in self.services(target):
                    slot = self.slots(sess, base, n, svc)
                    if slot is None:
                        ok = ok and svc in ("RadSec",)
                        checks.append({"command": f"{n['name'] or n['uuid']}: {svc}", "ok": svc == "RadSec",
                                       "hint": "slot not present on this node" if svc != "RadSec" else "no RadSec slot; skipped"})
                        continue
                    info = _slot_info(slot)
                    checks.append({"command": f"{n['name'] or n['uuid']}: {svc}", "ok": True,
                                   "note": f"{info.get('public_key_algorithm') or '?'} · expires {info.get('not_after') or '?'} · "
                                           f"serial {info.get('serial') or '?'} · {'enabled' if info.get('enabled', True) else 'disabled'}"})
        except ClearPassError as exc:
            checks.append({"command": exc.phase, "ok": False, "error": str(exc)})
            return StepResult("probe", ok=False, message=str(exc), detail={"phase": exc.phase, "kind": exc.kind, "checks": checks})
        msg = (f"Authenticated to {target.settings['host']} as API client {target.settings['client_id']}; "
               f"{len(nodes)} node(s), slots present for {', '.join(self.services(target))}." if ok else
               "Authenticated, but a selected certificate slot is missing on a node (see checks).")
        return StepResult("probe", ok=ok, message=msg, detail={"phase": "authorize", "checks": checks})

    # ---- pipeline -----------------------------------------------------------
    def deploy(self, target: Target, bundle: CertBundle) -> StepResult:
        """Non-disruptive: package the PKCS#12, authenticate, resolve nodes, check slots and key types."""
        if not bundle.present:
            return StepResult("deploy", ok=False, message="missing certificate files to deploy", detail={"phase": "prepare", "kind": "local"})
        try:
            p12, kind = build_pkcs12(bundle, target.certificate.domain if target.certificate else "cert")
        except ValueError as exc:
            return StepResult("deploy", ok=False, message=f"cannot package the certificate: {exc}", detail={"phase": "pkcs12", "kind": "local"})
        svc = self.services(target)
        if "HTTPS(ECC)" in svc and kind != "ec":
            return StepResult("deploy", ok=False, message="HTTPS(ECC) is selected but the certificate key is RSA; the slot rejects RSA keys.",
                              detail={"phase": "prepare", "kind": "config"})
        if kind == "ec" and any(x in svc for x in ("HTTPS(RSA)", "RADIUS", "RadSec")):
            return StepResult("deploy", ok=False, message="HTTPS(RSA)/RADIUS/RadSec are selected but the certificate key is EC.",
                              detail={"phase": "prepare", "kind": "config"})
        try:
            sess, base = self._session(target)
            nodes = self.nodes(sess, base, target)
            plan = []
            policy = target.settings.get("other_slot_policy") or "block"
            warnings = []
            for n in nodes:
                for s in svc:
                    slot = self.slots(sess, base, n, s)
                    if slot is None:
                        if s == "RadSec":
                            continue
                        raise ClearPassError("slots", f"node {n['name'] or n['uuid']} has no {s} slot")
                    plan.append((n, s))
                if "HTTPS(RSA)" in svc and "HTTPS(ECC)" not in svc or "HTTPS(ECC)" in svc and "HTTPS(RSA)" not in svc:
                    other = "HTTPS(ECC)" if "HTTPS(RSA)" in svc else "HTTPS(RSA)"
                    oslot = self.slots(sess, base, n, other)
                    if oslot is not None and _slot_info(oslot).get("enabled", True):
                        msg = (f"node {n['name'] or n['uuid']}: {other} is enabled and will keep serving its own certificate to "
                               f"{'ECC-capable' if other == 'HTTPS(ECC)' else 'RSA-only'} clients; update both slots "
                               f"(a second certificate with the other key type) or disable {other} in ClearPass")
                        if policy == "warn":
                            warnings.append(msg)
                        elif policy != "ignore":
                            raise ClearPassError("slots", msg + f" (other_slot_policy={policy})", kind="config")
        except ClearPassError as exc:
            return StepResult("deploy", ok=False, message=str(exc), detail={"phase": exc.phase, "kind": exc.kind, "status": exc.status})
        self._prepared[target.id] = {"p12": p12, "kind": kind, "nodes": nodes, "plan": plan, "serial": bundle.serial,
                                     "warnings": warnings}
        return StepResult("deploy", ok=True,
                          message=(f"PKCS#12 ({kind.upper()} key) ready for {len(nodes)} node(s) × {len(svc)} slot(s) on "
                                   f"{target.settings['host']}; installing is the activation step."),
                          detail={"phase": "prepare", "nodes": [n["name"] or n["uuid"] for n in nodes], "services": svc,
                                  "warnings": warnings})

    def _push(self, target: Target, bundle: CertBundle, nodes: list[dict], timeout: int) -> tuple[bool, list[dict]]:
        """PUT the PKCS#12 to every (node, service) and verify each node; (all_ok, per-node results)."""
        p12, _ = build_pkcs12(bundle, target.certificate.domain if target.certificate else "cert")
        passphrase = secrets.token_urlsafe(24)
        s = target.settings
        sess, base = self._session(target)
        allowed = set()
        for n in nodes:
            for key in ("management_ip", "server_ip"):
                if n.get(key):
                    allowed.add(str(n[key]))
            if n.get("fqdn"):
                allowed.update(_resolve(n["fqdn"]))
        allowed.update(_resolve(s["host"]))
        results: list[dict] = []
        all_ok = True
        with CallbackServer(s.get("callback_bind") or "0.0.0.0", int(s["callback_port"]), s["callback_host"],
                            wrap_pkcs12(p12, passphrase), f"{(target.certificate.domain if target.certificate else 'cert')}.p12",
                            allowed, int(s.get("callback_ttl") or 300)) as cb:
            for idx, n in enumerate(nodes):
                node_res = {"node": n["name"] or n["uuid"], "uuid": n["uuid"], "services": {}, "ok": True}
                verify_anyway = False
                for svc in self.services(target):
                    try:
                        present = self.slots(sess, base, n, svc) is not None
                    except ClearPassError as exc:
                        node_res["services"][svc] = f"api error before the PUT: {exc}"
                        node_res["ok"] = False
                        break
                    if not present:
                        node_res["services"][svc] = "skipped (no slot)"
                        continue
                    status, text = self._put(sess, f"{base}/server-cert/name/{n['uuid']}/{svc}",
                                             {"pkcs12_file_url": cb.url, "pkcs12_passphrase": passphrase})
                    if status == 0:
                        # The response was lost (timeout, reset while the node restarted its web service):
                        # the PUT may well have landed. Verification decides; the node counts as changed.
                        node_res["services"][svc] = f"unknown (response lost: {redact(text)})"
                        node_res["unknown"] = True
                        verify_anyway = True
                        break
                    if status not in (200, 201, 204):
                        node_res["services"][svc] = f"HTTP {status}: {redact(text)}"
                        node_res["ok"] = False
                        break
                    node_res["services"][svc] = f"HTTP {status}"
                if idx == len(nodes) - 1:
                    cb.stop()        # the last PUT is out; nothing else may fetch the PKCS#12
                if node_res["ok"] or verify_anyway:
                    try:
                        ok, waited, how = self._verify_node(sess, base, target, n, bundle.serial, timeout)
                    except ClearPassError as exc:
                        ok, waited, how = False, 0, f"api error during verification: {exc}"
                    node_res["verified"] = ok
                    node_res["verify"] = how
                    node_res["wait_seconds"] = waited
                    node_res["ok"] = ok
                node_res["fetches"] = cb.fetches
                results.append(node_res)
                if not node_res["ok"]:
                    all_ok = False
                    break
            node_res = results[-1] if results else {}
            if cb.rejected:
                node_res["callback_rejected"] = sorted(cb.rejected)
        return all_ok, results

    def _put(self, sess: requests.Session, url: str, body: dict) -> tuple[int, str]:
        last = (0, "")
        for attempt in range(1, _REPLICATION_RETRIES + 1):
            try:
                r = sess.put(url, json=body, timeout=_TIMEOUT)
            except requests.RequestException as exc:
                return 0, str(exc)
            last = (r.status_code, r.text)
            if r.status_code == 403 and attempt < _REPLICATION_RETRIES:
                time.sleep(_REPLICATION_DELAY)      # replication lag on a subscriber
                continue
            break
        return last

    def _verify_node(self, sess, base, target: Target, node: dict, serial: int, timeout: int) -> tuple[bool, int, str]:
        """API-reported certificate (and optionally the one served on :443) must carry the serial."""
        deadline = time.time() + timeout
        waited = 0
        svc = self.services(target)
        want_https = [x for x in svc if x.startswith("HTTPS")]
        while True:
            api_ok = True
            how = "api"
            for s in svc:
                try:
                    slot = self.slots(sess, base, node, s)
                except ClearPassError as exc:
                    if exc.kind == "rejected":
                        raise
                    api_ok = False
                    how = f"api unreachable while verifying: {exc}"
                    break
                if slot is None:
                    continue
                info = _slot_info(slot)
                if not info.get("serial") or int(info["serial"], 16) != serial:
                    api_ok = False
                    break
            served_ok = True
            if api_ok and want_https and target.settings.get("verify_served", True):
                host = node.get("management_ip") or node.get("fqdn") or target.settings["host"]
                sni = target.certificate.domain if target.certificate else host
                kind = "ec" if "HTTPS(ECC)" in want_https and "HTTPS(RSA)" not in want_https else ("rsa" if "HTTPS(RSA)" in want_https else None)
                got = fetch_served_serial(host, 443, sni, kind)
                served_ok = got == serial
                how = f"api+served({host})" if served_ok else f"api ok, served({host}) {format(got, 'x') if got else 'unreadable'}"
            if api_ok and served_ok:
                return True, waited, how
            if time.time() >= deadline:
                return False, waited, how if (api_ok or how != "api") else "api-reported certificate unchanged"
            time.sleep(_POLL_INTERVAL)
            waited += _POLL_INTERVAL

    def activate(self, target: Target) -> StepResult:
        return StepResult("activate", ok=True, message="installation is done per node in the activation step")

    def verify(self, target: Target, serial: int, timeout: int) -> tuple[bool, int]:
        try:
            sess, base = self._session(target)
            nodes = self.nodes(sess, base, target)
            waited = 0
            for n in nodes:
                ok, w, _ = self._verify_node(sess, base, target, n, serial, max(1, timeout - waited))
                waited += w
                if not ok:
                    return False, waited
            return True, waited
        except ClearPassError:
            return False, 0

    def served_info(self, target: Target) -> dict[str, Any]:
        """The certificate the entry node reports in the first selected slot, plus a per-node summary.

        Nodes are addressed by their real server_uuid from GET /api/cluster/server; the
        literal "this" is documented only for the cluster endpoint.
        """
        try:
            sess, base = self._session(target)
            svc = self.services(target)
            service = svc[0] if svc else "HTTPS(RSA)"
            nodes = self.nodes(sess, base, target)
            host = (target.settings.get("host") or "").lower()
            entry = next((n for n in nodes if host and host in {n["fqdn"].lower(), str(n["management_ip"]).lower(),
                                                                str(n["server_ip"]).lower()}), None) or nodes[-1]
            per_node = []
            info = None
            for n in nodes:
                try:
                    slot = self.slots(sess, base, n, service)
                except ClearPassError as exc:
                    per_node.append({"node": n["name"] or n["uuid"], "error": str(exc)[:160]})
                    continue
                if slot is None:
                    per_node.append({"node": n["name"] or n["uuid"], "error": "slot not present"})
                    continue
                pem = slot.get("cert_file") or ""
                if "BEGIN CERTIFICATE" not in pem:
                    per_node.append({"node": n["name"] or n["uuid"], "error": "no cert_file in the API response"})
                    continue
                parsed = certs.parse_pem(pem.encode())
                per_node.append({"node": n["name"] or n["uuid"], "serial": parsed.get("serial"), "not_after": parsed.get("not_after"),
                                 "enabled": _slot_info(slot).get("enabled", True)})
                if n is entry:
                    info = parsed
            if info is None:
                info = dict(certs.ABSENT)
                mine = next((p for p in per_node if p["node"] == (entry["name"] or entry["uuid"])), {})
                info["error"] = mine.get("error") or "slot not present"
            else:
                info["error"] = None
            serials = {p.get("serial") for p in per_node if p.get("serial")}
            info["nodes"] = per_node
            info["service"] = service
            if len(serials) > 1:
                info["warning"] = f"nodes serve different certificates in {service}: " + ", ".join(
                    f"{p['node']} {p.get('serial') or p.get('error')}" for p in per_node)
            return info
        except (ClearPassError, ValueError) as exc:
            info = dict(certs.ABSENT)
            info["error"] = str(exc)[:200]
            return info

    def activate_step(self, target: Target, bundle: CertBundle) -> StepResult:
        prep = self._prepared.pop(target.id, None)
        try:
            if prep is None:
                sess, base = self._session(target)
                nodes = self.nodes(sess, base, target)
            else:
                nodes = prep["nodes"]
            ok, results = self._push(target, bundle, nodes, activation_timeout())
        except ClearPassError as exc:
            return StepResult("activate", ok=False, message=str(exc), detail={"phase": exc.phase, "kind": exc.kind, "status": exc.status})
        except OSError as exc:
            return StepResult("activate", ok=False, message=f"callback listener could not start: {exc} (is the port published and free?)",
                              detail={"phase": "callback", "kind": "local"})
        if ok:
            self.snapshot(target, bundle)
            return StepResult("activate", ok=True,
                              message=f"New certificate installed and verified on {len(results)} node(s) of {target.settings['host']}.",
                              detail={"serial": bundle.serial_hex, "nodes": results, "warnings": (prep or {}).get("warnings", [])})
        changed = [r for r in results if r.get("unknown") or any(v.startswith("HTTP 2") for v in r["services"].values())]
        failed = results[-1] if results else {}
        base_msg = (f"activation failed on node {failed.get('node')}: "
                    + "; ".join(f"{k} {v}" for k, v in failed.get("services", {}).items() if not v.startswith("HTTP 2"))
                    + (f" (verify: {failed.get('verify')})" if failed.get("verify") else ""))
        if failed.get("callback_rejected"):
            base_msg += f"; the callback listener refused connections from {failed['callback_rejected']} (not a known node address)"
        # roll back the nodes already changed in this run
        snap = self.snapshot_bundle(target)
        if not changed:
            return StepResult("activate", ok=False, message=base_msg + "; nothing was changed", detail={"nodes": results, "rolled_back": False})
        if snap is None:
            return StepResult("activate", ok=False, message=base_msg + f"; {len(changed)} node(s) updated and no snapshot to roll back to",
                              detail={"nodes": results, "rolled_back": False, "reason": "no known-good snapshot"})
        refusal = cross_environment_refusal(target, snap, bundle)
        if refusal:
            return StepResult("activate", ok=False, message=base_msg + "; " + refusal,
                              detail={"nodes": results, "rolled_back": False, "reason": "cross-environment rollback refused"})
        try:
            rb_ok, rb_results = self._push(target, snap, [n for n in nodes if (n["name"] or n["uuid"]) in {c["node"] for c in changed}],
                                           rollback_timeout())
        except (ClearPassError, OSError) as exc:
            return StepResult("activate", ok=False, message=base_msg + f"; rollback failed: {exc}",
                              detail={"nodes": results, "rolled_back": False})
        return StepResult("activate", ok=False,
                          message=base_msg + ("; rolled back the updated node(s) to the previous certificate" if rb_ok
                                              else "; rollback did not verify on every updated node"),
                          detail={"nodes": results, "rollback": rb_results, "rolled_back": rb_ok,
                                  "restored_serial": snap.serial_hex, "failed_serial": bundle.serial_hex})


# --------------------------------------------------------------------------- helpers

class ClearPassError(Exception):
    def __init__(self, phase: str, message: str, status: int | None = None, kind: str = "http"):
        super().__init__(message)
        self.phase, self.status, self.kind = phase, status, kind


def _slot_info(slot: dict) -> dict:
    info = {"enabled": slot.get("enabled", True), "public_key_algorithm": slot.get("public_key_algorithm"),
            "service_name": slot.get("service_name"), "serial": None, "not_after": slot.get("expiry_date")}
    pem = slot.get("cert_file") or ""
    if "BEGIN CERTIFICATE" in pem:
        try:
            parsed = certs.parse_pem(pem.encode())
            info["serial"] = parsed["serial"]
            info["not_after"] = parsed["not_after"]
        except ValueError:
            pass
    return info


def _resolve(host: str) -> set[str]:
    out = set()
    if not host:
        return out
    try:
        ipaddress.ip_address(host)
        return {host}
    except ValueError:
        pass
    try:
        for _fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            out.add(sockaddr[0])
    except OSError:
        pass
    return out


def build_pkcs12(bundle: CertBundle, name: str) -> tuple[bytes, str]:
    """Unencrypted PKCS#12 (leaf + chain + key) and the key kind ('rsa' | 'ec'); the
    passphrase is applied per run by wrap_pkcs12() so the same package serves a rollback too."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.exceptions import UnsupportedAlgorithm
    try:
        key = serialization.load_pem_private_key(bundle.key.read_bytes(), password=None)
    except UnsupportedAlgorithm as exc:
        raise ValueError(f"unsupported private key algorithm: {exc}") from exc
    leaf = x509.load_pem_x509_certificate(bundle.cert.read_bytes())
    if leaf.public_key().public_numbers() != key.public_key().public_numbers():
        raise ValueError("the private key does not match the certificate")
    chain = [x509.load_pem_x509_certificate(b.encode()) for b in _pem_blocks(bundle.chain.read_text())]
    kind = "ec" if isinstance(key, ec.EllipticCurvePrivateKey) else ("rsa" if isinstance(key, rsa.RSAPrivateKey) else "other")
    data = pkcs12.serialize_key_and_certificates(name.encode()[:60], key, leaf, chain, serialization.NoEncryption())
    return data, kind


def wrap_pkcs12(unencrypted: bytes, passphrase: str) -> bytes:
    """Re-serialize with the run's passphrase (PBES2 AES-256-CBC, SHA-256 MAC: OpenSSL 3 defaults)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    key, leaf, extra = pkcs12.load_key_and_certificates(unencrypted, None)
    return pkcs12.serialize_key_and_certificates(b"cppm-server-cert", key, leaf, extra or [],
                                                 serialization.BestAvailableEncryption(passphrase.encode()))


def _pem_blocks(text: str) -> list[str]:
    begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    out, idx = [], 0
    while True:
        a = text.find(begin, idx)
        if a == -1:
            break
        b = text.find(end, a)
        if b == -1:
            break
        out.append(text[a:b + len(end)])
        idx = b + len(end)
    return out


def fetch_served_serial(host: str, port: int, sni: str, kind: str | None) -> int | None:
    """Serial of the certificate a node serves, negotiating only the slot's key type when asked."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if kind in ("rsa", "ec"):
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2      # TLS 1.3 suites are key-type agnostic
        ctx.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256"
                        if kind == "rsa" else "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256")
    try:
        with socket.create_connection((host, port), timeout=certs.SERVED_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None
    from cryptography import x509
    try:
        return x509.load_der_x509_certificate(der).serial_number
    except ValueError:
        return None


class CallbackServer:
    """Serves one PKCS#12 at one random path to allow-listed client addresses, briefly.

    ClearPass fetches ``pkcs12_file_url`` itself; every other request is 404
    and every request from an address that is not a cluster node is refused
    (and recorded for the diagnostics).
    """

    def __init__(self, bind: str, port: int, public_host: str, data: bytes, name: str, allowed: set[str], ttl: int):
        self.path = f"/{secrets.token_hex(16)}/{name}"
        self.url = f"http://{public_host}:{port}{self.path}"
        self.data, self.allowed, self.ttl = data, allowed, max(1, int(ttl))
        self.fetches = 0
        self._deadline = 0.0
        self._stopped = False
        self.rejected: set[str] = set()
        self._bind, self._port = bind, port
        self._srv = None
        self._thread = None

    def __enter__(self):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _allowed(self) -> bool:
                if outer._stopped or time.monotonic() > outer._deadline:
                    return False      # lifetime over: nothing is served, whoever asks
                ip = self.client_address[0]
                if outer.allowed and ip not in outer.allowed:
                    outer.rejected.add(ip)
                    return False
                return True

            def do_HEAD(self):
                if not self._allowed() or self.path != outer.path:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/x-pkcs12")
                self.send_header("Content-Length", str(len(outer.data)))
                self.end_headers()

            def do_GET(self):
                if not self._allowed() or self.path != outer.path:
                    self.send_response(404)
                    self.end_headers()
                    return
                outer.fetches += 1
                self.send_response(200)
                self.send_header("Content-Type", "application/x-pkcs12")
                self.send_header("Content-Length", str(len(outer.data)))
                self.end_headers()
                self.wfile.write(outer.data)

        self._deadline = time.monotonic() + self.ttl
        http.server.ThreadingHTTPServer.allow_reuse_address = True
        self._srv = http.server.ThreadingHTTPServer((self._bind, self._port), Handler)
        self._srv.timeout = 1
        self._thread = threading.Thread(target=self._srv.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        """Stop serving the PKCS#12 while the listener stays up for the diagnostics."""
        self._stopped = True

    def __exit__(self, *exc):
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()
        return False


register(ClearPassDriver())
