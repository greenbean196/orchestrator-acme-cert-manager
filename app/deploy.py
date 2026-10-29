"""Deploy the cert to Orchestrator via the httpsCertificate REST API.

deploy(server) uploads the current flattened cert from cert_dir_for(server).
deploy_paths(...) uploads a specific cert/key/chain — used by the rollback path
to re-install the last-known-good certificate.

Two API calls, in order, each reported with phase/status/attempt/elapsed:

  validation  POST .../httpsCertificate/validation   idempotent; retried with
              backoff on transport errors and HTTP 502/503/504 (a GMS backend
              that is restarting answers 502 through its reverse proxy).
  install     POST .../httpsCertificate              NOT retried: the appliance
              may have applied the upload even when the response was lost.

Nothing here ever contacts the ACME CA, so a retry can never spend an issuance.
Response bodies are kept in the step detail after redaction of key material,
PEM blocks and data: URIs.
"""
from __future__ import annotations

import base64
import logging
import os
import re
import time
from urllib.parse import urlsplit
from pathlib import Path

import requests
import urllib3

from . import config
from .models import ServerConfig, StepResult

log = logging.getLogger("deploy")

STEP = "deploy"
_CERT_MEDIA = "application/x-x509-ca-cert"
_KEY_MEDIA = "application/octet-stream"
_TIMEOUT = int(os.environ.get("DEPLOY_HTTP_TIMEOUT", "30"))
VALIDATION_ATTEMPTS = max(1, int(os.environ.get("DEPLOY_VALIDATION_ATTEMPTS", "3")))
RETRY_BACKOFF_S = float(os.environ.get("DEPLOY_RETRY_BACKOFF", "5"))
TRANSIENT_STATUSES = {502, 503, 504}
_EXCERPT_LEN = 600

_PEM_RE = re.compile(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", re.S)
_DATA_URI_RE = re.compile(r"data:[\w/+.-]+;base64,[A-Za-z0-9+/=]+")
_LONG_B64_RE = re.compile(r"[A-Za-z0-9+/=]{48,}")
_SECRET_FIELD_RE = re.compile(r'("(?:password|passPhrase|keyData|certificateData|'
                              r'intermediateCertFileContent|token|apiKey)"\s*:\s*)"[^"]*"', re.I)


def _location_summary(location: str) -> str:
    """scheme://host[:port]/path of a redirect target: no userinfo, query or fragment (they may echo the token)."""
    if not location:
        return "<none>"
    try:
        u = urlsplit(location)
    except ValueError:
        return "<unparseable>"
    host = u.hostname or ""
    if u.port:
        host = f"{host}:{u.port}"
    return f"{u.scheme}://{host}{u.path}" if u.scheme or host else (u.path or "<none>")


def redact(text: str, limit: int = _EXCERPT_LEN) -> str:
    """Strip anything that could be key material or a credential, then truncate."""
    if not text:
        return ""
    t = _PEM_RE.sub("<pem-redacted>", text)
    t = _DATA_URI_RE.sub("<data-uri-redacted>", t)
    t = _SECRET_FIELD_RE.sub(r'\1"<redacted>"', t)
    t = _LONG_B64_RE.sub("<b64-redacted>", t)
    t = " ".join(t.split())
    return t[:limit] + ("…" if len(t) > limit else "")


def deploy(server: ServerConfig) -> StepResult:
    """Upload the current flattened certificate for this server."""
    cert_dir = config.cert_dir_for(server)
    return deploy_paths(
        server,
        cert_dir / f"{server.domain}.cer",
        cert_dir / f"{server.domain}.key",
        cert_dir / "ca.cer",
    )


def deploy_paths(server: ServerConfig, cert_file: Path, key_file: Path, ca_file: Path) -> StepResult:
    """Upload a specific cert/key/chain trio (validate, then install)."""
    for f in (cert_file, key_file, ca_file):
        if not Path(f).exists():
            return StepResult(STEP, ok=False,
                              message=f"missing file for deploy: {Path(f).name}",
                              detail={"phase": "prepare", "kind": "local"})

    try:
        api_key = config.api_key_for(server)
    except config.ConfigError as exc:
        return StepResult(STEP, ok=False, message=str(exc), detail={"phase": "prepare", "kind": "config"})

    payload = {
        "certificateData": _data_uri(Path(cert_file).read_bytes(), _CERT_MEDIA),
        "keyData": _data_uri(Path(key_file).read_bytes(), _KEY_MEDIA),
        "intermediateCertFileContent": _data_uri(Path(ca_file).read_bytes(), _CERT_MEDIA),
    }
    headers = {"Content-Type": "application/json", "X-Auth-Token": api_key}
    base_url = server.base_url
    # Verified calls trust system roots + the lab root + the server's ca_bundle
    # together, independent of which CA is *configured*: during a migration or a
    # rollback the appliance still serves the previous CA's certificate.
    try:
        verify = (config.api_trust_bundle(server.ca_bundle, server.ca_bundle_mode)
                  if server.verify_ssl else False)
    except config.ConfigError as exc:
        return StepResult(STEP, ok=False, message=str(exc), detail={"phase": "prepare", "kind": "config"})

    if verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        log.warning("deploy(%s): verify_ssl is off — the Orchestrator API certificate is not "
                    "checked. Enable it once the production certificate is live.", server.id)

    r_val = _call(server, "validation", f"{base_url}/validation", payload, headers, verify,
                  attempts=VALIDATION_ATTEMPTS)
    if not r_val.ok:
        return r_val

    r_ins = _call(server, "install", base_url, payload, headers, verify, attempts=1)
    if not r_ins.ok:
        return r_ins

    v_status = r_val.detail["status"]
    i_status = r_ins.detail["status"]
    log.info("deploy(%s): uploaded (validation %s, install %s)", server.id, v_status, i_status)
    return StepResult(STEP, ok=True,
                      message=(f"Certificate uploaded to {server.orchestrator_host} "
                               f"(validation {v_status}, install {i_status})."),
                      detail={"validation_status": v_status, "install_status": i_status,
                              "validation_attempts": r_val.detail["attempts"],
                              "validation_response": r_val.detail.get("response_excerpt", "")})


# --------------------------------------------------------------------------- http

def _call(server: ServerConfig, phase: str, url: str, payload: dict, headers: dict,
          verify, attempts: int) -> StepResult:
    """POST once (install) or with bounded retries (validation); classify the outcome."""
    endpoint = "/httpsCertificate" + ("/validation" if phase == "validation" else "")
    started = time.monotonic()
    last: StepResult | None = None

    for attempt in range(1, attempts + 1):
        t0 = time.monotonic()
        try:
            resp = requests.post(url, json=payload, headers=headers, verify=verify, timeout=_TIMEOUT,
                                 allow_redirects=False)      # never forward the key or token to another host
        except requests.exceptions.SSLError as exc:
            elapsed = int((time.monotonic() - t0) * 1000)
            last = _failure(server, phase, endpoint, "tls", None, attempt, attempts, elapsed,
                            excerpt=redact(str(exc)))
            retryable = False        # a trust problem does not fix itself between attempts
        except requests.RequestException as exc:
            elapsed = int((time.monotonic() - t0) * 1000)
            kind = "transport"
            last = _failure(server, phase, endpoint, kind, None, attempt, attempts, elapsed,
                            excerpt=redact(str(exc)))
            retryable = attempts > 1
        else:
            elapsed = int((time.monotonic() - t0) * 1000)
            status = resp.status_code
            if 300 <= status < 400:
                last = _failure(server, phase, endpoint, "redirect", status, attempt, attempts, elapsed,
                                excerpt=f"Location: {_location_summary(resp.headers.get('Location', ''))}")
                retryable = False
                break
            if resp.ok:
                log.info("deploy(%s): %s HTTP %s in %dms (attempt %d/%d)",
                         server.id, phase, status, elapsed, attempt, attempts)
                return StepResult(STEP, ok=True, message=f"{phase} HTTP {status}",
                                  detail={"phase": phase, "status": status, "attempts": attempt,
                                          "elapsed_ms": elapsed,
                                          "response_excerpt": redact(resp.text)})
            if status in TRANSIENT_STATUSES:
                kind = "transient"
            elif status in (401, 403):
                kind = "auth"
            elif status < 500:
                kind = "rejected"
            else:
                kind = "http"
            last = _failure(server, phase, endpoint, kind, status, attempt, attempts, elapsed,
                            excerpt=redact(resp.text), request_id=resp.headers.get("X-Request-Id"))
            retryable = kind == "transient" and attempts > 1

        if retryable and attempt < attempts:
            delay = RETRY_BACKOFF_S * (2 ** (attempt - 1))
            log.warning("deploy(%s): %s attempt %d/%d failed (%s); retrying in %.0fs",
                        server.id, phase, attempt, attempts, last.message, delay)
            time.sleep(delay)
            continue
        break

    assert last is not None
    last.detail["total_elapsed_ms"] = int((time.monotonic() - started) * 1000)
    log.error("deploy(%s): %s", server.id, last.message)
    return last


def _failure(server: ServerConfig, phase: str, endpoint: str, kind: str, status: int | None,
             attempt: int, attempts: int, elapsed_ms: int, excerpt: str,
             request_id: str | None = None) -> StepResult:
    status_txt = f"HTTP {status}" if status is not None else "no HTTP response"
    if kind == "redirect":
        headline = "Certificate validation failed" if phase == "validation" else "Certificate install failed"
        message = (f"{headline} on {server.id}: {status_txt} ({kind}) on {endpoint} — the Orchestrator answered with a "
                   f"redirect to {excerpt.removeprefix('Location: ')}, which this tool never follows (it would send the "
                   f"private key and API key elsewhere). Check orchestrator_host; not retried.")
        return StepResult(STEP, ok=False, message=message, detail={
            "phase": phase, "kind": kind, "endpoint": endpoint, "status": status, "attempt": attempt,
            "attempts": attempts, "elapsed_ms": elapsed_ms, "response_excerpt": excerpt,
            "next_action": "fix orchestrator_host", "server_id": server.id, "host": server.orchestrator_host})
    if kind == "tls":
        headline = "Certificate validation failed" if phase == "validation" else "Certificate install failed"
        explain = ("TLS verification of the Orchestrator API failed: the appliance certificate does not chain "
                   "to a trusted root (a staging or self-signed certificate is still being served)")
        nxt = ("turn off verify_ssl for this target until the production certificate is live, or set "
               "ca_bundle to the CA that issued the appliance certificate; not retried")
        message = (f"{headline} on {server.id}: {status_txt} ({kind}) on {endpoint}, "
                   f"attempt {attempt} of {attempts} — {explain}. Next: {nxt}.")
        return StepResult(STEP, ok=False, message=message, detail={
            "phase": phase, "kind": kind, "endpoint": endpoint, "status": status, "attempt": attempt,
            "attempts": attempts, "elapsed_ms": elapsed_ms, "response_excerpt": excerpt,
            "next_action": nxt, "server_id": server.id, "host": server.orchestrator_host})
    if phase == "validation":
        if kind == "transient":
            explain = ("transient gateway error from the Orchestrator reverse proxy — the GMS "
                       "backend is probably restarting or overloaded")
            nxt = ("retry with Force deploy (reuses the issued certificate; no CA contact)"
                   if attempt >= attempts else "retrying after backoff")
        elif kind == "auth":
            explain = "the Orchestrator refused the API key"
            nxt = ("check the API key (X-Auth-Token): it must exist, be unexpired, allow this source address and "
                   "hold READ_WRITE for certificate management; not retried")
        elif kind == "rejected":
            explain = "the Orchestrator rejected the certificate/key/chain payload"
            nxt = "check the response excerpt; verify the key matches the certificate and the chain is complete"
        elif kind == "transport":
            explain = "could not reach the Orchestrator API"
            nxt = "check reachability, DNS, and TLS settings (verify_ssl / ca_bundle)"
        else:
            explain = "the Orchestrator API returned a server error"
            nxt = "inspect the appliance logs; retry with Force deploy"
        headline = "Certificate validation failed"
    else:
        headline = "Certificate install failed"
        if kind == "transport":
            explain = ("the install request did not complete — the appliance may or may not have "
                       "applied it")
            nxt = "do not re-issue; run Force deploy to re-validate and re-install, then verify the served serial"
        elif kind == "auth":
            explain = "the Orchestrator refused the API key during install"
            nxt = "check the API key (X-Auth-Token): validity, expiry, source-address allow list and READ_WRITE role; no certificate was activated"
        elif kind == "rejected":
            explain = "the Orchestrator rejected the install request"
            nxt = "check the response excerpt and the API key's role"
        elif kind == "transient":
            explain = ("the Orchestrator reverse proxy answered with a gateway error during install — the GMS backend "
                       "may still have applied the upload")
            nxt = "do not re-issue; run Force deploy to re-validate and re-install, then verify the served serial"
        else:
            explain = "the Orchestrator returned a server error during install"
            nxt = "run Force deploy once the appliance is healthy; no certificate was activated"

    message = (f"{headline} on {server.id}: {status_txt} ({kind}) on {endpoint}, "
               f"attempt {attempt} of {attempts} — {explain}. Next: {nxt}.")
    detail = {
        "phase": phase, "kind": kind, "endpoint": endpoint, "status": status,
        "attempt": attempt, "attempts": attempts, "elapsed_ms": elapsed_ms,
        "response_excerpt": excerpt, "next_action": nxt,
        "server_id": server.id, "host": server.orchestrator_host,
    }
    if request_id:
        detail["request_id"] = request_id
    return StepResult(STEP, ok=False, message=message, detail=detail)


def _data_uri(raw: bytes, media_type: str) -> str:
    return f"data:{media_type};base64,{base64.b64encode(raw).decode('ascii')}"
