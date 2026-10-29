"""ACME Renewal Information (RFC 9773) lookups.

Let's Encrypt publishes a suggested renewal window per certificate and uses it
to ask for early renewal after a revocation or an incident; renewals made
inside that window are exempt from rate limits. The lookup is an
unauthenticated GET keyed by the certificate's Authority Key Identifier and
serial, so it costs one request per scheduled pass and nothing when the CA
(the bundled step-ca, say) does not advertise ``renewalInfo``.
"""
from __future__ import annotations

import base64
import datetime
import logging
import time
from typing import Any

import requests

log = logging.getLogger("ari")

_TIMEOUT = 10
_DIRECTORY_TTL = 3600
_directories: dict[str, tuple[float, str | None]] = {}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def cert_id(leaf_pem: bytes) -> str | None:
    """base64url(AKI keyIdentifier) + '.' + base64url(DER serial), or None without an AKI."""
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(leaf_pem)
    try:
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
    except x509.ExtensionNotFound:
        return None
    if not aki:
        return None
    serial = cert.serial_number
    raw = serial.to_bytes((serial.bit_length() + 8) // 8, "big", signed=True)   # DER INTEGER contents, minimal
    return f"{_b64url(aki)}.{_b64url(raw)}"


def renewal_info_url(directory_url: str, verify) -> str | None:
    """The directory's renewalInfo endpoint (cached for an hour), or None when absent."""
    now = time.monotonic()
    hit = _directories.get(directory_url)
    if hit and now - hit[0] < _DIRECTORY_TTL:
        return hit[1]
    url = None
    try:
        r = requests.get(directory_url, timeout=_TIMEOUT, verify=verify)
        if r.status_code == 200:
            url = (r.json() or {}).get("renewalInfo")
    except (requests.RequestException, ValueError) as exc:
        log.debug("ARI: directory %s not readable: %s", directory_url, exc)
        return None            # not cached: try again next time
    _directories[directory_url] = (now, url)
    return url


def _parse(ts: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))


def renewal_info(directory_url: str, leaf_pem: bytes, verify=True) -> dict[str, Any] | None:
    """{'start', 'end', 'explanation_url', 'retry_after'} for this certificate, or None.

    None means "no ARI": the directory does not offer it, the CA does not know
    the certificate (it came from somewhere else), or the request failed.
    Callers fall back to their own renewal rule.
    """
    base = renewal_info_url(directory_url, verify)
    if not base:
        return None
    try:
        cid = cert_id(leaf_pem)
    except ValueError:
        return None
    if not cid:
        return None
    try:
        r = requests.get(f"{base.rstrip('/')}/{cid}", timeout=_TIMEOUT, verify=verify)
    except requests.RequestException as exc:
        log.info("ARI lookup failed (%s); using the local renewal rule", exc)
        return None
    if r.status_code != 200:
        log.info("ARI: CA answered HTTP %s for this certificate; using the local renewal rule", r.status_code)
        return None
    try:
        body = r.json()
        win = body["suggestedWindow"]
        start, end = _parse(win["start"]), _parse(win["end"])
    except (ValueError, KeyError, TypeError) as exc:
        log.info("ARI: unusable response (%s); using the local renewal rule", exc)
        return None
    if end <= start:
        return None
    return {"start": start, "end": end, "explanation_url": body.get("explanationURL"),
            "retry_after": r.headers.get("Retry-After")}


def reset_cache() -> None:
    _directories.clear()
