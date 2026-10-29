"""Certificate inspection shared by the pipeline, the drivers and the web UI.

Everything here is observation: parse a PEM leaf, read what a host serves on a
port, classify an issuer as lab / staging / production, and decide whether a
certificate is due for renewal from its own validity period.
"""
from __future__ import annotations

import datetime
import os
import socket
import ssl
from pathlib import Path
from typing import Any

from . import config

SERVED_TIMEOUT = 5


def environment_of(issuer: str | None) -> str | None:
    """'lab' / 'staging' / 'production' from an issuer DN, or None if unknown."""
    if not issuer:
        return None
    if issuer in config.lab_ca_issuer_names():
        return "lab"
    up = issuer.upper()
    if "STAGING" in up or "FAKE" in up or "ERSATZ" in up:
        return "staging"
    return "production"


def parse_pem(pem: bytes) -> dict[str, Any]:
    """Facts about one PEM certificate (the first in the data)."""
    from cryptography import x509  # lazy import
    cert = x509.load_pem_x509_certificate(pem)
    na = cert.not_valid_after_utc
    nb = cert.not_valid_before_utc
    now = datetime.datetime.now(datetime.timezone.utc)
    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()
    lifetime = (na - nb).total_seconds()
    remaining = (na - now).total_seconds()
    return {
        "present": True,
        "not_before": nb.strftime("%Y-%m-%d"),
        "not_after": na.strftime("%Y-%m-%d"),
        "not_after_iso": na.isoformat(),
        "days_left": (na - now).days,
        "seconds_left": int(remaining),
        "lifetime_days": max(1, int(round(lifetime / 86400))),
        "fraction_left": max(0.0, min(1.0, remaining / lifetime)) if lifetime > 0 else 0.0,
        "serial": format(cert.serial_number, "X"),
        "issuer": issuer,
        "subject": subject,
        "self_signed": issuer == subject,
        "environment": environment_of(issuer),
    }


ABSENT: dict[str, Any] = {"present": False, "not_before": None, "not_after": None, "days_left": None,
                          "seconds_left": None, "lifetime_days": None, "fraction_left": None, "serial": None, "issuer": None,
                          "subject": None, "self_signed": None, "environment": None}


def leaf_info(path: Path) -> dict[str, Any]:
    """The issued certificate on disk, or the ABSENT shape."""
    info = dict(ABSENT)
    if not Path(path).exists():
        return info
    try:
        info.update(parse_pem(Path(path).read_bytes()))
    except Exception as exc:  # noqa: BLE001 - a corrupt file is reported, never fatal
        info["error"] = str(exc)
    return info


def fetch_served(host: str, port: int = 443, timeout: int = SERVED_TIMEOUT, sni: str | None = None) -> dict[str, Any]:
    """The certificate a host presents on a port right now (no chain validation).

    ``sni`` is the name sent in the TLS handshake; it defaults to ``host`` but a
    target reached by IP or by a different name must send the certificate's own
    name, or a server with several virtual hosts answers with its default one.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni or host) as tls:
                der = tls.getpeercert(binary_form=True)
        if not der:
            raise ValueError("no certificate presented")
        info = parse_pem(ssl.DER_cert_to_PEM_cert(der).encode())
        info["error"] = None
        return info
    except (ssl.SSLError, OSError, ValueError) as exc:
        info = dict(ABSENT)
        info["error"] = str(exc) or exc.__class__.__name__
        return info


def renew_window_days() -> int | None:
    """An explicit RENEW_WINDOW_DAYS override, or None for the lifetime-fraction rule."""
    raw = os.environ.get("RENEW_WINDOW_DAYS", "").strip()
    if not raw:
        return None
    try:
        days = int(raw)
    except ValueError:
        return None
    return days if days > 0 else None          # 0 or negative: the lifetime rule


RENEW_FRACTION = 1 / 3          # renew once a third of the lifetime (or less) remains ...
RENEW_FRACTION_SHORT = 1 / 2    # ... or half of it for lifetimes of 10 days or less (LE / Lego / Certbot rule)
SHORT_LIFETIME_DAYS = 10


def renew_fraction(lifetime_days: float) -> float:
    return RENEW_FRACTION_SHORT if lifetime_days <= SHORT_LIFETIME_DAYS else RENEW_FRACTION


def due_for_renewal(info: dict[str, Any], ari: dict[str, Any] | None = None) -> tuple[bool, str]:
    """Whether the issued certificate should be renewed now, and why.

    Order of precedence:
      1. RENEW_WINDOW_DAYS, when set: an absolute days-before-expiry window.
      2. The CA's ARI suggested window (RFC 9773), when ``ari`` is given: due
         once the window has opened. This is how the CA asks for early renewal
         after a revocation or incident, and renewals inside it are exempt
         from rate limits.
      3. The lifetime rule: renew when a third of the certificate's own
         lifetime remains (30 days for 90, 15 for 45), or half of it for
         lifetimes of 10 days or less (about 3.3 days for a 6.7-day one).
    """
    if not info.get("present"):
        return True, "no certificate on disk"
    days_left = info.get("days_left")
    if days_left is None:
        return True, "certificate on disk could not be read"
    override = renew_window_days()
    if override is not None:
        due = days_left <= override
        return due, (f"{days_left} days left, window {override} days (RENEW_WINDOW_DAYS)")
    if ari and ari.get("start") and ari.get("end"):
        now = datetime.datetime.now(datetime.timezone.utc)
        start, end = ari["start"], ari["end"]
        if now >= start:
            return True, (f"ARI window open since {start.isoformat(timespec='minutes')} "
                          f"(until {end.isoformat(timespec='minutes')})")
        return False, f"{days_left} days left; ARI window opens {start.isoformat(timespec='minutes')}"
    lifetime = info.get("lifetime_days") or 90
    fraction = renew_fraction(lifetime)
    window_s = lifetime * 86400 * fraction
    remaining_s = info.get("seconds_left")
    if remaining_s is None:
        remaining_s = days_left * 86400
    due = remaining_s <= window_s
    window = max(1, int(lifetime * fraction + 0.999))
    return due, f"{days_left} days left of {lifetime}, renews at {window}"
