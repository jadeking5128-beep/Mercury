"""Strict hostname validation and DNS ownership challenge helpers."""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*\.?$")


def normalize_hostname(value: str) -> str:
    raw = value.strip()
    if "://" in raw:
        parsed = urlsplit(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
            raise ValueError("Only http/https URLs without credentials are accepted")
        raw = parsed.hostname
    raw = raw.rstrip(".").lower()
    if not raw or not _HOST_RE.fullmatch(raw):
        raise ValueError("Enter a valid hostname, not a URL path or arbitrary address")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        return raw
    raise ValueError("Register a DNS hostname; raw IP targets are not supported in this release")


def resolve_public_addresses(hostname: str) -> list[str]:
    """Resolve host and reject private, loopback, link-local and special-use IPs."""
    results = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)})
    if not results:
        raise ValueError("Hostname did not resolve")
    for value in results:
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise ValueError(f"Target resolves to a non-public address ({value}); blocked by network policy")
    return results


def verify_dns_challenge(hostname: str, token: str) -> bool:
    try:
        import dns.resolver
    except ImportError as exc:
        raise RuntimeError("Install dnspython to verify targets: pip install dnspython") from exc
    answers = dns.resolver.resolve(f"_mercury-challenge.{hostname}", "TXT", lifetime=5)
    expected = f"mercury-verification={token}"
    return any("".join(part.decode() if isinstance(part, bytes) else str(part) for part in answer.strings) == expected
               for answer in answers)
