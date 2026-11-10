"""Bounded baseline checks for verified public DNS targets.

HTTP probes pin connections to the public IP resolved by the scope guard and
never follow redirects, preventing a target from redirecting the scanner into
an unrelated network.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from mercury.security.scope import resolve_public_addresses

ALLOWED_MODULES = {"dns", "http", "tls", "headers", "nmap"}


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, address: str) -> None:
        super().__init__(host, timeout=8)
        self.address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str) -> None:
        super().__init__(host, timeout=8, context=ssl.create_default_context())
        self.address = address

    def connect(self) -> None:
        raw = socket.create_connection((self.address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _finding(module: str, severity: str, title: str, description: str,
             evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"module": module, "severity": severity, "title": title,
            "description": description, "evidence": evidence or {}}


def _probe_http(hostname: str, address: str, scheme: str) -> tuple[int, dict[str, str]]:
    connection: http.client.HTTPConnection
    if scheme == "https":
        connection = _PinnedHTTPSConnection(hostname, address)
    else:
        connection = _PinnedHTTPConnection(hostname, address)
    try:
        connection.request("HEAD", "/", headers={"Host": hostname, "User-Agent": "MercurySecurity/0.2"})
        response = connection.getresponse()
        return response.status, {key: value for key, value in response.getheaders()}
    finally:
        connection.close()


def run_assessment(hostname: str, modules: list[str]) -> list[dict[str, Any]]:
    unknown = set(modules) - ALLOWED_MODULES
    if unknown:
        raise ValueError(f"Unsupported scan modules: {', '.join(sorted(unknown))}")
    addresses = resolve_public_addresses(hostname)
    address = addresses[0]
    findings: list[dict[str, Any]] = []
    if "dns" in modules:
        findings.append(_finding("dns", "info", "DNS resolution completed",
                                 "Target resolved to public addresses.", {"addresses": addresses}))
    if "http" in modules or "headers" in modules:
        for scheme in ("https", "http"):
            try:
                status, headers = _probe_http(hostname, address, scheme)
                findings.append(_finding("http", "info", f"{scheme.upper()} endpoint reachable",
                                         "Received an HTTP response from the verified hostname.",
                                         {"status": status, "url": f"{scheme}://{hostname}/",
                                          "server": headers.get("Server", "")[:120]}))
                if "headers" in modules:
                    expected = ["Strict-Transport-Security", "Content-Security-Policy",
                                "X-Content-Type-Options", "Referrer-Policy"]
                    missing = [key for key in expected if key.lower() not in {h.lower() for h in headers}]
                    if missing:
                        findings.append(_finding("headers", "low", "Security headers missing",
                                                 "One or more recommended response headers were not present.",
                                                 {"missing": missing, "url": f"{scheme}://{hostname}/"}))
                break
            except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError):
                continue
        else:
            findings.append(_finding("http", "info", "HTTP endpoint not reachable",
                                     "No HTTP or HTTPS response was received within the timeout."))
    if "tls" in modules:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((address, 443), timeout=6) as raw:
                with context.wrap_socket(raw, server_hostname=hostname) as sock:
                    cert = sock.getpeercert()
                    findings.append(_finding("tls", "info", "TLS certificate validated",
                                             "A trusted TLS connection was established.",
                                             {"protocol": sock.version(),
                                              "subject": str(cert.get("subject", ""))[:500],
                                              "not_after": cert.get("notAfter", "")}))
        except (OSError, ssl.SSLError) as exc:
            findings.append(_finding("tls", "medium", "TLS connection failed",
                                     "The HTTPS service could not establish a trusted TLS connection.",
                                     {"error": str(exc)[:240]}))
    if "nmap" in modules:
        # Re-resolve immediately before execution and scan only a checked public address.
        addresses = resolve_public_addresses(hostname)
        checked_ip = ipaddress.ip_address(addresses[0])
        if not checked_ip.is_global:
            raise ValueError("Resolved address is outside the permitted public scope")
        command = ["nmap", "-sT", "-T3", "--top-ports", "100", "--max-retries", "1",
                   "--host-timeout", "90s", "-oX", "-", "--", str(checked_ip)]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=100, check=False)
            if result.returncode not in (0, 1):
                raise RuntimeError((result.stderr or "Nmap failed")[:400])
            root = ET.fromstring(result.stdout)
            ports = []
            for port in root.findall(".//port"):
                state = port.find("state")
                service = port.find("service")
                if state is not None and state.get("state") == "open":
                    ports.append({"port": port.get("portid"), "protocol": port.get("protocol"),
                                  "service": service.get("name") if service is not None else "unknown"})
            findings.append(_finding("nmap", "info", "Nmap TCP scan completed",
                                     f"Discovered {len(ports)} open TCP port(s) in the top 100.",
                                     {"address": str(checked_ip), "open_ports": ports}))
        except (OSError, subprocess.TimeoutExpired, ET.ParseError, RuntimeError) as exc:
            findings.append(_finding("nmap", "medium", "Nmap scan unavailable",
                                     "Nmap could not complete this bounded scan.",
                                     {"error": str(exc)[:400]}))
    return findings


def serialize_findings(findings: list[dict[str, Any]]) -> str:
    return json.dumps(findings, ensure_ascii=True)
