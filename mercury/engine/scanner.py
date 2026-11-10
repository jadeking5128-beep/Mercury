"""Bounded baseline checks for verified public DNS targets."""

from __future__ import annotations

import json
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any

from mercury.security.scope import resolve_public_addresses

ALLOWED_MODULES = {"dns", "http", "tls", "headers", "nmap"}


def _finding(module: str, severity: str, title: str, description: str,
             evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"module": module, "severity": severity, "title": title,
            "description": description, "evidence": evidence or {}}


def run_assessment(hostname: str, modules: list[str]) -> list[dict[str, Any]]:
    unknown = set(modules) - ALLOWED_MODULES
    if unknown:
        raise ValueError(f"Unsupported scan modules: {', '.join(sorted(unknown))}")
    addresses = resolve_public_addresses(hostname)
    findings: list[dict[str, Any]] = []
    if "dns" in modules:
        findings.append(_finding("dns", "info", "DNS resolution completed",
                                 "Target resolved to public addresses.",
                                 {"addresses": addresses}))
    if "http" in modules or "headers" in modules:
        for scheme in ("https", "http"):
            url = f"{scheme}://{hostname}/"
            request = urllib.request.Request(url, headers={"User-Agent": "MercurySecurity/0.2"})
            try:
                with urllib.request.urlopen(request, timeout=8) as response:
                    headers = dict(response.headers.items())
                    findings.append(_finding("http", "info", f"{scheme.upper()} endpoint reachable",
                                             "Received an HTTP response from the verified hostname.",
                                             {"status": response.status, "url": url,
                                              "server": headers.get("Server", "")[:120]}))
                    if "headers" in modules:
                        expected = ["Strict-Transport-Security", "Content-Security-Policy",
                                    "X-Content-Type-Options", "Referrer-Policy"]
                        missing = [key for key in expected if key not in headers]
                        if missing:
                            findings.append(_finding("headers", "low", "Security headers missing",
                                                     "One or more recommended response headers were not present.",
                                                     {"missing": missing, "url": url}))
                    break
            except (urllib.error.URLError, TimeoutError, OSError):
                continue
        else:
            findings.append(_finding("http", "info", "HTTP endpoint not reachable",
                                     "No HTTP or HTTPS response was received within the timeout."))
    if "tls" in modules:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=6) as raw:
                with context.wrap_socket(raw, server_hostname=hostname) as sock:
                    cert = sock.getpeercert()
                    findings.append(_finding("tls", "info", "TLS certificate validated",
                                             "A trusted TLS connection was established.",
                                             {"protocol": sock.version(), "subject": str(cert.get("subject", ""))[:500],
                                              "not_after": cert.get("notAfter", "")}))
        except (OSError, ssl.SSLError) as exc:
            findings.append(_finding("tls", "medium", "TLS connection failed",
                                     "The HTTPS service could not establish a trusted TLS connection.",
                                     {"error": str(exc)[:240]}))
    if "nmap" in modules:
        addresses = resolve_public_addresses(hostname)
        command = ["nmap", "-sT", "-T3", "--top-ports", "100", "--max-retries", "1",
                   "--host-timeout", "90s", "-oX", "-", "--", addresses[0]]
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
                                     {"address": addresses[0], "open_ports": ports}))
        except (OSError, subprocess.TimeoutExpired, ET.ParseError, RuntimeError) as exc:
            findings.append(_finding("nmap", "medium", "Nmap scan unavailable",
                                     "Nmap could not complete this bounded scan.",
                                     {"error": str(exc)[:400]}))
    return findings


def serialize_findings(findings: list[dict[str, Any]]) -> str:
    return json.dumps(findings, ensure_ascii=True)
