"""Metadata for external tools; discovery never executes a scan."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binary: str
    category: str
    purpose: str
    version_args: tuple[str, ...] = ("--version",)
    platforms: tuple[str, ...] = ("linux", "termux")
    requires_root: bool = False


@dataclass(frozen=True)
class ToolStatus:
    name: str
    binary: str
    category: str
    purpose: str
    installed: bool
    path: str | None
    version: str | None
    requires_root: bool


TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec("Nmap", "nmap", "network", "TCP port and service discovery", ("--version",)),
    ToolSpec("cURL", "curl", "web", "HTTP request and response diagnostics", ("--version",)),
    ToolSpec("dig", "dig", "dns", "DNS query diagnostics", ("-v",)),
    ToolSpec("Whois", "whois", "dns", "Domain registration lookup", ("--version",)),
    ToolSpec("OpenSSL", "openssl", "tls", "TLS and certificate diagnostics", ("version",)),
    ToolSpec("jq", "jq", "utility", "JSON parsing", ("--version",)),
    ToolSpec("Nuclei", "nuclei", "vulnerability", "Template-based security checks", ("-version",)),
    ToolSpec("httpx", "httpx", "web", "HTTP service probing", ("-version",)),
    ToolSpec("Katana", "katana", "web", "Web endpoint crawling", ("-version",)),
    ToolSpec("FFUF", "ffuf", "web", "Web content and parameter fuzzing", ("-V",)),
    ToolSpec("Nikto", "nikto", "web", "Web server configuration assessment", ("-Version",)),
    ToolSpec("Gobuster", "gobuster", "web", "Web content discovery", ("version",)),
    ToolSpec("Subfinder", "subfinder", "recon", "Passive subdomain discovery", ("-version",)),
    ToolSpec("Amass", "amass", "recon", "Attack-surface inventory", ("-version",)),
    ToolSpec("SQLmap", "sqlmap", "web", "SQL injection assessment", ("--version",)),
    ToolSpec("WPScan", "wpscan", "web", "WordPress security assessment", ("--version",)),
    ToolSpec("WhatWeb", "whatweb", "web", "Web technology identification", ("--version",)),
    ToolSpec("Netcat", "nc", "network", "Network connectivity diagnostics", ("-h",)),
    ToolSpec("tcpdump", "tcpdump", "network", "Packet capture diagnostics", ("--version",), requires_root=True),
)


def _read_version(spec: ToolSpec, executable: str) -> str | None:
    try:
        result = subprocess.run(
            [executable, *spec.version_args],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0][:180] if output else None


def discover_tools() -> list[ToolStatus]:
    """Return installed status and best-effort version for every known tool."""
    statuses: list[ToolStatus] = []
    for spec in TOOL_SPECS:
        executable = shutil.which(spec.binary)
        statuses.append(
            ToolStatus(
                name=spec.name,
                binary=spec.binary,
                category=spec.category,
                purpose=spec.purpose,
                installed=executable is not None,
                path=executable,
                version=_read_version(spec, executable) if executable else None,
                requires_root=spec.requires_root,
            )
        )
    return statuses


def tool_status_dicts() -> list[dict[str, object]]:
    return [asdict(item) for item in discover_tools()]
