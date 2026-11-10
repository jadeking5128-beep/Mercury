# Tool and scan support

Mercury distinguishes scan modules actually executed by the worker from the tool registry, which reports whether optional binaries are installed. A tool appearing in the registry does not mean Mercury invokes it.

## Executed modules

| Module | Behavior | Boundaries |
|---|---|---|
| `dns` | Resolves verified hostname and records public addresses | Rejects non-global addresses |
| `http` | Bounded HTTP(S) HEAD request | Pinned public IP; no redirect following; short timeout |
| `tls` | Trusted TLS handshake and certificate/protocol metadata | System certificate validation |
| `headers` | Checks selected recommended response headers | Observational; missing headers are not proof of exploitability |
| `nmap` | TCP connect scan of top 100 ports | Nmap required; bounded timeout; no SYN/raw scan |

The API rejects unknown modules and duplicate selections.

## Detected tool inventory

| Tool | Binary | Integration status |
|---|---|---|
| Nmap | `nmap` | Used by bounded Nmap module |
| cURL | `curl` | Detected only |
| dig | `dig` | Detected only |
| Whois | `whois` | Detected only |
| OpenSSL | `openssl` | Detected only |
| jq | `jq` | Detected only |
| Nuclei | `nuclei` | Detected only; no template adapter |
| httpx | `httpx` | Detected only |
| Katana | `katana` | Detected only |
| FFUF | `ffuf` | Detected only |
| Nikto | `nikto` | Detected only |
| Gobuster | `gobuster` | Detected only |
| Subfinder | `subfinder` | Detected only |
| Amass | `amass` | Detected only |
| SQLmap | `sqlmap` | Detected only |
| WPScan | `wpscan` | Detected only |
| WhatWeb | `whatweb` | Detected only |
| Netcat | `nc` | Detected only |
| tcpdump | `tcpdump` | Detected only; elevated privileges may be required |

## Termux helper

`mercury install-tools` installs `nmap curl dnsutils whois openssl-tool jq netcat-openbsd traceroute` using Termux's `pkg`. On other Linux distributions, install desired binaries with the system package manager. Some registry entries are not available in default Termux repositories.

## Adapter requirements

New adapters must re-check scope immediately before network activity; avoid shell interpolation; use argument arrays; set timeouts; bound requests, concurrency, and output; disable redirects or validate each destination; emit structured findings with evidence and rationale; default to non-destructive checks; and include tests using local fixtures or mocked subprocesses.
