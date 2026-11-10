# Mercury

**Termux-first, AI-assisted security assessment platform.**

Mercury is an open-source toolkit for assessing websites, servers, and APIs that you own or are explicitly authorized to test. It combines a portable command-line worker, an extensible tool registry, a remote API, and an AI-assisted analysis layer.

> Mercury is currently an early scaffold. The initial release focuses on environment diagnostics, tool discovery, strict target scope, and safe orchestration foundations. It does not yet implement a production scanner or remote dashboard.

## Design

- **Termux-first:** Python CLI designed to run on Android/ARM64 and Linux.
- **Real tools:** Detect installed tools such as Nmap, curl, dig, whois, OpenSSL, jq, Nuclei, and others.
- **Hybrid operation:** Operators choose tests; AI may recommend additional tests for explicit approval.
- **Scope enforcement:** Only pre-registered, ownership-verified targets may be assessed.
- **Remote-ready:** A future outbound worker connection will let a Vercel-hosted dashboard dispatch jobs without exposing the phone to inbound internet traffic.

## Quick start (Termux)

```bash
pkg update && pkg upgrade -y
pkg install -y python git nmap curl dnsutils whois openssl-tool jq
git clone https://github.com/jadeking5128-beep/Mercury.git
cd Mercury
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
mercury doctor
mercury tools
```

If a package is unavailable in your Termux repository, check `pkg search <name>` and the upstream project's official installation instructions. Do not pipe unverified remote scripts into a shell.

## Commands

- `mercury doctor` — inspect platform, architecture, Python, and supported tool availability.
- `mercury tools` — list registered tools and detected versions.
- `mercury version` — print the Mercury version.

## Repository layout

```text
mercury/
  mercury/
    cli.py
    tools/       # tool metadata and discovery
    security/    # target scope and policy primitives
  tests/
  docs/
```

## Security model

Mercury must not execute AI-generated shell commands. Integrations use fixed adapters and validated argument lists. Before any active scan is added, the project will require target ownership verification, explicit scope, rate limits, timeouts, audit logging, and isolated worker execution. No arbitrary-host scanning, destructive testing, persistence, credential theft, or data extraction is supported.

## Roadmap

1. CLI, Termux compatibility checks, and tool registry.
2. Target inventory and ownership verification.
3. Safe baseline checks (DNS, HTTP metadata, TLS, security headers).
4. Scan jobs, structured evidence, and reports.
5. Remote worker/API and dashboard.
6. AI planning and analysis with human approval gates.

## License

Apache-2.0. See [LICENSE](LICENSE).
