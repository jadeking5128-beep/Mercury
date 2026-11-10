# Mercury

**Open-source, Termux-first security assessment platform for assets you own or are explicitly authorized to test.**

Mercury combines a browser dashboard, authenticated FastAPI control plane, SQLite persistence, and an outbound-polling worker for Termux or Linux. The dashboard can be hosted separately from the scanner.

> **Status:** early-stage MVP. Implemented checks include DNS resolution, bounded HTTP(S) probes, TLS certificate checks, response-header checks, and an optional bounded Nmap TCP connect scan. Mercury is not a general-purpose exploitation framework or a substitute for a professional penetration test.

## Implemented capabilities

- DNS TXT challenge verification before a target can be scanned.
- Bearer-token authenticated API and responsive dashboard.
- Persistent targets, scan jobs, findings, workers, and audit events.
- Outbound worker polling; no inbound phone port forwarding required.
- DNS, HTTP, TLS, security-header, and Nmap modules.
- Public-address checks and pinned HTTP connections to reduce DNS-rebinding and redirect-based scope escapes.
- Tool inventory, Termux package helper, JSON reports, and optional AI-assisted finding analysis.
- OpenAPI schema at `/openapi.json` and interactive docs at `/docs`.

The tool registry detects installed binaries; it does **not** mean every listed tool is wired into scan execution. See [Tool support](docs/TOOLS.md).

## Quick start: Termux

```bash
pkg update && pkg upgrade -y
pkg install -y python git
git clone https://github.com/jadeking5128-beep/Mercury.git
cd Mercury
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[api,dev]"
mercury install-tools
mercury doctor
mercury tools
```

Start the local API; keep this shell running:

```bash
export MERCURY_API_TOKEN="$(mercury token)"
mercury init-db
mercury api
```

Open http://127.0.0.1:8765 and enter the generated token. The API binds to localhost by default.

In a second Termux session:

```bash
cd Mercury
. .venv/bin/activate
export MERCURY_API_TOKEN="the-same-token"
export MERCURY_API_URL="http://127.0.0.1:8765"
mercury worker
```

For remote use, the worker's API URL must be reachable over HTTPS. The Vercel dashboard URL is not the API URL.

## Verify and scan an owned domain

1. Register a DNS hostname in the dashboard.
2. Mercury returns a unique TXT record name and value.
3. Publish the TXT record in the authoritative DNS zone.
4. Trigger verification after DNS propagation.
5. Select supported modules and queue the scan.
6. Keep a worker online to process the job.

Example record (use the exact challenge returned by Mercury):

```text
Name:  _mercury-challenge.example.com
Type:  TXT
Value: mercury-verification=<challenge>
```

DNS control is a scope gate, not proof that every system behind a domain is yours. Obtain authorization for the exact hosts, services, cloud accounts, and methods before scanning. Read [Security and scope](docs/SECURITY.md).

## Deployment model

- **Vercel:** static dashboard only.
- **API:** persistent host/container with HTTPS ingress.
- **Database:** persistent volume; SQLite is single-node only.
- **Worker:** Termux phone or Linux host, making outbound HTTPS requests.

See [Deployment guide](docs/DEPLOYMENT.md). Do not expose an unauthenticated API or send bearer tokens over plain HTTP.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [API reference](docs/API.md)
- [Security, scope and threat model](docs/SECURITY.md)
- [Supported tools and modules](docs/TOOLS.md)
- [Deployment and operations](docs/DEPLOYMENT.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

## Development

```bash
python -m pip install -e ".[api,dev]"
pytest -q
ruff check mercury tests
```

GitHub Actions tests Python 3.10, 3.11, and 3.12. Verify a passing CI run before treating a release as production-ready.

## License

Mercury is distributed under the [MIT License](LICENSE).
