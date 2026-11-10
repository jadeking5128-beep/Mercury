# Mercury

**Termux-first, remotely accessible security assessment platform.**

Mercury is an open-source security assessment workspace for DNS-verified websites and services you own. It combines a web dashboard, authenticated FastAPI service, SQLite persistence, outbound-polling Termux/Linux workers, real tool integrations, and structured findings.

> Version 0.2 is an early functional MVP. It supports DNS TXT ownership verification, queued scans, HTTP/TLS/header checks, and a bounded Nmap top-100 TCP scan. It is not a full penetration-testing suite.

## Features

- Dark responsive dashboard served by the API at `/`.
- Bearer-token API authentication.
- Target registration and DNS TXT ownership verification.
- SQLite scan, job, finding, worker, and audit persistence.
- Outbound worker polling; no inbound port forwarding required on Termux.
- Baseline DNS, HTTP, TLS and security-header assessment.
- Optional bounded Nmap TCP scan (`-sT`, top 100 ports, timeout).
- Tool registry, Termux environment diagnostics, and curated `mercury install-tools` command.
- JSON reports and deterministic finding prioritization.
- OpenAPI docs at `/docs`.

## Termux installation

```bash
pkg update && pkg upgrade -y
pkg install -y python git nmap curl dnsutils whois openssl-tool jq
git clone https://github.com/jadeking5128-beep/Mercury.git
cd Mercury
python -m venv .venv
. .venv/bin/activate
pip install -e ".[api,dev]"
mercury install-tools
mercury doctor
mercury tools
```

## Run locally

Generate a token and export it in the same shell:

```bash
export MERCURY_API_TOKEN="$(mercury token)"
mercury init-db
mercury api
```

Open `http://127.0.0.1:8765`, enter the token, register a hostname you control, and publish the displayed TXT record:

`_mercury-challenge.YOUR-DOMAIN TXT mercury-verification=YOUR-CHALLENGE`

After DNS propagates, verify the target and queue a scan. Keep the API bound to localhost for local use.

In a second Termux session, export the same API token and start the worker:

```bash
export MERCURY_API_TOKEN="same-token"
export MERCURY_API_URL="http://127.0.0.1:8765"
mercury worker
```

For a remote deployment, host the API and database on a persistent service, configure HTTPS, set a strong secret token, and set `MERCURY_API_URL` on the Termux worker to the public API URL. The worker initiates outbound HTTPS requests; do not expose the phone's local server.

## API

- `GET /api/v1/health`
- `GET /api/v1/tools`
- `POST /api/v1/targets`
- `POST /api/v1/targets/{id}/verify`
- `GET /api/v1/targets`
- `DELETE /api/v1/targets/{id}`
- `POST /api/v1/scans`
- `GET /api/v1/scans`
- `GET /api/v1/scans/{id}`
- `GET /api/v1/scans/{id}/findings`
- `GET /api/v1/reports/{id}`
- `GET /api/v1/workers`
- Worker heartbeat, claim, complete, and fail endpoints under `/api/v1/worker(s)`.

All API endpoints require `Authorization: Bearer <MERCURY_API_TOKEN>`. Interactive API documentation is at `/docs`.

## Security boundaries

- Only DNS-verified hostnames can be scanned.
- Raw IP addresses and private, loopback, link-local, multicast, and other non-global resolved addresses are blocked.
- DNS is resolved again immediately before scan execution to reduce rebinding risk.
- Nmap is restricted to TCP connect scanning of the top 100 ports with timeouts.
- No arbitrary shell commands, destructive tests, credential attacks, persistence, or data extraction.
- Keep the API behind HTTPS and a trusted reverse proxy for remote use.
- The initial single-token authentication model is suitable only for a trusted single-operator deployment; multi-user RBAC and per-worker credentials remain future work.

## Optional AI analyst\n\nMercury uses deterministic severity triage by default. To enable an OpenAI-compatible chat-completions provider, configure these environment variables on the API host:\n\n- `MERCURY_AI_BASE_URL` — provider base URL, e.g. `https://api.openai.com/v1`\n- `MERCURY_AI_API_KEY` — provider key\n- `MERCURY_AI_MODEL` — model identifier\n\nThe model receives finding data for defensive explanation only. It cannot execute tools or dispatch scans.\n\n## Current limitations

- SQLite is intended for a single-node MVP; use PostgreSQL for a multi-instance production deployment.
- Worker jobs use the API token and should be upgraded to separate worker credentials before public multi-user hosting.
- AI analysis is deterministic rule-based triage, not an LLM. Provider integration and human-approved AI test planning are future work.
- Nmap is optional. Other registered tools are detected but not automatically executed.
- The dashboard can be deployed as a static site on Vercel from `dashboard/` using `vercel.json`. The API, persistent database, and worker run separately; see [Deployment](docs/DEPLOYMENT.md).

## Development

```bash
pip install -e ".[api,dev]"
pytest -q
ruff check mercury tests
```

## License

Apache-2.0. See [LICENSE](LICENSE).
