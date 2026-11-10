# Deployment and operations

Mercury has three independently running components: a static dashboard, an API/control plane, and one or more workers. The API and database require persistent infrastructure. Vercel is not the scan execution environment.

## Vercel dashboard

1. Import this repository into Vercel.
2. Keep the project root at the repository root.
3. Keep `vercel.json`; it publishes the static `dashboard/` directory.
4. Deploy and note the HTTPS origin, e.g. `https://mercury-example.vercel.app`.

The dashboard login asks for an API base URL and bearer token. The API URL is a separate service URL, not the Vercel URL.

## API and worker with Docker Compose

Use a persistent Linux host with Docker Engine and Compose. Set a random token and exact dashboard origin:

```bash
export MERCURY_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export MERCURY_CORS_ORIGINS="https://YOUR-PROJECT.vercel.app"
docker compose up -d --build
docker compose logs -f api worker
```

Compose binds the API to `127.0.0.1:8765`. Put a TLS reverse proxy or managed HTTPS ingress in front of it and preserve the `Authorization` header. Do not expose port 8765 directly without TLS and network controls.

The Compose worker uses the same token as the API administrator. Treat it as fully trusted; do not share this credential with untrusted workers.

## Connect a Termux worker

Install Mercury and its dependencies on the phone, then:

```bash
export MERCURY_API_URL="https://YOUR-API-HOST"
export MERCURY_API_TOKEN="the-same-secret-configured-on-the-api"
mercury worker
```

The phone makes outbound HTTPS requests; it needs no inbound port forwarding. If Android suspends the worker, exempt Termux from battery optimization.

## Environment variables

| Variable | Component | Purpose |
|---|---|---|
| `MERCURY_API_TOKEN` | API, worker, dashboard login | Shared bearer secret; minimum 32 characters |
| `MERCURY_API_URL` | Worker | API base URL |
| `MERCURY_DB` | API | SQLite file path |
| `MERCURY_HOST` | CLI API | Bind address; defaults to `127.0.0.1` |
| `MERCURY_PORT` | CLI API | Port; defaults to `8765` |
| `MERCURY_CORS_ORIGINS` | API | Comma-separated exact browser origins |
| `MERCURY_AI_BASE_URL` | API | Optional OpenAI-compatible API base URL |
| `MERCURY_AI_API_KEY` | API | Optional AI provider credential |
| `MERCURY_AI_MODEL` | API | Optional model identifier |

Use a secret manager. Never commit `.env`, tokens, or provider keys.

## Persistence and backups

- Persist `/data` in production; Compose stores the DB in `mercury-data`.
- Back up regularly and test restores.
- Stop the API before copying SQLite directly, or use SQLite's online backup mechanism.
- Do not run multiple API replicas against the same SQLite file.
- Monitor disk space, API logs, worker heartbeats, and failed scans.

## Reverse-proxy checklist

- Terminate TLS with a valid certificate.
- Preserve the `Authorization` header.
- Set suitable request-size and connection timeouts.
- Restrict network access where practical.
- Set CORS to the exact dashboard origin. CORS is not authentication or a firewall.
- Do not use wildcard origins in production.

## Updating

```bash
git pull --ff-only origin main
docker compose up -d --build
docker compose logs --tail=200 api worker
```

Review compatibility before upgrading. Tables initialize automatically, but no formal migration framework exists yet.
