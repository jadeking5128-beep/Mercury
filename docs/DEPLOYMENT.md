# Deployment

## Vercel dashboard

The repository includes `vercel.json` configured to deploy the static dashboard from `dashboard/`.

1. Import `jadeking5128-beep/Mercury` into Vercel.
2. Keep the project root at the repository root.
3. Deploy. Vercel serves the static dashboard.
4. The dashboard login asks for the separate Mercury API base URL and bearer token.

The dashboard is not the scan backend. It must connect to a separately hosted API.

## API and worker with Docker Compose

Use a persistent Linux host. Set a strong random token and the exact Vercel dashboard origin:

```bash
export MERCURY_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export MERCURY_CORS_ORIGINS="https://YOUR-PROJECT.vercel.app"
docker compose up -d --build
```

The API binds to localhost port 8765. Put it behind a TLS reverse proxy (Caddy, Nginx, or a managed HTTPS ingress) before remote access. Then use the resulting HTTPS URL in the Vercel dashboard. Do not expose the API over plain HTTP to the public internet.

The Compose worker is a Linux worker with Nmap. A Termux worker can run separately:

```bash
export MERCURY_API_URL="https://YOUR-API-HOST"
export MERCURY_API_TOKEN="the-same-token"
mercury worker
```

The Termux worker makes outbound HTTPS requests; no inbound phone port is required.

## Security notes

- Use a unique token with at least 32 characters and keep it out of source control.
- Restrict CORS to the exact dashboard origin.
- Use HTTPS and a trusted reverse proxy.
- Back up the SQLite volume. This MVP is single-instance; do not scale multiple API replicas against SQLite.
- Worker and admin credentials are currently shared. Use this only for a trusted single-operator deployment until per-worker credentials and RBAC are implemented.
- DNS ownership verification proves control of the DNS zone at verification time; re-verify after ownership or DNS changes.
