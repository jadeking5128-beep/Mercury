# Architecture

## Components

```text
Browser -> Static dashboard (Vercel or API-hosted)
       -> HTTPS JSON API -> Mercury control plane -> SQLite
                         -> outbound worker polling
Termux/Linux worker -> scope re-check -> fixed scan modules -> target
                    -> findings/failure -> API
```

## Request lifecycle

1. An authenticated operator registers a hostname.
2. The API normalizes it and creates a random TXT challenge.
3. The operator publishes the challenge at `_mercury-challenge.<hostname>`.
4. The API checks the TXT record and marks the target verified when it matches.
5. The operator queues allow-listed modules.
6. A worker polls the API and claims a queued job.
7. The worker runs the assessment. The scanner resolves the hostname again, rejects non-global addresses, and pins HTTP connections to a resolved public IP.
8. The worker submits findings; the API persists them and updates scan state.
9. The dashboard retrieves status, findings, and report data.

## Runtime boundaries

- **Dashboard:** static HTML/CSS/JavaScript; does not execute scans.
- **API:** authentication, DNS challenge verification, queue management, persistence.
- **Worker:** fixed Python assessment functions on Termux/Linux; outbound connections only.
- **Database:** SQLite at `MERCURY_DB`, default `~/.mercury/mercury.db`.
- **AI analyst:** optional explanation of supplied findings; cannot dispatch jobs or invoke tools.

## State and scaling

SQLite stores targets, scans, jobs, findings, workers, and audit events. Scans transition through queued, running, completed, or failed. Stale running jobs can be reclaimed after the lease timeout.

This is a single-operator MVP. Dashboard, API operator, and workers share one bearer token. There is no tenant isolation, per-user RBAC, per-worker credential, or robust lease ownership. SQLite is not a multi-replica database. Before public multi-user operation, add identities/RBAC, scoped worker credentials, lease ownership, rate limiting, PostgreSQL, migrations, and stronger audit controls.
