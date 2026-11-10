# Security, authorization, and threat model

## Authorized use only

Use Mercury only for systems you own or have explicit written permission to assess. Confirm authorization covers the exact hostname, IP space, cloud account, application, test window, and techniques selected.

DNS TXT verification demonstrates control of a DNS zone at verification time. It does not establish ownership of every subdomain, hosted tenant, third-party service, CDN origin, or infrastructure reachable through that name. Obtain separate authorization where required.

Do not use Mercury to attack third-party systems, evade access controls, steal credentials, deploy persistence, exfiltrate data, disrupt availability, or run destructive tests.

## Current scope controls

- Registration accepts DNS hostnames, not raw IP addresses.
- The API refuses to queue scans until a matching DNS TXT challenge is found.
- The scanner resolves the hostname again before assessment and rejects addresses Python does not classify as globally routable.
- HTTP connections are pinned to a resolved public address and do not follow redirects.
- Supported modules are allow-listed: `dns`, `http`, `tls`, `headers`, and `nmap`.
- Nmap uses TCP connect scanning, a bounded top-100-port set, and a timeout.
- The worker executes fixed Python assessment functions; API requests cannot provide arbitrary shell commands.

These controls reduce risk but do not replace authorization, network segmentation, or operator review. DNS and routing can change between verification and execution. Re-verify ownership after DNS changes and review targets before assessments.

## Authentication and deployment

- All `/api/v1/*` endpoints require `Authorization: Bearer <MERCURY_API_TOKEN>`.
- Configure a cryptographically random token of at least 32 characters; rotate it if exposed.
- Use HTTPS for remote dashboard/API and worker/API traffic.
- Keep the API behind a TLS reverse proxy.
- Set CORS to the exact dashboard origin. CORS is not authentication.
- Do not commit credentials, database files, logs containing secrets, or challenge values.
- The dashboard stores its entered API token in browser session storage; use a trusted device.
- Workers and operators currently share the API token. Treat workers as fully trusted.

## Data handled

Mercury stores hostnames, DNS challenge values, scan metadata, worker metadata, findings, evidence, and audit events in SQLite. Evidence can include IP addresses, certificate metadata, HTTP response metadata, and port/service observations. Protect database files and backups.

When configured, the AI provider receives finding objects submitted to the analysis endpoint. Do not send sensitive evidence to an external model unless policy permits it. AI output is advisory and requires human review.

## Known limitations

- One shared bearer token; no multi-user authentication or tenant isolation.
- Worker routes use the shared token; no per-worker credentials or robust lease ownership.
- No built-in rate limiting or abuse detection.
- SQLite is single-node; no HA or multi-replica support.
- DNS TXT proof is not a full authorization workflow.
- The registry detects binaries that are not yet executed by Mercury.
- Baseline checks do not prove that a target is secure or vulnerable.
- No formal database migration framework.

## Reporting a vulnerability

Do not publish exploit details or sensitive target data in a public issue. Use GitHub's private vulnerability reporting feature for this repository when available. Include affected commit/version, impact, reproducible steps against a local test environment, and suggested mitigation. Allow maintainers reasonable time to investigate and coordinate a fix.
