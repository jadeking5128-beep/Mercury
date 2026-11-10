# API reference

FastAPI publishes the OpenAPI schema at `/openapi.json` and interactive Swagger UI at `/docs`.

## Authentication

All `/api/v1/*` endpoints require `Authorization: Bearer <MERCURY_API_TOKEN>`. The root `GET /` serves the dashboard without API authentication; the dashboard then authenticates its API requests using the token entered at login.

## Operator endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/health` | Authenticated health/version |
| GET | `/api/v1/tools` | Tool inventory |
| POST | `/api/v1/targets` | Register hostname and issue TXT challenge |
| POST | `/api/v1/targets/{target_id}/verify` | Verify TXT challenge |
| GET | `/api/v1/targets` | List targets |
| DELETE | `/api/v1/targets/{target_id}` | Delete target and related scan data |
| POST | `/api/v1/scans` | Queue scan |
| GET | `/api/v1/scans` | List latest scans |
| GET | `/api/v1/scans/{scan_id}` | Scan status/details |
| GET | `/api/v1/scans/{scan_id}/findings` | Findings and evidence |
| GET | `/api/v1/reports/{scan_id}` | JSON report |
| GET | `/api/v1/workers` | Worker heartbeat inventory |
| GET | `/api/v1/audit` | Latest audit events |
| POST | `/api/v1/ai/analyze` | Analyze supplied findings |

## Worker endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/workers/heartbeat` | Worker heartbeat |
| POST | `/api/v1/worker/jobs/claim` | Claim next eligible job |
| POST | `/api/v1/worker/jobs/{job_id}/complete` | Submit findings |
| POST | `/api/v1/worker/jobs/{job_id}/fail` | Mark job failed |

Worker routes currently use the same bearer token as operator routes. Do not share this credential with untrusted workers.

## Register a target

```bash
curl -X POST "$MERCURY_API_URL/api/v1/targets" \
  -H "Authorization: Bearer $MERCURY_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"example.com"}'
```

The response includes an ID, challenge, TXT record name, and TXT value. Publish the record exactly as returned.

## Verify a target

```bash
curl -X POST "$MERCURY_API_URL/api/v1/targets/TARGET_ID/verify" \
  -H "Authorization: Bearer $MERCURY_API_TOKEN"
```

## Queue a scan

Supported modules: `dns`, `http`, `tls`, `headers`, `nmap`.

```bash
curl -X POST "$MERCURY_API_URL/api/v1/scans" \
  -H "Authorization: Bearer $MERCURY_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_id":"TARGET_ID","modules":["dns","http","tls","headers","nmap"]}'
```

A connected worker must be online to process the job.

## Retrieve a report

```bash
curl "$MERCURY_API_URL/api/v1/reports/SCAN_ID" \
  -H "Authorization: Bearer $MERCURY_API_TOKEN"
```

## Analyze findings

```bash
curl -X POST "$MERCURY_API_URL/api/v1/ai/analyze" \
  -H "Authorization: Bearer $MERCURY_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"findings":[{"severity":"medium","title":"Example","description":"Evidence"}]}'
```

Without provider settings, Mercury returns rule-based severity triage. With all three `MERCURY_AI_*` variables set, finding data is sent to the configured OpenAI-compatible provider. Treat output as advisory.

## Common status codes

401 means missing/invalid bearer credentials; 403 means an unverified target; 404 means a missing resource; 409 means a conflict; 422 means invalid input. A 503 on authenticated routes usually means `MERCURY_API_TOKEN` is unset or shorter than 32 characters.
