# Mercury API (early scaffold)

Install the optional API dependencies:

```bash
pip install -e ".[api]"
uvicorn mercury.api:app --host 127.0.0.1 --port 8765
```

Local endpoints:

- `GET /api/v1/health` — API health and version.
- `GET /api/v1/tools` — installed-tool inventory and best-effort versions.
- `GET /docs` — interactive OpenAPI documentation.

This initial API is intentionally read-only. It does not accept scan targets or execute tools. Remote access must not be enabled until authentication, target ownership verification, explicit scope, audit logging, worker identity, and execution policy are implemented. Do not expose this development server directly to the public internet.
