"""Minimal read-only API for local Mercury diagnostics.

This API intentionally exposes no scan-execution endpoint yet. Target
verification, authentication, policy enforcement, and worker isolation must
land before remote job execution is enabled.
"""

from fastapi import FastAPI

from mercury import __version__
from mercury.tools.registry import tool_status_dicts

app = FastAPI(
    title="Mercury API",
    version=__version__,
    description="Termux-first security assessment platform",
)


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "mercury-api", "version": __version__}


@app.get("/api/v1/tools")
def tools() -> dict[str, object]:
    return {"tools": tool_status_dicts()}
