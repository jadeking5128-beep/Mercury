"""Authenticated Mercury API, target verification, job queue, and dashboard."""

from __future__ import annotations

import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from mercury import __version__
from mercury.ai.analyst import analyze_findings
from mercury.security.scope import normalize_hostname, verify_dns_challenge
from mercury.storage import audit, connect, init_db
from mercury.tools.registry import tool_status_dicts

app = FastAPI(title="Mercury API", version=__version__,
              description="Termux-first security assessment platform")
_origins = [item.strip() for item in os.environ.get(
    "MERCURY_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:8765"
).split(",") if item.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
DASHBOARD = Path(__file__).resolve().parent / "dashboard" / "index.html"


@app.on_event("startup")
def startup() -> None:
    init_db()


def require_token(authorization: str | None = Header(default=None)) -> str:
    expected = os.environ.get("MERCURY_API_TOKEN", "")
    if len(expected) < 32:
        raise HTTPException(503, "API is not configured. Set MERCURY_API_TOKEN to a random value of at least 32 characters.")
    supplied = authorization.removeprefix("Bearer ").strip() if authorization else ""
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(401, "Invalid or missing bearer token")
    return "admin"


class TargetInput(BaseModel):
    hostname: str = Field(min_length=3, max_length=253)


class ScanInput(BaseModel):
    target_id: str
    modules: list[str] = Field(min_length=1, max_length=5)


class WorkerHeartbeat(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    platform: str = Field(default="", max_length=160)
    tools: list[dict[str, Any]] = Field(default_factory=list)


class WorkerClaim(BaseModel):
    worker: str = Field(min_length=1, max_length=80)


class JobResult(BaseModel):
    findings: list[dict[str, Any]] = Field(default_factory=list, max_length=500)


class JobFailure(BaseModel):
    error: str = Field(min_length=1, max_length=500)


@app.get("/", response_class=HTMLResponse)
def dashboard() -> Any:
    if not DASHBOARD.exists():
        return HTMLResponse("<h1>Mercury dashboard missing</h1>", status_code=500)
    return FileResponse(DASHBOARD)


@app.get("/api/v1/health")
def health(_: str = Depends(require_token)) -> dict[str, str]:
    return {"status": "ok", "service": "mercury-api", "version": __version__}


@app.get("/api/v1/tools")
def tools(_: str = Depends(require_token)) -> dict[str, object]:
    return {"tools": tool_status_dicts()}


@app.post("/api/v1/targets")
def create_target(body: TargetInput, _: str = Depends(require_token)) -> dict[str, str]:
    try:
        hostname = normalize_hostname(body.hostname)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    target_id, challenge = secrets.token_hex(12), secrets.token_urlsafe(24)
    try:
        with connect() as db:
            db.execute("INSERT INTO targets(id,hostname,challenge) VALUES(?,?,?)",
                       (target_id, hostname, challenge))
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise HTTPException(409, "Target already registered") from exc
        raise
    audit("target.created", target_id, {"hostname": hostname})
    return {"id": target_id, "hostname": hostname, "challenge": challenge,
            "record_name": f"_mercury-challenge.{hostname}",
            "record_value": f"mercury-verification={challenge}",
            "instructions": "Publish this TXT record in your authoritative DNS zone, then call the verify endpoint."}


@app.post("/api/v1/targets/{target_id}/verify")
def verify_target(target_id: str, _: str = Depends(require_token)) -> dict[str, Any]:
    with connect() as db:
        target = db.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    if not target:
        raise HTTPException(404, "Target not found")
    try:
        verified = verify_dns_challenge(target["hostname"], target["challenge"])
    except Exception as exc:
        raise HTTPException(400, f"DNS verification failed: {exc}") from exc
    if not verified:
        raise HTTPException(400, "Ownership TXT record not found or does not match")
    with connect() as db:
        db.execute("UPDATE targets SET verified=1 WHERE id=?", (target_id,))
    audit("target.verified", target_id, {"hostname": target["hostname"]})
    return {"id": target_id, "verified": True}


@app.get("/api/v1/targets")
def list_targets(_: str = Depends(require_token)) -> dict[str, Any]:
    with connect() as db:
        rows = db.execute("SELECT id,hostname,verified,created_at FROM targets ORDER BY created_at DESC").fetchall()
    return {"targets": [dict(row) for row in rows]}


@app.delete("/api/v1/targets/{target_id}")
def delete_target(target_id: str, _: str = Depends(require_token)) -> dict[str, bool]:
    with connect() as db:
        row = db.execute("SELECT id FROM targets WHERE id=?", (target_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Target not found")
        active = db.execute("SELECT 1 FROM scans WHERE target_id=? AND status IN ('queued','running')",
                             (target_id,)).fetchone()
        if active:
            raise HTTPException(409, "Cannot delete a target with active scans")
        db.execute("DELETE FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE target_id=?)", (target_id,))
        db.execute("DELETE FROM jobs WHERE scan_id IN (SELECT id FROM scans WHERE target_id=?)", (target_id,))
        db.execute("DELETE FROM scans WHERE target_id=?", (target_id,))
        db.execute("DELETE FROM targets WHERE id=?", (target_id,))
    audit("target.deleted", target_id)
    return {"deleted": True}


@app.post("/api/v1/scans")
def create_scan(body: ScanInput, _: str = Depends(require_token)) -> dict[str, str]:
    allowed = {"dns", "http", "tls", "headers", "nmap"}
    if not set(body.modules) <= allowed or len(set(body.modules)) != len(body.modules):
        raise HTTPException(422, f"Allowed modules: {', '.join(sorted(allowed))}")
    with connect() as db:
        target = db.execute("SELECT * FROM targets WHERE id=?", (body.target_id,)).fetchone()
        if not target:
            raise HTTPException(404, "Target not found")
        if not target["verified"]:
            raise HTTPException(403, "Verify target ownership before scanning")
        scan_id, job_id = secrets.token_hex(12), secrets.token_hex(12)
        db.execute("INSERT INTO scans(id,target_id,modules) VALUES(?,?,?)",
                   (scan_id, body.target_id, json.dumps(body.modules)))
        db.execute("INSERT INTO jobs(id,scan_id) VALUES(?,?)", (job_id, scan_id))
    audit("scan.queued", scan_id, {"target": target["hostname"], "modules": body.modules})
    return {"id": scan_id, "job_id": job_id, "status": "queued"}


@app.get("/api/v1/scans")
def list_scans(_: str = Depends(require_token)) -> dict[str, Any]:
    with connect() as db:
        rows = db.execute("""SELECT s.id,s.target_id,t.hostname,s.status,s.progress,s.created_at,
          COUNT(f.id) AS finding_count FROM scans s JOIN targets t ON t.id=s.target_id
          LEFT JOIN findings f ON f.scan_id=s.id GROUP BY s.id ORDER BY s.created_at DESC LIMIT 100""").fetchall()
    return {"scans": [dict(row) for row in rows]}


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: str, _: str = Depends(require_token)) -> dict[str, Any]:
    with connect() as db:
        row = db.execute("""SELECT s.*,t.hostname FROM scans s JOIN targets t ON t.id=s.target_id
                            WHERE s.id=?""", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Scan not found")
    result = dict(row)
    result["modules"] = json.loads(result["modules"])
    return result


@app.get("/api/v1/scans/{scan_id}/findings")
def get_findings(scan_id: str, _: str = Depends(require_token)) -> dict[str, Any]:
    with connect() as db:
        exists = db.execute("SELECT 1 FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not exists:
            raise HTTPException(404, "Scan not found")
        rows = db.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY created_at", (scan_id,)).fetchall()
    items = [dict(row) for row in rows]
    for item in items:
        item["evidence"] = json.loads(item["evidence"])
    return {"findings": items}


@app.get("/api/v1/reports/{scan_id}")
def report(scan_id: str, _: str = Depends(require_token)) -> dict[str, Any]:
    scan = get_scan(scan_id, "admin")
    findings = get_findings(scan_id, "admin")["findings"]
    return {"scan": scan, "findings": findings, "generated_by": f"Mercury {__version__}"}


@app.get("/api/v1/workers")
def list_workers(_: str = Depends(require_token)) -> dict[str, Any]:
    with connect() as db:
        rows = db.execute("SELECT id,name,last_seen,platform,tools_json FROM workers ORDER BY last_seen DESC").fetchall()
    workers = []
    for row in rows:
        item = dict(row)
        item["tools"] = json.loads(item.pop("tools_json"))
        workers.append(item)
    return {"workers": workers}


@app.post("/api/v1/workers/heartbeat")
def heartbeat(body: WorkerHeartbeat, _: str = Depends(require_token)) -> dict[str, bool]:
    with connect() as db:
        db.execute("""INSERT INTO workers(id,name,platform,tools_json,last_seen)
          VALUES(?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET
          name=excluded.name,platform=excluded.platform,tools_json=excluded.tools_json,
          last_seen=CURRENT_TIMESTAMP""",
          (body.name, body.name, body.platform, json.dumps(body.tools[:100])))
    return {"ok": True}


@app.post("/api/v1/worker/jobs/claim")
def claim_job(body: WorkerClaim, _: str = Depends(require_token)) -> dict[str, Any]:
    with connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("""SELECT j.id AS job_id,s.id AS scan_id,s.modules,t.hostname
          FROM jobs j JOIN scans s ON s.id=j.scan_id JOIN targets t ON t.id=s.target_id
          WHERE ((j.status='queued' AND s.status='queued') OR
                 (j.status='running' AND j.claimed_at < datetime('now','-10 minutes')
                  AND s.status='running')) AND t.verified=1
          ORDER BY s.created_at LIMIT 1""").fetchone()
        if not row:
            return {"job": None}
        db.execute("UPDATE jobs SET status='running',worker_id=?,claimed_at=CURRENT_TIMESTAMP WHERE id=?",
                   (body.worker, row["job_id"]))
        db.execute("UPDATE scans SET status='running',progress=10 WHERE id=?", (row["scan_id"],))
    return {"job": {"id": row["job_id"], "scan_id": row["scan_id"],
                    "hostname": row["hostname"], "modules": json.loads(row["modules"])}}


@app.post("/api/v1/worker/jobs/{job_id}/complete")
def complete_job(job_id: str, body: JobResult, _: str = Depends(require_token)) -> dict[str, bool]:
    with connect() as db:
        job = db.execute("SELECT scan_id,status FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not job or job["status"] != "running":
            raise HTTPException(404, "Active job not found")
        for item in body.findings:
            db.execute("""INSERT INTO findings(id,scan_id,module,severity,title,description,evidence)
              VALUES(?,?,?,?,?,?,?)""",
              (secrets.token_hex(12), job["scan_id"], str(item.get("module", "unknown"))[:40],
               str(item.get("severity", "info"))[:20], str(item.get("title", "Finding"))[:200],
               str(item.get("description", ""))[:2000], json.dumps(item.get("evidence", {}))[:12000]))
        db.execute("UPDATE jobs SET status='completed' WHERE id=?", (job_id,))
        db.execute("UPDATE scans SET status='completed',progress=100,finished_at=CURRENT_TIMESTAMP WHERE id=?",
                   (job["scan_id"],))
    audit("scan.completed", job["scan_id"], {"finding_count": len(body.findings)})
    return {"completed": True}


@app.post("/api/v1/worker/jobs/{job_id}/fail")
def fail_job(job_id: str, body: JobFailure, _: str = Depends(require_token)) -> dict[str, bool]:
    with connect() as db:
        job = db.execute("SELECT scan_id,status FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not job or job["status"] != "running":
            raise HTTPException(404, "Active job not found")
        db.execute("UPDATE jobs SET status='failed' WHERE id=?", (job_id,))
        db.execute("UPDATE scans SET status='failed',error=?,finished_at=CURRENT_TIMESTAMP WHERE id=?",
                   (body.error, job["scan_id"]))
    audit("scan.failed", job["scan_id"], {"error": body.error})
    return {"failed": True}



@app.get("/api/v1/audit")
def list_audit(_: str = Depends(require_token)) -> dict[str, Any]:
    with connect() as db:
        rows = db.execute("SELECT id,action,subject,details,created_at FROM audit ORDER BY created_at DESC LIMIT 200").fetchall()
    items = [dict(row) for row in rows]
    for item in items:
        item["details"] = json.loads(item["details"])
    return {"events": items}


@app.post("/api/v1/ai/analyze")
def ai_analyze(body: JobResult, _: str = Depends(require_token)) -> dict[str, Any]:
    try:
        return analyze_findings(body.findings)
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc
