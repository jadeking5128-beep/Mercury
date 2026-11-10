"""Outbound-polling worker for remote Mercury API deployments."""

from __future__ import annotations

import json
import os
import platform
import time
import urllib.error
import urllib.request
import uuid

from mercury.engine.scanner import run_assessment
from mercury.tools.registry import tool_status_dicts


class MercuryWorker:
    def __init__(self, api_url: str, token: str, name: str | None = None) -> None:
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.name = name or f"termux-{uuid.uuid4().hex[:8]}"

    def request(self, method: str, path: str, payload: dict | None = None) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.api_url + path, data=data, method=method,
                                     headers={"Authorization": f"Bearer {self.token}",
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=25) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}

    def run_forever(self, poll_seconds: int = 5) -> None:
        print(f"Mercury worker '{self.name}' connected to {self.api_url}")
        while True:
            try:
                self.request("POST", "/api/v1/workers/heartbeat",
                             {"name": self.name, "platform": platform.platform(),
                              "tools": tool_status_dicts()})
                job = self.request("POST", "/api/v1/worker/jobs/claim", {"worker": self.name})
                if not job.get("job"):
                    time.sleep(poll_seconds)
                    continue
                item = job["job"]
                try:
                    findings = run_assessment(item["hostname"], item["modules"])
                    self.request("POST", f"/api/v1/worker/jobs/{item['id']}/complete",
                                 {"findings": findings})
                    print(f"Completed scan {item['scan_id']}: {len(findings)} findings")
                except Exception as exc:
                    self.request("POST", f"/api/v1/worker/jobs/{item['id']}/fail",
                                 {"error": str(exc)[:500]})
            except KeyboardInterrupt:
                print("Mercury worker stopped.")
                return
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                print(f"Worker connection/error: {exc}")
                time.sleep(max(poll_seconds, 10))


def run_worker() -> None:
    api_url = os.environ.get("MERCURY_API_URL", "").strip()
    token = os.environ.get("MERCURY_API_TOKEN", "").strip()
    if not api_url or not token:
        raise SystemExit("Set MERCURY_API_URL and MERCURY_API_TOKEN before starting the worker.")
    MercuryWorker(api_url, token).run_forever()
