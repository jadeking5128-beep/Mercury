"""Small SQLite persistence layer; safe for a single-node MVP."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

DB_PATH = Path(os.environ.get("MERCURY_DB", str(Path.home() / ".mercury" / "mercury.db")))


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    """Open a connection, commit on success, roll back on error, and always close."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS targets (
          id TEXT PRIMARY KEY, hostname TEXT NOT NULL UNIQUE, challenge TEXT NOT NULL,
          verified INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS scans (
          id TEXT PRIMARY KEY, target_id TEXT NOT NULL, modules TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'queued', progress INTEGER NOT NULL DEFAULT 0,
          error TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          finished_at TEXT, FOREIGN KEY(target_id) REFERENCES targets(id)
        );
        CREATE TABLE IF NOT EXISTS jobs (
          id TEXT PRIMARY KEY, scan_id TEXT NOT NULL UNIQUE, status TEXT NOT NULL DEFAULT 'queued',
          worker_id TEXT, claimed_at TEXT, FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS findings (
          id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, module TEXT NOT NULL,
          severity TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL,
          evidence TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS workers (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          platform TEXT, tools_json TEXT NOT NULL DEFAULT '[]'
        );
        CREATE TABLE IF NOT EXISTS audit (
          id TEXT PRIMARY KEY, action TEXT NOT NULL, subject TEXT, details TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)


def rowdict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row else None


def audit(action: str, subject: str | None = None, details: dict[str, Any] | None = None) -> None:
    with connect() as db:
        db.execute("INSERT INTO audit(id,action,subject,details) VALUES(?,?,?,?)",
                   (secrets.token_hex(12), action, subject, json.dumps(details or {})))
