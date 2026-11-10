"""Mercury command-line interface."""

from __future__ import annotations

import argparse
import os
import platform
import secrets
import shutil
import sys

from mercury import __version__
from mercury.tools.registry import discover_tools


def command_doctor() -> int:
    print(f"Mercury {__version__}")
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Machine: {platform.machine()}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Termux: {'yes' if shutil.which('termux-info') else 'not detected'}")
    tools = discover_tools()
    print(f"Tools detected: {sum(item.installed for item in tools)}/{len(tools)}")
    print(f"API token configured: {'yes' if len(os.environ.get('MERCURY_API_TOKEN', '')) >= 32 else 'no'}")
    return 0


def command_tools() -> int:
    for item in discover_tools():
        status = "FOUND" if item.installed else "MISSING"
        version = f" — {item.version}" if item.version else ""
        root = " [root required]" if item.requires_root else ""
        print(f"[{status:7}] {item.name:12} {item.binary}{version}{root}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="mercury", description="Mercury security assessment toolkit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("doctor", help="inspect the local environment")
    sub.add_parser("tools", help="list supported security tools")\n    sub.add_parser("install-tools", help="install the curated native Termux tool set")
    sub.add_parser("token", help="generate a secure API token")
    sub.add_parser("api", help="run the Mercury API")
    sub.add_parser("worker", help="run an outbound-polling scan worker")
    sub.add_parser("init-db", help="initialize the local SQLite database")
    args = parser.parse_args()
    if args.command == "doctor":
        return command_doctor()
    if args.command == "tools":
        return command_tools()
    if args.command == "token":
        print(secrets.token_urlsafe(48))
        return 0
    if args.command == "init-db":
        from mercury.storage import init_db
        init_db()
        print("Mercury database initialized.")
        return 0
    if args.command == "api":
        try:
            import uvicorn
        except ImportError:
            print('Install API dependencies: pip install -e ".[api]"', file=sys.stderr)
            return 2
        uvicorn.run("mercury.api:app", host=os.environ.get("MERCURY_HOST", "127.0.0.1"),
                    port=int(os.environ.get("MERCURY_PORT", "8765")))
        return 0
    if args.command == "worker":
        from mercury.worker import run_worker
        run_worker()
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
