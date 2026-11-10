"""Mercury command-line interface."""

from __future__ import annotations

import argparse
import platform
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
    installed = sum(item.installed for item in tools)
    print(f"Tools detected: {installed}/{len(tools)}")
    print("Run 'mercury tools' for the full registry.")
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
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("doctor", help="inspect the local environment")
    subparsers.add_parser("tools", help="list supported security tools")
    args = parser.parse_args()

    if args.command == "doctor":
        return command_doctor()
    if args.command == "tools":
        return command_tools()
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
