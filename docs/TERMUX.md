# Termux setup

Mercury targets Android devices running Termux on ARM64 where possible. Tool availability varies by repository, device architecture, Android version, and upstream packaging.

## Base environment

```bash
pkg update && pkg upgrade -y
pkg install -y python git nmap curl dnsutils whois openssl-tool jq
```

Then install Mercury:

```bash
git clone https://github.com/jadeking5128-beep/Mercury.git
cd Mercury
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
mercury doctor
mercury tools
```

## Compatibility policy

- Mercury detects tools; it does not assume every Linux binary runs on Android.
- Root-only tools are marked and must not be silently invoked on unrooted devices.
- Optional tools should be installed from official Termux packages or verified upstream releases.
- Never install binaries from untrusted mirrors or execute remote shell scripts without inspection.
- Tool version checks are best-effort and time-limited.
