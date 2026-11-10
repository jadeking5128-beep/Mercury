# Security policy

## Supported versions

Mercury is an early-stage project. Security fixes are made against the latest commit on `main`; older commits may not receive patches.

## Reporting a vulnerability

Please do not publish exploit details, credentials, or sensitive target data in a public issue. Use GitHub's private vulnerability reporting feature for this repository when available.

Include the affected commit/version, impact, prerequisites, reproducible steps against a local test environment, and a suggested mitigation. Do not test against systems without explicit authorization. Allow maintainers reasonable time to investigate and coordinate a fix before public disclosure.

## Scope and safe harbor

Mercury is intended for authorized assessment only. DNS TXT verification is a technical scope gate and does not itself establish legal authorization over every service or system associated with a domain. Read [docs/SECURITY.md](docs/SECURITY.md) before using the scanner.
