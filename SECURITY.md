# Security Policy

## Reporting a Vulnerability

Do **not** open a public GitHub issue for security vulnerabilities.

Contact via GitHub: [@DevCraftXCoder](https://github.com/DevCraftXCoder)

Response time: 72 hours for acknowledgment, 7 days for critical issues.

---

## What this tool is

This repository is the **free, open-source code scanner** from the Security
Intelligence Center. It is a static analysis tool that reads source files and
reports potential issues. It is **read-only**:

- It never modifies, deletes, or moves your files.
- It never sends packets to remote hosts.
- It has no telemetry, callbacks, or phone-home behavior — findings stay on your
  machine.
- It runs on the Python standard library alone (no third-party runtime
  dependencies). Dependency-CVE scanning is optional and only runs if `pip-audit`
  is already installed.

## Responsible Use

The scanner is intended to be run against code you own or are authorized to
review. While it is read-only and non-destructive, scan output may surface
sensitive values (e.g. hardcoded secrets) — handle reports accordingly and do not
commit them to shared locations.

---

## Dependency Security

- The scanner itself has zero third-party runtime dependencies.
- `pip-audit` is an optional enhancement for dependency-CVE detection — install it
  separately if you want that feature.
