<div align="center">

# SIC — Codebase Scanner

### Free, read-only static analysis for your codebase

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![npm](https://img.shields.io/badge/npx-sic--security-red.svg)](https://www.npmjs.com/package/sic-security)

**Scan any codebase in one command. No setup, no account, no external tools.**

</div>

---

## Quick Start

```bash
# From the root of the project you want to scan:
npx sic-security scan
```

That's it. The scanner walks your source files and prints findings immediately.

```bash
# Scan a specific directory:
npx sic-security scan ./path/to/project
```

> **Prerequisites:** Python 3.8+ on your `PATH`. Node 14+ for the `npx` launcher.

### Run directly with Python

The scanner is a single self-contained file — no npm required:

```bash
git clone https://github.com/DevCraftXCoder/Security-Intelligence-Center.git
cd Security-Intelligence-Center
python scan_python.py /path/to/your-project
```

---

## What it does

SIC runs three independent passes over your codebase and reports everything it
finds in one shot:

**Static code analysis** — flags patterns in your source that are commonly
exploited, misused, or dangerous in production. Covers injection vectors,
unsafe deserialization, weak cryptography, debug flags left on, and more. Checks
`.ts`, `.tsx`, `.js`, `.jsx`, `.py`, `.env`, `.yaml`, `.yml`, `.json`, `.toml`,
`.sh`, and `.bash` files.

**Dependency vulnerability scan** — checks every `requirements*.txt` in your
project against the Python Advisory Database and reports known CVEs with fix
versions. Requires `pip-audit` (free, one-line install — see below).

**Read-only, local, no telemetry** — the scanner never modifies your files,
makes network requests, or phones home. Findings stay on your machine.

---

## Output

Findings are grouped by severity and printed with file path and line number.
Up to 50 findings are shown in the terminal; the rest appear in the JSON report.

```
SIC code scan - /path/to/your-project
6 findings  (2 critical  2 high  1 medium  1 low)

  CRITICAL <pattern>  config/settings.py:14
  CRITICAL <pattern>  certs/deploy.pem:1
  HIGH     <pattern>  app/db.py:30
  HIGH     <pattern>  scripts/deploy.py:88
  MEDIUM   <pattern>  api/server.py:140
  LOW      <pattern>  utils/hash.py:22

Full report: /tmp/soc_python_scan_abc123/python-scan.json
```

A full JSON report is written for every run — a flat array of findings, each with
`name`, `severity`, `description`, `file`, and `line`. Suitable for dashboards,
ticketing integrations, or diff-against-baseline workflows.

### Programmatic use

Pass `--json-only` to print only the JSON file path — useful in scripts:

```bash
python scan_python.py /path/to/project --json-only
# prints: /tmp/soc_python_scan_abc123/python-scan.json
```

---

## Optional: dependency CVE scanning

Install `pip-audit` to enable the dependency-vulnerability pass:

```bash
pip install pip-audit
```

Without it, the static analysis still runs in full — the dependency check is
simply skipped with a note in the output.

---

## Use in CI

The scanner exits 0 whether or not findings are present, so it never blocks your
build by default.

**GitHub Actions:**
```yaml
- name: SIC security scan
  run: npx --yes sic-security scan
```

**GitLab CI:**
```yaml
security-scan:
  script:
    - npx --yes sic-security scan
  artifacts:
    paths:
      - "*.json"
```

**Pre-commit hook:**
```bash
#!/bin/sh
npx --yes sic-security scan .
```

---

## What it skips

The scanner ignores directories that aren't your code: `node_modules`, `.git`,
`dist`, `.next`, `__pycache__`, `venv`, `build`, `out`, `.cache`, `coverage`,
`.turbo`, `.wrangler`, `_runs`, `_archive`, and `tests`.

It also skips its own source file to avoid false positives from its own pattern
definitions.

---

## What it doesn't replace

- **A full SAST tool** (Semgrep, Bandit, CodeQL) for deep dataflow analysis
- **Runtime security** — the scanner only sees static source, not runtime behavior
- **Manual code review** — context matters; some flagged patterns are intentional

Use it as a first-pass filter and a CI guardrail, not a complete security program.

---

## Authorized Use

Run this scanner against code you own or are authorized to review. Scan output
may surface sensitive values — handle reports accordingly.

See [SECURITY.md](SECURITY.md) for the security policy and responsible-disclosure
contact.

---

## License

[MIT](LICENSE) © DevCraftXCoder
