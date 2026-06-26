<div align="center">

# SIC — Code Scanner

### Free, read-only static analysis for secrets, unsafe patterns, and dependency CVEs

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![npm](https://img.shields.io/badge/npx-sic--security-red.svg)](https://www.npmjs.com/package/sic-security)

**Scan any codebase for hardcoded secrets, dangerous code patterns, and known
dependency vulnerabilities — in one command, with zero setup.**

</div>

---

## Quick Start

```bash
# From the root of the project you want to scan:
npx sic-security scan
```

That's it. The scanner reads your source files and prints findings immediately —
hardcoded secrets, dangerous patterns (`eval`, `shell=True`, SQL string-building,
unsafe YAML/pickle, CORS wildcards, weak hashing, …), and dependency CVEs when
`pip-audit` is available.

- **No setup** — runs on the Python standard library alone. No build step, no
  external binaries, no API key, no account.
- **Read-only** — it never modifies your files, sends packets, or phones home.
  Findings stay on your machine.
- **Scan a specific path:**
  ```bash
  npx sic-security scan ./path/to/project
  ```

> **Prerequisite:** Python 3.8+ on your `PATH` (used to run the scanner). Node 14+
> for the `npx` launcher.

### Run it directly with Python

The scanner is a single self-contained file — you can clone and run it without npm:

```bash
git clone https://github.com/DevCraftXCoder/Security-Intelligence-Center.git
cd Security-Intelligence-Center
python scan_python.py /path/to/your-project
```

---

## What it checks

| Category | Examples |
|----------|----------|
| **Hardcoded secrets** | API keys, passwords, JWTs, AWS/Stripe/GitHub tokens, private-key blocks, database connection strings |
| **Dangerous patterns** | `eval()`, `shell=True`, SQL built by string concatenation, `yaml.load` without `SafeLoader`, `pickle` loads, `DEBUG=True`, MD5, CORS wildcards, open redirects |
| **Dependency CVEs** | Known vulnerabilities in `requirements*.txt` (requires `pip-audit`) |

Findings are grouped by severity (critical / high / medium / low) and printed with
file and line numbers. A full JSON report is also written for programmatic use.

### Optional: dependency CVE scanning

Install `pip-audit` to enable the dependency-vulnerability check:

```bash
pip install pip-audit
```

Without it, the secret and dangerous-pattern scans still run — the dependency
check is simply skipped.

---

## Output

```
SIC code scan - /path/to/your-project
4 findings  (1 critical  2 high  1 medium)

  CRITICAL aws_access_key        config/settings.py:12
  HIGH     hardcoded_password     app/db.py:30
  HIGH     shell_true             scripts/deploy.py:88
  MEDIUM   cors_wildcard          api/server.py:140

Full report: <path-to-report>.json
```

The scanner exits cleanly whether or not findings are present, so it slots into
pre-commit hooks and CI pipelines.

---

## Use in CI

```bash
npx --yes sic-security scan
```

The JSON report path is printed at the end of every run for downstream tooling.

---

## Authorized Use

This scanner is read-only and non-destructive. Run it against code you own or are
authorized to review. Scan output may surface sensitive values (such as hardcoded
secrets) — handle reports accordingly.

See [SECURITY.md](SECURITY.md) for the security policy and responsible-disclosure
contact.

---

## License

[MIT](LICENSE) © DevCraftXCoder
