<div align="center">

# SIC — Codebase Scanner

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

That's it. No config file. No account. No API key. The scanner reads your source
files and prints findings immediately — hardcoded secrets, dangerous patterns, and
dependency CVEs (when `pip-audit` is available).

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

## What it checks

### Hardcoded secrets

The scanner looks for secrets embedded directly in source code — the kind that get
accidentally committed and then live in git history forever.

| Pattern | Examples caught |
|---------|----------------|
| Generic API keys | `api_key = "..."`, `API_KEY="abc123"` (16+ char values) |
| Secret keys | `secret_key = "..."`, `app_secret = "..."` |
| Passwords in code | `password = "hunter2"`, `db_pass = "..."` |
| Auth / access tokens | `auth_token = "..."`, `access_token = "..."` |
| JWT strings | Long `eyJ...` base64 blobs hardcoded in source |
| AWS credentials | `AKIA...` access keys |
| Stripe keys | `sk_live_...`, `sk_test_...`, `pk_live_...`, `rk_live_...` |
| GitHub tokens | `ghp_...`, `gho_...`, `ghu_...`, `ghs_...`, `ghr_...` |
| Cloudflare API tokens | `cf_token = "..."`, `cf_api_token = "..."` (30+ chars) |
| Wrangler secrets | `wrangler_secret = "..."` (CF Workers deploy credentials) |
| Private key blocks | `-----BEGIN RSA PRIVATE KEY-----` and EC / OPENSSH variants |
| PostgreSQL URLs | `postgres://user:password@host/db` with embedded credentials |
| MySQL URLs | `mysql://user:password@host/db` with embedded credentials |
| Generic database URLs | `DATABASE_URL = "..."`, `DB_URL = "..."`, `CONNECTION_STRING = "..."` |

Matching uses targeted regexes — a variable named `api_key_description` won't
trigger, but `api_key = "abc..."` will.

### Dangerous code patterns

Beyond secrets, the scanner flags patterns that are technically valid but commonly
exploited, misused, or wrong in production code.

| Pattern | Why it matters |
|---------|---------------|
| `eval()` | Executes arbitrary code — common injection vector |
| `subprocess` with `shell=True` | Shell expansion enables command injection |
| SQL built by string concat | Classic SQL injection — use parameterized queries |
| `yaml.load()` without `Loader` | Unsafe deserialization; use `yaml.safe_load()` |
| `pickle.loads()` | Arbitrary code execution on deserialization of untrusted data |
| `DEBUG = True` | Exposes stack traces, internal state, and admin panels in production |
| MD5 for hashing | Broken algorithm — use SHA-256 or better |
| `assert` for validation | Stripped by Python's `-O` flag; use explicit checks |
| Open redirect via request params | Unvalidated `request.args` / `request.params` in a redirect call |
| CORS wildcard | `Access-Control-Allow-Origin: *` lets any origin read credentialed responses |

### Dependency CVEs

When `pip-audit` is installed, the scanner checks every `requirements*.txt` in the
project against the Python Advisory Database. It reports package name, installed
version, CVE ID, and fix version for any known vulnerabilities.

```bash
pip install pip-audit   # enable dependency CVE scanning
```

Without it, secrets and pattern scanning still run — the dependency check is simply
skipped with a note in the output.

---

## Output

Findings are grouped by severity and printed with file path and line number. Up to
50 findings are shown in the terminal; the rest appear in the JSON report.

```
SIC code scan - /path/to/your-project
6 findings  (2 critical  2 high  1 medium  1 low)

  CRITICAL aws_access_key  config/settings.py:14
  CRITICAL private_key_block  certs/deploy.pem:1
  HIGH     hardcoded_password  app/db.py:30
  HIGH     shell_true  scripts/deploy.py:88
  MEDIUM   cors_wildcard  api/server.py:140
  LOW      md5_usage  utils/hash.py:22

Full report: /tmp/soc_python_scan_abc123/python-scan.json
```

A full JSON report (a flat array of findings) is written for every run, suitable
for downstream tooling, dashboards, or diff-against-baseline workflows.

### JSON report format

The report file is a flat JSON array — one object per finding:

```json
[
  {
    "name": "aws_access_key",
    "severity": "critical",
    "description": "Potential hardcoded secret (aws_access_key) in config/settings.py:14",
    "file": "config/settings.py",
    "line": 14
  },
  {
    "name": "shell_true",
    "severity": "high",
    "description": "subprocess with shell=True enables shell injection — scripts/deploy.py:88",
    "file": "scripts/deploy.py",
    "line": 88
  }
]
```

Each finding has:
- `name` — machine-readable pattern ID for filtering
- `severity` — `critical` / `high` / `medium` / `low`
- `description` — human-readable summary with location
- `file` — relative path from the scan root
- `line` — line number (0 for dependency CVEs)

### Programmatic use

Pass `--json-only` to suppress the human-readable report and print only the JSON
file path — useful in scripts that parse the output directly:

```bash
python scan_python.py /path/to/project --json-only
# prints: /tmp/soc_python_scan_abc123/python-scan.json
```

---

## Use in CI

Drop into any pipeline — the scanner exits 0 whether or not findings are present,
so it never blocks your build by default. Pipe the JSON report path to your
preferred alert or ticketing system.

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

## How it works

The scanner is a single Python file (`scan_python.py`) with no third-party
dependencies. It walks your project tree, skips non-code directories, and runs
three independent passes:

1. **Secret scan** — 14 regex patterns across all text files (`.ts`, `.tsx`, `.js`,
   `.jsx`, `.py`, `.env`, `.yaml`, `.yml`, `.json`, `.toml`, `.sh`, `.bash`)
2. **Pattern scan** — 10 dangerous code constructs checked line by line
3. **Dependency scan** — delegates to `pip-audit` if installed; skips gracefully if not

Skipped directories: `node_modules`, `.git`, `dist`, `.next`, `__pycache__`,
`.venv`, `venv`, `env`, `build`, `out`, `.cache`, `coverage`, `.turbo`,
`.wrangler`, `_runs`, `_archive`, `tests`.

Findings from all three passes are merged, deduplicated, sorted by severity, and
written to a temp JSON file. The file path is printed at the end of every run.

**No network calls. No file modifications. No telemetry.**
Everything runs locally and stays on your machine.

---

## What it doesn't replace

The scanner is fast and zero-setup — it is not a substitute for:

- **A full SAST tool** (Semgrep, Bandit, CodeQL) for deep dataflow analysis
- **Secret rotation** — finding a secret in code doesn't revoke it; rotate immediately
- **Runtime security** — the scanner only sees static source, not runtime behavior
- **Manual code review** — context matters; some flagged patterns are intentional

Use it as a first-pass filter and a CI guardrail, not as a complete security program.

---

## Authorized Use

This scanner is read-only and non-destructive. Run it against code you own or are
authorized to review. Scan output may surface sensitive values (such as hardcoded
secrets) — treat reports as sensitive and handle them accordingly.

See [SECURITY.md](SECURITY.md) for the security policy and responsible-disclosure
contact.

---

## License

[MIT](LICENSE) © DevCraftXCoder
