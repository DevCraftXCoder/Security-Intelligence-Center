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
| Generic API keys | `api_key = "sk-..."`, `API_KEY="abc123"` |
| Passwords in code | `password = "hunter2"`, `db_pass = "..."` |
| Bearer tokens | `Authorization: Bearer <literal token>` |
| JWT strings | Long `eyJ...` base64 blobs hardcoded in source |
| AWS credentials | `AKIA...` access keys, secret keys |
| Stripe keys | `sk_live_...`, `rk_live_...` |
| GitHub tokens | `ghp_...`, `github_pat_...` |
| Private key blocks | `-----BEGIN RSA PRIVATE KEY-----` and variants |
| Database URLs | `postgres://user:password@host/db`, `mongodb+srv://...` |

It uses whole-word regex matching to minimize false positives — a variable named
`api_key_description` won't trigger, but `api_key = "..."` will.

### Dangerous code patterns

Beyond secrets, the scanner flags patterns that are technically valid but commonly
exploited, misused, or simply wrong in production code.

| Pattern | Why it matters |
|---------|---------------|
| `eval()` | Executes arbitrary code — common injection vector |
| `subprocess` with `shell=True` | Shell expansion enables command injection |
| SQL built by string concat | Classic SQL injection — use parameterized queries |
| `yaml.load()` without `Loader` | Unsafe deserialization; use `yaml.safe_load()` |
| `pickle.loads()` on untrusted data | Arbitrary code execution on deserialization |
| `DEBUG = True` in production configs | Exposes stack traces, internal state, and admin panels |
| MD5 for cryptographic use | Broken hash algorithm — use SHA-256 or better |
| `assert` for validation | Stripped by Python's `-O` flag; use explicit checks |
| Open redirect patterns | Unvalidated `next=` / `redirect=` parameters |
| CORS wildcard (`Access-Control-Allow-Origin: *`) | Allows any origin to read credentialed responses |

### Dependency CVEs

When `pip-audit` is installed, the scanner checks every `requirements*.txt` in the
project against the Python Advisory Database. It reports package name, installed
version, and CVE IDs for any known vulnerabilities.

```bash
pip install pip-audit   # enable dependency CVE scanning
```

Without it, secrets and pattern scanning still run — the dependency check is simply
skipped with a note in the output.

---

## Output

Findings are grouped by severity and printed with file path and line number:

```
SIC Code Scanner v7.0.0
Scanning /path/to/your-project ...

6 findings  (2 critical  2 high  1 medium  1 low)

  CRITICAL  aws_access_key          config/settings.py:14
  CRITICAL  private_key_block       certs/deploy.pem:1
  HIGH      hardcoded_password      app/db.py:30
  HIGH      shell_true              scripts/deploy.py:88
  MEDIUM    cors_wildcard           api/server.py:140
  LOW       md5_usage               utils/hash.py:22

Full report → /tmp/sic-scan-1234567890.json
```

Each finding includes:
- **Severity** — critical / high / medium / low
- **Pattern ID** — machine-readable name for filtering
- **File + line** — jump directly to the source

A full JSON report is written for every run, suitable for downstream tooling,
dashboards, or diff-against-baseline workflows.

### JSON report format

```json
{
  "scan_target": "/path/to/project",
  "timestamp": "2026-01-01T00:00:00",
  "total_findings": 6,
  "findings": [
    {
      "severity": "critical",
      "pattern": "aws_access_key",
      "file": "config/settings.py",
      "line": 14,
      "match": "AKIA..."
    }
  ],
  "summary": {
    "critical": 2,
    "high": 2,
    "medium": 1,
    "low": 1
  }
}
```

---

## Use in CI

Drop into any pipeline — the scanner exits 0 whether or not findings are present,
so it never blocks your build by default. Pipe the JSON report to your preferred
alert or ticketing system.

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
dependencies. It walks your project tree, skips common non-code directories
(`node_modules`, `.git`, `__pycache__`, `dist`, `build`, `.venv`), and runs three
independent passes:

1. **Secret scan** — regex matching against 14 patterns across all text files
2. **Pattern scan** — AST-aware and regex matching for 10 dangerous code constructs
3. **Dependency scan** — delegates to `pip-audit` if installed; skips gracefully if not

Findings from all three passes are merged, deduplicated, and sorted by severity
before output. The JSON report is written atomically to a temp file and the path
is printed at the end of the run.

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
