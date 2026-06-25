"""
scan_python.py — Python-native security scanner (no external tool deps).

Produces findings in the generic list format consumed by scan_merge._collect():
    [{"name": str, "severity": str, "description": str}, ...]

Scanners:
  - scan_secrets: regex patterns for hardcoded credentials, tokens, keys
  - scan_dangerous_patterns: unsafe code patterns (eval, shell=True, SQL concat)
  - scan_pip_audit: CVE data from pip-audit on requirements*.txt files
  - run_all: runs all scanners, writes merged JSON, returns output path
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

# Directories to skip when scanning source files.
_SKIP_DIRS = {
    "node_modules", ".git", "dist", ".next", "__pycache__",
    ".venv", "venv", "env", "build", "out", ".cache",
    "coverage", ".turbo", ".wrangler",
    # Scanner output — scanning prior artifacts inflates FP count
    "_runs", "_archive",
    # Test code — asserts, SQL fixtures, etc. are expected patterns
    "tests",
}

# This scanner's own source file — skip to avoid detecting its own pattern definitions
_SELF_FILE = Path(__file__).name

# Source file extensions to scan for secrets and dangerous patterns.
_SCAN_EXTENSIONS = {
    ".ts", ".tsx", ".js", ".jsx", ".py", ".env", ".env.example",
    ".yaml", ".yml", ".json", ".toml", ".sh", ".bash",
}

# Secrets regex patterns: (pattern_name, compiled_regex, severity)
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("hardcoded_api_key",
     re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']'),
     "high"),
    ("hardcoded_secret",
     re.compile(r'(?i)(secret[_-]?key|app[_-]?secret)\s*[:=]\s*["\']([A-Za-z0-9_\-\/+]{16,})["\']'),
     "high"),
    ("hardcoded_password",
     re.compile(r'(?i)password\s*[:=]\s*["\']([^"\']{6,})["\']'),
     "high"),
    ("hardcoded_token",
     re.compile(r'(?i)(auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']'),
     "high"),
    ("jwt_token",
     re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'),
     "critical"),
    ("database_url",
     re.compile(r'(?i)(database_url|db_url|connection_string)\s*[:=]\s*["\']([^"\']{10,})["\']'),
     "high"),
    ("postgres_url",
     re.compile(r'postgres(?:ql)?://[^:]+:[^@]+@[^\s"\']+'),
     "critical"),
    ("mysql_url",
     re.compile(r'mysql://[^:]+:[^@]+@[^\s"\']+'),
     "critical"),
    ("aws_access_key",
     re.compile(r'AKIA[A-Z0-9]{16}'),
     "critical"),
    ("stripe_key",
     re.compile(r'(?:sk|pk|rk)_(live|test)_[A-Za-z0-9]{20,}'),
     "critical"),
    ("cloudflare_api_token",
     re.compile(r'(?i)cf[_-]?(?:api[_-]?)?token\s*[:=]\s*["\']([A-Za-z0-9_\-]{30,})["\']'),
     "high"),
    ("github_token",
     re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}'),
     "critical"),
    ("private_key_block",
     re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
     "critical"),
    ("hardcoded_wrangler_secret",
     re.compile(r'(?i)wrangler[_-]?secret\s*[:=]\s*["\']([A-Za-z0-9_\-]{8,})["\']'),
     "medium"),
]

# Dangerous code patterns: (pattern_name, compiled_regex, severity, description)
_DANGEROUS_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    ("eval_usage",
     re.compile(r'\beval\s*\('),
     "high",
     "eval() is dangerous — arbitrary code execution risk"),
    ("shell_true",
     re.compile(r'shell\s*=\s*True'),
     "high",
     "subprocess with shell=True enables shell injection"),
    ("sql_concatenation",
     re.compile(r'(?i)(execute|query)\s*\(\s*[f"\'].*(%s|%d|\+|\.format|f"|\{)'),
     "high",
     "SQL query built via string concatenation — SQL injection risk"),
    ("unsafe_yaml_load",
     re.compile(r'\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)'),
     "medium",
     "yaml.load() without SafeLoader is unsafe"),
    ("pickle_usage",
     re.compile(r'\bpickle\.loads?\s*\('),
     "medium",
     "pickle deserialization of untrusted data is unsafe"),
    ("hardcoded_debug_true",
     re.compile(r'(?i)DEBUG\s*=\s*True'),
     "medium",
     "DEBUG=True should not be present in production code"),
    ("md5_usage",
     re.compile(r'\bmd5\s*\(|hashlib\.md5'),
     "low",
     "MD5 is cryptographically weak — use SHA-256 or better"),
    ("assert_in_production",
     re.compile(r'^\s*assert\s+'),
     "low",
     "assert statements are stripped in optimized builds (python -O)"),
    ("open_redirect",
     re.compile(r'(?i)redirect\s*\(\s*request\.(args|params|query)'),
     "medium",
     "Potential open redirect from unvalidated user input"),
    ("cors_wildcard",
     re.compile(r'(?i)Access-Control-Allow-Origin["\s:]*\*'),
     "medium",
     "CORS wildcard allows any origin — restrict to known domains"),
]


def _walk_source_files(project_path: str) -> list[Path]:
    """Yield all scannable source files, skipping ignored directories."""
    root = Path(project_path)
    results: list[Path] = []
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.name == _SELF_FILE:
            continue
        if path.is_file() and path.suffix in _SCAN_EXTENSIONS:
            results.append(path)
    return results


def scan_secrets(project_path: str) -> list[dict[str, Any]]:
    """Scan source files for hardcoded secrets and credentials."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for file_path in _walk_source_files(project_path):
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for pattern_name, regex, severity in _SECRET_PATTERNS:
            for match in regex.finditer(text):
                line_no = text[:match.start()].count("\n") + 1
                dedup_key = f"{pattern_name}:{file_path}:{line_no}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                rel_path = str(file_path.relative_to(project_path))
                findings.append({
                    "name": pattern_name,
                    "severity": severity,
                    "description": (
                        f"Potential hardcoded secret ({pattern_name}) "
                        f"in {rel_path}:{line_no}"
                    ),
                    "file": rel_path,
                    "line": line_no,
                })

    return findings


def scan_dangerous_patterns(project_path: str) -> list[dict[str, Any]]:
    """Scan source files for dangerous code patterns."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for file_path in _walk_source_files(project_path):
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        lines = text.splitlines()
        for pattern_name, regex, severity, description in _DANGEROUS_PATTERNS:
            for line_no, line in enumerate(lines, 1):
                if regex.search(line):
                    dedup_key = f"{pattern_name}:{file_path}:{line_no}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    rel_path = str(file_path.relative_to(project_path))
                    findings.append({
                        "name": pattern_name,
                        "severity": severity,
                        "description": (
                            f"{description} — {rel_path}:{line_no}"
                        ),
                        "file": rel_path,
                        "line": line_no,
                    })

    return findings


def scan_pip_audit(project_path: str) -> list[dict[str, Any]]:
    """Run pip-audit on all requirements*.txt files found in the project."""
    findings: list[dict[str, Any]] = []
    root = Path(project_path)

    req_files = list(root.rglob("requirements*.txt"))
    if not req_files:
        return findings

    for req_file in req_files:
        if any(part in _SKIP_DIRS for part in req_file.parts):
            continue
        rel = str(req_file.relative_to(project_path))
        try:
            proc = subprocess.run(
                ["pip-audit", "-r", str(req_file), "--format", "json"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except FileNotFoundError:
            print("[scan_python] pip-audit not found in PATH — skipping dep scan", file=sys.stderr)
            break
        except subprocess.TimeoutExpired:
            print(f"[scan_python] pip-audit timed out on {rel} — skipping", file=sys.stderr)
            continue
        except OSError as exc:
            print(f"[scan_python] pip-audit failed ({exc}) — skipping", file=sys.stderr)
            break

        if not proc.stdout.strip():
            continue

        try:
            audit_data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            continue

        # pip-audit JSON format: {"dependencies": [{"name": ..., "version": ...,
        #   "vulns": [{"id": ..., "description": ..., "fix_versions": [...]}]}]}
        for dep in audit_data.get("dependencies", []):
            dep_name = dep.get("name", "unknown")
            dep_version = dep.get("version", "?")
            for vuln in dep.get("vulns", []):
                vuln_id = vuln.get("id", "unknown")
                desc = vuln.get("description", "No description available.")
                fix = vuln.get("fix_versions", [])
                fix_str = f" Fix: upgrade to {fix[0]}" if fix else ""
                findings.append({
                    "name": f"CVE:{vuln_id}",
                    "severity": "high",
                    "description": (
                        f"{dep_name}=={dep_version} has known vulnerability {vuln_id} "
                        f"(from {rel}).{fix_str} {desc[:200]}"
                    ),
                    "file": rel,
                    "line": 0,
                })

    return findings


def run_all(project_path: str, output_dir: Optional[str] = None) -> str:
    """Run all Python-native scanners and write a unified JSON findings file.

    Returns the path to the written JSON file.
    Output format: flat list compatible with scan_merge._collect().
    """
    print(f"[scan_python] Scanning {project_path} ...", file=sys.stderr)

    all_findings: list[dict[str, Any]] = []

    secrets = scan_secrets(project_path)
    print(f"[scan_python] secrets: {len(secrets)} findings", file=sys.stderr)
    all_findings.extend(secrets)

    patterns = scan_dangerous_patterns(project_path)
    print(f"[scan_python] dangerous_patterns: {len(patterns)} findings", file=sys.stderr)
    all_findings.extend(patterns)

    pip_findings = scan_pip_audit(project_path)
    print(f"[scan_python] pip_audit: {len(pip_findings)} findings", file=sys.stderr)
    all_findings.extend(pip_findings)

    out_dir = output_dir or tempfile.mkdtemp(prefix="soc_python_scan_")
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    out_file = str(Path(out_dir) / "python-scan.json")

    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(all_findings, fh, indent=2)

    print(
        f"[scan_python] wrote {len(all_findings)} findings -> {out_file}",
        file=sys.stderr,
    )
    return out_file


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Python-native security scanner")
    p.add_argument("path", nargs="?", default=".", help="Project path to scan")
    p.add_argument("--output-dir", help="Output directory for findings JSON")
    args = p.parse_args()

    out = run_all(args.path, args.output_dir)
    print(out)
