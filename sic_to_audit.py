#!/usr/bin/env python3
"""
sic_to_audit.py  --  SIC scan JSON -> 3SIXTYCO. security audit HTML report

Parses SIC tool output (nuclei / trivy / checkov / smart-scan), maps findings
to the 42 audit control IDs, and injects window.AUDIT.fill({...}) into the
3SIXTYCO. audit template HTML.

Usage:
    python C:/Za/sic/sic_to_audit.py \
        --results  C:/Za/sic/_runs/scan-20260529-120000.json \
        --template "C:/Users/J/Documents/3sixtyco-security-audit-v1.html" \
        --project  "FrxncoisApp" \
        --output   C:/Za/sic/_runs/qa/FrxncoisApp-audit-20260529-120000.html
"""

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Control mapping table
# ---------------------------------------------------------------------------

# nuclei tag / tool-name keyword -> control ID
TAG_TO_CONTROL = {
    # sp -- Critical Security Architecture (p0)
    "idor":                  "sp-02",
    "broken-access-control": "sp-02",
    "bac":                   "sp-02",
    "mass-assignment":       "sp-02",
    "oauth":                 "sp-03",
    "oidc":                  "sp-03",
    "pkce":                  "sp-03",
    "open-redirect":         "sp-03",
    "iam":                   "sp-05",
    "cloud-iam":             "sp-05",
    "imds":                  "sp-05",
    "crypto":                "sp-06",
    "tls":                   "sp-06",
    "ssl":                   "sp-06",
    "weak-crypto":           "sp-06",
    "rce":                   "sp-04",
    "lfi":                   "sp-04",
    "xxe":                   "sp-04",
    "command-injection":     "sp-04",
    "deserialization":       "sp-04",
    # s -- Core Security Controls (p1)
    "session":               "s-02",
    "cookie":                "s-02",
    "api":                   "s-03",
    "bola":                  "s-03",
    "injection":             "s-03",
    "secret":                "s-05",
    "secrets":               "s-05",
    "exposure":              "s-05",
    "token-exposure":        "s-05",
    "hardcoded":             "s-05",
    "leaked":                "s-05",
    # sm -- Security Hardening (p2)
    "xss":                   "sm-02",
    "csrf":                  "sm-02",
    "sqli":                  "sm-02",
    "ssrf":                  "sm-03",
    "jwt":                   "sm-04",
    "alg-none":              "sm-04",
    "log":                   "sm-06",
    "logging":               "sm-06",
    "pii":                   "sm-06",
    # app -- Infrastructure & Supply Chain (p2)
    "docker":                "app-01",
    "container":             "app-01",
    "kubernetes":            "app-01",
    "k8s":                   "app-01",
    "privileged":            "app-01",
    "supply-chain":          "app-02",
    "sbom":                  "app-02",
    "cve":                   "app-03",
    "vulnerability":         "app-03",
    "outdated":              "app-03",
    "file-upload":           "app-06",
    "upload":                "app-06",
    # ap -- Operational Security (p3)
    "cicd":                  "ap-03",
    "github-actions":        "ap-03",
    "ci":                    "ap-03",
    "pipeline":              "ap-03",
    # a -- Defense in Depth (p3)
    "cors":                  "a-03",
    "csp":                   "a-03",
    "headers":               "a-03",
    "hsts":                  "a-03",
    "token-revocation":      "a-05",
    "token-reuse":           "a-05",
    "refresh-token":         "a-05",
    "waf":                   "a-01",
    # bp -- Security Hygiene (p3)
    "dns":                   "bp-01",
    "dnssec":                "bp-01",
    "subdomain-takeover":    "bp-01",
    "sast":                  "bp-02",
    "misconfig":             "bp-02",
    "geo":                   "bp-03",
    "audit-log":             "bp-06",
    "retention":             "bp-06",
}

SEVERITY_FALLBACK = {
    "critical": "sp-04",
    "high":     "s-03",
    "medium":   "sm-02",
    "low":      "bp-02",
    "info":     "bp-02",
    "unknown":  "bp-02",
}

ALL_IDS = [
    "sp-01", "sp-02", "sp-03", "sp-04", "sp-05", "sp-06",
    "s-01",  "s-02",  "s-03",  "s-04",  "s-05",  "s-06",
    "sm-01", "sm-02", "sm-03", "sm-04", "sm-05", "sm-06",
    "app-01","app-02","app-03","app-04","app-05","app-06",
    "ap-01", "ap-02", "ap-03", "ap-04", "ap-05", "ap-06",
    "a-01",  "a-02",  "a-03",  "a-04",  "a-05",  "a-06",
    "bp-01", "bp-02", "bp-03", "bp-04", "bp-05", "bp-06",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_nested(obj, *keys):
    for k in keys:
        if isinstance(obj, dict):
            obj = obj.get(k)
        else:
            return None
    return obj


def _sev(finding):
    raw = (
        finding.get("severity")
        or _get_nested(finding, "info", "severity")
        or finding.get("Severity")
        or "unknown"
    )
    return str(raw).lower()


def _tags(finding):
    tags = []
    for src in (
        finding.get("tags"),
        _get_nested(finding, "info", "tags"),
        _get_nested(finding, "classification", "cvss-tags"),
    ):
        if isinstance(src, list):
            tags.extend(str(t).lower() for t in src)
        elif isinstance(src, str):
            tags.extend(src.lower().replace(",", " ").split())

    for key in ("name", "template-id", "templateID", "vulnerabilityName",
                "checkID", "check_id", "Title", "title"):
        v = finding.get(key, "")
        if v:
            tags.append(str(v).lower())
    return [t.strip() for t in tags if t.strip()]


def map_finding(finding):
    """Return (control_id, note_str) for a single finding."""
    for tag in _tags(finding):
        for keyword, cid in TAG_TO_CONTROL.items():
            if keyword in tag:
                note = (
                    finding.get("name")
                    or finding.get("vulnerabilityName")
                    or finding.get("Title")
                    or tag
                )
                return cid, str(note)[:200]

    sev = _sev(finding)
    cid = SEVERITY_FALLBACK.get(sev, "bp-02")
    note = (
        finding.get("name")
        or finding.get("vulnerabilityName")
        or finding.get("Title")
        or f"{sev} finding"
    )
    return cid, str(note)[:200]


# ---------------------------------------------------------------------------
# JSON loader — handles concatenated / newline-delimited / nested JSON
# ---------------------------------------------------------------------------

def load_findings(path):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    findings = []
    decoder = json.JSONDecoder()
    pos = 0
    while pos < len(text):
        while pos < len(text) and text[pos] in " \t\n\r":
            pos += 1
        if pos >= len(text):
            break
        try:
            obj, end = decoder.raw_decode(text, pos)
            pos = end
            findings.extend(_collect(obj))
        except json.JSONDecodeError:
            pos += 1
    return findings


def _collect(obj):
    """Recursively collect dicts that look like individual findings.

    Handles three schemas beyond the generic nuclei/smart-scan format:
    - trivy: Results[].Vulnerabilities[] with VulnerabilityID/Severity/Title/Description
    - checkov: results.failed_checks[] with check_id/severity/resource/check_result
    """
    if isinstance(obj, list):
        out = []
        for item in obj:
            out.extend(_collect(item))
        return out
    if isinstance(obj, dict):
        # trivy: top-level Results array containing Vulnerabilities sub-arrays
        if "Results" in obj and isinstance(obj["Results"], list):
            out = []
            for result in obj["Results"]:
                vulns = result.get("Vulnerabilities") or []
                for v in vulns:
                    # Normalise to the shared finding schema
                    out.append({
                        "name":            v.get("VulnerabilityID") or v.get("Title") or "Unknown CVE",
                        "vulnerabilityName": v.get("Title") or v.get("VulnerabilityID") or "",
                        "severity":        (v.get("Severity") or "unknown").lower(),
                        "description":     v.get("Description") or "",
                        "template-id":     v.get("VulnerabilityID") or "",
                        "tags":            ["cve", "vulnerability"],
                        "references":      v.get("References") or [],
                        "_source":         "trivy",
                    })
            if out:
                return out

        # checkov: results.failed_checks[] (may appear as top-level results key)
        failed = (
            (obj.get("results") or {}).get("failed_checks")
            if isinstance(obj.get("results"), dict)
            else None
        )
        if isinstance(failed, list) and failed:
            out = []
            for fc in failed:
                sev = str(fc.get("severity") or "medium").lower()
                if sev not in ("critical", "high", "medium", "low", "info"):
                    sev = "medium"
                out.append({
                    "name":        fc.get("check_id") or "CKV_UNKNOWN",
                    "Title":       fc.get("check_id") or "Checkov finding",
                    "severity":    sev,
                    "description": (
                        f"Resource: {fc.get('resource') or 'unknown'}. "
                        f"File: {(fc.get('repo_file_path') or fc.get('file_path') or '')}. "
                        f"Lines: {fc.get('file_line_range') or ''}."
                    ),
                    "checkID":     fc.get("check_id") or "",
                    "tags":        ["misconfig", "iac"],
                    "_source":     "checkov",
                })
            if out:
                return out

        # Generic nuclei / smart-scan findings
        finding_keys = {"severity", "Severity", "vulnerabilityName", "name",
                        "template-id", "templateID", "Title", "checkID"}
        if finding_keys & obj.keys():
            sub = obj.get("findings") or obj.get("results") or obj.get("Vulnerabilities")
            if isinstance(sub, list):
                return _collect(sub)
            return [obj]
        # recurse into list values
        out = []
        for v in obj.values():
            if isinstance(v, list):
                out.extend(_collect(v))
        return out
    return []


# ---------------------------------------------------------------------------
# LLM-assisted control mapping
# ---------------------------------------------------------------------------

_CONTROL_DESCRIPTIONS = {
    "sp-01": "Authentication architecture — auth system design, MFA, session tokens",
    "sp-02": "Access control / IDOR / BOLA — authorization, ownership checks, mass assignment",
    "sp-03": "OAuth / OIDC / open redirect — third-party auth flows, PKCE, redirect validation",
    "sp-04": "Remote code execution / injection — RCE, LFI, XXE, command injection, deserialization",
    "sp-05": "Cloud IAM / privilege escalation — cloud roles, IMDS, over-privileged accounts",
    "sp-06": "Cryptography — weak ciphers, TLS config, certificate issues",
    "s-01":  "Input validation — unvalidated user input across all entry points",
    "s-02":  "Session management — cookie flags, session fixation, token lifecycle",
    "s-03":  "API security / injection — SQLi, NoSQLi, BOLA, API authentication",
    "s-04":  "Error handling — stack traces in responses, information disclosure",
    "s-05":  "Secrets management — hardcoded credentials, token exposure, API key leaks",
    "s-06":  "Dependency vulnerabilities — third-party CVEs, outdated packages",
    "sm-01": "Security headers — missing or misconfigured HTTP security headers",
    "sm-02": "Client-side security — XSS, CSRF, DOM injection, content injection",
    "sm-03": "SSRF — server-side request forgery, internal network access",
    "sm-04": "JWT security — alg:none, weak signing, claim validation",
    "sm-05": "File handling — path traversal, unsafe file operations",
    "sm-06": "Logging / PII — sensitive data in logs, missing audit trail",
    "app-01": "Container security — Docker misconfig, privileged containers, K8s security",
    "app-02": "Supply chain — SBOMs, dependency integrity, build pipeline security",
    "app-03": "Known CVEs — unpatched vulnerabilities, EOL components",
    "app-04": "Infrastructure as code — Terraform/Helm misconfigurations",
    "app-05": "Secrets in code — hardcoded values, .env exposure, git history",
    "app-06": "File upload security — malicious uploads, MIME validation, storage exposure",
    "ap-01":  "Monitoring and alerting — security event detection, SIEM integration",
    "ap-02":  "Incident response — runbooks, escalation paths, breach procedures",
    "ap-03":  "CI/CD pipeline security — GitHub Actions, pipeline injection, secrets in CI",
    "ap-04":  "Network segmentation — firewall rules, VPC config, exposure minimization",
    "ap-05":  "Backup and recovery — data backup integrity, restore testing",
    "ap-06":  "Vendor risk — third-party service security, SLA, data handling",
    "a-01":   "WAF / DDoS protection — edge protection, rate limiting at perimeter",
    "a-02":   "Data encryption at rest — database encryption, storage encryption",
    "a-03":   "CORS / CSP / security headers — browser-enforced protections",
    "a-04":   "Penetration testing — scheduled testing, findings tracking",
    "a-05":   "Token revocation — refresh token rotation, logout invalidation",
    "a-06":   "Zero trust / least privilege — access scoping, privilege minimization",
    "bp-01":  "DNS security — DNSSEC, subdomain takeover, DNS hijacking",
    "bp-02":  "Security scanning — SAST/DAST coverage, misconfiguration scanning",
    "bp-03":  "Geo-blocking / IP controls — geographic access restrictions",
    "bp-04":  "Security training — developer awareness, phishing resistance",
    "bp-05":  "Vulnerability disclosure — responsible disclosure policy, bug bounty",
    "bp-06":  "Audit log retention — log archival, tamper-evident logging",
}


def _llm_map_findings(findings, gateway_key):
    """
    Call LLM Gateway to get control mappings for findings that the static table
    couldn't confidently classify. Returns {finding_index: (control_id, confidence)}.
    Only called when LLM_GATEWAY_KEY is available in env.
    """
    if not findings or not gateway_key:
        return {}

    # Build a compact representation of each finding for the prompt
    finding_list = []
    for idx, f in enumerate(findings):
        name = f.get("name") or f.get("vulnerabilityName") or f.get("Title") or "Unknown"
        desc = (f.get("description") or f.get("details") or "")[:150]
        tags = ", ".join(_tags(f)[:5])
        sev  = _sev(f)
        finding_list.append(
            f"{idx}: name={name!r} severity={sev} tags=[{tags}] desc={desc!r}"
        )

    control_list = "\n".join(
        f"  {cid}: {desc}" for cid, desc in _CONTROL_DESCRIPTIONS.items()
    )

    prompt = (
        "You are a security control mapper. Given a list of security findings and a "
        "list of control IDs with descriptions, return a JSON object mapping each "
        "finding index to the BEST matching control ID and a confidence float (0.0-1.0).\n\n"
        "Respond ONLY with a JSON object like: {\"0\": {\"control\": \"sp-02\", \"confidence\": 0.91}, ...}\n\n"
        f"Controls:\n{control_list}\n\n"
        f"Findings:\n" + "\n".join(finding_list)
    )

    payload = json.dumps({
        "model": "anthropic/claude-haiku-4.5",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
    }).encode()

    req = urllib.request.Request(
        "https://llm.frxncois.workers.dev/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {gateway_key}",
            "HTTP-Referer":  "https://frxncois.com",
            "X-Title":       "sic_to_audit",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
        text = body["choices"][0]["message"]["content"].strip()
        # Strip markdown code fences if model wrapped JSON
        text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        result = json.loads(text)
        return {
            int(k): (v["control"], float(v.get("confidence", 0.5)))
            for k, v in result.items()
            if v.get("control") in _CONTROL_DESCRIPTIONS
        }
    except Exception as e:
        print(f"[sic_to_audit] LLM mapping skipped: {e}", file=sys.stderr)
        return {}


# ---------------------------------------------------------------------------
# Fill data builder
# ---------------------------------------------------------------------------

def build_fill_data(findings, gateway_key=None):
    """
    Each finding -> that control FAILS.
    Controls with no findings -> pass: null (manual review required).
    LLM mapping (when gateway_key provided) overrides heuristic on high-confidence hits.
    """
    # Static heuristic pass first
    heuristic_map = {}
    for idx, f in enumerate(findings):
        cid, note = map_finding(f)
        heuristic_map[idx] = (cid, note)

    # LLM override pass — only upgrade mappings with confidence >= 0.75
    llm_map = _llm_map_findings(findings, gateway_key) if gateway_key else {}
    if llm_map:
        print(f"[sic_to_audit] LLM mapped {len(llm_map)} finding(s)", file=sys.stderr)

    fail_map = {}
    for idx, f in enumerate(findings):
        h_cid, h_note = heuristic_map[idx]
        if idx in llm_map:
            l_cid, conf = llm_map[idx]
            cid = l_cid if conf >= 0.75 else h_cid
        else:
            cid = h_cid
        note = h_note
        fail_map.setdefault(cid, []).append(note)

    fill = {}
    for cid in ALL_IDS:
        if cid in fail_map:
            notes = fail_map[cid]
            seen, deduped = set(), []
            for n in notes:
                if n not in seen:
                    seen.add(n)
                    deduped.append(n)
            combined = "; ".join(deduped[:3])
            if len(deduped) > 3:
                combined += f" (+{len(deduped) - 3} more)"
            fill[cid] = {"pass": False, "notes": combined}
        else:
            fill[cid] = {"pass": None, "notes": "Not tested -- manual review required"}

    return fill


# ---------------------------------------------------------------------------
# HTML injection
# ---------------------------------------------------------------------------

# The template's HTML comment (line ~10) has a fill example with single quotes.
# The QA regex finds the FIRST window.AUDIT.fill( in the file, so we replace
# the comment example with the real compact JSON — making it QA-regex-first
# and valid JSON. We also inject the executable call after render().
_COMMENT_FILL_STUB = (
    "window.AUDIT.fill({ 'sp-01': { pass: true, notes: '...', ref: 'CVE-...' }, ... })"
)


def inject_fill(html, fill_data, project):
    """
    Two-pass injection:
    1. Replace the HTML comment's fill example stub with the real compact JSON
       (makes it the FIRST occurrence in the file → QA regex parses it first).
    2. Insert an executable window.AUDIT.fill() call in the main script body
       after render() so the report actually reflects the scan results.
    """
    # Compact one-liner — no indent so it fits the comment line neatly
    fill_compact = json.dumps(fill_data, separators=(",", ":"))
    safe_project = project.replace("\\", "\\\\").replace('"', '\\"')
    fill_call = f"window.AUDIT.fill({fill_compact})"

    # Pass 1: replace comment stub (if still present in template)
    html = html.replace(_COMMENT_FILL_STUB, fill_call, 1)

    # Pass 2: inject executable call after render()
    exec_inject = (
        f'\n/* sic_to_audit.py auto-fill: {safe_project} */\n'
        f'{fill_call};\n'
    )
    target = "render();\n</script>"
    if target in html:
        return html.replace(target, "render();" + exec_inject + "</script>", 1)

    # Fallback: separate script block
    block = f"<script>\n{exec_inject}</script>\n"
    if "</body>" in html:
        return html.replace("</body>", block + "</body>", 1)
    return html + block


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Map SIC scan output to 3SIXTYCO. audit HTML report"
    )
    parser.add_argument("--results",  required=True,
                        help="SIC scan JSON file (from sic/_runs/)")
    parser.add_argument("--template", required=True,
                        help="3SIXTYCO. audit HTML template path")
    parser.add_argument("--project",  required=True,
                        help="Project display name")
    parser.add_argument("--output",   required=True,
                        help="Output HTML file path")
    args = parser.parse_args()

    gateway_key = os.environ.get("LLM_GATEWAY_KEY")
    if gateway_key:
        print("[sic_to_audit] LLM_GATEWAY_KEY found — LLM mapping enabled")
    else:
        print("[sic_to_audit] LLM_GATEWAY_KEY not set — using heuristic mapping only")

    print(f"[sic_to_audit] Loading {args.results}")
    findings = load_findings(args.results)
    print(f"[sic_to_audit] {len(findings)} findings parsed")

    fill_data = build_fill_data(findings, gateway_key=gateway_key)
    failed = sum(1 for v in fill_data.values() if v["pass"] is False)
    manual = sum(1 for v in fill_data.values() if v["pass"] is None)
    passed = sum(1 for v in fill_data.values() if v["pass"] is True)
    print(f"[sic_to_audit] FAIL={failed}  PASS={passed}  MANUAL={manual}  TOTAL=42")

    html = Path(args.template).read_text(encoding="utf-8", errors="replace")
    out  = inject_fill(html, fill_data, args.project)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(out, encoding="utf-8")
    print(f"[sic_to_audit] Written -> {args.output}")
    print(f"[sic_to_audit] Summary: PASS={passed} FAIL={failed} MANUAL={manual}")


if __name__ == "__main__":
    main()
