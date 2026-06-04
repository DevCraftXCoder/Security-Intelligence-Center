#!/usr/bin/env python3
"""
cwe_owasp.py  --  CWE -> OWASP Top 10 2021 lookup + finding enrichment.

Maps common CWE IDs to their OWASP Top 10 2021 category, enriches SIC
findings with an owasp_category field, and builds the attackMapping[]
array consumed by the SOC handoff report template.

stdlib only, no external dependencies.
"""

from __future__ import annotations

import re
import sys

# OWASP Top 10 2021 category constants.
A01 = "A01:2021 Broken Access Control"
A02 = "A02:2021 Cryptographic Failures"
A03 = "A03:2021 Injection"
A04 = "A04:2021 Insecure Design"
A05 = "A05:2021 Security Misconfiguration"
A06 = "A06:2021 Vulnerable and Outdated Components"
A07 = "A07:2021 Identification and Authentication Failures"
A08 = "A08:2021 Software and Data Integrity Failures"
A09 = "A09:2021 Security Logging and Monitoring Failures"
A10 = "A10:2021 Server-Side Request Forgery"

CWE_TO_OWASP: dict[str, str] = {
    # A01 Broken Access Control
    "CWE-22":   A01,  # Path Traversal
    "CWE-200":  A01,  # Exposure of Sensitive Information
    "CWE-284":  A01,  # Improper Access Control
    "CWE-285":  A01,  # Improper Authorization
    "CWE-352":  A01,  # CSRF
    "CWE-601":  A01,  # Open Redirect
    "CWE-639":  A01,  # Authorization Bypass (IDOR)
    "CWE-863":  A01,  # Incorrect Authorization
    # A02 Cryptographic Failures
    "CWE-311":  A02,  # Missing Encryption of Sensitive Data
    "CWE-326":  A02,  # Inadequate Encryption Strength
    "CWE-327":  A02,  # Use of a Broken/Risky Crypto Algorithm
    "CWE-330":  A02,  # Use of Insufficiently Random Values
    # A03 Injection
    "CWE-79":   A03,  # Cross-site Scripting (XSS)
    "CWE-89":   A03,  # SQL Injection
    "CWE-78":   A03,  # OS Command Injection
    "CWE-94":   A03,  # Code Injection
    # A04 Insecure Design
    "CWE-602":  A04,  # Client-Side Enforcement of Server-Side Security
    # A05 Security Misconfiguration
    "CWE-611":  A05,  # XML External Entity (XXE)
    "CWE-1021": A05,  # Improper Restriction of Rendered UI Layers (clickjacking)
    # A06 Vulnerable and Outdated Components
    # (component CVEs map here; no canonical single CWE)
    # A07 Identification and Authentication Failures
    "CWE-287":  A07,  # Improper Authentication
    "CWE-306":  A07,  # Missing Authentication for Critical Function
    # A08 Software and Data Integrity Failures
    "CWE-502":  A08,  # Deserialization of Untrusted Data
    "CWE-434":  A08,  # Unrestricted Upload of Dangerous File Type
    # A09 Security Logging and Monitoring Failures
    "CWE-532":  A09,  # Insertion of Sensitive Info into Log File
    # A10 Server-Side Request Forgery
    "CWE-918":  A10,  # SSRF
    # Cross-cutting / resource handling
    "CWE-20":   A03,  # Improper Input Validation (commonly injection root)
    "CWE-400":  A04,  # Uncontrolled Resource Consumption (design)
}

_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def _normalize_cwe(value: str | None) -> str | None:
    """Normalize any CWE-ish string to canonical 'CWE-NNN' form."""
    if not value:
        return None
    match = _CWE_RE.search(str(value))
    if not match:
        return None
    return f"CWE-{int(match.group(1))}"


def get_owasp_category(cwe_id: str) -> str | None:
    """Return the OWASP Top 10 2021 category for a CWE, or None if unmapped."""
    normalized = _normalize_cwe(cwe_id)
    if normalized is None:
        return None
    return CWE_TO_OWASP.get(normalized)


def _extract_cwe(finding: dict) -> str | None:
    """Pull a CWE id from a finding's enrichment or its name/title fields."""
    enrichment = finding.get("enrichment")
    if isinstance(enrichment, dict):
        cwe = _normalize_cwe(enrichment.get("cwe"))
        if cwe:
            return cwe
    for key in ("name", "vulnerabilityName", "Title", "template-id", "checkID"):
        cwe = _normalize_cwe(finding.get(key))
        if cwe:
            return cwe
    return None


def enrich_with_owasp(findings: list[dict]) -> list[dict]:
    """Add owasp_category to each finding's enrichment dict (in place).

    Returns the same list for chaining.
    """
    if not isinstance(findings, list):
        print(
            f"[cwe_owasp] findings is not a list "
            f"({type(findings).__name__}); returning empty list",
            file=sys.stderr,
        )
        return []

    for finding in findings:
        if not isinstance(finding, dict):
            print(
                f"[cwe_owasp] skipping non-dict finding "
                f"({type(finding).__name__})",
                file=sys.stderr,
            )
            continue
        enrichment = finding.get("enrichment")
        if not isinstance(enrichment, dict):
            enrichment = {}
            finding["enrichment"] = enrichment
        cwe = _extract_cwe(finding)
        enrichment["owasp_category"] = get_owasp_category(cwe) if cwe else None

    return findings


def build_attack_mapping(findings: list[dict]) -> list[dict]:
    """Build the attackMapping[] array for the SOC report template.

    Groups findings by OWASP category. Each entry lists the distinct CWE
    ids that mapped into it. Sorted by count descending, then category.
    """
    if not isinstance(findings, list):
        print(
            f"[cwe_owasp] findings is not a list "
            f"({type(findings).__name__}); returning empty mapping",
            file=sys.stderr,
        )
        return []

    grouped: dict[str, dict] = {}

    for finding in findings:
        if not isinstance(finding, dict):
            print(
                f"[cwe_owasp] skipping non-dict finding "
                f"({type(finding).__name__})",
                file=sys.stderr,
            )
            continue

        cwe = _extract_cwe(finding)
        category = get_owasp_category(cwe) if cwe else None
        if category is None:
            continue

        entry = grouped.setdefault(
            category, {"category": category, "count": 0, "_cwes": []}
        )
        entry["count"] += 1
        if cwe and cwe not in entry["_cwes"]:
            entry["_cwes"].append(cwe)

    result = []
    for entry in grouped.values():
        result.append(
            {
                "category": entry["category"],
                "count": entry["count"],
                "findings": entry["_cwes"],
            }
        )

    result.sort(key=lambda e: (-e["count"], e["category"]))
    return result
