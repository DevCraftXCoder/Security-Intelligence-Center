#!/usr/bin/env python3
"""
cwe_owasp.py  --  CWE -> OWASP Top 10 2025 lookup + finding enrichment.

Maps CWE IDs to their OWASP Top 10:2025 category (official release, sourced
from owasp.org/Top10/2025/). Enriches SIC findings with an owasp_category
field and builds the attackMapping[] array for the SOC handoff report template.

OWASP Top 10:2025 categories (significant changes from 2021):
  A01 Broken Access Control       — unchanged, SSRF + CSRF now mapped here
  A02 Security Misconfiguration   — moved up from A05:2021
  A03 Software Supply Chain Fail. — NEW; was "Vulnerable Components" A06:2021
  A04 Cryptographic Failures      — was A02:2021
  A05 Injection                   — dropped from A03:2021
  A06 Insecure Design             — was A04:2021
  A07 Authentication Failures     — was A07:2021 (name shortened)
  A08 Software/Data Integrity     — was A08:2021
  A09 Logging and Alerting Fail.  — was A09:2021 ("Monitoring" → "Alerting")
  A10 Mishandling Exceptional Cond — NEW; replaced SSRF A10:2021

stdlib only, no external dependencies.
"""

from __future__ import annotations

import re
import sys

# ---------------------------------------------------------------------------
# OWASP Top 10:2025 category constants
# ---------------------------------------------------------------------------

A01 = "A01:2025 Broken Access Control"
A02 = "A02:2025 Security Misconfiguration"
A03 = "A03:2025 Software Supply Chain Failures"
A04 = "A04:2025 Cryptographic Failures"
A05 = "A05:2025 Injection"
A06 = "A06:2025 Insecure Design"
A07 = "A07:2025 Authentication Failures"
A08 = "A08:2025 Software and Data Integrity Failures"
A09 = "A09:2025 Security Logging and Alerting Failures"
A10 = "A10:2025 Mishandling of Exceptional Conditions"

# ---------------------------------------------------------------------------
# CWE → OWASP Top 10:2025 mapping
# Source: https://owasp.org/Top10/2025/ (each category's "List of Mapped CWEs")
# ---------------------------------------------------------------------------

CWE_TO_OWASP: dict[str, str] = {

    # ---- A01:2025  Broken Access Control -----------------------------------
    "CWE-22":   A01,   # Path Traversal
    "CWE-23":   A01,   # Relative Path Traversal
    "CWE-36":   A01,   # Absolute Path Traversal
    "CWE-59":   A01,   # Improper Link Resolution Before File Access
    "CWE-200":  A01,   # Exposure of Sensitive Information to Unauthorized Actor
    "CWE-201":  A01,   # Exposure of Sensitive Information Through Sent Data
    "CWE-219":  A01,   # Storage of File with Sensitive Data Under Web Root
    "CWE-276":  A01,   # Incorrect Default Permissions
    "CWE-284":  A01,   # Improper Access Control
    "CWE-285":  A01,   # Improper Authorization
    "CWE-352":  A01,   # Cross-Site Request Forgery (CSRF)
    "CWE-359":  A01,   # Exposure of Private Personal Info to Unauthorized Actor
    "CWE-377":  A01,   # Insecure Temporary File
    "CWE-402":  A01,   # Transmission of Private Resources into a New Sphere
    "CWE-425":  A01,   # Direct Request ('Forced Browsing')
    "CWE-441":  A01,   # Unintended Proxy or Intermediary
    "CWE-497":  A01,   # Exposure of Sensitive System Information
    "CWE-538":  A01,   # Insertion of Sensitive Information into Externally-Accessible File
    "CWE-540":  A01,   # Inclusion of Sensitive Information in Source Code
    "CWE-548":  A01,   # Exposure of Information Through Directory Listing
    "CWE-552":  A01,   # Files or Directories Accessible to External Parties
    "CWE-566":  A01,   # Authorization Bypass Through User-Controlled SQL Primary Key
    "CWE-601":  A01,   # Open Redirect
    "CWE-639":  A01,   # Authorization Bypass Through User-Controlled Key (IDOR)
    "CWE-651":  A01,   # Exposure of WSDL File Containing Sensitive Information
    "CWE-668":  A01,   # Exposure of Resource to Wrong Sphere
    "CWE-706":  A01,   # Use of Incorrectly-Resolved Name or Reference
    "CWE-862":  A01,   # Missing Authorization
    "CWE-863":  A01,   # Incorrect Authorization
    "CWE-913":  A01,   # Improper Control of Dynamically-Managed Code Resources
    "CWE-918":  A01,   # Server-Side Request Forgery (SSRF) — moved from A10:2021
    "CWE-1275": A01,   # Sensitive Cookie with Improper SameSite Attribute

    # ---- A02:2025  Security Misconfiguration --------------------------------
    "CWE-5":    A02,   # J2EE Misconfiguration: Data Transmission Without Encryption
    "CWE-11":   A02,   # ASP.NET Misconfiguration: Creating Debug Binary
    "CWE-13":   A02,   # ASP.NET Misconfiguration: Password in Configuration File
    "CWE-15":   A02,   # External Control of System or Configuration Setting
    "CWE-16":   A02,   # Configuration
    "CWE-260":  A02,   # Password in Configuration File
    "CWE-315":  A02,   # Cleartext Storage of Sensitive Information in a Cookie
    "CWE-489":  A02,   # Active Debug Code
    "CWE-526":  A02,   # Exposure of Sensitive Information Through Environmental Variables
    "CWE-547":  A02,   # Use of Hard-coded Security-relevant Constants
    "CWE-611":  A02,   # XML External Entity (XXE) — moved from A05:2021
    "CWE-614":  A02,   # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
    "CWE-756":  A02,   # Missing Custom Error Page
    "CWE-776":  A02,   # Improper Restriction of Recursive Entity References in DTDs
    "CWE-942":  A02,   # Permissive Cross-domain Policy with Untrusted Domains
    "CWE-1021": A02,   # Improper Restriction of Rendered UI Layers (Clickjacking)
    "CWE-1173": A02,   # Improper Use of Validation Framework

    # ---- A03:2025  Software Supply Chain Failures ---------------------------
    # NEW category — previously "Vulnerable and Outdated Components" (A06:2021)
    "CWE-447":  A03,   # Use of Obsolete Function
    "CWE-1035": A03,   # Using Components with Known Vulnerabilities
    "CWE-1104": A03,   # Use of Unmaintained Third Party Components
    "CWE-1329": A03,   # Reliance on Component That is Not Updateable
    "CWE-1357": A03,   # Reliance on Insufficiently Trustworthy Component
    "CWE-1395": A03,   # Dependency on Vulnerable Third-Party Component

    # ---- A04:2025  Cryptographic Failures -----------------------------------
    "CWE-261":  A04,   # Weak Encoding for Password
    "CWE-296":  A04,   # Improper Following of a Certificate's Chain of Trust
    "CWE-319":  A04,   # Cleartext Transmission of Sensitive Information
    "CWE-320":  A04,   # Key Management Errors
    "CWE-321":  A04,   # Use of Hard-coded Cryptographic Key
    "CWE-322":  A04,   # Key Exchange without Entity Authentication
    "CWE-323":  A04,   # Reusing a Nonce, Key Pair in Encryption
    "CWE-324":  A04,   # Use of a Key Past its Expiration Date
    "CWE-325":  A04,   # Missing Required Cryptographic Step
    "CWE-326":  A04,   # Inadequate Encryption Strength
    "CWE-327":  A04,   # Use of a Broken or Risky Cryptographic Algorithm
    "CWE-328":  A04,   # Use of Weak Hash
    "CWE-329":  A04,   # Generation of Predictable IV with CBC Mode
    "CWE-330":  A04,   # Use of Insufficiently Random Values
    "CWE-331":  A04,   # Insufficient Entropy
    "CWE-335":  A04,   # Incorrect Usage of Seeds in Pseudo-Random Number Generator
    "CWE-336":  A04,   # Same Seed in Pseudo-Random Number Generator
    "CWE-337":  A04,   # Predictable Seed in Pseudo-Random Number Generator
    "CWE-338":  A04,   # Use of Cryptographically Weak PRNG
    "CWE-340":  A04,   # Generation of Predictable Numbers or Identifiers
    "CWE-347":  A04,   # Improper Verification of Cryptographic Signature
    "CWE-523":  A04,   # Unprotected Transport of Credentials
    "CWE-720":  A04,   # OWASP Top Ten 2007 A7 - Broken Authentication and Session Management
    "CWE-757":  A04,   # Selection of Less-Secure Algorithm During Negotiation
    "CWE-759":  A04,   # Use of a One-Way Hash without a Salt
    "CWE-760":  A04,   # Use of a One-Way Hash with a Predictable Salt
    "CWE-780":  A04,   # Use of RSA Algorithm without OAEP
    "CWE-818":  A04,   # Insufficient Transport Layer Protection
    "CWE-916":  A04,   # Use of Password Hash With Insufficient Computational Effort

    # ---- A05:2025  Injection ------------------------------------------------
    "CWE-20":   A05,   # Improper Input Validation (injection root cause)
    "CWE-74":   A05,   # Improper Neutralization of Special Elements in Output
    "CWE-77":   A05,   # Command Injection
    "CWE-78":   A05,   # OS Command Injection
    "CWE-79":   A05,   # Cross-site Scripting (XSS)
    "CWE-80":   A05,   # Basic XSS
    "CWE-83":   A05,   # XSS in Attributes
    "CWE-87":   A05,   # Failure to Sanitize Alternate XSS Syntax
    "CWE-88":   A05,   # Argument Injection
    "CWE-89":   A05,   # SQL Injection
    "CWE-90":   A05,   # LDAP Injection
    "CWE-91":   A05,   # XML Injection
    "CWE-93":   A05,   # CRLF Injection
    "CWE-94":   A05,   # Code Injection
    "CWE-95":   A05,   # Eval Injection
    "CWE-96":   A05,   # Static Code Injection
    "CWE-97":   A05,   # Server-Side Includes (SSI) Injection
    "CWE-98":   A05,   # PHP File Inclusion
    "CWE-99":   A05,   # Resource Injection
    "CWE-100":  A05,   # Technology-Specific Input Validation Problems
    "CWE-113":  A05,   # Header Injection
    "CWE-116":  A05,   # Improper Encoding or Escaping of Output
    "CWE-138":  A05,   # Improper Neutralization of Special Elements
    "CWE-184":  A05,   # Incomplete List of Disallowed Inputs (bypass)
    "CWE-470":  A05,   # Use of Externally-Controlled Input to Select Classes
    "CWE-564":  A05,   # SQL Injection: Hibernate
    "CWE-643":  A05,   # XPath Injection
    "CWE-644":  A05,   # Improper Neutralization of HTTP Headers for Scripting Syntax
    "CWE-652":  A05,   # Improper Neutralization of Data within XQuery Expressions
    "CWE-917":  A05,   # Expression Language Injection

    # ---- A06:2025  Insecure Design ------------------------------------------
    "CWE-73":   A06,   # External Control of File Name or Path
    "CWE-183":  A06,   # Permissive List of Allowed Inputs
    "CWE-256":  A06,   # Unprotected Storage of Credentials
    "CWE-266":  A06,   # Incorrect Privilege Assignment
    "CWE-269":  A06,   # Improper Privilege Management
    "CWE-286":  A06,   # Incorrect User Management
    "CWE-311":  A06,   # Missing Encryption of Sensitive Data
    "CWE-312":  A06,   # Cleartext Storage of Sensitive Information
    "CWE-313":  A06,   # Cleartext Storage in a File or on Disk
    "CWE-316":  A06,   # Cleartext Storage of Sensitive Information in Memory
    "CWE-419":  A06,   # Unprotected Primary Channel
    "CWE-430":  A06,   # Deployment of Wrong Handler
    "CWE-434":  A06,   # Unrestricted Upload of Dangerous File Type (moved from A08:2021)
    "CWE-444":  A06,   # Inconsistent Interpretation of HTTP Requests
    "CWE-451":  A06,   # User Interface (UI) Misrepresentation of Critical Information
    "CWE-472":  A06,   # External Control of Assumed-Immutable Web Parameter
    "CWE-501":  A06,   # Trust Boundary Violation
    "CWE-522":  A06,   # Insufficiently Protected Credentials
    "CWE-525":  A06,   # Use of Web Browser Cache Containing Sensitive Information
    "CWE-539":  A06,   # Use of Persistent Cookies Containing Sensitive Information
    "CWE-579":  A06,   # J2EE Bad Practices: Non-serializable Object Stored in Session
    "CWE-598":  A06,   # Sensitive Information in Query String
    "CWE-602":  A06,   # Client-Side Enforcement of Server-Side Security
    "CWE-642":  A06,   # External Control of Critical State Data
    "CWE-646":  A06,   # Reliance on File Name or Extension of Externally-Supplied File
    "CWE-650":  A06,   # Trusting HTTP Permission Methods on the Server Side
    "CWE-653":  A06,   # Insufficient Compartmentalization
    "CWE-656":  A06,   # Reliance on Security Through Obscurity
    "CWE-657":  A06,   # Violation of Secure Design Principles
    "CWE-799":  A06,   # Improper Control of Interaction Frequency
    "CWE-807":  A06,   # Reliance on Untrusted Inputs in a Security Decision
    "CWE-840":  A06,   # Business Logic Errors
    "CWE-841":  A06,   # Improper Enforcement of Behavioral Workflow
    "CWE-927":  A06,   # Use of Implicit Intent for Sensitive Communication
    "CWE-400":  A06,   # Uncontrolled Resource Consumption

    # ---- A07:2025  Authentication Failures ----------------------------------
    "CWE-258":  A07,   # Empty Password in Configuration File
    "CWE-259":  A07,   # Use of Hard-coded Password
    "CWE-287":  A07,   # Improper Authentication
    "CWE-288":  A07,   # Authentication Bypass Using an Alternate Path
    "CWE-290":  A07,   # Authentication Bypass by Spoofing
    "CWE-294":  A07,   # Authentication Bypass by Capture-replay
    "CWE-295":  A07,   # Improper Certificate Validation
    "CWE-297":  A07,   # Improper Validation of Certificate with Host Mismatch
    "CWE-300":  A07,   # Channel Accessible by Non-Endpoint
    "CWE-302":  A07,   # Authentication Bypass by Assumed-Immutable Data
    "CWE-304":  A07,   # Missing Critical Step in Authentication
    "CWE-306":  A07,   # Missing Authentication for Critical Function
    "CWE-307":  A07,   # Improper Restriction of Excessive Authentication Attempts
    "CWE-346":  A07,   # Origin Validation Error
    "CWE-384":  A07,   # Session Fixation
    "CWE-521":  A07,   # Weak Password Requirements
    "CWE-613":  A07,   # Insufficient Session Expiration
    "CWE-620":  A07,   # Unverified Password Change
    "CWE-640":  A07,   # Weak Password Recovery Mechanism for Forgotten Password
    "CWE-798":  A07,   # Use of Hard-coded Credentials

    # ---- A08:2025  Software and Data Integrity Failures ---------------------
    "CWE-345":  A08,   # Insufficient Verification of Data Authenticity
    "CWE-353":  A08,   # Missing Support for Integrity Check
    "CWE-426":  A08,   # Untrusted Search Path
    "CWE-427":  A08,   # Uncontrolled Search Path Element
    "CWE-494":  A08,   # Download of Code Without Integrity Check
    "CWE-502":  A08,   # Deserialization of Untrusted Data
    "CWE-506":  A08,   # Embedded Malicious Code
    "CWE-565":  A08,   # Reliance on Cookies without Validation and Integrity Checking
    "CWE-784":  A08,   # Reliance on Cookies without Validation in a Security Decision

    # ---- A09:2025  Security Logging and Alerting Failures -------------------
    "CWE-117":  A09,   # Improper Output Neutralization for Logs
    "CWE-221":  A09,   # Information Loss of Omission
    "CWE-223":  A09,   # Omission of Security-relevant Information
    "CWE-532":  A09,   # Insertion of Sensitive Information into Log File
    "CWE-778":  A09,   # Insufficient Logging

    # ---- A10:2025  Mishandling of Exceptional Conditions -------------------
    # NEW category — replaced SSRF (A10:2021)
    "CWE-209":  A10,   # Generation of Error Message Containing Sensitive Information
    "CWE-215":  A10,   # Insertion of Sensitive Information Into Debugging Code
    "CWE-248":  A10,   # Uncaught Exception
    "CWE-252":  A10,   # Unchecked Return Value
    "CWE-274":  A10,   # Improper Handling of Insufficient Privileges
    "CWE-390":  A10,   # Detection of Error Condition Without Action
    "CWE-391":  A10,   # Unchecked Error Condition
    "CWE-396":  A10,   # Declaration of Catch for Generic Exception
    "CWE-460":  A10,   # Improper Cleanup on Thrown Exception
    "CWE-476":  A10,   # NULL Pointer Dereference
    "CWE-636":  A10,   # Not Failing Securely ('Failing Open')
    "CWE-730":  A10,   # OWASP Top Ten 2004 Category A9 - Denial of Service (via exception)
    "CWE-1071": A10,   # Empty Exception Block
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
    """Return the OWASP Top 10:2025 category for a CWE, or None if unmapped."""
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

    Groups findings by OWASP Top 10:2025 category. Each entry lists the
    distinct CWE ids that mapped into it. Sorted by count descending.
    """
    if not isinstance(findings, list):
        return []

    grouped: dict[str, dict] = {}

    for finding in findings:
        if not isinstance(finding, dict):
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

    result = [
        {"category": e["category"], "count": e["count"], "findings": e["_cwes"]}
        for e in grouped.values()
    ]
    result.sort(key=lambda e: (-e["count"], e["category"]))
    return result


def owasp_categories() -> list[str]:
    """Return all OWASP Top 10:2025 categories in order."""
    return [A01, A02, A03, A04, A05, A06, A07, A08, A09, A10]
