"""
threat_catalog.py — Architecture-derived threat class catalog for SIC SOC pipeline.

Maps system component types to threat control section templates.
Each template carries CWE/OWASP/MITRE references and probe metadata
used by the refinement stage to match scanner findings.
"""
from __future__ import annotations

import re
from typing import Any

# 12 system component types → threat control templates.
# Keys in SYSTEM_COMPONENTS match detection signals in detect_system_profile().
# Each value is a list of control-section dicts; each dict has:
#   id, tag, title, priority, description, cwe, owasp, mitre, probes
# probes: list of strings that finding names/IDs are matched against (case-insensitive)

SYSTEM_COMPONENTS: dict[str, list[dict[str, Any]]] = {
    "cf-workers": [
        {
            "id": "net-cfworkers-env",
            "tag": "SECRET-LEAK",
            "title": "CF Worker Secret / Env-Var Exposure",
            "priority": "p1",
            "description": (
                "Worker env vars (SECRETS) may be logged, returned in responses, or "
                "accessible via Workers introspection APIs without proper sanitisation."
            ),
            "cwe": "CWE-312",
            "owasp": "A02:2021",
            "mitre": "T1552.001",
            "probes": ["secret", "env", "worker", "wrangler", "credential"],
            "covered_by": ["trivy", "gitleaks"],
        },
        {
            "id": "net-cfworkers-cors",
            "tag": "CORS-MISCFG",
            "title": "CF Worker CORS Misconfiguration",
            "priority": "p2",
            "description": (
                "Wildcard or overly-permissive Access-Control-Allow-Origin allows "
                "cross-origin reads of authenticated responses."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
            "mitre": "T1071",
            "probes": ["cors", "origin", "access-control"],
        },
        {
            "id": "net-cfworkers-cache",
            "tag": "CACHE-POISON",
            "title": "CF Worker Cache Poisoning via Unkeyed Headers",
            "priority": "p2",
            "description": (
                "Responses cached without keying on Auth/user context may serve "
                "one user's private data to another."
            ),
            "cwe": "CWE-601",
            "owasp": "A04:2021",
            "mitre": "T1565",
            "probes": ["cache", "cdn", "vary", "cache-control"],
        },
    ],
    "durable-objects": [
        {
            "id": "net-do-auth",
            "tag": "AUTH-BYPASS",
            "title": "Durable Object Unauthenticated Access",
            "priority": "p0",
            "description": (
                "DurableObject stubs accessed directly without re-validating the "
                "caller's JWT/ticket can be exploited to bypass auth checks."
            ),
            "cwe": "CWE-287",
            "owasp": "A01:2021",
            "mitre": "T1078",
            "probes": ["durable", "do ", "stub", "object", "websocket ticket"],
        },
        {
            "id": "net-do-state",
            "tag": "STATE-CORRUPTION",
            "title": "Durable Object Concurrent State Corruption",
            "priority": "p1",
            "description": (
                "Concurrent requests to the same DO without atomic transaction "
                "wrapping can produce race conditions corrupting shared state."
            ),
            "cwe": "CWE-362",
            "owasp": "A04:2021",
            "mitre": "T1499",
            "probes": ["durable", "race", "concurrent", "state", "atomic"],
        },
    ],
    "token-auth": [
        {
            "id": "net-token-lifecycle",
            "tag": "TOKEN-LIFECYCLE",
            "title": "JWT / Refresh-Token Lifecycle Vulnerabilities",
            "priority": "p0",
            "description": (
                "Short-lived access tokens not properly invalidated on logout; "
                "refresh tokens not rotated; HMAC secret weak or reused across envs."
            ),
            "cwe": "CWE-613",
            "owasp": "A07:2021",
            "mitre": "T1550.001",
            "probes": ["jwt", "token", "refresh", "hmac", "secret", "expir", "revok"],
        },
        {
            "id": "net-token-timing",
            "tag": "TIMING-ATTACK",
            "title": "Non-Timing-Safe Token / Secret Comparison",
            "priority": "p1",
            "description": (
                "String equality (===) used to compare secrets instead of "
                "crypto.timingSafeEqual / hmac comparison — enables timing oracle."
            ),
            "cwe": "CWE-208",
            "owasp": "A02:2021",
            "mitre": "T1110",
            "probes": ["timing", "safe", "comparison", "timingsafeequal", "hmac"],
        },
        {
            "id": "net-token-toctou",
            "tag": "TOCTOU",
            "title": "Token TOCTOU — Check-then-Use Race",
            "priority": "p1",
            "description": (
                "Token validity checked at request start but not re-validated before "
                "database writes; a revoked token can still complete state-changing ops."
            ),
            "cwe": "CWE-367",
            "owasp": "A01:2021",
            "mitre": "T1499.004",
            "probes": ["toctou", "race", "revoke", "revocation", "check-then-use"],
        },
    ],
    "object-storage": [
        {
            "id": "net-r2-idor",
            "tag": "IDOR",
            "title": "R2 / S3 Object Key IDOR — Unverified Ownership",
            "priority": "p0",
            "description": (
                "Client-supplied R2/S3 object keys accepted without verifying the "
                "key belongs to the authenticated user (IDOR via key namespace traversal)."
            ),
            "cwe": "CWE-639",
            "owasp": "A01:2021",
            "mitre": "T1530",
            "probes": ["r2", "s3", "object", "bucket", "key", "presign", "idor"],
        },
        {
            "id": "net-r2-presign",
            "tag": "PRESIGN-ABUSE",
            "title": "Pre-Signed URL Expiry / Scope Abuse",
            "priority": "p1",
            "description": (
                "Pre-signed upload URLs with no expiry or overly broad bucket-level "
                "scope allow attackers to overwrite arbitrary objects."
            ),
            "cwe": "CWE-732",
            "owasp": "A04:2021",
            "mitre": "T1530",
            "probes": ["presign", "presigned", "url", "expire", "scope"],
        },
    ],
    "sql": [
        {
            "id": "net-sql-injection",
            "tag": "SQLI",
            "title": "SQL Injection via String Interpolation",
            "priority": "p0",
            "description": (
                "User-controlled values interpolated into SQL strings instead of "
                "parameterized bind variables — allows full database read/write."
            ),
            "cwe": "CWE-89",
            "owasp": "A03:2021",
            "mitre": "T1190",
            "probes": ["sql", "injection", "sqli", "query", "interpolat", "bind"],
            "covered_by": ["nuclei", "trivy"],
        },
        {
            "id": "net-sql-audit",
            "tag": "AUDIT-LOG",
            "title": "Missing / Tamperable Audit Log Integrity",
            "priority": "p1",
            "description": (
                "Audit / error log tables writable by the same principal being logged; "
                "no append-only guarantee; log entries can be silently deleted."
            ),
            "cwe": "CWE-778",
            "owasp": "A09:2021",
            "mitre": "T1565.001",
            "probes": ["audit", "log", "integrity", "append", "tamper", "delete"],
        },
    ],
    "docker": [
        {
            "id": "net-docker-root",
            "tag": "PRIV-ESC",
            "title": "Container Running as Root User",
            "priority": "p0",
            "description": (
                "Container process runs as UID 0; host escape via mounted volumes "
                "or kernel exploits grants full host access."
            ),
            "cwe": "CWE-250",
            "owasp": "A05:2021",
            "mitre": "T1611",
            "probes": ["root", "user", "privilege", "uid", "container", "docker"],
            "covered_by": ["checkov", "trivy"],
        },
        {
            "id": "net-docker-secrets",
            "tag": "SECRET-IN-IMAGE",
            "title": "Secrets Baked into Docker Image Layers",
            "priority": "p0",
            "description": (
                "ENV / ARG instructions with secret values baked into intermediate "
                "image layers — readable via docker history even if removed later."
            ),
            "cwe": "CWE-312",
            "owasp": "A02:2021",
            "mitre": "T1552.001",
            "probes": ["env", "arg", "secret", "layer", "image", "dockerfile", "history"],
            "covered_by": ["checkov", "trivy"],
        },
        {
            "id": "net-docker-network",
            "tag": "NETWORK-EXPOSURE",
            "title": "Container Ports Bound to 0.0.0.0",
            "priority": "p1",
            "description": (
                "Ports exposed without binding to 127.0.0.1 are reachable on all "
                "interfaces, bypassing firewall rules."
            ),
            "cwe": "CWE-284",
            "owasp": "A05:2021",
            "mitre": "T1049",
            "probes": ["port", "expose", "bind", "0.0.0.0", "network", "interface"],
        },
    ],
    "oauth": [
        {
            "id": "net-oauth-state",
            "tag": "CSRF-OAUTH",
            "title": "OAuth State Parameter Missing / Weak",
            "priority": "p1",
            "description": (
                "OAuth2 authorization requests without a cryptographically random "
                "state parameter are vulnerable to CSRF account-linking attacks."
            ),
            "cwe": "CWE-352",
            "owasp": "A01:2021",
            "mitre": "T1078.004",
            "probes": ["oauth", "state", "csrf", "authorization_code", "callback"],
        },
        {
            "id": "net-oauth-openredirect",
            "tag": "OPEN-REDIRECT",
            "title": "OAuth Redirect URI Open Redirect",
            "priority": "p1",
            "description": (
                "Redirect URI validation accepts wildcards or path-prefix matching "
                "allowing attackers to exfiltrate authorization codes."
            ),
            "cwe": "CWE-601",
            "owasp": "A01:2021",
            "mitre": "T1190",
            "probes": ["redirect", "uri", "callback", "open redirect", "oauth"],
        },
    ],
    "stripe": [
        {
            "id": "net-stripe-webhook",
            "tag": "WEBHOOK-BYPASS",
            "title": "Stripe Webhook Signature Skipped",
            "priority": "p0",
            "description": (
                "Webhook handler processes events without verifying "
                "stripe.webhooks.constructEvent() signature — allows forged events."
            ),
            "cwe": "CWE-347",
            "owasp": "A02:2021",
            "mitre": "T1190",
            "probes": ["webhook", "stripe", "signature", "constructevent", "verify"],
        },
        {
            "id": "net-stripe-tier",
            "tag": "TIER-BYPASS",
            "title": "Subscription Tier Server-Trust Mismatch",
            "priority": "p1",
            "description": (
                "Client-controlled tier header accepted without re-verifying against "
                "Stripe subscription state — allows tier escalation."
            ),
            "cwe": "CWE-285",
            "owasp": "A01:2021",
            "mitre": "T1078",
            "probes": ["tier", "subscription", "stripe", "header", "escalat"],
        },
    ],
    "websocket": [
        {
            "id": "net-ws-origin",
            "tag": "WS-ORIGIN",
            "title": "WebSocket Missing Origin Validation",
            "priority": "p1",
            "description": (
                "WebSocket upgrade accepts connections from any origin — browsers "
                "send cookies/credentials, enabling cross-site WebSocket hijacking."
            ),
            "cwe": "CWE-346",
            "owasp": "A07:2021",
            "mitre": "T1071.001",
            "probes": ["websocket", "origin", "upgrade", "ws", "wss"],
        },
        {
            "id": "net-ws-auth",
            "tag": "WS-AUTH",
            "title": "WebSocket Auth Token in Query String",
            "priority": "p1",
            "description": (
                "JWT / auth tokens passed in WebSocket URL query params are logged "
                "by servers and proxies — use one-time tickets in D1 instead."
            ),
            "cwe": "CWE-598",
            "owasp": "A07:2021",
            "mitre": "T1552",
            "probes": ["websocket", "token", "query", "url", "ticket", "param"],
        },
    ],
    "edge-runtime": [
        {
            "id": "net-edge-nodeapis",
            "tag": "RUNTIME-BREAK",
            "title": "Node.js APIs Used in Edge Runtime",
            "priority": "p1",
            "description": (
                "crypto / fs / Buffer Node.js APIs imported in CF Workers — "
                "breaks silently or at deploy time; use Web Crypto / fetch instead."
            ),
            "cwe": "CWE-477",
            "owasp": "A06:2021",
            "mitre": "T1195",
            "probes": ["import crypto", "require crypto", "node:", "fs ", "buffer", "edge"],
        },
        {
            "id": "net-edge-response-size",
            "tag": "RESPONSE-OVERFLOW",
            "title": "CF Workers 1 MB Response Limit Bypass",
            "priority": "p2",
            "description": (
                "Unstreamed large responses (e.g. audio, bulk exports) truncated "
                "silently by the Workers runtime — should stream or redirect to R2."
            ),
            "cwe": "CWE-400",
            "owasp": "A04:2021",
            "mitre": "T1499",
            "probes": ["response", "size", "limit", "stream", "1mb", "worker"],
        },
    ],
    "secrets-store": [
        {
            "id": "net-secrets-hardcoded",
            "tag": "HARDCODED-SECRET",
            "title": "Hardcoded API Keys / Secrets in Source",
            "priority": "p0",
            "description": (
                "API keys, tokens, or passwords committed to the repository in "
                "source files, config files, or env.example."
            ),
            "cwe": "CWE-798",
            "owasp": "A02:2021",
            "mitre": "T1552.001",
            "probes": ["hardcoded", "secret", "api_key", "password", "token", "commit"],
            "covered_by": ["trivy", "gitleaks"],
        },
        {
            "id": "net-secrets-rotation",
            "tag": "STALE-SECRET",
            "title": "No Secret Rotation Policy / Evidence",
            "priority": "p2",
            "description": (
                "Long-lived secrets with no documented rotation schedule; "
                "credentials leaked in a breach remain valid indefinitely."
            ),
            "cwe": "CWE-321",
            "owasp": "A02:2021",
            "mitre": "T1552",
            "probes": ["rotation", "rotate", "stale", "expire", "secret", "policy"],
        },
    ],
    "public-web": [
        {
            "id": "net-web-xss",
            "tag": "XSS",
            "title": "Cross-Site Scripting via Unsanitised User Content",
            "priority": "p0",
            "description": (
                "User-controlled strings rendered without sanitisation into HTML "
                "context — enables session hijacking and data exfiltration."
            ),
            "cwe": "CWE-79",
            "owasp": "A03:2021",
            "mitre": "T1059.007",
            "probes": [
                "xss",
                "cross-site",
                "script",
                "sanitize",
                "innerhtml",
                "dangerouslysetinnerhtml",
            ],
        },
        {
            "id": "net-web-csp",
            "tag": "CSP-MISSING",
            "title": "Missing or Weak Content-Security-Policy Header",
            "priority": "p1",
            "description": (
                "No CSP header or unsafe-inline/unsafe-eval directives allow "
                "XSS payloads to load external scripts and exfiltrate data."
            ),
            "cwe": "CWE-693",
            "owasp": "A05:2021",
            "mitre": "T1059.007",
            "probes": ["csp", "content-security-policy", "unsafe-inline", "unsafe-eval"],
        },
        {
            "id": "net-web-ratelimit",
            "tag": "NO-RATELIMIT",
            "title": "Missing Rate Limiting on Auth / Write Endpoints",
            "priority": "p1",
            "description": (
                "Auth and creation endpoints lack per-IP or per-user rate limiting "
                "— enables credential stuffing, brute force, and spam."
            ),
            "cwe": "CWE-307",
            "owasp": "A04:2021",
            "mitre": "T1110",
            "probes": ["rate", "limit", "throttle", "brute", "auth", "login"],
        },
    ],
    "app-server": [
        {
            "id": "net-appserver-authmw",
            "tag": "MISSING-AUTHZ",
            "title": "Missing Auth Middleware on Protected Routes",
            "priority": "p0",
            "description": (
                "Application routes that mutate or expose user data without an "
                "authentication / authorization middleware gate — anonymous "
                "callers reach privileged handlers."
            ),
            "cwe": "CWE-306",
            "owasp": "A01:2021",
            "mitre": "T1190",
            "probes": [
                "auth middleware",
                "authentication",
                "authorization",
                "missing auth",
                "unauthenticated",
                "access control",
            ],
            "covered_by": ["nuclei"],
        },
        {
            "id": "net-appserver-injection",
            "tag": "INPUT-INJECTION",
            "title": "Unvalidated Input / Injection",
            "priority": "p0",
            "description": (
                "Request parameters, bodies, or headers consumed without "
                "schema validation — feeds injection (SQLi/command/template) "
                "and logic-abuse vectors."
            ),
            "cwe": "CWE-20",
            "owasp": "A03:2021",
            "mitre": "T1190",
            "probes": [
                "injection",
                "unvalidated",
                "input validation",
                "sqli",
                "command injection",
                "deserialization",
            ],
            "covered_by": ["nuclei", "trivy"],
        },
        {
            "id": "net-appserver-errorleak",
            "tag": "ERROR-LEAK",
            "title": "Verbose Error / Stack-Trace Leakage",
            "priority": "p1",
            "description": (
                "Internal exceptions, stack traces, or DB error strings returned "
                "to API consumers — leaks implementation detail and aids attackers."
            ),
            "cwe": "CWE-209",
            "owasp": "A05:2021",
            "mitre": "T1592",
            "probes": [
                "stack trace",
                "stacktrace",
                "error leak",
                "verbose error",
                "exception",
                "information disclosure",
            ],
            "covered_by": ["nuclei"],
        },
        {
            "id": "net-appserver-ratelimit",
            "tag": "NO-RATELIMIT",
            "title": "Missing Rate Limiting on API Endpoints",
            "priority": "p1",
            "description": (
                "API endpoints lack per-IP / per-user rate limiting — enables "
                "brute force, scraping, and resource-exhaustion abuse (OWASP API4)."
            ),
            "cwe": "CWE-770",
            "owasp": "API4:2023",
            "mitre": "T1499",
            "probes": [
                "rate limit",
                "rate limiting",
                "throttle",
                "brute force",
                "resource exhaustion",
            ],
        },
    ],
    "llm-api": [
        {
            "id": "llm-prompt-injection",
            "tag": "PROMPT-INJECTION",
            "title": "Prompt Injection — Direct and Indirect",
            "priority": "p0",
            "description": (
                "Attacker-controlled text injected into a prompt overrides the system "
                "instruction, bypasses guardrails, or causes the model to execute "
                "unintended actions. Direct: user input in the prompt. Indirect: "
                "content retrieved from external sources (RAG, tool output, web fetch)."
            ),
            "cwe": "CWE-77",
            "owasp": "LLM01:2025",
            "mitre": "T1059",
            "probes": [
                "prompt injection", "jailbreak", "ignore previous instructions",
                "system prompt override", "instruction leak", "role confusion",
                "indirect injection", "rag injection",
            ],
            "covered_by": ["llm-probe"],
        },
        {
            "id": "llm-output-handling",
            "tag": "INSECURE-OUTPUT",
            "title": "Insecure Output Handling — XSS / SQLi via Model Response",
            "priority": "p0",
            "description": (
                "LLM output rendered directly in HTML, passed to SQL queries, or "
                "executed as shell commands without sanitisation. An attacker who "
                "controls the model input can craft output that exploits downstream "
                "sinks (stored XSS, second-order SQLi, command injection)."
            ),
            "cwe": "CWE-116",
            "owasp": "LLM02:2025",
            "mitre": "T1059.007",
            "probes": [
                "output handling", "unsanitized output", "llm xss",
                "model response injection", "downstream sink",
            ],
            "covered_by": ["llm-probe"],
        },
        {
            "id": "llm-model-dos",
            "tag": "MODEL-DOS",
            "title": "Model Denial of Service — Token / Context Exhaustion",
            "priority": "p1",
            "description": (
                "Inputs crafted to maximally consume context window, trigger recursive "
                "generation, or cause abnormally long inference times — leading to "
                "high API cost, service degradation, or timeout-based DoS."
            ),
            "cwe": "CWE-400",
            "owasp": "LLM04:2025",
            "mitre": "T1499.004",
            "probes": [
                "model dos", "token exhaustion", "context flood",
                "recursive generation", "infinite loop prompt", "resource exhaustion",
            ],
            "covered_by": ["llm-probe"],
        },
        {
            "id": "llm-sensitive-disclosure",
            "tag": "SYSPROMPT-LEAK",
            "title": "Sensitive Information Disclosure — System Prompt / Training Data Leakage",
            "priority": "p1",
            "description": (
                "Model reveals contents of its system prompt, fine-tuning examples, "
                "or confidential training data through direct request, indirect "
                "extraction probes, or completion attacks. Verified against a corpus "
                "of 255 real leaked system prompts."
            ),
            "cwe": "CWE-200",
            "owasp": "LLM06:2025",
            "mitre": "T1552",
            "probes": [
                "system prompt leak", "prompt disclosure", "training data",
                "confidential instructions", "repeat after me", "reveal your instructions",
            ],
            "covered_by": ["llm-probe", "llm-corpus"],
        },
        {
            "id": "llm-plugin-design",
            "tag": "UNSAFE-PLUGIN",
            "title": "Insecure Plugin / Tool Design — Unrestricted Tool Execution",
            "priority": "p1",
            "description": (
                "LLM plugins or function-call tools accept raw user-controlled input "
                "without parameter validation, scope restriction, or confirmation gates. "
                "Enables an attacker to invoke sensitive operations (file I/O, HTTP "
                "requests, DB writes) via prompt manipulation."
            ),
            "cwe": "CWE-20",
            "owasp": "LLM07:2025",
            "mitre": "T1059",
            "probes": [
                "unsafe plugin", "unrestricted tool", "tool call injection",
                "function call abuse", "plugin scope", "tool parameter validation",
            ],
            "covered_by": ["llm-probe"],
        },
        {
            "id": "llm-model-theft",
            "tag": "MODEL-THEFT",
            "title": "Model Theft / Extraction — Distillation via API Abuse",
            "priority": "p2",
            "description": (
                "Attacker issues systematic, structured queries to replicate model "
                "behaviour or extract fine-tuning data at scale. Detectable by "
                "abnormal query volume, parameter sweeps, and low-variance structured "
                "response patterns."
            ),
            "cwe": "CWE-1421",
            "owasp": "LLM10:2025",
            "mitre": "T1074",
            "probes": [
                "model extraction", "distillation", "api scraping",
                "query sweep", "model theft", "systematic probing",
            ],
            "covered_by": ["llm-probe"],
        },
    ],
}


def build_net(profile: dict) -> list[dict]:
    """Build ordered list of threat control sections for the detected system profile.

    Args:
        profile: Output of detect_system_profile() — {"components": [...], "scanners": [...]}

    Returns:
        List of control section dicts (id, tag, title, priority, description,
        cwe, owasp, mitre, probes, status="net") ready for SOC template injection.
    """
    components = profile.get("components", [])
    net: list[dict] = []
    seen_ids: set[str] = set()

    for component in components:
        templates = SYSTEM_COMPONENTS.get(component, [])
        for tmpl in templates:
            if tmpl["id"] not in seen_ids:
                section = dict(tmpl)
                section["status"] = "net"  # will be refined to proven/untested/refuted
                section["items"] = []  # findings slot — filled during refinement
                net.append(section)
                seen_ids.add(tmpl["id"])

    # Sort: p0 first, then p1, then p2
    _prio = {"p0": 0, "p1": 1, "p2": 2}
    net.sort(key=lambda s: _prio.get(s.get("priority", "p2"), 2))
    return net


def _probe_match(finding: dict, probes: list[str]) -> bool:
    """Return True if any probe matches a semantic field of the finding.

    Matching is token-boundary (whole-word) and only considers semantic
    identity fields — NOT severity/type/category, which carry no topical
    meaning and would otherwise make every "high" finding match every probe
    list that happens to contain a generic word.
    """
    parts = [
        str(finding.get("name") or ""),
        str(finding.get("vulnerabilityName") or ""),
        str(finding.get("Title") or ""),
        str(finding.get("template-id") or ""),
        str(finding.get("checkID") or ""),
        str(finding.get("description") or ""),
        str(finding.get("message") or ""),
        str(finding.get("rule_id") or ""),
        str(finding.get("rule") or ""),
    ]
    tags = finding.get("tags")
    if isinstance(tags, list):
        parts.extend(str(t) for t in tags)
    elif isinstance(tags, str):
        parts.append(tags)
    haystack = " ".join(parts)
    for p in probes:
        if re.search(r"\b" + re.escape(p) + r"\b", haystack, re.IGNORECASE):
            return True
    return False


def adjudicate_net(
    net: list[dict],
    findings: list[dict],
    scanners_run: list[str] | None = None,
) -> list[dict]:
    """Match scanner findings against net sections; set proven/refuted/untested.

    Status semantics:
      - ``proven``   — a scanner finding matched the section's probes.
      - ``refuted``  — the section declares a ``covered_by`` scanner that DID
                       run, and that scanner produced no matching finding. The
                       absence is meaningful: the surface was tested and clean.
      - ``untested`` — no match, and no scanner covering this section ran (or
                       the section declares no coverage). The absence is NOT
                       evidence of safety.

    Args:
        net: Output of build_net() — list of control section dicts.
        findings: Raw merged scanner findings list.
        scanners_run: List of scanner source labels that actually ran
            (e.g. merge_meta.sources). Used to decide refuted vs untested.

    Returns:
        Updated net with status set and matched findings attached to each section.
    """
    ran = {str(s).lower() for s in (scanners_run or [])}

    for section in net:
        probes = section.get("probes", [])
        matched = [f for f in findings if _probe_match(f, probes)]
        if matched:
            section["status"] = "proven"
            section["items"] = matched
            continue

        section["items"] = []
        covered_by = [str(c).lower() for c in (section.get("covered_by") or [])]
        # Refuted only when a covering scanner actually ran and found nothing.
        if covered_by and any(c in ran for c in covered_by):
            section["status"] = "refuted"
        else:
            section["status"] = "untested"
    return net
