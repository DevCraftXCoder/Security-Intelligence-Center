<div align="center">

> **Zero-Trust IP Allowlisting** — All admin operations (scans, audits, infra controls) are locked behind IP allowlisting. Even with valid credentials, requests must originate from the home network. VPN, proxy, and foreign IPs are rejected. IPv6 prefix matching requires a minimum /64 specificity to prevent broad-prefix bypass.

# SIC — Security Intelligence Center

### Penetration Testing MCP Framework for Authorized Security Testing

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](#mcp-integration)
[![Version](https://img.shields.io/badge/Version-6.0.0-orange.svg)](#)
[![Tools](https://img.shields.io/badge/Security%20Tools-150%2B-brightgreen.svg)](#security-tools-arsenal)
[![Agents](https://img.shields.io/badge/Agents-12%2B-purple.svg)](#agents)

**A penetration testing MCP framework with 150+ security tools and 12+ specialized agents for authorized security testing, CTF challenges, and defensive research.**

[SIC Engine](#sic-engine) | [Quick Start](#quick-start) | [API Reference](#api-reference)

</div>

---

## Overview

SIC runs as a local server, exposing a Flask REST API and MCP interface for integration with any MCP-compatible client (Claude Code, Copilot, Cursor). All operations are IP-allowlisted to the home network — unauthorized IPs are rejected at the application layer regardless of credentials.

---

## Architecture

### How It Works

```
MCP Client (Claude Code / Copilot / Cursor)
  │
  ▼ (MCP Protocol)
mcp_server.py  (FastMCP server)
  │
  ▼ (HTTP — loopback only)
server.py  (Flask REST API — 127.0.0.1:9888)
  │  ├─ Intelligent decision engine
  │  ├─ Tool selection & parameter optimization
  │  ├─ Scope enforcer (scope_enforcer.py)
  │  ├─ Auth & IP allowlist (auth.py)
  │  └─ 150+ security tools (installed on host)
  │
  ├─ billing_server.py  (Flask — :9015, X-Billing-Key auth)
  └─ launcher.py  (CLI entry point)
```

### Application-Layer Security Controls

| Control | Implementation | Purpose |
|---------|---------------|---------|
| IP allowlisting | `auth.py` — home network CIDR check | Blocks all external IPs regardless of credentials |
| Scope enforcement | `scope_enforcer.py` — ALLOWED_TARGETS | Whitelist-only target scanning |
| Loopback binding | `127.0.0.1:9888` | API never reachable from network |
| IPv6 prefix | min `/64` specificity | Prevents broad-prefix bypass |
| Audit log | `audit_log.py` | All operations logged with actor + timestamp |
| Billing quota | `billing_server.py` | Per-tool, per-session request budgets |

---

## SIC Engine

MCP framework with tool orchestration, agent dispatch, and visual output. Connects to Claude Code, Copilot, Cursor, or any MCP-compatible client.

### Architecture

```mermaid
graph TD
    A[MCP Client - Claude Code / Copilot / Cursor] -->|MCP Protocol| B[SIC MCP Server v6.0]

    B --> C[Intelligent Decision Engine]
    B --> D[12+ Specialized Agents]
    B --> E[Modern Visual Engine]

    C --> F[Tool Selection]
    C --> G[Parameter Optimization]
    C --> H[Attack Chain Discovery]

    D --> I[BugBounty Agent]
    D --> J[CTF Solver Agent]
    D --> K[CVE Intelligence Agent]
    D --> L[Exploit Generator Agent]

    B --> P[150+ Security Tools]
    P --> Q[Network - 25+]
    P --> R[Web App - 40+]
    P --> S[Cloud - 20+]
    P --> T[Binary - 25+]
    P --> U[CTF - 20+]
    P --> V[OSINT - 20+]
```

### How It Works

1. MCP client sends commands via MCP protocol
2. Decision engine selects optimal tools and parameters
3. Security tools execute scans, exploits, and analysis
4. Results formatted and returned through MCP with visual output

### Agents

| Agent | Capability |
|-------|-----------|
| **BugBounty Agent** | Automated bug bounty hunting workflow |
| **CTF Solver Agent** | Challenge analysis and solution strategies |
| **CVE Intelligence Agent** | CVE lookup, exploitability analysis, patch tracking |
| **Exploit Generator Agent** | Proof-of-concept exploit development |
| **Recon Agent** | Automated reconnaissance and asset discovery |
| **Web Scanner Agent** | Comprehensive web application assessment |
| **Cloud Auditor Agent** | Multi-cloud security posture review |
| **Network Agent** | Internal/external network penetration testing |
| **Forensics Agent** | Digital forensics and incident response |
| **OSINT Agent** | Open-source intelligence gathering |
| **Social Engineering Agent** | Phishing simulation and awareness |
| **Report Generator Agent** | Automated pentest report creation |

### Security Tools Arsenal

<details>
<summary><strong>Network Security (25+ tools)</strong></summary>

nmap, masscan, rustscan, netcat, tcpdump, wireshark-cli, arp-scan, ping sweep, traceroute, DNS zone transfer, subdomain enumeration, and more.
</details>

<details>
<summary><strong>Web Application Security (40+ tools)</strong></summary>

sqlmap, nikto, wfuzz, gobuster, feroxbuster, httpx, nuclei, XSS detection, SSRF scanner, CORS checker, directory brute-forcing, and more.
</details>

<details>
<summary><strong>Cloud Security (20+ tools)</strong></summary>

ScoutSuite, Prowler, CloudSploit, S3 bucket scanner, IAM analyzer, container security scanning, and more.
</details>

<details>
<summary><strong>Binary Analysis (25+ tools)</strong></summary>

GDB, Radare2, Ghidra, Binwalk, checksec, ROPgadget, pwntools, and more.
</details>

<details>
<summary><strong>CTF Tools (20+ tools)</strong></summary>

CyberChef, John the Ripper, Hashcat, Stegsolve, memory/disk forensics toolkit, and more.
</details>

<details>
<summary><strong>OSINT (20+ tools)</strong></summary>

theHarvester, Shodan, SpiderFoot, Recon-ng, Maltego, and more.
</details>

---

## Quick Start

```bash
# Start the full server (MCP + REST API)
python server.py

# MCP-only mode (for Claude Code / Cursor integration)
python mcp_server.py

# CLI launcher
python launcher.py

# Standalone billing server (managed by PM2 on :9015)
python billing_server.py

# Verify health
curl http://127.0.0.1:9888/health
```

Add to your MCP client config:

```json
{
  "mcpServers": {
    "sic": {
      "command": "python",
      "args": ["path/to/mcp_server.py"]
    }
  }
}
```

## sic_to_audit.py v2 — Audit Report Bridge

`sic_to_audit.py` maps SIC, Nuclei, Trivy, and Checkov output to the 42-item 3SIXTYCO. security audit checklist and emits a self-contained HTML report with `window.AUDIT.fill()` pre-injected. v2 is a ground-up rework of the v1 regex-only bridge.

### Top 5 v2 Improvements

1. **Structured JSON parsers for Nuclei, Trivy, and Checkov**
   v1 ran regex against flattened text. v2 parses the native JSON of each tool — Nuclei `template-id` + `info.severity`, Trivy `Vulnerabilities` / `Secrets` / `Misconfigurations`, Checkov `failed_checks` — and emits typed `StructuredFinding` objects with item-ID mapping, source attribution, and severity. The result: real findings instead of false positives from prose matches in logs.

2. **Severity-weighted FAIL / WARN / PASS with confidence tiers**
   Critical/high structured findings flip an item to **FAIL** with `[source] name: description` evidence. Medium findings (or 1–2 regex hits) downgrade to **WARN** with a `MEDIUM FINDING` prefix for manual review. Three or more regex hits escalate to **FAIL** with `HIGH` confidence. The 42-item checklist now reflects actual risk, not match count.

3. **NDJSON + multi-format ingestion (one file, many tools)**
   `load_results_file()` accepts a single JSON object, JSON array, NDJSON (one object per line), or two objects concatenated with whitespace — so you can `>> append` raw scanner output from multiple tools into one file and feed it in directly. Falls back to wrapping unstructured text in a synthetic record so nothing gets dropped.

4. **Auto tool detection + SIC smart-scan recursion**
   `_detect_tool()` heuristically identifies Nuclei / Trivy / Checkov / SIC smart-scan blobs by shape (`template-id`, `Results` + `SchemaVersion`, `failed_checks`, `tools_executed`). Smart-scan results are recursed into, so a single SIC smart-scan response unpacks into all child tool findings — no manual tool-by-tool wiring.

5. **Embedded scan-metadata bar + filled HTML in one file**
   `inject_fill()` rewrites the audit template with a `<script>` block that calls `window.AUDIT.fill()` on `DOMContentLoaded` and pins a fixed scan-info bar (date, target, tools used, tool count, duration) to the bottom-right of the report. The output is a single portable HTML — open in any browser, no server, no follow-up steps.

### Usage

```bash
# Live SIC smart-scan -> HTML report
python sic_to_audit.py --target https://example.com --output report.html

# Offline: feed existing JSON / NDJSON from any combination of tools
python sic_to_audit.py --results sic-results.json --output report.html

# Dry-run — print the fill dict without writing HTML
python sic_to_audit.py --target https://example.com --dry-run
```

---

## Recent Additions

- `sic_to_audit.py` v2 — structured tool parsing, severity weighting, NDJSON ingestion (see above)
- Standalone billing server with machine-to-machine API key auth (`X-Billing-Key`)
- Sentry SDK integrated into HexStrike server for error tracking
- Login page: large centered clickable logo, background cycles on click
- Settings panel hidden behind logo-toggle control bar
- Letter Glitch background added as 3rd theme option (alongside galaxy + navy)
- Logo upload + background toggle — customize dashboard appearance
- Published `npx sic-security@beta` for quick install

## Run with npx

```bash
npx sic-security@beta
```

## Authorized Use Only

> SIC is designed exclusively for authorized security testing. All operations must target systems you own or have explicit written permission to test. The IP allowlist enforces this at the application layer — requests from unauthorized IPs are blocked regardless of credentials.
