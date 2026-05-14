<div align="center">

> **Zero-Trust IP Allowlisting** — All admin operations (scans, audits, infra controls) are locked behind IP allowlisting. Even with valid credentials, requests must originate from the home network. VPN, proxy, and foreign IPs are rejected. IPv6 prefix matching requires a minimum /64 specificity to prevent broad-prefix bypass.

# SIC — Security Intelligence Center

### AI-Powered Pentesting MCP Framework for Authorized Security Testing

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](#ai-client-integration)
[![Version](https://img.shields.io/badge/Version-6.0.0-orange.svg)](#)
[![Tools](https://img.shields.io/badge/Security%20Tools-150%2B-brightgreen.svg)](#security-tools-arsenal)
[![Agents](https://img.shields.io/badge/AI%20Agents-12%2B-purple.svg)](#ai-agents)

**An AI-powered pentesting MCP framework with 150+ security tools and 12+ autonomous agents for authorized security testing, CTF challenges, and defensive research.**

[SIC Engine](#sic-engine) | [Run with npx](#run-with-npx) | [API Reference](#api-reference)

</div>

---

## Overview

SIC is an AI-powered penetration testing framework that runs as a local server, exposing a comprehensive API and MCP interface for integration with AI clients (Claude Code, Copilot, Cursor, and any MCP-compatible client).

---


## Architecture

SIC runs 150+ real offensive security tools (nmap, sqlmap, nuclei, hydra, etc.) — fully sandboxed in a hardened Docker container with multiple security layers.

### How It Works

```
AI Client (Claude, GPT, Copilot, Cursor)
  │
  ▼ (MCP Protocol)
SIC MCP Server
  │  ├─ Intelligent decision engine
  │  ├─ Tool selection & parameter optimization
  │  └─ Attack chain discovery
  │
  ▼
127.0.0.1:9888 (loopback only — never exposed)
  │
  ▼
Docker Container (sic-scanner)
  │  ├─ Scope enforcer (ALLOWED_TARGETS whitelist)
  │  ├─ Dry-run gate (on by default)
  │  └─ Tool execution (150+ tools)
  │
  ▼
./output/ (results only — source baked into image)
```

### Container Isolation

The Docker container enforces 12 security controls:

| Control | Setting | Purpose |
|---------|---------|---------|
| Port binding | `127.0.0.1:9888` | Never reachable from network |
| User | `scanner` (uid 1001) | Non-root, no privilege escalation |
| Capabilities | `cap_drop: ALL` | Zero Linux capabilities |
| Privilege escalation | `no-new-privileges: true` | Blocks setuid/setgid |
| CPU limit | 2 cores | Prevents self-DoS |
| Memory limit | 2 GB | Bounded resource usage |
| DNS | `127.0.0.1` only | Blocks external hostname resolution |
| Network | `scanner-net` bridge (internal on Linux) | No cross-container routes |
| Scanner mode | `SCANNER_MODE=sandbox` | Restricts target scope at app layer |
| Allowed targets | `target.example.com,192.168.1.0/24` | Whitelist-only scanning |
| Request budget | `MAX_REQUESTS_PER_SCAN=500` | Prevents runaway scans |
| Dry-run default | `DRY_RUN_DEFAULT=true` | Must explicitly opt into live scans |
| Scan timeout | `300s` hard wall | Kills scans after 5 minutes |
| Volume mounts | `./output` only | Source code baked into image, never mounted |

### Multi-Stage Build

The Dockerfile uses 3 stages to keep the image lean and the build fast:

| Stage | Base | What It Builds |
|-------|------|---------------|
| `go-builder` | `golang:1.24-alpine` | 13 Go tools (ffuf, gobuster, nuclei, httpx, subfinder, katana, etc.) |
| `py-builder` | `python:3.12-slim` | 30+ Python packages (sqlmap, dirsearch, theHarvester, pwntools, etc.) |
| `runtime` | `python:3.12-slim` | Final image — all tools + HexStrike API server |

Heavy packages (angr, autorecon, spiderfoot) are stubbed — the System Tab runs `which <tool>` to show availability, so stubs satisfy that without the OOM risk.

### Running It

```bash
# Start the sandboxed container
cd docker/sic-scanner
docker compose up -d

# Verify health
curl http://127.0.0.1:9888/health
```

---

## SIC Engine

AI-powered penetration testing framework with MCP protocol support. Connects to Claude Code, Copilot, Cursor, or any MCP-compatible AI client.

### Architecture

```mermaid
graph TD
    A[AI Agent - LLM/Copilot/Cursor] -->|MCP Protocol| B[SIC MCP Server v6.0]

    B --> C[Intelligent Decision Engine]
    B --> D[12+ Autonomous AI Agents]
    B --> E[Modern Visual Engine]

    C --> F[Tool Selection AI]
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

1. AI client sends commands via MCP protocol
2. Decision engine selects optimal tools and parameters
3. Security tools execute scans, exploits, and analysis
4. Results formatted and returned through MCP with visual output

### AI Agents

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

### Advanced Capabilities

- **Intelligent Decision Engine** — AI-driven tool selection based on target context
- **Parameter Optimization** — Automatic tuning per tool/target combination
- **Attack Chain Discovery** — Links vulnerabilities into exploitable chains
- **Smart Caching** — Avoids redundant scans, caches intermediate results
- **Resource Management** — CPU/memory-aware scheduling
- **Error Recovery** — Automatic retry with fallback strategies

---

## Run with npx

One command · no install · latest beta

```bash
# Latest beta tag
npx sic-security@beta
```

```bash
# Pin a version
npx sic-security@6.0.0-beta.1
```

```bash
# Direct from the repo
npx github:DevCraftXCoder/sic
```

### AI Client Integration

**Claude Code / Cursor:**
```json
{
  "mcpServers": {
    "sic": {
      "command": "python",
      "args": ["/path/to/sic/sic_mcp.py"]
    }
  }
}
```

**VS Code Copilot:**
```json
{
  "mcp.servers": {
    "sic": {
      "command": "python",
      "args": ["/path/to/sic/sic_mcp.py"]
    }
  }
}
```

---

## API Reference

### SIC Engine Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Full system health + telemetry |
| `/api/tools` | GET | List all available tools |
| `/api/tools/<name>` | GET | Tool detail and status |
| `/api/scan` | POST | Run a targeted scan |
| `/api/agents` | GET | List AI agents |
| `/api/agents/<name>/run` | POST | Execute an agent task |
| `/api/processes` | GET | List running processes |
| `/api/processes/<id>` | DELETE | Kill a process |
| `/api/cache/clear` | POST | Clear scan cache |

### Common MCP Tools

```
# Network
sic_nmap_scan(target, flags)
sic_masscan(target, ports)
sic_port_scan(target)

# Web
sic_nikto_scan(target)
sic_sqlmap(target, params)
sic_directory_bruteforce(target, wordlist)

# Recon
sic_subdomain_enum(domain)
sic_whois(domain)
sic_dns_lookup(domain)

# Vulnerability
sic_nuclei_scan(target, templates)
sic_cve_lookup(cve_id)
sic_exploit_search(query)
```

---

## Security & Responsible Use

SIC is an **offensive security toolkit** for professionals. It generates real exploits, runs real scans, and can cause real damage if misused.

- All tools run locally — no telemetry, no data exfiltration
- API key auth protects the server
- Smart caching stores results locally — clear with `/api/cache/clear`
- Exploit generation and CVE research are first-class features

This is a private tool shared among trusted peers. If you have access, you already know the rules: **test only what you're authorized to test.**

---

## Recent Additions

- **Payment system + billing hardening** — SIC subscription management; public-checkout endpoint secured with exact-match auth allowlist; email removed from checkout URLs
- **Security hardening (v6.0.0)** — 38 tool routes patched for shell injection safety; zero injection vectors remain across all endpoints
- **Per-service API tokens** — Individual tokens per integrated service with expiry warnings (#25 token-expiry system)
- **Rate limiting** — All endpoints rate-limited; 25 CVEs addressed via pip-audit dependency audit
- **Admin panic-stop** — Admin role gate on `/api/admin/panic-stop` (was unauthenticated)
- **Generic error responses** — P0 scope_status and internal error details no longer leaked to API consumers
- **Auth/tier/scope enforcement** — P1 complete: request validation wired across all tool routes
- **Claude Code `/sic` command** — Direct Claude Code integration for interactive pentesting sessions (#27)
- **Zero-Trust IP Allowlisting** — All admin operations locked behind IP allowlisting; IPv6 prefix matching requires minimum /64 specificity

---

## License

MIT License — see [LICENSE](LICENSE) for details.
