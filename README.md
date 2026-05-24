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

**An Intelligence-driven pentesting MCP framework with 150+ security tools and 12+ autonomous agents for authorized security testing, CTF challenges, and defensive research.**

[SIC Engine](#sic-engine) | [Run with npx](#run-with-npx) | [API Reference](#api-reference)

</div>

---

## Overview

SIC is an Intelligence-driven penetration testing framework that runs as a local server, exposing a comprehensive API and MCP interface for integration with AI clients (Claude Code, Copilot, Cursor, and any MCP-compatible client).

---


## Architecture

SIC runs 150+ real offensive security tools (nmap, sqlmap, nuclei, hydra, etc.) — fully sandboxed in a hardened Docker container with multiple security layers.

### How It Works

```
AI Client (Claude Code, GPT, Copilot, Cursor)
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

Intelligence-driven penetration testing framework with MCP protocol support. Connects to Claude Code, Copilot, Cursor, or any MCP-compatible AI client.

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

## Recent Additions

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

> SIC is designed exclusively for authorized security testing. All operations must target systems you own or have explicit written permission to test. The IP allowlist enforces this at the network layer — scans from unauthorized IPs are blocked regardless of credentials.

