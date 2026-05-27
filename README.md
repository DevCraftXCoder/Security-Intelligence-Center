# Security Intelligence Center

![Python](https://img.shields.io/badge/Python_3.8+-3776AB?style=flat&logo=python&logoColor=white)
![MCP](https://img.shields.io/badge/MCP_Interface-000000?style=flat&logo=anthropic&logoColor=white)
![Docker](https://img.shields.io/badge/Docker_Sandboxed-2496ED?style=flat&logo=docker&logoColor=white)
![Local First](https://img.shields.io/badge/Local--First-111111?style=flat&logo=homeassistant&logoColor=white)
![Tools](https://img.shields.io/badge/150%2B_Security_Tools-e94560?style=flat&logoColor=white)

**AI-powered penetration testing framework — MCP interface, 150+ security tools, 12 specialized agents, Docker-sandboxed execution.**

> Runs as a local server exposing a REST API and MCP interface for direct integration with Claude, Cursor, or any MCP-compatible AI client. Point your AI at real security tooling — recon, exploitation, post-exploitation, bug bounty, CTF — all sandboxed in Docker with IP allowlisting.

## Architecture

```
AI Client (Claude / Cursor / any MCP host)
  └── MCP Interface  ──────────────────────────────┐
        │                                           │
        ▼                                           ▼
  REST API (:8080)                         Tool Registry (150+)
    ├── Agent Dispatcher (12 agents)            ├── Recon & OSINT
    ├── Billing & Quota                         ├── Exploitation
    ├── Incident Tracker                        ├── Post-Exploitation
    └── Session Manager                         ├── Bug Bounty Toolkit
                                                ├── CTF Utilities
                                                └── Vulnerability Intel
                          │
                          ▼
              Docker Sandbox (IP allowlisted)
                ├── Tool execution environment
                └── Network-isolated container
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Runtime | Python 3.8+ |
| API | FastAPI (REST + async) |
| Protocol | MCP (Model Context Protocol) |
| Sandboxing | Docker with IP allowlisting |
| Agents | 12 specialized security agents |
| Tools | 150+ security tools across all phases |
| Billing | Built-in quota + usage tracking |

## Security Agents

| Agent | Domain |
|-------|--------|
| Recon Agent | Target enumeration, OSINT, asset discovery |
| Exploit Agent | Vulnerability exploitation, payload delivery |
| Post-Exploit Agent | Lateral movement, privilege escalation |
| Bug Bounty Agent | Scope validation, report generation, triage |
| CTF Agent | Capture-the-flag challenge automation |
| Vuln Intel Agent | CVE research, exploitability scoring |
| OSINT Agent | Open-source intelligence gathering |
| Network Agent | Port scanning, service fingerprinting |
| Web Scanner Agent | DAST, injection testing, auth bypass |
| Forensics Agent | Artifact analysis, log parsing, IR support |
| Social Engineering Agent | Phishing simulation, pretexting support |
| Report Agent | Finding consolidation, executive summaries |

## Key Features

- **MCP-native** — drop into any MCP-compatible AI client with zero config
- **REST API** — full programmatic access for automation pipelines
- **Docker sandboxing** — all tool execution isolated, IP allowlisted to home network
- **12 specialized agents** — each owns a phase of the kill chain
- **150+ tools** — covers recon through reporting across all engagement types
- **Billing module** — built-in quota tracking per tool, per agent, per session
- **Incident tracker** — log findings, track severity, export reports
- **Local-first** — no cloud dependency, no data leaves your machine

## Quick Start

```bash
# Start the full server (MCP + REST API)
python hexstrike_server.py

# MCP-only mode (for Claude / Cursor integration)
python hexstrike_mcp.py

# CLI launcher
python hexstrike_launcher.py
```

Add to your MCP client config:

```json
{
  "mcpServers": {
    "sic": {
      "command": "python",
      "args": ["path/to/hexstrike_mcp.py"]
    }
  }
}
```

## Tool Categories

| Category | Tools | Examples |
|----------|-------|---------|
| Recon & OSINT | 30+ | subfinder, amass, theHarvester, shodan |
| Web Scanning | 25+ | nuclei, nikto, sqlmap, ffuf, feroxbuster |
| Exploitation | 20+ | metasploit, searchsploit, custom payloads |
| Network | 20+ | nmap, masscan, nessus integrations |
| Bug Bounty | 25+ | scope validator, report templates, CVSS calc |
| CTF | 15+ | pwntools, crypto utils, stego, reversing |
| Forensics | 15+ | log analysis, artifact extraction, IR tools |

## Health Check

```bash
curl http://localhost:8080/health
```

---

> ⚠️ **Authorized use only.** For penetration testing engagements, CTF competitions, security research, and defensive security. Never use against systems you do not own or have explicit written permission to test.
