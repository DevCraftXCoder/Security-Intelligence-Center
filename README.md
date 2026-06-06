# Security Intelligence Center

![Python](https://img.shields.io/badge/Python_3.8+-3776AB?style=flat&logo=python&logoColor=white)
![MCP](https://img.shields.io/badge/MCP_Interface-000000?style=flat&logo=anthropic&logoColor=white)
![Docker](https://img.shields.io/badge/Docker_Sandboxed-2496ED?style=flat&logo=docker&logoColor=white)
![Local First](https://img.shields.io/badge/Local--First-111111?style=flat&logo=homeassistant&logoColor=white)

**Penetration testing framework — MCP interface, 85 security tools, 12 specialized agents, Docker-sandboxed execution.**

> Runs as a local server exposing a REST API and MCP interface for direct integration with Claude, Cursor, or any MCP-compatible client. Connect your toolchain to purpose-built security tooling — recon, exploitation, post-exploitation, bug bounty, CTF — all sandboxed in Docker with IP allowlisting.

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

- **MCP-native** — integrates with any MCP-compatible client with zero configuration
- **REST API** — full programmatic access for automation pipelines
- **Docker sandboxing** — all tool execution isolated, IP allowlisted to home network
- **12 specialized agents** — each owns a distinct phase of the engagement lifecycle
- **85 tools** — covers recon through reporting across all engagement types
- **Billing module** — built-in quota tracking per tool, per agent, per session
- **Incident tracker** — log findings, track severity, export reports
- **Local-first** — no cloud dependency, no data leaves your machine

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

## Installation

**Requires Python 3.8+**

```bash
# Paying customers — fastest path
npx sic-security

# Self-hosted
git clone https://github.com/DevCraftXCoder/Security-Intelligence-Center.git
cd Security-Intelligence-Center
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements-core.txt               # Linux/Docker: requirements.txt
cp .env.example .env                               # fill in your values
python start_server.py                             # → http://localhost:9888
```

### MCP Setup (Claude Code / Cursor)

```json
{
  "mcpServers": {
    "sic": {
      "command": "python",
      "args": ["/path/to/Security-Intelligence-Center/mcp_server.py"]
    }
  }
}
```

### Required `.env` values

| Variable | Description |
|----------|-------------|
| `SIC_SECRET_KEY` | Random secret (min 32 chars) |
| `SIC_ADMIN_EMAILS` | Your email address |
| `SIC_BASE_URL` | Public URL of your SIC instance |
| `RESEND_API_KEY` | Email delivery for magic links |

Run `python sic-audit.py` to verify your setup before starting.

## Health Check

```bash
curl http://localhost:9888/health
```

---

> ⚠️ **Authorized use only.** For penetration testing engagements, CTF competitions, security research, and defensive security. Never use against systems you do not own or have explicit written permission to test.
