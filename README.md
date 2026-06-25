<div align="center">

# SIC — Security Intelligence Center

### Penetration Testing & SOC Reporting Framework for Authorized Security Testing

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](#mcp-integration)

**A penetration testing MCP framework with specialized agents for authorized security testing, CTF challenges, defensive research, and automated SOC reporting.**

</div>

---

## Overview

SIC runs as a local server exposing an MCP interface for integration with any MCP-compatible client (Claude Code, Copilot, Cursor). All scan operations are IP-allowlisted to the home network. Scan output flows through a reporting pipeline that produces both a detailed security audit report and a SOC handoff HTML — with week-over-week posture tracking built in.

---

## Quick Start

### Fastest path (paying customers) — one command

```bash
# Run this from the root of the codebase you want SIC to inspect:
cd /path/to/your-project
npx sic-security          # launch the full dashboard / MCP server
npx sic-security scan     # instant code scan — no external tools required
```

**`npx sic-security scan`** runs SIC's built-in, zero-dependency code scanner
against your project and prints findings immediately — hardcoded secrets,
dangerous patterns (`eval`, `shell=True`, SQL string-building, unsafe YAML/pickle,
CORS wildcards, …), and dependency CVEs (when `pip-audit` is present). It needs no
nmap/nuclei/external binaries, so it works on a fresh install on any machine.

`npx sic-security` (the `bin/sic.js` launcher) creates an isolated Python venv
under `~/.sic-security/venv`, installs the core dependencies (first run only),
and starts the server for you. It detects the project type of the directory you
run it from (Node.js, Python, Go, Rust, Docker, …) and points SIC's inspect /
Claude Code actions at **that** codebase via `SIC_PROJECT_DIR` — not at SIC's own
files. This is the recommended install path after you subscribe and receive your
magic-link.

> **Tailored to your codebase:** SIC scans and INSPECT operations are confined to
> the directory you launched from (or an explicit `SIC_PROJECT_DIR`). Run it from
> your repo root for the best results.
>
> **Prerequisites:** a system Python 3.8+ must be on `PATH` (used once to create
> the venv). If it is missing, the launcher prints an actionable error and exits.
> Before first use, copy `.env.example` to `.env` and set the required variables
> (see First-Run Setup below). Re-run with `npx sic-security --reinstall` to force
> a dependency refresh.

### Manual path

```bash
# 1. Clone the repository
git clone https://github.com/DevCraftXCoder/Security-Intelligence-Center.git
cd Security-Intelligence-Center

# 2. Create + activate a virtual environment
python -m venv .venv
# Windows:  .venv\Scripts\activate     Linux/macOS:  source .venv/bin/activate

# 3. Install dependencies
#    Windows  → use the core set (skips Linux-only tools: angr, pwntools, mitmproxy)
pip install -r requirements-core.txt
#    Linux / Docker → full set
#    pip install -r requirements.txt

# 4. Configure environment (see First-Run Setup below)
cp .env.example .env        # then edit .env

# 5. Start the server
python start_server.py      # loads .env, then runs the Flask app (hexstrike_server.py)

# MCP-only mode
python mcp_server.py

# CLI launcher
python launcher.py
```

> **Entry point note:** the Flask app lives in `hexstrike_server.py`. `start_server.py`
> is a thin wrapper that loads `.env` and forces UTF-8 I/O before launching it — this is
> what PM2 (`ecosystem.config.cjs`) runs. There is no `server.py`.

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

---

## Prerequisites

Before running SIC, ensure the following external tools are on your `PATH`. Run
`install\check-prerequisites.ps1` to check which are present and get one-line
install commands for any that are missing.

| Tool | Used for |
|------|---------|
| `nmap` | Network/port scanning |
| `nuclei` | Vulnerability scanning templates |
| `nikto` | Web server scanning |
| `gobuster` | Directory/DNS brute-forcing |
| `ffuf` | Web fuzzing |
| `sqlmap` | SQL injection testing |
| `subfinder` | Subdomain enumeration |
| `amass` | Asset discovery |
| `httpx` | HTTP probing |

See [`install/check-prerequisites.ps1`](install/check-prerequisites.ps1) for the full
tool list and install guidance.

---

## First-Run Setup (Required)

1. **Copy `.env.example` to `.env`**  
   ```bash
   cp .env.example .env
   ```

2. **Activate your SIC token.**  
   After purchasing a subscription you will receive a magic-link email. Click it to
   activate your account. The activation sets `SIC_TOKEN` — the **only** credential
   you need for scanning.

3. **Set your token in `.env`:**

   | Variable | Description |
   |----------|-------------|
   | `SIC_TOKEN` | Activation token from your magic-link email |
   | `SIC_ADMIN_EMAILS` | Your email (comma-separated for multiple admins) |
   | `SIC_BASE_URL` | Public URL where you reach the dashboard (default: `http://localhost:9888`) |

   > **Note:** Stripe and Resend credentials (`STRIPE_SECRET_KEY`, `RESEND_API_KEY`,
   > etc.) are operator-side secrets managed by the SIC cloud service. You do **not**
   > need these for scanning — they are never required in a customer install.

<!-- archived: operator-secret requirement removed
   Old table that exposed operator billing secrets to customers:
   | `STRIPE_SECRET_KEY` | From Stripe Dashboard → API Keys |
   | `STRIPE_WEBHOOK_SECRET` | From Stripe Dashboard → Webhooks |
   | `STRIPE_PRICE_TEAM` | Stripe Price ID for Team plan |
   | `STRIPE_PRICE_STUDIO` | Stripe Price ID for Studio plan |
   | `BILLING_API_KEY` | Random secret for billing M2M auth |
   | `RESEND_API_KEY` | For magic link email delivery |
   | `SIC_ALERT_FROM` | Verified sender email (e.g. sic@yourdomain.com) |
-->

4. **Check prerequisites:**
   ```powershell
   .\install\check-prerequisites.ps1
   ```

5. **Run the audit to verify setup:**
   ```bash
   python sic-audit.py
   ```

6. **Start SIC:**
   ```bash
   python start_server.py    # SIC main server (port 9888)
   # Or with PM2:
   pm2 start ecosystem.config.cjs
   ```

7. **Open your browser:** [http://localhost:9888](http://localhost:9888)

---

## Reporting Pipeline

SIC ships two report generators that convert scan output into production-quality HTML reports.

### `sic_to_audit.py` — 3SIXTYCO. Security Audit Report

Maps SIC scan findings to 42 audit control IDs (7 tiers: SP → BP) with pass/fail/manual status, score ring, and per-item evidence blocks.

Supports nuclei, smart-scan, trivy (`Results[].Vulnerabilities[]`), and checkov (`results.failed_checks[]`). LLM-assisted control mapping via LLM Gateway for high-confidence cross-control assignment.

```bash
python sic_to_audit.py \
  --results  _runs/scan-20260529-120000.json \
  --template /path/to/3sixtyco-security-audit-v1.html \
  --project  "MyApp" \
  --output   _runs/qa/MyApp-audit-20260529-120000.html
```

### `sic_to_soc.py` — SOC Handoff Report

Generates a SOC handoff HTML from scan findings, grouped into P0–P3 severity sections. Includes week-over-week posture history via a `project-data` snapshots array — consecutive same-week scans dedup into one snapshot; cross-week runs accumulate automatically.

```bash
python sic_to_soc.py \
  --scan     _runs/scan-20260529-120000.json \
  --project  "MyApp" \
  --output   _runs/qa/MyApp-soc-20260529-120000.html \
  --template /path/to/soc-handoff-template-blank.html \
  --score    85          # optional: override posture score for week-0 snapshot
```

**Output layout**

```
_runs/
  scan-<ts>.json                   raw SIC tool output
  qa/
    <project>-audit-<ts>.html      3SIXTYCO. audit report (42 controls, scored)
    <project>-soc-<ts>.html        SOC handoff report (findings by severity, weekly history)
```

---

## Supported Scan Schemas

| Tool | Schema | Extractor |
|------|--------|-----------|
| nuclei / smart-scan | `{severity, name, template-id, ...}` | Generic `_collect()` |
| trivy | `Results[].Vulnerabilities[]` | trivy-specific branch |
| checkov | `results.failed_checks[]` | checkov-specific branch |
| Concatenated JSON | Multiple JSON objects in one file | Streaming decoder |

---

## Stripe Billing

SIC billing runs as a standalone Flask server on port 9015 (`billing_server.py`). Two subscription tiers are pre-configured in Stripe test mode:

| Plan | Price | Stripe Product |
|------|-------|----------------|
| Team | $29 / month | `prod_URLViBAWBPAsCx` |
| Studio | $99 / month | `prod_URLVVFcQ637BJM` |

Price IDs are pre-populated in `.env` (`STRIPE_PRICE_TEAM`, `STRIPE_PRICE_STUDIO`).

### Local webhook forwarding (dev)

```bash
# Forward Stripe events to the local billing server
stripe listen --forward-to localhost:9015/api/billing/webhook
# Copy the whsec_... value printed and set it as STRIPE_WEBHOOK_SECRET in .env
```

### Production webhook endpoint

Create a permanent endpoint in the Stripe Dashboard pointing to:
```
https://<your-sic-domain>/api/billing/webhook
```
Events to subscribe: `checkout.session.completed`, `customer.subscription.updated`,
`customer.subscription.deleted`, `invoice.payment_failed`

---

## MCP Integration

SIC exposes 85 security tools and 12+ specialized agents over MCP. Example tools: `smart-scan`, `nuclei`, `trivy`, `checkov`, `nmap`, `gobuster`, `ffuf`, `sqlmap`, and dedicated CTF, bug bounty, and recon modules.

All tool calls are sandboxed and scope-validated. Unauthorized targets are rejected at the API layer.

---

## Authorized Use Only

> SIC is designed exclusively for authorized security testing. All operations must target systems you own or have explicit written permission to test. Unauthorized scanning is illegal and prohibited.
