<div align="center">

# SIC — Security Intelligence Center

### Penetration Testing & SOC Reporting Framework for Authorized Security Testing

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](#mcp-integration)

**A penetration testing MCP framework with specialized agents for authorized security testing, CTF challenges, defensive research, and automated SOC reporting.**

</div>

---

## Installation

**Requires Python 3.8+**

```bash
# Fastest — paying customers
npx sic-security

# Self-hosted
git clone https://github.com/DevCraftXCoder/SIC.git
cd SIC
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
      "args": ["/path/to/SIC/mcp_server.py"]
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

---

## Overview

SIC runs as a local server exposing an MCP interface for integration with any MCP-compatible client (Claude Code, Copilot, Cursor). All scan operations are IP-allowlisted to the home network. Scan output flows through a reporting pipeline that produces both a detailed security audit report and a SOC handoff HTML — with week-over-week posture tracking built in.

---

## Quick Start

```bash
# Paying customers — fastest path
npx sic-security

# Open dashboard
open http://localhost:9888
```

> **Entry point note:** the Flask app lives in `hexstrike_server.py`. `start_server.py`
> is a thin wrapper that loads `.env` and forces UTF-8 I/O before launching it — this is
> what PM2 (`ecosystem.config.cjs`) runs.

See [Installation & Setup](#installation--setup) above for all install paths (npx, manual, Docker, PM2) and full environment configuration.

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
