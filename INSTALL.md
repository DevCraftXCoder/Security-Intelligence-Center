# SIC — Installation Guide

SIC (Security Intelligence Center) is a self-hosted Python Flask security platform with 85 tools and 12+ AI-powered agents.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.8+ | Tested on 3.11 / 3.12 |
| Node.js + npm | 16+ | Required for PM2 process manager |
| PM2 | Any | Installed automatically by `install.sh` / `install.ps1` |
| Docker Desktop | Latest | Optional — required for the sandboxed `sic-scanner` container (85 Linux pentest tools) |

---

## Quick Install

### Linux / macOS

```bash
git clone https://github.com/DevCraftXCoder/SIC-private && cd SIC-private
chmod +x install.sh
./install.sh
```

### Windows (PowerShell)

```powershell
git clone https://github.com/DevCraftXCoder/SIC-private
cd SIC-private
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

The installer will:
1. Verify Python 3.8+ and Node.js 16+
2. Create a Python virtual environment (`venv/`)
3. Install core pip dependencies from `requirements-core.txt` (add `--full` for angr/pwntools/mitmproxy)
4. Generate `.env` from `.env.example` with auto-generated secrets
5. Install PM2 globally if missing
6. Start `sic-main`, `sic-mcp`, `sic-billing`, and `sic-soc-feed` via PM2

> **Ports:** The SIC Flask web dashboard (`sic-main`) runs on **port 9890** by default. The Docker `sic-scanner` health endpoint runs on **port 9888**. These are separate services — do not conflate them.

---

## Post-Install Configuration

After running the installer, open `.env` and fill in the values marked below.
Auto-generated secrets are already populated — do not change them unless you are rotating.

| Variable | Required | Source | Description |
|----------|----------|--------|-------------|
| `SIC_ADMIN_EMAILS` | YES | Your choice | Comma-separated admin emails that can receive magic-link logins. Magic-link auth is disabled for everyone if this is unset. |
| `RESEND_API_KEY` | YES | [resend.com/api-keys](https://resend.com/api-keys) | Enables provisioning emails after a customer pays. Without it, SIC logs a warning and fires a Discord alert instead. |
| `SIC_ALERT_FROM` | YES | Resend dashboard | Verified sender address on your Resend domain (e.g. `noreply@yourdomain.com`). |
| `STRIPE_SECRET_KEY` | YES | Stripe > Developers > API keys | `sk_test_...` for development, `sk_live_...` for production. |
| `STRIPE_WEBHOOK_SECRET` | YES | Stripe > Webhooks > signing secret | `whsec_...` — run `stripe listen --forward-to localhost:9015/api/billing/webhook` locally to get the test value. |
| `STRIPE_PRICE_TEAM` | YES | Stripe > Products | Test-mode price ID for the SIC Team tier. |
| `STRIPE_PRICE_TEAM_YEARLY` | YES | Stripe > Products | Test-mode yearly price ID. |
| `STRIPE_PRICE_STUDIO` | YES | Stripe > Products | Test-mode price ID for the SIC Studio tier. |
| `STRIPE_PRICE_STUDIO_YEARLY` | YES | Stripe > Products | Test-mode yearly price ID. |
| `STRIPE_PRICE_*_LIVE` | Prod only | Stripe > Products | Live-mode counterparts — only read when `SIC_ENV=production`. |
| `DISCORD_WEBHOOK_URL` | Optional | Discord > Server Settings > Integrations | Billing alerts (payment failures, provisioning skips). |
| `DISCORD_WEBHOOK_SOC` | Optional | Discord | SOC report channel notifications. |
| `OPENROUTER_API_KEY` | Optional | [openrouter.ai/keys](https://openrouter.ai/keys) | Powers AI grading and remediation guidance (`/api/ai/grade`). |
| `ALLOWED_TARGETS` | Optional | Your choice | Comma-separated hostnames you are authorised to scan. Defaults to loopback-only when empty. |
| `SIC_SECRET_KEY` | Auto-generated | installer | Flask session signing key — do not share. |
| `SIC_AUTH_SECRET` | Auto-generated | installer | Magic-link HMAC signing key — do not share. |
| `BILLING_API_KEY` | Auto-generated | installer | M2M secret between billing server and francois-landing proxy. |
| `SOC_FEED_SECRET` | Auto-generated | installer | SOC findings feed auth token. |

---

## Wiring BILLING_API_KEY to the Cloudflare Worker

The billing server and the `francois-landing` CF Worker share a secret. After running the installer:

1. Copy the value of `BILLING_API_KEY` from `sic/.env`
2. Set it as a CF Worker secret named `SIC_BILLING_KEY`:

```bash
cd francois-landing
wrangler secret put SIC_BILLING_KEY
# Paste the value from sic/.env when prompted
```

The worker reads `env.SIC_BILLING_KEY` and forwards it as `Authorization: Bearer <key>` to `localhost:9015`. The billing server validates it against `BILLING_API_KEY` in its `.env`. They must match exactly.

---

## Verifying the Install

```bash
# Main dashboard
curl http://localhost:9888/health

# Billing server
curl http://localhost:9015/health

# PM2 process list
pm2 status

# Tail logs
pm2 logs sic-main
pm2 logs sic-billing
```

A healthy response from `/health` looks like:

```json
{"status": "ok", "version": "6.0.1"}
```

---

## Optional: Cloudflare Tunnel (Remote Access)

Expose SIC externally via a Cloudflare Named Tunnel without opening firewall ports.

```bash
# One-time tunnel setup
cloudflared tunnel login
cloudflared tunnel create sic-api

# Create tunnel config at ~/.cloudflared/config.yml
# (replace TUNNEL_ID with the ID printed above)
cat > ~/.cloudflared/config.yml <<EOF
tunnel: TUNNEL_ID
credentials-file: /root/.cloudflared/TUNNEL_ID.json

ingress:
  - hostname: sic.yourdomain.com
    service: http://localhost:9888
  - hostname: sic-billing.yourdomain.com
    service: http://localhost:9015
  - service: http_status:404
EOF

# Route DNS
cloudflared tunnel route dns sic-api sic.yourdomain.com
cloudflared tunnel route dns sic-api sic-billing.yourdomain.com

# Run (or add to PM2)
cloudflared tunnel run sic-api
```

---

## Optional: Docker Scanner Container

The Docker `sic-scanner` container provides 85 Linux pentest tools in a sandboxed network:

```bash
# Build and start
docker compose -f docker/sic-scanner/docker-compose.yml up -d

# Verify
curl http://127.0.0.1:9888/health
```

The MCP server (`sic-mcp` PM2 process) targets this container at `http://127.0.0.1:9888` by default. The `sic-main` process serves the web dashboard on port 9890 (mapped via `start_server.py`).

Requires: `SIC_SECRET_KEY` in shell env before `docker compose up` (the compose file reads `${SIC_SECRET_KEY:?required}`).

---

## Troubleshooting

### PM2 process crashes on startup

```bash
pm2 logs sic-main --lines 50
```

Common causes:
- Missing required env vars (`SIC_ADMIN_EMAILS`, `SIC_SECRET_KEY`)
- Port conflict — `sic-main` (Flask dashboard) uses **port 9890**, `sic-billing` uses **port 9015**, and the Docker `sic-scanner` container uses **port 9888**. Check each separately:
  - Linux/Mac: `lsof -i :9890` / `lsof -i :9888`
  - Windows: `netstat -ano | findstr :9890` / `netstat -ano | findstr :9888`
- Python venv not activated — the ecosystem config uses an absolute interpreter path on Windows; on Linux/Mac the venv `python` is used. Ensure `venv/bin/python` (Linux/Mac) or `venv\Scripts\python.exe` (Windows) exists.

### Port conflict

Stop whatever is using the port, then:

```bash
pm2 restart sic-main
pm2 restart sic-billing
```

### Database not found

SIC creates its SQLite database on first run. If the `logs/` or data directory is missing:

```bash
mkdir -p logs
pm2 restart ecosystem.config.cjs
```

### pip install fails (binary deps)

Some packages (`pwntools`, `angr`, `mitmproxy`) have native components. On fresh systems:

```bash
# Debian/Ubuntu
sudo apt-get install -y build-essential libssl-dev libffi-dev python3-dev

# macOS (Homebrew)
brew install openssl libffi
```

Then re-run the installer or `pip install -r requirements.txt` inside the venv.

### Windows: "execution of scripts is disabled"

Run PowerShell as Administrator and execute:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then re-run the installer.

### Re-generate secrets

Delete `.env` and re-run the installer. All four auto-generated secrets will be regenerated. Remember to update `SIC_BILLING_KEY` in the CF Worker after regenerating `BILLING_API_KEY`.
