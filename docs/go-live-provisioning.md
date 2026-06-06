# SIC Go-Live Provisioning Guide

Last updated: 2026-06-06

---

## Prerequisites

- Stripe account with live keys + SIC price IDs configured
- Resend account with verified sender domain
- SIC installer `.zip` or `.exe` hosted at a stable URL (see `SIC_DOWNLOAD_URL`)

---

## 1. Set Secrets in `C:\Za\sic\.env`

All values must be non-empty. The billing server refuses to start in production if any are blank.

```bash
# Stripe live keys
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...

# Stripe price IDs (create in Stripe dashboard → Products → SIC)
STRIPE_TEAM_PRICE_ID=price_...       # Team plan monthly
STRIPE_STUDIO_PRICE_ID=price_...     # Studio plan monthly

# Stripe webhook secret — set AFTER step 3
STRIPE_WEBHOOK_SECRET=whsec_...

# Billing API auth (Claude Code app-to-billing-server)
BILLING_API_KEY=<generate: python -c "import secrets; print(secrets.token_urlsafe(32))">

# SIC token for app auth
SIC_SECRET_KEY=<generate: python -c "import secrets; print(secrets.token_urlsafe(32))">
SIC_AUTH_SECRET=<generate: python -c "import secrets; print(secrets.token_urlsafe(32))">

# Email (Resend)
RESEND_API_KEY=re_...
SIC_ALERT_FROM=noreply@frxncois.com   # must be a verified sender in Resend

# URLs
SIC_BASE_URL=https://frxncois.com/sic
SIC_DOWNLOAD_URL=https://frxncois.com/sic/download/sic-latest.zip

# Switch to production mode
SIC_ENV=production
SIC_WAITLIST_MODE=false
```

---

## 2. Set `SIC_BILLING_KEY` in francois-landing

Add to `C:\Za\francois-landing\.env.local`:

```bash
SIC_BILLING_KEY=<same value as BILLING_API_KEY above>
```

Then redeploy francois-landing:
```
! node C:/Za/francois-landing/scripts/deploy.cjs 2>&1
```

---

## 3. Register Stripe Webhook

In Stripe dashboard → **Developers → Webhooks → Add endpoint**:

- **Endpoint URL:** `https://frxncois.com/api/billing/webhook`
- **Events to listen for** (check all 8):
  - `checkout.session.completed`
  - `customer.subscription.created`
  - `customer.subscription.updated`
  - `customer.subscription.deleted`
  - `invoice.payment_succeeded`
  - `invoice.payment_failed`
  - `customer.updated`
  - `payment_intent.payment_failed`

After saving, Stripe shows the **Signing secret** (`whsec_...`). Copy it into `SIC_ENV` → `STRIPE_WEBHOOK_SECRET` in `.env`.

---

## 4. Start Production PM2 Stack

```bash
pm2 start C:/Za/sic/ecosystem.config.prod.cjs
pm2 save
```

This starts sic-billing in production mode. The startup guard in `billing_server.py` will FATAL if any required secret is missing — check `C:\Za\sic\logs\billing-error.log` if it fails to come up.

Verify:
```bash
curl http://127.0.0.1:9015/health
# Expected: {"service":"sic-billing","status":"ok","env":"production"}
```

---

## 5. Customer Setup (Distribute with Installer)

Customers must set two environment variables for the INSPECT widget's "spawn Claude" commands to work:

| Variable | Description | Example |
|----------|-------------|---------|
| `CLAUDE_BIN` | Full path to the `claude` binary | `C:\Users\Name\AppData\Roaming\npm\claude.cmd` |
| `SIC_PROJECT_DIR` | Path to the project SIC should analyze | `C:\Projects\my-app` |

Include in installer README / first-run wizard:

```
To complete SIC setup, set these variables in your system environment:

CLAUDE_BIN   = path to your claude.exe / claude.cmd
SIC_PROJECT_DIR = path to your project folder

Windows: System Properties → Advanced → Environment Variables
Mac/Linux: add to ~/.bashrc or ~/.zshrc
```

---

## 6. Post-Launch Verification Checklist

- [ ] `curl http://127.0.0.1:9015/health` → `status: ok, env: production`
- [ ] `curl https://frxncois.com/sic-signup` loads without "14-day free trial" text
- [ ] Stripe test checkout (`?test=1`) completes → subscription visible in Stripe dashboard
- [ ] Webhook fires → check Stripe dashboard → Webhooks → recent deliveries → 200
- [ ] Email receipt arrives from `SIC_ALERT_FROM` address
- [ ] Subscription expiry test: set `expires_at` in past → verify tier downgrades to `community`
- [ ] `pm2 save` run → confirm sic-billing in `C:\Users\J\.pm2\dump.pm2`

---

## Known Constraints

- `ecosystem.config.cjs` has `SIC_ENV: "development"` — this is the dev default. Production runs via `ecosystem.config.prod.cjs` which sets `SIC_ENV: "production"`.
- `pm2 restart sic-billing` does NOT reload ecosystem config — always use `pm2 delete sic-billing && pm2 start ecosystem.config.cjs --only sic-billing` when the config file changed.
- `SIC_WAITLIST_MODE=true` disables checkout and returns 503 — set to `false` before go-live.
