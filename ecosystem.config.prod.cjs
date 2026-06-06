// ============================================================================
//  PRODUCTION PM2 config for the SIC stack — SIC_ENV is "production" here.
//
//  Setting SIC_ENV: "production":
//    • selects the *_LIVE Stripe price IDs (STRIPE_PRICE_TEAM_LIVE, etc.),
//    • ENFORCES BILLING_API_KEY on the public-checkout / public-trial /
//      portal-by-email endpoints (in dev those endpoints fall through with a
//      warning when the key is unset — in production they 503 / 401 instead),
//    • activates the billing_server.py startup guards (SIC_SECRET_KEY +
//      BILLING_API_KEY required, SIC_WAITLIST_MODE must be off), and
//    • marks session/auth cookies "secure".
//
//  IMPORTANT — env precedence: billing_server.py loads sic/.env via
//  os.environ.setdefault, so any value already present in the PM2 `env` block
//  (like SIC_ENV below) WINS over .env. ALL SECRET VALUES live in sic/.env —
//  never hardcode a secret in this file. Required secret env var NAMES:
//    STRIPE_SECRET_KEY            (sk_live_...)
//    STRIPE_WEBHOOK_SECRET        (whsec_... — from the registered webhook)
//    STRIPE_PRICE_TEAM_LIVE       STRIPE_PRICE_TEAM_YEARLY_LIVE
//    STRIPE_PRICE_STUDIO_LIVE     STRIPE_PRICE_STUDIO_YEARLY_LIVE
//    BILLING_API_KEY             (M2M auth for public endpoints)
//    SIC_SECRET_KEY              (HMAC signing — bridged to SIC_AUTH_SECRET)
//    RESEND_API_KEY  SIC_ALERT_FROM  SIC_BASE_URL  (provisioning email)
//    DISCORD_WEBHOOK_URL         (billing alerts — optional)
//    SOC_FEED_SECRET             (soc-feed auth)
//
//  Before `pm2 start ecosystem.config.prod.cjs`:
//    1. Populate sic/.env with the LIVE secret values listed above.
//    2. Ensure SIC_WAITLIST_MODE is unset or "off" in sic/.env.
//    3. Register the Stripe webhook → /api/billing/webhook (the 8 handled
//       events) and set STRIPE_WEBHOOK_SECRET in sic/.env (operator task).
// ============================================================================
//
// Full interpreter path — never bare "python". A bare interpreter resolves
// via CreateProcess search order, which hits 0-byte stub files in System32 /
// cwd / WindowsApps before the real install and pops the Windows "Select an
// app to open 'python'" picker on every PM2 respawn.
const PYTHON = "C:/Users/J/AppData/Local/Programs/Python/Python312/python.exe";

module.exports = {
  apps: [
    {
      name: "sic-billing",
      script: "billing_server.py",
      cwd: "C:/Za/sic",
      interpreter: PYTHON,
      windowsHide: true,
      env: {
        // PRODUCTION: live Stripe keys/prices, BILLING_API_KEY enforced on the
        // public endpoints, startup guards active. All secret VALUES come from
        // sic/.env (loaded via os.environ.setdefault — this flag wins; .env
        // supplies the secrets). Never put a secret value in this file.
        SIC_ENV: "production",
      },
      max_memory_restart: "512M",
      error_file: "logs/billing-error.log",
      out_file: "logs/billing-out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
    {
      name: "sic-main",
      script: "start_server.py",
      cwd: "C:/Za/sic",
      interpreter: PYTHON,
      windowsHide: true,
      args: "--port 9890",
      env: {
        SIC_ENV: "production",
        SIC_PORT: "9888",
        HEXSTRIKE_PORT: "9890",
      },
      max_memory_restart: "1G",
      error_file: "logs/sic-error.log",
      out_file: "logs/sic-out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
    {
      name: "sic-mcp",
      script: "mcp_server.py",
      cwd: "C:/Za/sic",
      interpreter: PYTHON,
      windowsHide: true,
      // Docker sic-scanner container at :9888 has 85 working Linux pentest tools.
      // sic-main (:9890) is Windows-only and has 0 Linux tools. MCP must target Docker.
      args: "--server http://127.0.0.1:9888",
      env: {
        SIC_ENV: "production",
        HEXSTRIKE_SERVER: "http://127.0.0.1:9888",
        HEXSTRIKE_PORT: "9888",
      },
      max_memory_restart: "512M",
      error_file: "logs/sic-mcp-error.log",
      out_file: "logs/sic-mcp-out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
    {
      // Weekly SOC rollup — cron-only (Monday 9 AM), autorestart off.
      name: "sic-weekly-scan",
      script: "soc_rollup.py",
      cwd: "C:/Za/sic",
      interpreter: PYTHON,
      windowsHide: true,
      args: "--sync-incidents",
      autorestart: false,
      cron_restart: "0 9 * * 1",
      env: {
        PYTHONPATH: "C:/Za/sic",
        SIC_ENV: "production",
      },
      max_memory_restart: "256M",
      error_file: "logs/weekly-scan-error.log",
      out_file: "logs/weekly-scan-out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
    {
      // SOC rollup feed — serves findings JSON on 127.0.0.1:9016 for the admin
      // SystemsTab. Secret read from environment (set SOC_FEED_SECRET in .env).
      name: "sic-soc-feed",
      script: "soc_feed.py",
      cwd: "C:/Za/sic",
      interpreter: PYTHON,
      windowsHide: true,
      env: {
        PYTHONPATH: "C:/Za/sic",
        SIC_ENV: "production",
        SOC_FEED_SECRET: process.env.SOC_FEED_SECRET,
      },
      max_memory_restart: "128M",
      error_file: "logs/soc-feed-error.log",
      out_file: "logs/soc-feed-out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
  ],
};
