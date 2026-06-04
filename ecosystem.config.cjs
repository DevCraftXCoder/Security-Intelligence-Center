// ============================================================================
// ⚠️  SIC_ENV is "development" in every app below — this is a LOCAL DEV config.
//     For a LIVE billing deployment you MUST set SIC_ENV: "production", which:
//       • enforces BILLING_API_KEY on the public-checkout endpoint,
//       • uses the *_LIVE Stripe price IDs instead of test IDs,
//       • activates the SIC_SECRET_KEY startup guard, and
//       • refuses to start if SIC_WAITLIST_MODE is not "off".
//     Copy this file to ecosystem.config.prod.cjs, set SIC_ENV: "production"
//     and supply live secrets via .env before `pm2 start ecosystem.config.prod.cjs`.
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
      name: "sic-main",
      script: "start_server.py",
      cwd: "C:/Za/sic",
      interpreter: PYTHON,
      windowsHide: true,
      args: "--port 9890",
      env: {
        SIC_ENV: "development",
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
        SIC_ENV: "development",
        HEXSTRIKE_SERVER: "http://127.0.0.1:9888",
        HEXSTRIKE_PORT: "9888",
      },
      max_memory_restart: "512M",
      error_file: "logs/sic-mcp-error.log",
      out_file: "logs/sic-mcp-out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
    {
      name: "sic-billing",
      script: "billing_server.py",
      cwd: "C:/Za/sic",
      interpreter: PYTHON,
      windowsHide: true,
      env: {
        SIC_ENV: "development",
      },
      max_memory_restart: "512M",
      error_file: "logs/billing-error.log",
      out_file: "logs/billing-out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
    {
      // Weekly SOC rollup — links open P0/P1 findings to incidents (the
      // "scan + merge" step in this codebase). Cron-only: fires Monday 9 AM
      // and exits, so autorestart is off (otherwise PM2 would respawn it in a
      // tight loop after each run completes).
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
      },
      max_memory_restart: "256M",
      error_file: "logs/weekly-scan-error.log",
      out_file: "logs/weekly-scan-out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
    {
      // SOC rollup feed — serves findings JSON over HTTP on 127.0.0.1:9016 for
      // francois-landing's admin SystemsTab. Daemon (autorestart on).
      name: "sic-soc-feed",
      script: "soc_feed.py",
      cwd: "C:/Za/sic",
      interpreter: PYTHON,
      windowsHide: true,
      env: {
        PYTHONPATH: "C:/Za/sic",
        SIC_ENV: "development",
        SOC_FEED_SECRET: "tXs-LuKirSgI9DwkzlXXMIQsqsGXJgnRO1tI5KPmGxU",
      },
      max_memory_restart: "128M",
      error_file: "logs/soc-feed-error.log",
      out_file: "logs/soc-feed-out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
  ],
};
