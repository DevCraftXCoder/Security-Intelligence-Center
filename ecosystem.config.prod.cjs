const PYTHON = "C:/Users/J/AppData/Local/Programs/Python/Python312/python.exe";
module.exports = {
  apps: [{
    name: "sic-billing",
    script: "billing_server.py",
    cwd: "C:/Za/sic",
    interpreter: PYTHON,
    windowsHide: true,
    env: {
      SIC_ENV: "production",
      // --- Email provisioning (Resend) ---
      // RESEND_API_KEY: "",        // fill in: your Resend API key
      // SIC_ALERT_FROM: "",        // fill in: e.g. "SIC <noreply@frxncois.com>"
      // SIC_BASE_URL: "https://sic-api.frxncois.com",  // magic link base (public tunnel)
      // --- Stats-server email logging ---
      // STATS_SERVER_URL: "https://stats.frxncois.com",  // fill in
      // STATS_SECRET: "",          // fill in: same secret as livestat STATS_SECRET
      // --- Discord alerts (optional) ---
      // DISCORD_BILLING_WEBHOOK: "",  // fill in: webhook URL for billing alerts
    },
    max_memory_restart: "512M",
    error_file: "logs/billing-error.log",
    out_file: "logs/billing-out.log",
    log_date_format: "YYYY-MM-DD HH:mm:ss",
  }],
};
