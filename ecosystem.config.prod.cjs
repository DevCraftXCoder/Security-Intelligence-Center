const PYTHON = "C:/Users/J/AppData/Local/Programs/Python/Python312/python.exe";
module.exports = {
  apps: [{
    name: "sic-billing",
    script: "billing_server.py",
    cwd: "C:/Za/sic",
    interpreter: PYTHON,
    windowsHide: true,
    env: { SIC_ENV: "production" },
    max_memory_restart: "512M",
    error_file: "logs/billing-error.log",
    out_file: "logs/billing-out.log",
    log_date_format: "YYYY-MM-DD HH:mm:ss",
  }],
};
