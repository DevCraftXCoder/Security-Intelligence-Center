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
      interpreter: PYTHON,
      windowsHide: true,
      env: {
        SIC_ENV: "development",
        SIC_PORT: "9888",
        HEXSTRIKE_PORT: "9890",
      },
      max_memory_restart: "512M",
      error_file: "logs/sic-mcp-error.log",
      out_file: "logs/sic-mcp-out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
    {
      name: "sic-billing",
      script: "billing_server.py",
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
  ],
};
