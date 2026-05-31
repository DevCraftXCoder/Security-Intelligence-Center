module.exports = {
  apps: [
    {
      name: "sic",
      script: "server.py",
      interpreter: "python",
      env: {
        SIC_ENV: "development",
      },
      max_memory_restart: "1G",
      error_file: "logs/sic-error.log",
      out_file: "logs/sic-out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
    {
      name: "sic-billing",
      script: "billing_server.py",
      interpreter: "python",
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
