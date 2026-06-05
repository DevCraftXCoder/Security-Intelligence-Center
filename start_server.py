#!/usr/bin/env python
"""
Wrapper that loads C:/Za/sic/.env before starting the SIC main server.

PM2 does not load .env automatically — this shim bridges that gap.
Also sets PYTHONUTF8=1 so emoji in log messages don't crash on Windows cp1252.

Usage (via PM2):
    pm2 start start_server.py --name sic-main --interpreter python --cwd C:/Za/sic -- --port 9890
"""

import os
import sys
from pathlib import Path

# Force UTF-8 I/O so emoji in log messages (BANNER, worker thread messages)
# don't trigger UnicodeEncodeError on Windows cp1252 stdout/stderr.
os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

# Reconfigure stdout/stderr to UTF-8 now that the env vars are set
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Load .env from the same directory as this script (C:/Za/sic/.env)
_env_path = Path(__file__).parent / ".env"
if _env_path.is_file():
    from dotenv import load_dotenv
    load_dotenv(_env_path, override=False)  # override=False: shell/PM2 env takes precedence

# Default SIC_ENV to development so the server doesn't require SIC_IP_ALLOWLIST override
# when running locally. SIC_SECRET_KEY is supplied by .env.
if not os.environ.get("SIC_ENV"):
    os.environ["SIC_ENV"] = "development"

# Now import and run the server module as __main__.
# runpy executes hexstrike_server.py with __name__ == "__main__" so that the
# argparse + app.run() block at the bottom (and the production startup guards:
# DEBUG_MODE + SIC_WAITLIST_MODE + SIC_SECRET_KEY) fire correctly.
# NOTE: the Flask app lives in hexstrike_server.py — there is no server.py.
import runpy  # noqa: E402
runpy.run_path(str(Path(__file__).parent / "hexstrike_server.py"), run_name="__main__")
