"""billing_server.py — Standalone SIC billing server.

Serves only /api/billing/ routes via the billing Flask blueprint.
Loads env vars from sic/.env so PM2 config stays secret-free.
Runs on SIC_BILLING_PORT (default 9015).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Load .env before any other import (billing/__init__.py checks env at import)
# ---------------------------------------------------------------------------

_ENV_FILE = Path(__file__).parent / ".env"


def _load_env(path: Path) -> None:
    if not path.exists():
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            # Skip blanks, comments, and continuation-like lines (no = at start)
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", stripped)
            if not m:
                continue
            key, value = m.group(1), m.group(2).strip()
            # Unquote if wrapped in single or double quotes
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            os.environ.setdefault(key, value)


_load_env(_ENV_FILE)

# ---------------------------------------------------------------------------
# Ensure sic/ is on the path so `from auth import ...` works in billing/routes.py
# ---------------------------------------------------------------------------

_SIC_DIR = str(Path(__file__).parent)
if _SIC_DIR not in sys.path:
    sys.path.insert(0, _SIC_DIR)

# ---------------------------------------------------------------------------
# Build Flask app with only the billing blueprint
# ---------------------------------------------------------------------------

from flask import Flask  # noqa: E402
from billing import billing_bp, init_db  # noqa: E402

app = Flask(__name__)
app.register_blueprint(billing_bp)

with app.app_context():
    init_db()

if __name__ == "__main__":
    port = int(os.environ.get("SIC_BILLING_PORT", "9015"))
    host = os.environ.get("SIC_HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=False, use_reloader=False)
