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

import collections as _collections  # noqa: E402
import threading as _threading  # noqa: E402
import time as _time  # noqa: E402

from flask import Flask, Response, jsonify, request  # noqa: E402
from billing import billing_bp, init_db  # noqa: E402

app = Flask(__name__)
app.register_blueprint(billing_bp)

# ---------------------------------------------------------------------------
# P1: Per-IP rate limit on /api/billing/checkout — 5 req/hour
# ---------------------------------------------------------------------------
_CHECKOUT_RL_WINDOW = 3600   # 1 hour
_CHECKOUT_RL_MAX = 5
_checkout_rl: dict[str, _collections.deque] = {}
_checkout_rl_lock = _threading.Lock()


def _checkout_rate_check(ip: str) -> bool:
    """Return True if within limit, False if exceeded."""
    now = _time.time()
    cutoff = now - _CHECKOUT_RL_WINDOW
    with _checkout_rl_lock:
        dq = _checkout_rl.get(ip)
        if dq is None:
            dq = _collections.deque(maxlen=_CHECKOUT_RL_MAX)
            _checkout_rl[ip] = dq
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= _CHECKOUT_RL_MAX:
            return False
        dq.append(now)
        return True


@app.before_request
def _checkout_rate_limit() -> None:  # type: ignore[return-value]
    """P1: Rate-limit /api/billing/checkout to 5 req/hour per IP."""
    if request.path != "/api/billing/checkout":
        return None  # type: ignore[return-value]
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if not _checkout_rate_check(client_ip):
        return jsonify({"error": "rate_limit_exceeded", "retry_after": _CHECKOUT_RL_WINDOW}), 429  # type: ignore[return-value]
    return None  # type: ignore[return-value]

# ---------------------------------------------------------------------------
# CORS — allow the SIC dashboard origins to reach the billing server
# ---------------------------------------------------------------------------

_CORS_ORIGINS = frozenset({
    "http://localhost:9888",
    "http://localhost:9889",
    "http://127.0.0.1:9888",
    "http://127.0.0.1:9889",
})


@app.after_request
def _add_cors_headers(response: Response) -> Response:
    origin = request.headers.get("Origin", "")
    if origin in _CORS_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, X-Billing-Key"
        )
    return response


@app.route("/api/billing/<path:path>", methods=["OPTIONS"])
def _billing_preflight(path: str) -> Response:  # noqa: ARG001
    resp = Response()
    origin = request.headers.get("Origin", "")
    if origin in _CORS_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, X-Billing-Key"
        )
    return resp


@app.route("/auth/me", methods=["OPTIONS"])
def _auth_me_preflight() -> Response:
    resp = Response()
    origin = request.headers.get("Origin", "")
    if origin in _CORS_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, X-Billing-Key"
        )
    return resp

@app.route("/health", methods=["GET"])
def _health() -> Response:
    from flask import jsonify
    return jsonify({"status": "ok", "service": "sic-billing"})


with app.app_context():
    init_db()

if __name__ == "__main__":
    port = int(os.environ.get("SIC_BILLING_PORT", "9015"))
    host = os.environ.get("SIC_HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=False, use_reloader=False)
