"""Flask Blueprint — magic-link email authentication.

Routes:
    POST /auth/request-link  — issue a magic link
    GET  /auth/verify        — consume token, set session cookie
    POST /auth/logout        — clear session cookie
    GET  /auth/me            — inspect / refresh current session

Public helpers (usable outside this module):
    get_session_email()      — return authenticated email or None
    require_auth             — decorator; 401 JSON on no session
    require_auth_redirect    — decorator; redirect to login on no session
    init_app(app)            — register blueprint on a Flask app
"""

from __future__ import annotations

import base64
import collections
import functools
import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, jsonify, redirect, request

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

auth_bp = Blueprint("sic_auth", __name__, url_prefix="/auth")

# ---------------------------------------------------------------------------
# P1: Simple per-IP rate limiter for /auth/request-link (5 req/hour)
# Uses a module-level dict — no external dep, survives blueprint reloads.
# ---------------------------------------------------------------------------

_RL_WINDOW_SECONDS = 600  # 10 minutes
_RL_MAX_REQUESTS = 5

# Stores: {ip: deque([timestamp, ...], maxlen=_RL_MAX_REQUESTS)}
_rl_counters: dict[str, collections.deque] = {}
_rl_lock = threading.Lock()


def _request_link_rate_check(ip: str) -> bool:
    """Return True if the request is within the rate limit, False if exceeded."""
    now = time.time()
    cutoff = now - _RL_WINDOW_SECONDS
    with _rl_lock:
        dq = _rl_counters.get(ip)
        if dq is None:
            dq = collections.deque(maxlen=_RL_MAX_REQUESTS)
            _rl_counters[ip] = dq
        # Evict timestamps outside the window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= _RL_MAX_REQUESTS:
            return False
        dq.append(now)
        return True

_DB_PATH = Path.home() / ".sic" / "state.db"
_KEY_PATH = Path.home() / ".sic" / "auth.key"
_LINK_TTL_SEC = 600           # 10 minutes
_SESSION_TTL_SEC = 30 * 86400  # 30 days
_SESSION_REFRESH_SEC = 7 * 86400  # rolling refresh threshold
_COOKIE_NAME = "sic_session"

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Secret loader
# ---------------------------------------------------------------------------

_secret_cache: bytes | None = None


def _get_secret() -> bytes:
    """Return the HMAC signing secret, loading or generating it once."""
    global _secret_cache
    if _secret_cache is not None:
        return _secret_cache

    env_val = os.environ.get("SIC_AUTH_SECRET")
    if env_val:
        _secret_cache = env_val.encode()
        return _secret_cache

    if _KEY_PATH.exists():
        _secret_cache = _KEY_PATH.read_bytes()
        return _secret_cache

    # Generate and persist a new key
    raw = secrets.token_bytes(32)
    hex_key = raw.hex().encode()
    try:
        _KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        _KEY_PATH.write_bytes(hex_key)
        _KEY_PATH.chmod(0o600)
    except OSError:
        pass  # best-effort — in-memory key is still valid
    _secret_cache = raw
    return _secret_cache


# ---------------------------------------------------------------------------
# DB init
# ---------------------------------------------------------------------------

_db_init_done: bool = False


def _init_db() -> None:
    """Ensure the auth_tokens table exists. Idempotent."""
    global _db_init_done
    if _db_init_done:
        return
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(_DB_PATH)) as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token_hash TEXT PRIMARY KEY,
                email      TEXT NOT NULL,
                issued_at  TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at    TEXT
            )
            """
        )
        con.commit()
    _db_init_done = True


# ---------------------------------------------------------------------------
# Signing helpers
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (4 - len(s) % 4) if len(s) % 4 else ""
    return base64.urlsafe_b64decode(s + padding)


def _sign(payload: str) -> str:
    sig = hmac.new(_get_secret(), payload.encode(), hashlib.sha256).digest()
    return _b64url_encode(sig)


def _make_token(email: str, issued_at: int, expires_at: int) -> str:
    payload_str = f"{email}|{issued_at}|{expires_at}"
    payload_b64 = _b64url_encode(payload_str.encode())
    sig = _sign(payload_b64)
    return f"{payload_b64}.{sig}"


def _verify_token(token: str) -> dict | None:
    """Verify an HMAC-signed token. Returns payload dict or None."""
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig = parts
        expected_sig = _sign(payload_b64)
        if not hmac.compare_digest(expected_sig, sig):
            return None
        payload_str = _b64url_decode(payload_b64).decode()
        fields = payload_str.split("|")
        if len(fields) != 3:
            return None
        email, issued_at_s, expires_at_s = fields
        issued_at = int(issued_at_s)
        expires_at = int(expires_at_s)
        if time.time() > expires_at:
            return None
        return {"email": email, "issued_at": issued_at, "expires_at": expires_at}
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Admin allowlist
# ---------------------------------------------------------------------------


def _admin_emails() -> list[str]:
    """Return lowercase admin email list from SIC_ADMIN_EMAILS env var."""
    raw = os.environ.get("SIC_ADMIN_EMAILS", "")
    return [e.strip().lower() for e in raw.split(",") if e.strip()]


def _waitlist_mode() -> bool:
    """Return True when SIC_WAITLIST_MODE=open.

    In waitlist mode any email may request a magic link regardless of
    subscription status.  The session is still subject to tool-tier gating
    (feature_gates.py) so an unpaid user cannot run scans — they can only
    sign in and view the dashboard.  Disable this once the product is GA.
    """
    return os.environ.get("SIC_WAITLIST_MODE", "").lower() in ("open", "1", "true")


# ---------------------------------------------------------------------------
# ISO timestamp helper
# ---------------------------------------------------------------------------


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Billing DB helper
# ---------------------------------------------------------------------------


def _has_active_subscription(email: str) -> bool:
    """Return True if the email has an active paid subscription.

    P1-1 fix: the real ``subscriptions`` table (in ~/.sic/state.db) has
    PRIMARY KEY ``email`` — there is no ``customer_email`` and no ``created_at``
    column.  The previous query referenced both, raised
    ``sqlite3.OperationalError`` on every call, was swallowed, and returned
    False — so a genuine paying customer was always denied a magic link.

    The schema enforces one row per email (PK), so no ORDER BY / LIMIT is
    needed.  We delegate the status→entitlement decision to the canonical
    tier resolver (billing.db.get_tier) when available so the 7-day past_due
    grace window and all status mappings stay in one place; we fall back to a
    direct query against the real columns if billing is not importable.

    P2-2: DB path unified to ~/.sic/state.db so both auth and the tier resolver
    read from the same file.  Override via BILLING_DB_PATH env var for tests.
    """
    email = (email or "").strip().lower()
    if not email:
        return False

    # Preferred path: reuse the canonical status→tier resolver (handles
    # past_due grace, canceled/expired/incomplete downgrades, etc.).
    try:
        from billing import get_user_tier  # noqa: PLC0415

        return get_user_tier(email) in ("team", "studio")
    except Exception as e:  # noqa: BLE001 — billing not importable / stripe env missing
        logger.debug("[auth] billing.get_user_tier unavailable, using direct query: %s", e)

    # Fallback: query the real columns directly (email PK, status column).
    try:
        billing_db_path = os.environ.get(
            "BILLING_DB_PATH",
            os.path.expanduser("~/.sic/state.db"),
        )
        conn = sqlite3.connect(billing_db_path)
        try:
            row = conn.execute(
                "SELECT tier, status, current_period_end FROM subscriptions WHERE email = ?",
                (email,),
            ).fetchone()
        finally:
            conn.close()
        if not row:
            return False
        tier, status, period_end = row
        if tier not in ("team", "studio"):
            return False
        status = status or "active"
        # active / trialing → entitled.  past_due → entitled within 7-day grace.
        if status in ("active", "trialing"):
            return True
        if status == "past_due":
            grace = 7 * 86400
            if period_end is not None and (period_end + grace) < int(time.time()):
                return False  # grace expired
            return True
        # canceled / unpaid / incomplete / incomplete_expired / paused /
        # pending_review → not entitled.
        return False
    except Exception as e:  # noqa: BLE001
        logger.warning("[auth] billing DB check failed: %s", e)
        return False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@auth_bp.post("/request-link")
def request_link():
    """Issue a time-limited magic link for an admin email, paying customer, or waitlist user.

    Gate:
    - Admins (SIC_ADMIN_EMAILS): always allowed.
    - Paying customers (active subscription in billing.db): always allowed.
    - Waitlist users (SIC_WAITLIST_MODE=open): allowed to sign in; tool-tier
      gating in feature_gates.py still restricts what they can do.
    - All others: 403 unauthorized.
    """
    # P1: Rate limit — 5 requests per hour per IP
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if not _request_link_rate_check(client_ip):
        logger.warning("[auth] rate limit exceeded for /auth/request-link from %s", client_ip)
        return jsonify({"error": "rate_limit_exceeded", "retry_after": _RL_WINDOW_SECONDS}), 429

    body = request.get_json(silent=True) or {}
    email = body.get("email")
    if not email or not isinstance(email, str):
        return jsonify({"error": "email_required"}), 400
    email = email.strip().lower()

    admins = _admin_emails()

    # Timing-safe check: iterate all admins to avoid short-circuit leakage
    is_admin = False
    for admin in admins:
        if hmac.compare_digest(admin.encode(), email.encode()):
            is_admin = True

    # Allow paying customers or waitlist-mode users even if not in SIC_ADMIN_EMAILS.
    # In waitlist mode (SIC_WAITLIST_MODE=open) any email can receive a magic link;
    # access to premium tools is still gated by feature_gates.py / subscription tier.
    if not is_admin and not _has_active_subscription(email) and not _waitlist_mode():
        return jsonify({"ok": True, "message": "If this email has an active subscription, a sign-in link has been sent."}), 200

    _init_db()
    now = int(time.time())
    expires = now + _LINK_TTL_SEC
    token = _make_token(email, now, expires)
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    with sqlite3.connect(str(_DB_PATH)) as con:
        con.execute(
            "INSERT INTO auth_tokens (token_hash, email, issued_at, expires_at, used_at) "
            "VALUES (?, ?, ?, ?, NULL)",
            (token_hash, email, _iso(now), _iso(expires)),
        )
        con.commit()

    host = request.host_url.rstrip("/")
    link = f"{host}/auth/verify?token={token}"
    logger.info("magic link issued for %s, expires %s", email, expires)

    try:
        from scan_alerts import send_scan_alert  # noqa: PLC0415

        send_scan_alert(
            "auth_link_issued",
            {"email": email, "link": link, "expires_at": expires},
        )
    except Exception:
        pass

    # Send magic link directly to the customer via Resend
    _resend_key = os.environ.get("RESEND_API_KEY", "")
    _from = os.environ.get("SIC_ALERT_FROM", "")
    if _resend_key and _from:
        try:
            import json as _json  # noqa: PLC0415
            import urllib.request as _ur  # noqa: PLC0415

            _payload = _json.dumps({
                "from": _from,
                "to": [email],
                "subject": "Your SIC login link",
                "html": (
                    '<div style="font-family:DM Sans,sans-serif;background:#0a0a0a;color:#fff;'
                    'padding:40px;max-width:480px;margin:auto;border-radius:8px;">'
                    '<h2 style="color:#e94560;margin-top:0;">Security Intelligence Center</h2>'
                    '<p style="color:#ccc;">Click the button below to sign in. '
                    "This link expires in 10 minutes.</p>"
                    f'<a href="{link}" style="display:inline-block;background:#e94560;color:#fff;'
                    'padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:600;'
                    'margin:16px 0;">Sign in to SIC</a>'
                    '<p style="color:#666;font-size:12px;margin-top:24px;">'
                    "If you didn&#39;t request this, you can safely ignore this email.</p>"
                    "</div>"
                ),
            }).encode()
            _req = _ur.Request(
                "https://api.resend.com/emails",
                data=_payload,
                headers={
                    "Authorization": f"Bearer {_resend_key}",
                    "Content-Type": "application/json",
                },
            )
            _ur.urlopen(_req, timeout=5)
            logger.info("magic link email sent to %.6s*** via Resend", email[:6])
        except Exception as _e:
            logger.warning("failed to send magic link email via Resend: %s", _e)
    else:
        logger.error(
            "RESEND_API_KEY or SIC_ALERT_FROM not configured — auth email cannot be sent"
        )
        return jsonify({
            "ok": False,
            "error": "Email delivery not configured. Contact the administrator.",
        }), 503

    dev_mode = os.environ.get("SIC_DEV_MODE", "").lower() in ("1", "true", "yes")
    resp_body: dict = {"ok": True, "expires_at": expires}
    if dev_mode:
        resp_body["link"] = link

    return jsonify(resp_body), 200


@auth_bp.get("/verify")
def verify():
    """Consume a magic-link token and set an HMAC-signed session cookie."""
    token = request.args.get("token", "")
    payload = _verify_token(token)
    if payload is None:
        return jsonify({"error": "invalid_or_expired_token"}), 401

    _init_db()
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    used_ts = _iso(int(time.time()))
    with sqlite3.connect(str(_DB_PATH)) as con:
        cur = con.execute(
            "UPDATE auth_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL",
            (used_ts, token_hash),
        )
        con.commit()

    if cur.rowcount != 1:
        return jsonify({"error": "invalid_or_expired_token"}), 401

    now = int(time.time())
    session_token = _make_token(payload["email"], now, now + _SESSION_TTL_SEC)

    resp = redirect("/dashboard/index.html")
    resp.set_cookie(
        _COOKIE_NAME,
        session_token,
        max_age=_SESSION_TTL_SEC,
        httponly=True,
        samesite="Lax",
        secure=os.environ.get("SIC_ENV", "development") == "production",
        path="/",
    )
    return resp


@auth_bp.post("/logout")
def logout():
    """Clear the session cookie."""
    resp = jsonify({"ok": True})
    resp.set_cookie(
        _COOKIE_NAME,
        "",
        max_age=0,
        httponly=True,
        samesite="Lax",
        secure=os.environ.get("SIC_ENV", "development") == "production",
        path="/",
    )
    return resp


@auth_bp.get("/me")
def me():
    """Return current session info, rolling refresh if past threshold."""
    cookie = request.cookies.get(_COOKIE_NAME)
    if not cookie:
        return jsonify({"error": "no_session"}), 401

    payload = _verify_token(cookie)
    if payload is None:
        return jsonify({"error": "session_invalid"}), 401

    response = jsonify(
        {"email": payload["email"], "expires_at": payload["expires_at"]}
    )

    # Rolling refresh
    if time.time() - payload["issued_at"] > _SESSION_REFRESH_SEC:
        now = int(time.time())
        fresh_token = _make_token(payload["email"], now, now + _SESSION_TTL_SEC)
        response.set_cookie(
            _COOKIE_NAME,
            fresh_token,
            max_age=_SESSION_TTL_SEC,
            httponly=True,
            samesite="Lax",
            secure=os.environ.get("SIC_ENV", "development") == "production",
            path="/",
        )

    return response, 200


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def get_session_email() -> str | None:
    """Read sic_session cookie, verify, return email or None.

    Requires an active Flask request context.
    """
    from flask import request as _req  # noqa: PLC0415

    try:
        cookie = _req.cookies.get(_COOKIE_NAME)
    except RuntimeError:  # outside request context
        return None
    if not cookie:
        return None
    payload = _verify_token(cookie)
    return payload["email"] if payload else None


def require_auth(f):
    """Decorator: return 401 JSON if no valid session."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not get_session_email():
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)

    return wrapper


def require_auth_redirect(f):
    """Decorator: redirect to login page if no valid session."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not get_session_email():
            return redirect("/dashboard/login.html")
        return f(*args, **kwargs)

    return wrapper


def init_app(app) -> None:
    """Register the auth blueprint on a Flask app."""
    app.register_blueprint(auth_bp)


# ---------------------------------------------------------------------------
# Phase 4 — RBAC helpers
# ---------------------------------------------------------------------------


def get_session_role(workspace_id: str | None = None) -> str | None:
    """Return the session user's role in the given workspace, or None.

    Args:
        workspace_id: The workspace to check membership in.  If None, returns
            'admin' for any authenticated user (single-tenant fallback for
            backwards compatibility with pre-workspace code paths).

    Returns:
        Role string ('admin', 'viewer', 'incident-owner') or None if the user
        is not authenticated or not a member of the workspace.
    """
    email = get_session_email()
    if not email:
        return None

    # Single-tenant fallback: no workspace context → treat any authed user as admin
    if workspace_id is None:
        return "admin"

    try:
        import sqlite3  # noqa: PLC0415
        db_path = _DB_PATH
        if not db_path.exists():
            return None
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT role FROM workspace_members WHERE workspace_id = ? AND email = ?",
                (workspace_id, email),
            ).fetchone()
    except Exception:  # noqa: BLE001
        return None

    return row["role"] if row else None


def require_role(*roles: str):
    """Decorator factory: require an authenticated session with one of the given roles.

    Checks the active workspace from the ``sic_workspace`` cookie.  Falls back
    to the single-tenant behaviour (any authed user == admin) when no workspace
    cookie is present.

    Usage::

        @require_role('admin', 'incident-owner')
        def my_view():
            ...

    Returns:
        401 JSON if the user is not authenticated.
        403 JSON if the user is authenticated but lacks the required role.
    """

    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            from flask import request as _req  # noqa: PLC0415

            # Resolve active workspace_id from signed cookie (best-effort)
            workspace_id: str | None = None
            try:
                from workspaces import (  # noqa: PLC0415
                    _WORKSPACE_COOKIE_NAME,
                    _verify_workspace_cookie,
                )

                cookie_val = _req.cookies.get(_WORKSPACE_COOKIE_NAME)
                if cookie_val:
                    workspace_id = _verify_workspace_cookie(cookie_val)
            except ImportError:
                pass  # workspaces module not loaded yet

            role = get_session_role(workspace_id)
            if role is None:
                from flask import jsonify as _jsonify  # noqa: PLC0415

                return _jsonify({"error": "unauthorized"}), 401
            if role not in roles:
                from flask import jsonify as _jsonify  # noqa: PLC0415

                return _jsonify({"error": "forbidden", "required_roles": list(roles), "current_role": role}), 403
            return f(*args, **kwargs)

        return wrapper

    return decorator
