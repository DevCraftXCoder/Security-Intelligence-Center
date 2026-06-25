"""
api_tokens.py — Flask Blueprint for per-workspace API token management.

Each token is scoped to a workspace (or personal if workspace_id is None).
Raw tokens are shown ONCE at creation; only the sha256 hash is stored.

Table created (idempotent):
  - api_tokens

Routes (URL prefix /api/tokens):
  GET    /api/tokens           — list active tokens for the session user
  GET    /api/tokens/expiring  — tokens expiring within 7 days
  POST   /api/tokens           — create a new token (returns raw token once)
  DELETE /api/tokens/<id>      — revoke a token

Public helper:
  verify_api_token(raw_token)  — validate & update last_used_at; returns row or None
  api_tokens_init_db()         — idempotent schema creation; call from app startup
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Blueprint, abort, jsonify, request

from feature_gates import require_tier, TIER_LIMITS, current_user_tier

api_tokens_bp = Blueprint("sic_api_tokens", __name__, url_prefix="/api")

_DB_PATH = Path.home() / ".sic" / "state.db"
_db_init_done: bool = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _nanoid() -> str:
    """Return a URL-safe 20-character random ID."""
    return secrets.token_urlsafe(15)[:20]


def _iso_now() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat()


def _db_path() -> Path:
    """Ensure DB parent directory exists and return the DB path."""
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return _DB_PATH


def _connect() -> sqlite3.Connection:
    """Return a sqlite3 connection with Row factory, WAL mode, and busy timeout."""
    conn = sqlite3.connect(str(_db_path()))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _hash_token(raw: str) -> str:
    """Return sha256 hex digest of the raw token."""
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# DB init
# ---------------------------------------------------------------------------


def api_tokens_init_db() -> None:
    """Create api_tokens table and indexes.  Idempotent."""
    global _db_init_done
    if _db_init_done:
        return
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_tokens (
                id           TEXT PRIMARY KEY,
                workspace_id TEXT,
                name         TEXT NOT NULL,
                token_hash   TEXT NOT NULL UNIQUE,
                token_prefix TEXT NOT NULL,
                scopes       TEXT NOT NULL DEFAULT 'read',
                created_by   TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                expires_at   TEXT,
                last_used_at TEXT,
                revoked_at   TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_api_tokens_created_by"
            " ON api_tokens(created_by)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_api_tokens_workspace"
            " ON api_tokens(workspace_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_api_tokens_hash"
            " ON api_tokens(token_hash)"
        )
        conn.commit()
    _db_init_done = True


# ---------------------------------------------------------------------------
# Auth gate
# ---------------------------------------------------------------------------


def _require_auth() -> str:
    """Abort 401 if no authenticated session.  Returns email on success."""
    try:
        from auth import get_session_email  # noqa: PLC0415
    except ImportError:
        abort(401)
        return ""  # unreachable — satisfies type checker
    email = get_session_email()
    if not email:
        abort(401)
    return email  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Public helper — token verification (importable by other modules)
# ---------------------------------------------------------------------------

_VALID_SCOPES = {"read", "write", "admin"}


def verify_api_token(raw_token: str, required_scope: str | None = None) -> dict | None:
    """Return token row dict if valid (not revoked, not expired, scope satisfied), else None.

    Also updates last_used_at in a best-effort background thread so the
    calling path is not blocked by a DB write.

    Args:
        raw_token: The raw ``sic_`` prefixed token string.
        required_scope: If provided, the token's ``scopes`` JSON list must contain
            this value. Returns None if the scope is missing (H4: API token scope
            enforcement).

    Returns:
        Token row as a plain dict (keys: id, workspace_id, name, token_prefix,
        scopes, created_by, created_at, expires_at, last_used_at, revoked_at),
        or None if the token is invalid, revoked, expired, or lacks required scope.
    """
    api_tokens_init_db()
    if not raw_token:
        return None
    h = _hash_token(raw_token)
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM api_tokens WHERE token_hash = ?", (h,)
        ).fetchone()
    if row is None:
        return None

    token = dict(row)

    # Revoked?
    if token.get("revoked_at") is not None:
        return None

    # Expired?
    expires_at = token.get("expires_at")
    if expires_at is not None:
        try:
            exp_dt = datetime.fromisoformat(expires_at)
            if datetime.now(tz=timezone.utc) > exp_dt:
                return None
        except ValueError:
            return None

    # H4: scope check — if caller requires a specific scope, verify the token grants it
    if required_scope is not None:
        import json as _json  # noqa: PLC0415
        raw_scopes = token.get("scopes") or "[]"
        try:
            token_scopes: list = _json.loads(raw_scopes) if isinstance(raw_scopes, str) else list(raw_scopes)
        except (ValueError, TypeError):
            token_scopes = []
        if required_scope not in token_scopes:
            return None

    # Update last_used_at asynchronously — non-blocking
    def _update_last_used() -> None:
        try:
            with _connect() as c:
                c.execute(
                    "UPDATE api_tokens SET last_used_at = ? WHERE id = ?",
                    (_iso_now(), token["id"]),
                )
                c.commit()
        except Exception:  # noqa: BLE001
            pass

    threading.Thread(target=_update_last_used, daemon=True).start()

    return token


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@api_tokens_bp.get("/tokens")
def list_tokens_route():
    """GET /api/tokens — list non-revoked tokens for the session user.

    Also fires best-effort expiry warnings for tokens expiring within 7 days.
    Never returns raw token values — only prefix, metadata, and scopes.
    """
    email = _require_auth()
    api_tokens_init_db()

    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, workspace_id, name, token_prefix, scopes, created_at,
                   expires_at, last_used_at
              FROM api_tokens
             WHERE created_by = ?
               AND revoked_at IS NULL
             ORDER BY created_at DESC
            """,
            (email,),
        ).fetchall()

    tokens = [dict(r) for r in rows]

    # Best-effort expiry warning — non-blocking thread
    def _fire_expiry_warnings(token_list: list[dict]) -> None:
        soon = datetime.now(tz=timezone.utc) + timedelta(days=7)
        for tok in token_list:
            exp = tok.get("expires_at")
            if not exp:
                continue
            try:
                exp_dt = datetime.fromisoformat(exp)
                if datetime.now(tz=timezone.utc) < exp_dt <= soon:
                    try:
                        from scan_alerts import send_scan_alert  # noqa: PLC0415
                        send_scan_alert(
                            "token_expiry_warning",
                            {
                                "token_id": tok["id"],
                                "token_name": tok["name"],
                                "token_prefix": tok["token_prefix"],
                                "expires_at": exp,
                                "owner": email,
                            },
                        )
                    except Exception:  # noqa: BLE001
                        pass
            except ValueError:
                pass

    threading.Thread(
        target=_fire_expiry_warnings,
        args=(tokens,),
        daemon=True,
    ).start()

    return jsonify({"tokens": tokens, "count": len(tokens)})


@api_tokens_bp.get("/tokens/expiring")
def list_expiring_tokens_route():
    """GET /api/tokens/expiring — tokens expiring within 7 days."""
    email = _require_auth()
    api_tokens_init_db()

    now_str = _iso_now()
    cutoff_str = (datetime.now(tz=timezone.utc) + timedelta(days=7)).isoformat()

    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, workspace_id, name, token_prefix, scopes, created_at,
                   expires_at, last_used_at
              FROM api_tokens
             WHERE created_by = ?
               AND revoked_at IS NULL
               AND expires_at IS NOT NULL
               AND expires_at > ?
               AND expires_at <= ?
             ORDER BY expires_at ASC
            """,
            (email, now_str, cutoff_str),
        ).fetchall()

    return jsonify({"tokens": [dict(r) for r in rows]})


@api_tokens_bp.post("/tokens")
@require_tier("community")
def create_token_route():
    """POST /api/tokens — create a new API token.

    Body: {name, workspace_id?, scopes?, expires_in_days?}
    Returns the raw token ONCE in the response.  It is not stored.
    """
    email = _require_auth()
    api_tokens_init_db()

    # Per-tier token count enforcement
    tier = current_user_tier()
    token_limit = TIER_LIMITS.get(tier, TIER_LIMITS["community"]).get("api_tokens", 1)
    if token_limit != -1:
        with _connect() as conn:
            active_count = conn.execute(
                "SELECT COUNT(*) FROM api_tokens WHERE created_by = ? AND revoked_at IS NULL",
                (email,),
            ).fetchone()[0]
        if active_count >= token_limit:
            return jsonify({"error": "token_limit_reached", "limit": token_limit, "tier": tier}), 403

    body = request.get_json(silent=True) or {}
    name = body.get("name")
    workspace_id = body.get("workspace_id")  # optional
    scopes_raw = body.get("scopes", "read")
    expires_in_days = body.get("expires_in_days")

    if not name or not isinstance(name, str) or not name.strip():
        return jsonify({"error": "name_required"}), 400
    name = name.strip()

    # Validate scopes
    if isinstance(scopes_raw, list):
        scopes_list = [s.strip() for s in scopes_raw if isinstance(s, str)]
    else:
        scopes_list = [s.strip() for s in str(scopes_raw).split(",") if s.strip()]

    invalid_scopes = [s for s in scopes_list if s not in _VALID_SCOPES]
    if invalid_scopes:
        return jsonify({"error": "scope_invalid", "invalid": invalid_scopes, "valid": sorted(_VALID_SCOPES)}), 400
    if not scopes_list:
        scopes_list = ["read"]
    scopes = ",".join(sorted(scopes_list))

    # Validate workspace membership if workspace_id provided
    if workspace_id is not None:
        if not isinstance(workspace_id, str) or not workspace_id.strip():
            return jsonify({"error": "workspace_id_invalid"}), 400
        workspace_id = workspace_id.strip()
        with _connect() as conn:
            member = conn.execute(
                "SELECT email FROM workspace_members WHERE workspace_id = ? AND email = ?",
                (workspace_id, email),
            ).fetchone()
        if member is None:
            return jsonify({"error": "not_a_member_of_workspace"}), 403

    # Validate expires_in_days
    expires_at: str | None = None
    if expires_in_days is not None:
        try:
            days = int(expires_in_days)
            if days <= 0:
                return jsonify({"error": "expires_in_days_must_be_positive"}), 400
            expires_at = (datetime.now(tz=timezone.utc) + timedelta(days=days)).isoformat()
        except (TypeError, ValueError):
            return jsonify({"error": "expires_in_days_invalid"}), 400

    # Generate token: sic_ + 32-char random
    raw_token = "sic_" + secrets.token_urlsafe(24)[:32]
    token_hash = _hash_token(raw_token)
    token_prefix = raw_token[:8]
    token_id = _nanoid()
    now = _iso_now()

    try:
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO api_tokens
                    (id, workspace_id, name, token_hash, token_prefix, scopes,
                     created_by, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (token_id, workspace_id, name, token_hash, token_prefix,
                 scopes, email, now, expires_at),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "token_collision"}), 500

    logger.info(
        "api_token created: id=%s name=%s prefix=%s by=%s ws=%s",
        token_id, name, token_prefix, email, workspace_id,
    )

    return jsonify({
        "id": token_id,
        "name": name,
        "token": raw_token,   # ONLY returned at creation
        "token_prefix": token_prefix,
        "scopes": scopes,
        "workspace_id": workspace_id,
        "created_at": now,
        "expires_at": expires_at,
    }), 201


@api_tokens_bp.delete("/tokens/<token_id>")
def revoke_token_route(token_id: str):
    """DELETE /api/tokens/<id> — revoke a token (owner only)."""
    email = _require_auth()
    api_tokens_init_db()

    with _connect() as conn:
        row = conn.execute(
            "SELECT id, created_by, revoked_at FROM api_tokens WHERE id = ?",
            (token_id,),
        ).fetchone()

    if row is None:
        abort(404)
    if row["created_by"] != email:
        abort(403)
    if row["revoked_at"] is not None:
        return jsonify({"error": "already_revoked"}), 409

    now = _iso_now()
    with _connect() as conn:
        conn.execute(
            "UPDATE api_tokens SET revoked_at = ? WHERE id = ?",
            (now, token_id),
        )
        conn.commit()

    logger.info("api_token revoked: id=%s by=%s", token_id, email)
    return jsonify({"ok": True, "revoked_at": now})
