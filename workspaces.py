"""
workspaces.py — Flask Blueprint for multi-tenant workspace management.

Provides isolated namespaces per team/client.  Each scan and incident belongs
to a workspace.  Workspace membership carries a role: admin, viewer, or
incident-owner.

Tables created (idempotent):
  - workspaces
  - workspace_members
  Also migrates: scan_runs.workspace_id, incidents.workspace_id

Routes (URL prefix /api/workspaces):
  GET    /api/workspaces                    — list workspaces for session user
  POST   /api/workspaces                    — create workspace
  GET    /api/workspaces/<id>               — detail + member list
  PATCH  /api/workspaces/<id>               — update name/slug (admin only)
  DELETE /api/workspaces/<id>               — delete workspace (admin only)
  POST   /api/workspaces/<id>/members       — invite member (admin only)
  DELETE /api/workspaces/<id>/members/<email> — remove member (admin only)
  GET    /api/workspace/current             — get active workspace from session cookie
  POST   /api/workspace/current            — set active workspace in session cookie

Public helpers:
  workspaces_init_db()  — idempotent schema creation; call from app startup
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, abort, jsonify, request

from feature_gates import require_tier

workspaces_bp = Blueprint("sic_workspaces", __name__, url_prefix="/api")

_DB_PATH = Path.home() / ".sic" / "state.db"
_db_init_done: bool = False
_WORKSPACE_COOKIE_NAME = "sic_workspace"

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


# ---------------------------------------------------------------------------
# Workspace session cookie signing
# Uses the same HMAC approach as auth.py.
# Importing _get_secret from auth would create a circular dependency, so we
# resolve the secret independently via the same SIC_AUTH_SECRET env var / key
# file that auth.py uses.  Both modules end up with the same secret at runtime.
# ---------------------------------------------------------------------------

_KEY_PATH = Path.home() / ".sic" / "auth.key"
_ws_secret_cache: bytes | None = None


def _get_ws_secret() -> bytes:
    """Return the HMAC signing secret for workspace cookies."""
    global _ws_secret_cache
    if _ws_secret_cache is not None:
        return _ws_secret_cache

    env_val = os.environ.get("SIC_AUTH_SECRET")
    if env_val:
        _ws_secret_cache = env_val.encode()
        return _ws_secret_cache

    if _KEY_PATH.exists():
        _ws_secret_cache = _KEY_PATH.read_bytes()
        return _ws_secret_cache

    # Fallback — should rarely be hit because auth.py creates the key first
    _ws_secret_cache = b"sic-default-key"
    return _ws_secret_cache


def _sign_workspace_cookie(workspace_id: str) -> str:
    """Return HMAC-signed cookie value for the given workspace_id."""
    sig = hmac.new(
        _get_ws_secret(),
        workspace_id.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{workspace_id}.{sig}"


def _verify_workspace_cookie(value: str) -> str | None:
    """Verify workspace cookie and return workspace_id or None."""
    if not value or "." not in value:
        return None
    parts = value.split(".", 1)
    workspace_id, provided_sig = parts[0], parts[1]
    expected_sig = hmac.new(
        _get_ws_secret(),
        workspace_id.encode(),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_sig, provided_sig):
        return None
    return workspace_id


# ---------------------------------------------------------------------------
# DB init / migrations
# ---------------------------------------------------------------------------


def workspaces_init_db() -> None:
    """Create workspace tables and run column migrations.  Idempotent."""
    global _db_init_done
    if _db_init_done:
        return
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS workspaces (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                slug        TEXT NOT NULL UNIQUE,
                created_by  TEXT NOT NULL,
                created_at  TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS workspace_members (
                workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                email        TEXT NOT NULL,
                role         TEXT NOT NULL DEFAULT 'viewer',
                joined_at    TEXT NOT NULL,
                PRIMARY KEY (workspace_id, email)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ws_members_email"
            " ON workspace_members(email)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_workspaces_slug"
            " ON workspaces(slug)"
        )

        # Migration: add workspace_id to scan_runs if it exists
        try:
            existing_tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "scan_runs" in existing_tables:
                try:
                    conn.execute(
                        "ALTER TABLE scan_runs ADD COLUMN workspace_id TEXT"
                    )
                    logger.info("workspaces: migrated scan_runs.workspace_id")
                except sqlite3.OperationalError:
                    pass  # column already exists

            if "incidents" in existing_tables:
                try:
                    conn.execute(
                        "ALTER TABLE incidents ADD COLUMN workspace_id TEXT"
                    )
                    logger.info("workspaces: migrated incidents.workspace_id")
                except sqlite3.OperationalError:
                    pass  # column already exists
        except Exception as exc:  # noqa: BLE001
            logger.warning("workspaces: migration check failed: %s", exc)

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
        return "dev@local"
    email = get_session_email()
    if not email:
        abort(401)
    return email  # type: ignore[return-value]


def _require_member(workspace_id: str, email: str) -> dict:
    """Return the workspace_members row or abort 403."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM workspace_members WHERE workspace_id = ? AND email = ?",
            (workspace_id, email),
        ).fetchone()
    if row is None:
        abort(403)
    return dict(row)


def _require_admin(workspace_id: str, email: str) -> None:
    """Abort 403 if the user is not an admin member of the workspace."""
    row = _require_member(workspace_id, email)
    if row.get("role") != "admin":
        abort(403)


# ---------------------------------------------------------------------------
# Routes — workspace CRUD
# ---------------------------------------------------------------------------


@workspaces_bp.get("/workspaces")
def list_workspaces_route():
    """GET /api/workspaces — list workspaces the session user belongs to."""
    email = _require_auth()
    workspaces_init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT w.id, w.name, w.slug, w.created_by, w.created_at, wm.role
              FROM workspaces w
              JOIN workspace_members wm ON wm.workspace_id = w.id
             WHERE wm.email = ?
             ORDER BY w.created_at DESC
            """,
            (email,),
        ).fetchall()
    return jsonify({"workspaces": [dict(r) for r in rows]})


@workspaces_bp.post("/workspaces")
def create_workspace_route():
    """POST /api/workspaces — create a workspace and add creator as admin."""
    email = _require_auth()
    workspaces_init_db()

    body = request.get_json(silent=True) or {}
    name = body.get("name")
    slug = body.get("slug")

    if not name or not isinstance(name, str) or not name.strip():
        return jsonify({"error": "name_required"}), 400
    if not slug or not isinstance(slug, str) or not slug.strip():
        return jsonify({"error": "slug_required"}), 400

    name = name.strip()
    slug = slug.strip().lower()

    # Validate slug — alphanumeric + hyphens only
    import re  # noqa: PLC0415
    if not re.match(r"^[a-z0-9][a-z0-9\-]{0,62}$", slug):
        return jsonify({"error": "slug_invalid", "detail": "lowercase alphanumeric and hyphens only"}), 400

    ws_id = _nanoid()
    now = _iso_now()

    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO workspaces (id, name, slug, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
                (ws_id, name, slug, email, now),
            )
            conn.execute(
                "INSERT INTO workspace_members (workspace_id, email, role, joined_at) VALUES (?, ?, 'admin', ?)",
                (ws_id, email, now),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "slug_taken"}), 409

    logger.info("workspace created: id=%s slug=%s by=%s", ws_id, slug, email)
    return jsonify({"id": ws_id, "name": name, "slug": slug, "created_by": email, "created_at": now}), 201


@workspaces_bp.get("/workspaces/<workspace_id>")
def get_workspace_route(workspace_id: str):
    """GET /api/workspaces/<id> — detail with members list (must be member)."""
    email = _require_auth()
    workspaces_init_db()
    _require_member(workspace_id, email)

    with _connect() as conn:
        ws_row = conn.execute(
            "SELECT * FROM workspaces WHERE id = ?", (workspace_id,)
        ).fetchone()
        if ws_row is None:
            abort(404)
        members = conn.execute(
            "SELECT email, role, joined_at FROM workspace_members WHERE workspace_id = ? ORDER BY joined_at ASC",
            (workspace_id,),
        ).fetchall()

    result = dict(ws_row)
    result["members"] = [dict(m) for m in members]
    return jsonify(result)


@workspaces_bp.patch("/workspaces/<workspace_id>")
def update_workspace_route(workspace_id: str):
    """PATCH /api/workspaces/<id> — update name and/or slug (admin only)."""
    email = _require_auth()
    workspaces_init_db()
    _require_admin(workspace_id, email)

    with _connect() as conn:
        ws_row = conn.execute(
            "SELECT * FROM workspaces WHERE id = ?", (workspace_id,)
        ).fetchone()
        if ws_row is None:
            abort(404)

    body = request.get_json(silent=True) or {}
    updates: list[str] = []
    params: list = []

    name = body.get("name")
    slug = body.get("slug")

    if name is not None:
        if not isinstance(name, str) or not name.strip():
            return jsonify({"error": "name_invalid"}), 400
        updates.append("name = ?")
        params.append(name.strip())

    if slug is not None:
        if not isinstance(slug, str) or not slug.strip():
            return jsonify({"error": "slug_invalid"}), 400
        import re  # noqa: PLC0415
        slug = slug.strip().lower()
        if not re.match(r"^[a-z0-9][a-z0-9\-]{0,62}$", slug):
            return jsonify({"error": "slug_invalid", "detail": "lowercase alphanumeric and hyphens only"}), 400
        updates.append("slug = ?")
        params.append(slug)

    if not updates:
        return jsonify({"error": "no_fields_to_update"}), 400

    params.append(workspace_id)
    try:
        with _connect() as conn:
            conn.execute(
                f"UPDATE workspaces SET {', '.join(updates)} WHERE id = ?",  # noqa: S608
                params,
            )
            conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "slug_taken"}), 409

    with _connect() as conn:
        updated = conn.execute(
            "SELECT * FROM workspaces WHERE id = ?", (workspace_id,)
        ).fetchone()
    return jsonify(dict(updated))


@workspaces_bp.delete("/workspaces/<workspace_id>")
def delete_workspace_route(workspace_id: str):
    """DELETE /api/workspaces/<id> — delete workspace (admin only)."""
    email = _require_auth()
    workspaces_init_db()
    _require_admin(workspace_id, email)

    with _connect() as conn:
        row = conn.execute(
            "SELECT id FROM workspaces WHERE id = ?", (workspace_id,)
        ).fetchone()
        if row is None:
            abort(404)
        conn.execute("DELETE FROM workspaces WHERE id = ?", (workspace_id,))
        conn.commit()

    logger.info("workspace deleted: id=%s by=%s", workspace_id, email)
    return jsonify({"ok": True, "deleted_id": workspace_id})


# ---------------------------------------------------------------------------
# Routes — member management
# ---------------------------------------------------------------------------

_VALID_ROLES = {"admin", "viewer", "incident-owner"}


@workspaces_bp.post("/workspaces/<workspace_id>/members")
def invite_member_route(workspace_id: str):
    """POST /api/workspaces/<id>/members — invite a member (admin only)."""
    email = _require_auth()
    workspaces_init_db()
    _require_admin(workspace_id, email)

    with _connect() as conn:
        ws_row = conn.execute(
            "SELECT id FROM workspaces WHERE id = ?", (workspace_id,)
        ).fetchone()
        if ws_row is None:
            abort(404)

    body = request.get_json(silent=True) or {}
    invite_email = body.get("email")
    role = body.get("role", "viewer")

    if not invite_email or not isinstance(invite_email, str) or not invite_email.strip():
        return jsonify({"error": "email_required"}), 400
    invite_email = invite_email.strip().lower()

    if role not in _VALID_ROLES:
        return jsonify({"error": "role_invalid", "valid": sorted(_VALID_ROLES)}), 400

    now = _iso_now()
    try:
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO workspace_members (workspace_id, email, role, joined_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(workspace_id, email) DO UPDATE SET role = excluded.role
                """,
                (workspace_id, invite_email, role, now),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "member_add_failed"}), 409

    logger.info(
        "workspace member invited: ws=%s email=%s role=%s by=%s",
        workspace_id, invite_email, role, email,
    )
    return jsonify({"workspace_id": workspace_id, "email": invite_email, "role": role, "joined_at": now}), 201


@workspaces_bp.delete("/workspaces/<workspace_id>/members/<member_email>")
def remove_member_route(workspace_id: str, member_email: str):
    """DELETE /api/workspaces/<id>/members/<email> — remove a member (admin only)."""
    email = _require_auth()
    workspaces_init_db()
    _require_admin(workspace_id, email)

    # Prevent self-removal of the last admin
    with _connect() as conn:
        ws_row = conn.execute(
            "SELECT id FROM workspaces WHERE id = ?", (workspace_id,)
        ).fetchone()
        if ws_row is None:
            abort(404)
        target_row = conn.execute(
            "SELECT email, role FROM workspace_members WHERE workspace_id = ? AND email = ?",
            (workspace_id, member_email.lower()),
        ).fetchone()
        if target_row is None:
            abort(404)

        if target_row["role"] == "admin":
            admin_count = conn.execute(
                "SELECT COUNT(*) FROM workspace_members WHERE workspace_id = ? AND role = 'admin'",
                (workspace_id,),
            ).fetchone()[0]
            if admin_count <= 1:
                return jsonify({"error": "cannot_remove_last_admin"}), 409

        conn.execute(
            "DELETE FROM workspace_members WHERE workspace_id = ? AND email = ?",
            (workspace_id, member_email.lower()),
        )
        conn.commit()

    logger.info(
        "workspace member removed: ws=%s email=%s by=%s",
        workspace_id, member_email, email,
    )
    return jsonify({"ok": True, "removed_email": member_email.lower()})


# ---------------------------------------------------------------------------
# Routes — active workspace session cookie
# ---------------------------------------------------------------------------


@workspaces_bp.get("/workspace/current")
def get_current_workspace_route():
    """GET /api/workspace/current — return active workspace_id from signed cookie."""
    cookie_val = request.cookies.get(_WORKSPACE_COOKIE_NAME)
    if not cookie_val:
        return jsonify({"workspace_id": None})
    workspace_id = _verify_workspace_cookie(cookie_val)
    return jsonify({"workspace_id": workspace_id})


@workspaces_bp.post("/workspace/current")
def set_current_workspace_route():
    """POST /api/workspace/current — set active workspace in signed cookie.

    Body: {workspace_id}. User must be a member of the workspace.
    Pass workspace_id=null to clear the active workspace.
    """
    email = _require_auth()
    workspaces_init_db()

    body = request.get_json(silent=True) or {}
    workspace_id = body.get("workspace_id")

    if workspace_id is None:
        # Clear the cookie
        resp = jsonify({"workspace_id": None})
        resp.set_cookie(
            _WORKSPACE_COOKIE_NAME,
            "",
            max_age=0,
            httponly=True,
            samesite="Lax",
            secure=request.is_secure,
            path="/",
        )
        return resp

    if not isinstance(workspace_id, str) or not workspace_id.strip():
        return jsonify({"error": "workspace_id_required"}), 400

    workspace_id = workspace_id.strip()

    # Verify membership
    with _connect() as conn:
        member_row = conn.execute(
            "SELECT role FROM workspace_members WHERE workspace_id = ? AND email = ?",
            (workspace_id, email),
        ).fetchone()
    if member_row is None:
        return jsonify({"error": "not_a_member"}), 403

    signed = _sign_workspace_cookie(workspace_id)
    resp = jsonify({"workspace_id": workspace_id, "role": member_row["role"]})
    resp.set_cookie(
        _WORKSPACE_COOKIE_NAME,
        signed,
        max_age=30 * 86400,
        httponly=True,
        samesite="Lax",
        secure=request.is_secure,
        path="/",
    )
    return resp


# ---------------------------------------------------------------------------
# #22 Per-Service API Tokens + #25 Token-Expiry Warnings
# ---------------------------------------------------------------------------
# Schema: api_tokens table added via workspaces_init_db migration below.
# Routes (all require workspace membership; create/revoke require admin):
#   POST   /api/workspaces/<id>/tokens               — create token
#   GET    /api/workspaces/<id>/tokens               — list tokens
#   DELETE /api/workspaces/<id>/tokens/<token_id>    — revoke token
#   GET    /api/workspaces/<id>/tokens/expiring-soon — tokens expiring in ≤7 days



def _ensure_tokens_table() -> None:
    """Idempotent creation of the api_tokens table."""
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_tokens (
                id           TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                service_name TEXT NOT NULL,
                token_hash   TEXT NOT NULL UNIQUE,
                token_prefix TEXT NOT NULL,
                created_by   TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                expires_at   TEXT,
                last_used_at TEXT,
                revoked      INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_api_tokens_workspace"
            " ON api_tokens(workspace_id)"
        )
        conn.commit()


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


@workspaces_bp.post("/workspaces/<workspace_id>/tokens")
@require_tier("studio")
def create_token_route(workspace_id: str):
    """POST /api/workspaces/<id>/tokens — issue a scoped API token (admin only).

    Body: {"service_name": "ci-pipeline", "expires_in_days": 90}
    Returns: {"token": "sic_...", "id": "...", "expires_at": "..."}
    The raw token is returned once only — store it securely.
    """
    _ensure_tokens_table()
    email = _require_auth()
    _require_admin(workspace_id, email)

    body = request.get_json(silent=True) or {}
    service_name = (body.get("service_name") or "").strip()
    if not service_name:
        return jsonify({"error": "service_name_required"}), 400

    expires_in_days = body.get("expires_in_days")
    expires_at = None
    if expires_in_days is not None:
        try:
            days = int(expires_in_days)
            if days <= 0:
                raise ValueError
        except (ValueError, TypeError):
            return jsonify({"error": "expires_in_days_must_be_positive_integer"}), 400
        expires_ts = time.time() + days * 86400
        expires_at = _iso_now_from_ts(expires_ts)

    raw = "sic_" + secrets.token_urlsafe(32)
    token_id = _nanoid()
    prefix = raw[:12]

    with _connect() as conn:
        conn.execute(
            "INSERT INTO api_tokens"
            " (id, workspace_id, service_name, token_hash, token_prefix,"
            "  created_by, created_at, expires_at, revoked)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
            (token_id, workspace_id, service_name, _hash_token(raw),
             prefix, email, _iso_now(), expires_at),
        )
        conn.commit()

    return jsonify({
        "token": raw,
        "id": token_id,
        "service_name": service_name,
        "prefix": prefix,
        "created_at": _iso_now(),
        "expires_at": expires_at,
        "note": "Store this token securely — it will not be shown again.",
    }), 201


@workspaces_bp.get("/workspaces/<workspace_id>/tokens")
def list_tokens_route(workspace_id: str):
    """GET /api/workspaces/<id>/tokens — list active (non-revoked) tokens."""
    _ensure_tokens_table()
    email = _require_auth()
    _require_member(workspace_id, email)

    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, service_name, token_prefix, created_by, created_at,"
            "       expires_at, last_used_at"
            " FROM api_tokens"
            " WHERE workspace_id = ? AND revoked = 0"
            " ORDER BY created_at DESC",
            (workspace_id,),
        ).fetchall()

    tokens = []
    now_ts = time.time()
    for r in rows:
        d = dict(r)
        d["expired"] = bool(
            d["expires_at"] and _parse_iso_ts(d["expires_at"]) < now_ts
        )
        tokens.append(d)

    return jsonify({"tokens": tokens, "total": len(tokens)})


@workspaces_bp.delete("/workspaces/<workspace_id>/tokens/<token_id>")
def revoke_token_route(workspace_id: str, token_id: str):
    """DELETE /api/workspaces/<id>/tokens/<token_id> — revoke token (admin only)."""
    _ensure_tokens_table()
    email = _require_auth()
    _require_admin(workspace_id, email)

    with _connect() as conn:
        result = conn.execute(
            "UPDATE api_tokens SET revoked = 1"
            " WHERE id = ? AND workspace_id = ? AND revoked = 0",
            (token_id, workspace_id),
        )
        conn.commit()

    if result.rowcount == 0:
        return jsonify({"error": "token_not_found_or_already_revoked"}), 404

    return jsonify({"revoked": True, "id": token_id})


@workspaces_bp.get("/workspaces/<workspace_id>/tokens/expiring-soon")
def expiring_tokens_route(workspace_id: str):
    """GET /api/workspaces/<id>/tokens/expiring-soon — tokens expiring within 7 days.

    Used by #25 to surface expiry warnings in the dashboard and trigger webhook
    alerts. Excludes already-expired and revoked tokens.
    """
    _ensure_tokens_table()
    email = _require_auth()
    _require_member(workspace_id, email)

    warning_window = 7 * 86400
    now_ts = time.time()
    cutoff_ts = now_ts + warning_window

    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, service_name, token_prefix, created_by, created_at, expires_at"
            " FROM api_tokens"
            " WHERE workspace_id = ? AND revoked = 0 AND expires_at IS NOT NULL"
            " ORDER BY expires_at ASC",
            (workspace_id,),
        ).fetchall()

    expiring = []
    for r in rows:
        d = dict(r)
        exp_ts = _parse_iso_ts(d["expires_at"])
        if now_ts < exp_ts <= cutoff_ts:
            d["days_remaining"] = max(0, int((exp_ts - now_ts) / 86400))
            d["warning"] = True
            expiring.append(d)

    # Fire webhook alert if tokens are expiring and scan_alerts is available
    if expiring:
        try:
            from scan_alerts import send_alert  # noqa: PLC0415
            for t in expiring:
                send_alert(
                    event="token_expiring_soon",
                    data={
                        "workspace_id": workspace_id,
                        "token_id": t["id"],
                        "service_name": t["service_name"],
                        "days_remaining": t["days_remaining"],
                        "expires_at": t["expires_at"],
                    },
                )
        except Exception:  # noqa: BLE001
            pass

    return jsonify({
        "expiring_soon": expiring,
        "total": len(expiring),
        "warning_window_days": 7,
    })


def _iso_now_from_ts(ts: float) -> str:
    from datetime import datetime, timezone  # noqa: PLC0415
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _parse_iso_ts(iso: str) -> float:
    from datetime import datetime, timezone  # noqa: PLC0415
    try:
        return datetime.fromisoformat(iso).replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, AttributeError):
        return 0.0
