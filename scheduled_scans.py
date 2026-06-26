"""
scheduled_scans.py — Flask Blueprint for scheduled scan management.

Scheduled scans are available on Team and Studio tiers only
(feature gate: scheduled_scans).  Community users get a 402 on every
write route and a filtered empty list on GET.

Table created (idempotent):
  - scheduled_scans

Routes (URL prefix /api/schedules):
  GET    /api/schedules             — list schedules for the session user
  POST   /api/schedules             — create a new schedule (team+)
  GET    /api/schedules/<id>        — get a single schedule
  PATCH  /api/schedules/<id>        — update schedule (team+)
  DELETE /api/schedules/<id>        — delete a schedule (team+)

Cron expressions are stored as-is; execution is handled externally
(PM2 cron job or CF cron-scheduler).  This module only manages the
schedule registry.
"""

from __future__ import annotations

import logging
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, abort, jsonify, request

from feature_gates import feature_enabled

logger = logging.getLogger(__name__)

scheduled_scans_bp = Blueprint("sic_scheduled_scans", __name__, url_prefix="/api")

_DB_PATH = Path.home() / ".sic" / "state.db"
_db_init_done: bool = False

# ---------------------------------------------------------------------------
# DB helpers  (same WAL/busy_timeout pattern as api_tokens.py)
# ---------------------------------------------------------------------------


def _db_path() -> Path:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return _DB_PATH


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_db_path()))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _nanoid() -> str:
    return secrets.token_urlsafe(15)[:20]


def _iso_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# DB init
# ---------------------------------------------------------------------------


def scheduled_scans_init_db() -> None:
    """Create scheduled_scans table.  Idempotent."""
    global _db_init_done
    if _db_init_done:
        return
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scheduled_scans (
                id           TEXT PRIMARY KEY,
                owner_email  TEXT NOT NULL,
                workspace_id TEXT,
                name         TEXT NOT NULL,
                scan_type    TEXT NOT NULL DEFAULT 'full',
                target       TEXT NOT NULL,
                cron_expr    TEXT NOT NULL,
                enabled      INTEGER NOT NULL DEFAULT 1,
                last_run_at  TEXT,
                next_run_at  TEXT,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sched_scans_owner"
            " ON scheduled_scans(owner_email)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sched_scans_workspace"
            " ON scheduled_scans(workspace_id)"
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
        return ""
    email = get_session_email()
    if not email:
        abort(401)
    return email  # type: ignore[return-value]


def _scheduled_scans_gate():
    """Return a 402 JSON response if the user's tier lacks scheduled_scans."""
    if not feature_enabled("scheduled_scans"):
        return (
            jsonify(
                {
                    "error": "scheduled_scans_requires_team_or_studio_tier",
                    "upgrade_url": "/billing",
                }
            ),
            402,
        )
    return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@scheduled_scans_bp.get("/schedules")
def list_schedules_route():
    """GET /api/schedules — list all schedules owned by the session user."""
    email = _require_auth()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scheduled_scans WHERE owner_email = ? ORDER BY created_at DESC",
            (email,),
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@scheduled_scans_bp.post("/schedules")
def create_schedule_route():
    """POST /api/schedules — create a new scheduled scan (Team+ only)."""
    email = _require_auth()
    gate = _scheduled_scans_gate()
    if gate is not None:
        return gate

    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    target = (body.get("target") or "").strip()
    cron_expr = (body.get("cron_expr") or "").strip()
    scan_type = (body.get("scan_type") or "full").strip()
    workspace_id = body.get("workspace_id")
    next_run_at = body.get("next_run_at")  # optional ISO string

    if not name or not target or not cron_expr:
        return jsonify({"error": "missing_fields", "required": ["name", "target", "cron_expr"]}), 400

    now = _iso_now()
    sched_id = _nanoid()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO scheduled_scans
              (id, owner_email, workspace_id, name, scan_type, target,
               cron_expr, enabled, next_run_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
            """,
            (sched_id, email, workspace_id, name, scan_type, target,
             cron_expr, next_run_at, now, now),
        )
        conn.commit()

    logger.info("[scheduled_scans] created schedule %s for %s", sched_id, email)
    return jsonify({"id": sched_id, "created_at": now}), 201


@scheduled_scans_bp.get("/schedules/<sched_id>")
def get_schedule_route(sched_id: str):
    """GET /api/schedules/<id> — fetch a single schedule."""
    email = _require_auth()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scheduled_scans WHERE id = ? AND owner_email = ?",
            (sched_id, email),
        ).fetchone()
    if row is None:
        abort(404)
    return jsonify(dict(row))


@scheduled_scans_bp.patch("/schedules/<sched_id>")
def update_schedule_route(sched_id: str):
    """PATCH /api/schedules/<id> — update fields (Team+ only)."""
    email = _require_auth()
    gate = _scheduled_scans_gate()
    if gate is not None:
        return gate

    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scheduled_scans WHERE id = ? AND owner_email = ?",
            (sched_id, email),
        ).fetchone()
        if row is None:
            abort(404)

        body = request.get_json(silent=True) or {}
        allowed = {"name", "target", "cron_expr", "scan_type", "enabled", "next_run_at", "workspace_id"}
        updates = {k: v for k, v in body.items() if k in allowed}
        if not updates:
            return jsonify({"error": "no_updatable_fields"}), 400

        updates["updated_at"] = _iso_now()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [sched_id, email]
        conn.execute(
            f"UPDATE scheduled_scans SET {set_clause} WHERE id = ? AND owner_email = ?",  # noqa: S608
            values,
        )
        conn.commit()

    return jsonify({"id": sched_id, "updated": list(updates.keys())})


@scheduled_scans_bp.delete("/schedules/<sched_id>")
def delete_schedule_route(sched_id: str):
    """DELETE /api/schedules/<id> — remove a schedule (Team+ only)."""
    email = _require_auth()
    gate = _scheduled_scans_gate()
    if gate is not None:
        return gate

    with _connect() as conn:
        result = conn.execute(
            "DELETE FROM scheduled_scans WHERE id = ? AND owner_email = ?",
            (sched_id, email),
        )
        conn.commit()

    if result.rowcount == 0:
        abort(404)

    logger.info("[scheduled_scans] deleted schedule %s for %s", sched_id, email)
    return jsonify({"deleted": sched_id})
