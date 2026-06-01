"""
incidents.py — Flask Blueprint for incident management.

Routes:
    GET    /api/incidents           — list incidents (filterable by severity, status)
    POST   /api/incidents           — create incident (auth required)
    GET    /api/incidents/<id>      — detail with timeline notes
    PATCH  /api/incidents/<id>      — update status + optional note (auth required)
    DELETE /api/incidents/<id>      — soft delete (auth required)

Public helpers:
    incidents_init_db()  — idempotent schema creation; call from app startup
"""

from __future__ import annotations

import logging
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, abort, jsonify, request

incidents_bp = Blueprint("sic_incidents", __name__, url_prefix="/api")

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


def incidents_init_db() -> None:
    """Create incidents and incident_timeline tables if not present. Idempotent."""
    global _db_init_done
    if _db_init_done:
        return
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id           TEXT PRIMARY KEY,
                severity     TEXT NOT NULL CHECK(severity IN ('P0','P1','P2')),
                title        TEXT NOT NULL,
                description  TEXT,
                status       TEXT NOT NULL DEFAULT 'open'
                                 CHECK(status IN ('open','in-progress','resolved')),
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL,
                resolved_at  TEXT,
                mttr_seconds INTEGER,
                deleted_at   TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_timeline (
                id          TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL REFERENCES incidents(id),
                note        TEXT NOT NULL,
                created_at  TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timeline_incident ON incident_timeline(incident_id, created_at)"
        )
        conn.commit()
    _db_init_done = True


# ---------------------------------------------------------------------------
# Auth gate (lazy import — consistent with scan_history.py pattern)
# ---------------------------------------------------------------------------


def _require_auth() -> str:
    """Abort 401 if no authenticated session. Returns email on success."""
    try:
        from auth import get_session_email  # noqa: PLC0415
    except ImportError:
        return "dev@local"  # fail open in dev when auth module absent
    email = get_session_email()
    if not email:
        abort(401)
    return email  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@incidents_bp.get("/incidents")
def list_incidents_route():
    """GET /api/incidents — list incidents, optional ?severity=P0&status=open."""
    incidents_init_db()
    severity = request.args.get("severity")
    status = request.args.get("status")

    valid_severities = {"P0", "P1", "P2"}
    valid_statuses = {"open", "in-progress", "resolved"}

    where: list[str] = ["deleted_at IS NULL"]
    params: list = []

    if severity:
        if severity not in valid_severities:
            return jsonify({"error": "invalid_severity", "valid": sorted(valid_severities)}), 400
        where.append("severity = ?")
        params.append(severity)

    if status:
        if status not in valid_statuses:
            return jsonify({"error": "invalid_status", "valid": sorted(valid_statuses)}), 400
        where.append("status = ?")
        params.append(status)

    where_sql = "WHERE " + " AND ".join(where)
    sql = f"SELECT * FROM incidents {where_sql} ORDER BY created_at DESC"

    with _connect() as conn:
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]

    return jsonify({"incidents": rows, "count": len(rows)})


@incidents_bp.post("/incidents")
def create_incident_route():
    """POST /api/incidents — create a new incident."""
    email = _require_auth()
    incidents_init_db()

    body = request.get_json(silent=True) or {}
    severity = body.get("severity")
    title = body.get("title")
    description = body.get("description")

    if not severity or severity not in {"P0", "P1", "P2"}:
        return jsonify({"error": "severity_required", "valid": ["P0", "P1", "P2"]}), 400
    if not title or not isinstance(title, str) or not title.strip():
        return jsonify({"error": "title_required"}), 400

    title = title.strip()
    now = _iso_now()
    inc_id = _nanoid()

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO incidents (id, severity, title, description, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'open', ?, ?)
            """,
            (inc_id, severity, title, description, now, now),
        )
        conn.commit()

    logger.info("incident created: id=%s severity=%s by=%s", inc_id, severity, email)
    return jsonify({"id": inc_id, "severity": severity, "title": title, "status": "open",
                    "created_at": now}), 201


@incidents_bp.get("/incidents/<incident_id>")
def get_incident_route(incident_id: str):
    """GET /api/incidents/<id> — incident detail with timeline."""
    incidents_init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ? AND deleted_at IS NULL",
            (incident_id,),
        ).fetchone()
        if row is None:
            abort(404)
        incident = dict(row)
        timeline = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM incident_timeline WHERE incident_id = ? ORDER BY created_at ASC",
                (incident_id,),
            ).fetchall()
        ]

    incident["timeline"] = timeline
    return jsonify(incident)


@incidents_bp.patch("/incidents/<incident_id>")
def update_incident_route(incident_id: str):
    """PATCH /api/incidents/<id> — update status and/or add a timeline note."""
    email = _require_auth()
    incidents_init_db()

    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ? AND deleted_at IS NULL",
            (incident_id,),
        ).fetchone()
        if row is None:
            abort(404)
        incident = dict(row)

    body = request.get_json(silent=True) or {}
    new_status = body.get("status")
    note = body.get("note")

    valid_statuses = {"open", "in-progress", "resolved"}
    if new_status and new_status not in valid_statuses:
        return jsonify({"error": "invalid_status", "valid": sorted(valid_statuses)}), 400

    now = _iso_now()
    updates: list[str] = ["updated_at = ?"]
    params: list = [now]

    resolved_at: str | None = None
    mttr_seconds: int | None = None

    if new_status and new_status != incident["status"]:
        updates.append("status = ?")
        params.append(new_status)

        if new_status == "resolved":
            resolved_at = now
            updates.append("resolved_at = ?")
            params.append(resolved_at)
            # Calculate MTTR from created_at to now
            try:
                created_dt = datetime.fromisoformat(incident["created_at"])
                now_dt = datetime.fromisoformat(now)
                mttr_seconds = int((now_dt - created_dt).total_seconds())
            except Exception:  # noqa: BLE001
                mttr_seconds = None
            if mttr_seconds is not None:
                updates.append("mttr_seconds = ?")
                params.append(mttr_seconds)

    set_sql = ", ".join(updates)
    params.append(incident_id)

    with _connect() as conn:
        conn.execute(
            f"UPDATE incidents SET {set_sql} WHERE id = ?",  # noqa: S608
            params,
        )
        if note and isinstance(note, str) and note.strip():
            note_id = _nanoid()
            conn.execute(
                "INSERT INTO incident_timeline (id, incident_id, note, created_at) VALUES (?, ?, ?, ?)",
                (note_id, incident_id, note.strip(), now),
            )
        conn.commit()

    logger.info("incident updated: id=%s status=%s by=%s", incident_id, new_status, email)

    with _connect() as conn:
        updated_row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        timeline = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM incident_timeline WHERE incident_id = ? ORDER BY created_at ASC",
                (incident_id,),
            ).fetchall()
        ]

    result = dict(updated_row)
    result["timeline"] = timeline
    return jsonify(result)


@incidents_bp.delete("/incidents/<incident_id>")
def delete_incident_route(incident_id: str):
    """DELETE /api/incidents/<id> — soft delete."""
    email = _require_auth()
    incidents_init_db()

    with _connect() as conn:
        row = conn.execute(
            "SELECT id FROM incidents WHERE id = ? AND deleted_at IS NULL",
            (incident_id,),
        ).fetchone()
        if row is None:
            abort(404)
        now = _iso_now()
        conn.execute(
            "UPDATE incidents SET deleted_at = ?, updated_at = ? WHERE id = ?",
            (now, now, incident_id),
        )
        conn.commit()

    logger.info("incident soft-deleted: id=%s by=%s", incident_id, email)
    return jsonify({"ok": True, "deleted_at": now})
