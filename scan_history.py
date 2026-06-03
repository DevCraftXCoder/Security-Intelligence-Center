"""
scan_history.py — Flask Blueprint for SQLite-backed scan history persistence.

Provides:
  - record_scan_start / record_scan_complete — write helpers for scan runners
  - get_scan / list_scans — read helpers
  - Blueprint routes: GET /api/scans, /api/scans/<id>, /api/export/<id>

Retention gating: list_scans_route enforces scan_history_days per tier via
feature_gates.get_tier_limit / feature_gates.current_user_tier.  list_scans()
itself is ungated so internal callers are unaffected.
"""

import csv
import hashlib
import io
import json
import logging
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Blueprint, Response, abort, jsonify, request

from feature_gates import require_tier

scan_history_bp = Blueprint("sic_scan_history", __name__, url_prefix="/api")

_DB_PATH = Path.home() / ".sic" / "state.db"
_db_init_done: bool = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def nanoid() -> str:
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
    return conn


def _init_db() -> None:
    """Create scan_runs table and indexes if not already done (idempotent)."""
    global _db_init_done
    if _db_init_done:
        return
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_runs (
                id TEXT PRIMARY KEY,
                scan_type TEXT NOT NULL,
                target TEXT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                duration_s INTEGER,
                status TEXT NOT NULL,
                findings_count INTEGER DEFAULT 0,
                findings_json TEXT,
                error TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_started ON scan_runs(started_at DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_type ON scan_runs(scan_type)"
        )
        conn.commit()
    _db_init_done = True


# ---------------------------------------------------------------------------
# Public write helpers
# ---------------------------------------------------------------------------


def record_scan_start(scan_type: str, target: str | None = None) -> str:
    """Insert a new scan_runs row with status='running'. Return scan_id."""
    _init_db()
    sid = nanoid()
    started = _iso_now()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO scan_runs (id, scan_type, target, started_at, status) VALUES (?, ?, ?, ?, 'running')",
            (sid, scan_type, target, started),
        )
        conn.commit()
    logger.debug("scan started: id=%s type=%s target=%s", sid, scan_type, target)
    return sid


def record_scan_complete(
    scan_id: str,
    findings: list,
    status: str = "completed",
    error: str | None = None,
) -> None:
    """Update scan_runs row with completion data."""
    _init_db()
    finished = _iso_now()
    findings_json = json.dumps(findings) if findings is not None else None
    findings_count = len(findings) if findings else 0
    with _connect() as conn:
        row = conn.execute(
            "SELECT started_at FROM scan_runs WHERE id = ?", (scan_id,)
        ).fetchone()
        duration: int | None = None
        if row:
            try:
                started_dt = datetime.fromisoformat(row["started_at"])
                finished_dt = datetime.fromisoformat(finished)
                duration = int((finished_dt - started_dt).total_seconds())
            except Exception:  # noqa: BLE001
                duration = None
        conn.execute(
            "UPDATE scan_runs SET finished_at=?, duration_s=?, status=?, findings_count=?, findings_json=?, error=? WHERE id=?",
            (finished, duration, status, findings_count, findings_json, error, scan_id),
        )
        conn.commit()
    logger.debug(
        "scan complete: id=%s status=%s findings=%d", scan_id, status, findings_count
    )


# ---------------------------------------------------------------------------
# Public read helpers
# ---------------------------------------------------------------------------


def get_scan(scan_id: str) -> dict | None:
    """Return scan dict or None. Parses findings_json into findings list."""
    _init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scan_runs WHERE id = ?", (scan_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    raw = d.pop("findings_json", None)
    if raw:
        try:
            d["findings"] = json.loads(raw)
        except Exception:  # noqa: BLE001
            d["findings"] = []
    else:
        d["findings"] = []
    return d


def list_scans(
    cursor: str | None,
    scan_type: str | None,
    status: str | None,
    limit: int,
    oldest_allowed: str | None = None,
) -> tuple[list[dict], str | None]:
    """Cursor-paginated scan list.

    Cursor is a started_at ISO string (exclusive lower bound for DESC order).
    oldest_allowed, when provided, is an ISO string acting as an inclusive lower
    bound — scans older than this value are excluded (retention gate).
    Returns (rows, next_cursor).
    """
    _init_db()
    limit = max(1, min(100, int(limit or 20)))
    where: list[str] = []
    params: list = []
    if cursor:
        where.append("started_at < ?")
        params.append(cursor)
    if oldest_allowed:
        where.append("started_at >= ?")
        params.append(oldest_allowed)
    if scan_type:
        where.append("scan_type = ?")
        params.append(scan_type)
    if status:
        where.append("status = ?")
        params.append(status)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    sql = (
        f"SELECT id, scan_type, target, started_at, finished_at, duration_s, status, findings_count"
        f" FROM scan_runs {where_sql}"
        f" ORDER BY started_at DESC, id DESC LIMIT ?"
    )
    params.append(limit + 1)
    with _connect() as conn:
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = page[-1]["started_at"] if (has_more and page) else None
    return page, next_cursor


# ---------------------------------------------------------------------------
# Auth gate (lazy import — auth module may be created in parallel)
# ---------------------------------------------------------------------------


def _require_auth():
    """Abort 401 if no authenticated session. Fails open if auth module absent."""
    try:
        from auth import get_session_email  # noqa: PLC0415
    except ImportError:
        return None  # auth module not loaded — fail open in dev
    email = get_session_email()
    if not email:
        abort(401)
    return email


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@scan_history_bp.get("/scans")
def list_scans_route():
    """GET /api/scans — paginated scan history (retention-gated by tier)."""
    _require_auth()
    cursor = request.args.get("cursor")
    scan_type = request.args.get("type")
    status = request.args.get("status")
    try:
        limit = int(request.args.get("limit", 20))
    except (TypeError, ValueError):
        limit = 20

    # Tier-based retention gate: clamp cursor to the oldest allowed scan date.
    try:
        from feature_gates import current_user_tier, get_tier_limit  # noqa: PLC0415
        retention_days: int = get_tier_limit(current_user_tier(), "scan_history_days")
    except ImportError:
        retention_days = 7  # fail-safe: community default

    retention_cutoff: str | None = None
    if retention_days != -1:  # -1 = unlimited (studio)
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=retention_days)
        retention_cutoff = cutoff_dt.isoformat()
        # If the caller's cursor is older than the cutoff, clamp it.
        if cursor and cursor < retention_cutoff:
            cursor = None

    rows, next_cursor = list_scans(cursor, scan_type, status, limit, oldest_allowed=retention_cutoff)
    return jsonify({"scans": rows, "next_cursor": next_cursor})


@scan_history_bp.get("/scans/<scan_id>")
def get_scan_route(scan_id: str):
    """GET /api/scans/<scan_id> — single scan detail."""
    _require_auth()
    scan = get_scan(scan_id)
    if scan is None:
        abort(404)
    return jsonify(scan)


@scan_history_bp.get("/export/<scan_id>")
def export_scan_route(scan_id: str):
    """GET /api/export/<scan_id>?format=json|csv|pdf — download scan data.

    Supported formats:
      - json (default) — full scan record as indented JSON.
      - csv — findings flattened to CSV rows.
      - pdf — paginated PDF report; requires team or studio tier
        (feature gate: pdf_export).  Returns 402 if the current user's tier
        does not include pdf_export.  Returns 501 if WeasyPrint and its native
        Cairo/Pango dependencies are not installed on the server.
    """
    _require_auth()
    scan = get_scan(scan_id)
    if scan is None:
        abort(404)

    fmt = request.args.get("format", "json").lower()

    if fmt == "csv":
        findings: list = scan.get("findings") or []
        buf = io.StringIO()
        if not findings:
            writer = csv.writer(buf)
            writer.writerow(["index"])
        else:
            # Build union of all keys across finding dicts, sorted for stability
            all_keys: list[str] = sorted(
                {k for f in findings if isinstance(f, dict) for k in f.keys()}
            )
            if not all_keys:
                # findings are non-dict scalars — wrap as {"value": ...}
                all_keys = ["value"]
                findings = [{"value": f} for f in findings]
            writer = csv.DictWriter(
                buf,
                fieldnames=all_keys,
                extrasaction="ignore",
                lineterminator="\r\n",
            )
            writer.writeheader()
            for finding in findings:
                if not isinstance(finding, dict):
                    finding = {"value": finding}
                row: dict = {}
                for k in all_keys:
                    v = finding.get(k, "")
                    if isinstance(v, (dict, list)):
                        row[k] = json.dumps(v)
                    else:
                        row[k] = str(v) if v is not None else ""
                writer.writerow(row)
        csv_text = buf.getvalue()
        return Response(
            csv_text,
            mimetype="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="scan-{scan_id}.csv"'
            },
        )

    if fmt == "pdf":
        from feature_gates import feature_enabled  # noqa: PLC0415

        if not feature_enabled("pdf_export"):
            return (
                jsonify(
                    {
                        "error": "pdf_export_requires_team_tier",
                        "upgrade_url": "/billing",
                    }
                ),
                402,
            )

        try:
            from weasyprint import HTML  # noqa: PLC0415
        except ImportError:
            return (
                jsonify(
                    {
                        "error": "pdf_export_unavailable",
                        "message": "weasyprint not installed on server",
                    }
                ),
                501,
            )

        findings_pdf: list = scan.get("findings") or []
        findings_count: int = len(findings_pdf)

        # Build findings table rows
        finding_rows_html = ""
        if findings_pdf:
            all_cols: list[str] = sorted(
                {k for f in findings_pdf if isinstance(f, dict) for k in f.keys()}
            ) or ["value"]
            header_cells = "".join(
                f"<th>{col}</th>" for col in all_cols
            )
            body_rows = ""
            for finding in findings_pdf:
                if not isinstance(finding, dict):
                    finding = {"value": finding}
                cells = "".join(
                    "<td>{}</td>".format(
                        json.dumps(finding.get(col, ""), default=str)
                        if isinstance(finding.get(col), (dict, list))
                        else str(finding.get(col, ""))
                    )
                    for col in all_cols
                )
                body_rows += "<tr>{}</tr>".format(cells)
            finding_rows_html = (
                "<table>"
                "<thead><tr>{}</tr></thead>"
                "<tbody>{}</tbody>"
                "</table>"
            ).format(header_cells, body_rows)
        else:
            finding_rows_html = "<p class='no-findings'>No findings recorded.</p>"

        html_str = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: Helvetica, Arial, sans-serif;
    font-size: 11px;
    color: #1a1a1a;
    background: #ffffff;
    padding: 32px 40px;
  }}
  .report-header {{
    background: #0a0a0a;
    color: #ffffff;
    padding: 20px 24px;
    border-left: 6px solid #e94560;
    margin-bottom: 28px;
  }}
  .report-header h1 {{
    font-size: 18px;
    font-weight: 700;
    color: #e94560;
    margin-bottom: 4px;
    letter-spacing: 0.5px;
  }}
  .report-header .subtitle {{
    font-size: 11px;
    color: #aaaaaa;
  }}
  .meta-grid {{
    display: table;
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 28px;
  }}
  .meta-row {{
    display: table-row;
  }}
  .meta-label {{
    display: table-cell;
    font-weight: 700;
    padding: 5px 12px 5px 0;
    width: 160px;
    color: #555555;
    vertical-align: top;
  }}
  .meta-value {{
    display: table-cell;
    padding: 5px 0;
    color: #1a1a1a;
    vertical-align: top;
  }}
  .section-title {{
    font-size: 13px;
    font-weight: 700;
    color: #0a0a0a;
    border-bottom: 2px solid #e94560;
    padding-bottom: 4px;
    margin-bottom: 14px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 10px;
  }}
  thead tr {{
    background: #0a0a0a;
    color: #ffffff;
  }}
  thead th {{
    padding: 7px 10px;
    text-align: left;
    font-weight: 600;
    letter-spacing: 0.3px;
  }}
  tbody tr:nth-child(even) {{
    background: #f7f7f7;
  }}
  tbody tr:nth-child(odd) {{
    background: #ffffff;
  }}
  tbody td {{
    padding: 6px 10px;
    border-bottom: 1px solid #eeeeee;
    vertical-align: top;
    word-break: break-word;
  }}
  .no-findings {{
    color: #888888;
    font-style: italic;
    margin-top: 8px;
  }}
  .footer {{
    margin-top: 32px;
    font-size: 9px;
    color: #aaaaaa;
    border-top: 1px solid #eeeeee;
    padding-top: 10px;
  }}
</style>
</head>
<body>
  <div class="report-header">
    <h1>SIC Scan Report</h1>
    <div class="subtitle">Security Intelligence Center &mdash; Automated Export</div>
  </div>

  <div class="meta-grid">
    <div class="meta-row">
      <div class="meta-label">Scan ID</div>
      <div class="meta-value">{scan_id}</div>
    </div>
    <div class="meta-row">
      <div class="meta-label">Target</div>
      <div class="meta-value">{target}</div>
    </div>
    <div class="meta-row">
      <div class="meta-label">Type</div>
      <div class="meta-value">{scan_type}</div>
    </div>
    <div class="meta-row">
      <div class="meta-label">Status</div>
      <div class="meta-value">{status}</div>
    </div>
    <div class="meta-row">
      <div class="meta-label">Started</div>
      <div class="meta-value">{started_at}</div>
    </div>
    <div class="meta-row">
      <div class="meta-label">Finished</div>
      <div class="meta-value">{finished_at}</div>
    </div>
    <div class="meta-row">
      <div class="meta-label">Duration (s)</div>
      <div class="meta-value">{duration_s}</div>
    </div>
    <div class="meta-row">
      <div class="meta-label">Findings</div>
      <div class="meta-value">{findings_count}</div>
    </div>
  </div>

  <div class="section-title">Findings</div>
  {finding_rows}

  <div class="footer">
    Generated by SIC &mdash; {generated_at}
  </div>
</body>
</html>""".format(
            scan_id=scan_id,
            target=str(scan.get("target", "")),
            scan_type=str(scan.get("scan_type", "")),
            status=str(scan.get("status", "")),
            started_at=str(scan.get("started_at", "")),
            finished_at=str(scan.get("finished_at", "")),
            duration_s=str(scan.get("duration_s", "")),
            findings_count=findings_count,
            finding_rows=finding_rows_html,
            generated_at=_iso_now(),
        )

        pdf_bytes: bytes = HTML(string=html_str).write_pdf()
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="scan-{scan_id}.pdf"'
            },
        )

    if fmt == "json":
        body = json.dumps(scan, indent=2, default=str)
        return Response(
            body,
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="scan-{scan_id}.json"'
            },
        )

    return jsonify({"error": "invalid_format", "allowed": ["json", "csv", "pdf"]}), 400


@scan_history_bp.get("/scans/diff")
@require_tier("team")
def diff_scans_route():
    """GET /api/scans/diff?run_a=<id>&run_b=<id> — compare two scan runs.

    Findings are keyed by sha256(category + ":" + title)[:12].
    Returns new (only in run_b), resolved (only in run_a), and unchanged findings.
    """
    _require_auth()
    run_a_id = request.args.get("run_a")
    run_b_id = request.args.get("run_b")
    if not run_a_id or not run_b_id:
        return jsonify({"error": "run_a and run_b query parameters are required"}), 400
    if run_a_id == run_b_id:
        return jsonify({"error": "run_a and run_b must be different scan IDs"}), 400

    scan_a = get_scan(run_a_id)
    if scan_a is None:
        abort(404)
    scan_b = get_scan(run_b_id)
    if scan_b is None:
        abort(404)

    def _stable_key(finding: dict) -> str:
        """sha256(category:title)[:12] — stable identity key for a finding."""
        category = str(finding.get("category", ""))
        title = str(finding.get("title", ""))
        raw = (category + ":" + title).encode()
        return hashlib.sha256(raw).hexdigest()[:12]

    findings_a: list[dict] = scan_a.get("findings") or []
    findings_b: list[dict] = scan_b.get("findings") or []

    # Normalize: ensure every entry is a dict
    def _normalize(findings: list) -> list[dict]:
        out: list[dict] = []
        for f in findings:
            if isinstance(f, dict):
                out.append(f)
            else:
                out.append({"value": f})
        return out

    findings_a = _normalize(findings_a)
    findings_b = _normalize(findings_b)

    map_a: dict[str, dict] = {_stable_key(f): f for f in findings_a}
    map_b: dict[str, dict] = {_stable_key(f): f for f in findings_b}

    keys_a = set(map_a)
    keys_b = set(map_b)

    new_findings = [map_b[k] for k in sorted(keys_b - keys_a)]
    resolved_findings = [map_a[k] for k in sorted(keys_a - keys_b)]
    unchanged_findings = [map_b[k] for k in sorted(keys_a & keys_b)]

    # Strip heavy fields from meta before returning
    meta_keys = {"id", "scan_type", "target", "started_at", "finished_at", "duration_s", "status", "findings_count"}
    meta_a = {k: v for k, v in scan_a.items() if k in meta_keys}
    meta_b = {k: v for k, v in scan_b.items() if k in meta_keys}

    return jsonify(
        {
            "run_a": meta_a,
            "run_b": meta_b,
            "new": new_findings,
            "resolved": resolved_findings,
            "unchanged": unchanged_findings,
            "summary": {
                "new_count": len(new_findings),
                "resolved_count": len(resolved_findings),
                "unchanged_count": len(unchanged_findings),
            },
        }
    )


# ---------------------------------------------------------------------------
# App registration
# ---------------------------------------------------------------------------


def init_app(app) -> None:
    """Register the scan_history blueprint on a Flask app."""
    app.register_blueprint(scan_history_bp)


# ---------------------------------------------------------------------------
# Phase 4 — Shareable read-only report tokens
# ---------------------------------------------------------------------------

_share_db_init_done: bool = False


def _init_share_db() -> None:
    """Create share_tokens table if not present.  Idempotent."""
    global _share_db_init_done
    if _share_db_init_done:
        return
    _init_db()  # ensure scan_runs exists first
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS share_tokens (
                token       TEXT PRIMARY KEY,
                scan_id     TEXT NOT NULL,
                created_by  TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                accessed_at TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_share_tokens_scan ON share_tokens(scan_id)"
        )
        conn.commit()
    _share_db_init_done = True


@scan_history_bp.post("/scans/<scan_id>/share")
@require_tier("team")
def create_share_token_route(scan_id: str):
    """POST /api/scans/<scan_id>/share — create a shareable read-only token.

    Requires authentication.  Returns the token and a ready-to-use share URL.
    Tokens expire after 7 days by default.
    """
    email = _require_auth()
    _init_share_db()

    # Verify the scan exists
    scan = get_scan(scan_id)
    if scan is None:
        abort(404)

    token = secrets.token_urlsafe(24)[:32]
    now = _iso_now()
    expires_at = (datetime.now(tz=timezone.utc) + timedelta(days=7)).isoformat()

    with _connect() as conn:
        conn.execute(
            "INSERT INTO share_tokens (token, scan_id, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (token, scan_id, email, now, expires_at),
        )
        conn.commit()

    logger.info("share token created: scan=%s by=%s", scan_id, email)
    return jsonify({
        "token": token,
        "expires_at": expires_at,
        "share_url": f"/api/scans/shared/{token}",
    }), 201


@scan_history_bp.get("/scans/shared/<share_token>")
def get_shared_scan_route(share_token: str):
    """GET /api/scans/shared/<token> — public read-only scan detail.

    No authentication required.  Validates token is not expired, returns the
    scan detail, and updates accessed_at.
    """
    _init_share_db()

    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM share_tokens WHERE token = ?", (share_token,)
        ).fetchone()

    if row is None:
        abort(404)

    token_data = dict(row)

    # Check expiry
    try:
        exp_dt = datetime.fromisoformat(token_data["expires_at"])
        if datetime.now(tz=timezone.utc) > exp_dt:
            abort(404)
    except ValueError:
        abort(404)

    scan = get_scan(token_data["scan_id"])
    if scan is None:
        abort(404)

    # Update accessed_at best-effort
    try:
        with _connect() as conn:
            conn.execute(
                "UPDATE share_tokens SET accessed_at = ? WHERE token = ?",
                (_iso_now(), share_token),
            )
            conn.commit()
    except Exception:  # noqa: BLE001
        pass

    return jsonify(scan)


# ---------------------------------------------------------------------------
# BUGS.md archive
# ---------------------------------------------------------------------------

@scan_history_bp.get("/bugs-archive")
def bugs_archive_route():
    """GET /api/bugs-archive — Resolved incidents cross-referenced with BUGS.md.

    Searches for BUGS.md in the SIC repo root and parent directories (up to 3
    levels).  Returns parsed checkbox entries alongside resolved incidents from
    the local SQLite store.
    """
    import re as _re

    bugs_text = None
    for p in [
        Path(__file__).parent / "BUGS.md",
        Path(__file__).parent.parent / "BUGS.md",
        Path(__file__).parent.parent.parent / "BUGS.md",
        Path.cwd() / "BUGS.md",
    ]:
        if p.exists():
            try:
                bugs_text = p.read_text(encoding="utf-8")
            except OSError:
                pass
            break

    entries: list[dict] = []
    if bugs_text:
        for line in bugs_text.splitlines():
            m = _re.match(r"^[-*]\s+\[([ xX])\]\s+(.+)", line)
            if m:
                resolved = m.group(1).lower() == "x"
                entries.append({
                    "text": m.group(2).strip(),
                    "resolved": resolved,
                    "status": "resolved" if resolved else "open",
                })

    resolved_incidents: list[dict] = []
    try:
        _init_db()
        with _connect() as conn:
            rows = conn.execute(
                "SELECT id, title, severity, status, resolved_at, created_at"
                " FROM incidents WHERE status = 'resolved'"
                " ORDER BY resolved_at DESC LIMIT 100"
            ).fetchall()
            resolved_incidents = [dict(r) for r in rows]
    except Exception:  # noqa: BLE001
        pass

    return jsonify({
        "bugs_md_found": bugs_text is not None,
        "bugs_md_entries": entries,
        "resolved_entries": [e for e in entries if e["resolved"]],
        "open_entries": [e for e in entries if not e["resolved"]],
        "resolved_incidents": resolved_incidents,
        "total_bugs": len(entries),
        "total_resolved_incidents": len(resolved_incidents),
    })
