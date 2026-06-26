"""Durable audit log — append-only JSONL per day under logs/audit/.

Exports (Studio tier only):
  GET /api/audit-log/export
      ?from=YYYY-MM-DD  (default: today)
      &to=YYYY-MM-DD    (default: today)
      &format=jsonl|zip (default: jsonl for single day, zip for ranges)

  Returns a .jsonl file (single day) or a .zip archive (multi-day).
  Requires studio tier — returns 402 otherwise.
"""
from __future__ import annotations

import io
import json
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, Response, jsonify, request

_lock = threading.Lock()
_LOG_DIR = Path(__file__).parent / "logs" / "audit"

audit_log_export_bp = Blueprint("audit_log_export", __name__)


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


def audit_log(event: str, **kwargs: object) -> None:
    """Append one audit entry. Never raises — failures are silently swallowed."""
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        log_file = _LOG_DIR / f"{today}.jsonl"
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **{k: v for k, v in kwargs.items() if v is not None},
        }
        line = json.dumps(entry, default=str) + "\n"
        with _lock:
            with log_file.open("a", encoding="utf-8") as fh:
                fh.write(line)
    except Exception as exc:  # noqa: BLE001
        import sys as _sys  # noqa: PLC0415
        print(f"[audit_log] WARNING: write failed — {exc}", file=_sys.stderr)


# ---------------------------------------------------------------------------
# Export route (Studio tier gate)
# ---------------------------------------------------------------------------


@audit_log_export_bp.get("/api/audit-log/export")
def export_audit_log_route():
    """Studio-only: download audit log files for a date range.

    Query params:
      from   ISO date string, default today (UTC)
      to     ISO date string, default today (UTC)
      format 'jsonl' or 'zip'; ignored for single-day (always jsonl); for
             multi-day defaults to 'zip'
    """
    from feature_gates import feature_enabled  # noqa: PLC0415

    # Inline tier check (not decorator) so we can return the right JSON body
    if not feature_enabled("audit_log_export"):
        return (
            jsonify(
                {
                    "error": "audit_log_export_requires_studio_tier",
                    "upgrade_url": "/billing",
                }
            ),
            402,
        )

    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    from_str = request.args.get("from", today_str)
    to_str = request.args.get("to", today_str)

    try:
        from_date = datetime.strptime(from_str, "%Y-%m-%d").date()
        to_date = datetime.strptime(to_str, "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"error": "invalid_date_format", "message": "Use YYYY-MM-DD"}), 400

    if from_date > to_date:
        return jsonify({"error": "invalid_range", "message": "'from' must be <= 'to'"}), 400

    from datetime import timedelta  # noqa: PLC0415

    days: list[str] = []
    cur = from_date
    while cur <= to_date:
        days.append(cur.strftime("%Y-%m-%d"))
        cur += timedelta(days=1)

    # Collect existing log files
    found: list[tuple[str, Path]] = []
    for day in days:
        p = _LOG_DIR / f"{day}.jsonl"
        if p.exists():
            found.append((day, p))

    if not found:
        return jsonify({"error": "no_audit_logs_found", "range": {"from": from_str, "to": to_str}}), 404

    if len(found) == 1:
        # Single day — return raw JSONL
        day, path = found[0]
        content = path.read_bytes()
        return Response(
            content,
            mimetype="application/x-ndjson",
            headers={"Content-Disposition": f'attachment; filename="audit-{day}.jsonl"'},
        )

    # Multi-day — return zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for day, path in found:
            zf.write(path, arcname=f"audit-{day}.jsonl")
    buf.seek(0)
    filename = f"audit-{from_str}--{to_str}.zip"
    return Response(
        buf.read(),
        mimetype="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
