"""
findings_db.py — Persistent findings storage for SIC→SOC pipeline.

Provides:
  - findings_init_db()      — idempotent schema creation
  - upsert_finding()        — insert or update by fingerprint (dedup across scans)
  - list_findings()         — query with optional filters
  - get_finding()           — single finding by id
  - link_incident()         — attach an incident_id to a finding
  - accept_finding()        — mark a finding as risk-accepted
  - rollup_by_project()     — multi-project heat map query
  - findings_summary()      — counts by priority/status for a project

Fingerprint strategy: SHA-256 of (project_slug + "|" + cve_or_check_id + "|" + name[:40])
so the same finding across multiple scans of the same project deduplicates correctly
while different projects keep independent finding records.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_DB_PATH = Path.home() / ".sic" / "state.db"
_db_init_done: bool = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _nanoid() -> str:
    return secrets.token_urlsafe(15)[:20]


def _iso_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


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


def _fingerprint(project_slug: str, name: str, cve_id: str | None, check_id: str | None) -> str:
    key = f"{project_slug}|{cve_id or check_id or ''}|{name[:40]}"
    return hashlib.sha256(key.encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def findings_init_db() -> None:
    """Create findings table if not present. Idempotent."""
    global _db_init_done
    if _db_init_done:
        return
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id                  TEXT PRIMARY KEY,
                project             TEXT NOT NULL,
                fingerprint         TEXT NOT NULL,
                severity            TEXT NOT NULL,
                priority            TEXT NOT NULL,
                name                TEXT NOT NULL,
                description         TEXT,
                cve_id              TEXT,
                check_id            TEXT,
                source              TEXT,
                first_seen          TEXT NOT NULL,
                last_seen           TEXT NOT NULL,
                sla_deadline        TEXT,
                days_allowed        INTEGER,
                exploitation_status TEXT,
                asset_tier          TEXT DEFAULT 'production',
                incident_id         TEXT REFERENCES incidents(id),
                status              TEXT NOT NULL DEFAULT 'open'
                                        CHECK(status IN ('open','accepted','remediated')),
                kev                 INTEGER DEFAULT 0,
                epss                REAL,
                cvss_v3             REAL,
                cwe                 TEXT,
                owasp_category      TEXT,
                risk_accept_reason  TEXT,
                risk_accept_expires TEXT,
                deleted_at          TEXT
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_project "
            "ON findings(project, status, priority)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_fingerprint "
            "ON findings(fingerprint)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_sla "
            "ON findings(sla_deadline, status)"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uidx_findings_fp "
            "ON findings(fingerprint) WHERE deleted_at IS NULL"
        )
        conn.commit()
    _db_init_done = True


# ---------------------------------------------------------------------------
# Priority mapping
# ---------------------------------------------------------------------------

_SEV_TO_PRIORITY = {
    "critical": "P0",
    "high":     "P1",
    "medium":   "P2",
    "low":      "P3",
    "info":     "P3",
    "unknown":  "P3",
}


def _priority(severity: str, force_p0: bool = False) -> str:
    if force_p0:
        return "P0"
    return _SEV_TO_PRIORITY.get(severity.lower(), "P3")


# ---------------------------------------------------------------------------
# Write operations
# ---------------------------------------------------------------------------


def upsert_finding(
    project_slug: str,
    finding: dict[str, Any],
    asset_tier: str = "production",
    sla_info: dict[str, Any] | None = None,
) -> str:
    """Insert or update a finding by fingerprint. Returns finding id.

    On conflict (same fingerprint, not deleted): updates last_seen, enrichment
    fields, and SLA deadline. first_seen is preserved from the original insert.
    """
    findings_init_db()

    enrichment = finding.get("enrichment") or {}
    name = _extract_name(finding)
    severity = _extract_severity(finding)
    cve_id = enrichment.get("cve_id") or _extract_cve(finding)
    check_id = finding.get("checkID") or finding.get("check_id")
    description = finding.get("description") or finding.get("Description") or finding.get("details") or ""
    source = finding.get("_source") or "unknown"
    force_p0 = bool(enrichment.get("force_p0"))
    priority = _priority(severity, force_p0)

    fp = _fingerprint(project_slug, name, cve_id, check_id)
    now = _iso_now()

    sla_deadline = None
    days_allowed = None
    exploitation_status = None
    if sla_info:
        sla_deadline = sla_info.get("deadline")
        days_allowed = sla_info.get("days_allowed")
        exploitation_status = sla_info.get("exploitation_status")

    with _connect() as conn:
        existing = conn.execute(
            "SELECT id FROM findings WHERE fingerprint = ? AND deleted_at IS NULL",
            (fp,),
        ).fetchone()

        if existing:
            fid = existing["id"]
            conn.execute(
                """
                UPDATE findings SET
                    last_seen=?, severity=?, priority=?, description=?,
                    sla_deadline=COALESCE(?,sla_deadline),
                    days_allowed=COALESCE(?,days_allowed),
                    exploitation_status=COALESCE(?,exploitation_status),
                    kev=?, epss=?, cvss_v3=?, cwe=?,
                    owasp_category=COALESCE(?,owasp_category)
                WHERE id=?
                """,
                (
                    now, severity, priority, description[:500],
                    sla_deadline, days_allowed, exploitation_status,
                    int(bool(enrichment.get("kev"))),
                    enrichment.get("epss"),
                    enrichment.get("cvss_v3"),
                    enrichment.get("cwe"),
                    enrichment.get("owasp_category"),
                    fid,
                ),
            )
        else:
            fid = _nanoid()
            conn.execute(
                """
                INSERT INTO findings (
                    id, project, fingerprint, severity, priority, name, description,
                    cve_id, check_id, source, first_seen, last_seen,
                    sla_deadline, days_allowed, exploitation_status, asset_tier,
                    kev, epss, cvss_v3, cwe, owasp_category
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    fid, project_slug, fp, severity, priority,
                    name[:120], description[:500],
                    cve_id, check_id, source,
                    now, now,
                    sla_deadline, days_allowed, exploitation_status, asset_tier,
                    int(bool(enrichment.get("kev"))),
                    enrichment.get("epss"),
                    enrichment.get("cvss_v3"),
                    enrichment.get("cwe"),
                    enrichment.get("owasp_category"),
                ),
            )
        conn.commit()

    return fid


def upsert_findings_batch(
    project_slug: str,
    findings: list[dict[str, Any]],
    asset_tier: str = "production",
    sla_map: dict[str, dict] | None = None,
) -> list[str]:
    """Batch upsert. sla_map keys are finding fingerprints."""
    findings_init_db()
    ids = []
    for f in findings:
        enrichment = f.get("enrichment") or {}
        name = _extract_name(f)
        cve_id = enrichment.get("cve_id") or _extract_cve(f)
        check_id = f.get("checkID") or f.get("check_id")
        fp = _fingerprint(project_slug, name, cve_id, check_id)
        sla_info = (sla_map or {}).get(fp)
        fid = upsert_finding(project_slug, f, asset_tier=asset_tier, sla_info=sla_info)
        ids.append(fid)
    return ids


def link_incident(finding_id: str, incident_id: str) -> None:
    """Attach an incident to a finding."""
    findings_init_db()
    with _connect() as conn:
        conn.execute(
            "UPDATE findings SET incident_id=? WHERE id=?",
            (incident_id, finding_id),
        )
        conn.commit()


def accept_finding(finding_id: str, reason: str, expires: str) -> None:
    """Mark a finding as risk-accepted with reason and expiry date."""
    findings_init_db()
    with _connect() as conn:
        conn.execute(
            """
            UPDATE findings SET status='accepted', risk_accept_reason=?,
            risk_accept_expires=? WHERE id=?
            """,
            (reason, expires, finding_id),
        )
        conn.commit()


def mark_remediated(finding_id: str) -> None:
    """Mark a finding as remediated."""
    findings_init_db()
    with _connect() as conn:
        conn.execute(
            "UPDATE findings SET status='remediated' WHERE id=?",
            (finding_id,),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Read operations
# ---------------------------------------------------------------------------


def list_findings(
    project: str | None = None,
    priority: str | None = None,
    status: str | None = None,
    overdue_only: bool = False,
    limit: int = 200,
) -> list[dict]:
    """Query findings with optional filters."""
    findings_init_db()
    where = ["deleted_at IS NULL"]
    params: list[Any] = []

    if project:
        where.append("project = ?")
        params.append(project)
    if priority:
        where.append("priority = ?")
        params.append(priority)
    if status:
        where.append("status = ?")
        params.append(status)
    if overdue_only:
        where.append("sla_deadline < ? AND status = 'open'")
        params.append(_iso_now()[:10])

    sql = (
        f"SELECT * FROM findings WHERE {' AND '.join(where)} "
        f"ORDER BY priority ASC, first_seen DESC LIMIT ?"
    )
    params.append(limit)

    with _connect() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def get_finding(finding_id: str) -> dict | None:
    findings_init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM findings WHERE id=? AND deleted_at IS NULL",
            (finding_id,),
        ).fetchone()
        return dict(row) if row else None


def findings_summary(project: str | None = None) -> dict:
    """Counts by priority and status. Includes overdue count."""
    findings_init_db()
    where = "WHERE deleted_at IS NULL"
    params: list[Any] = []
    if project:
        where += " AND project = ?"
        params.append(project)

    today = _iso_now()[:10]

    with _connect() as conn:
        rows = conn.execute(
            f"SELECT priority, status, COUNT(*) as cnt FROM findings {where} "
            f"GROUP BY priority, status",
            params,
        ).fetchall()

        overdue_params = list(params) + [today]
        overdue_where = where + " AND sla_deadline < ? AND status = 'open'"
        overdue = conn.execute(
            f"SELECT COUNT(*) FROM findings {overdue_where}",
            overdue_params,
        ).fetchone()[0]

    summary: dict[str, Any] = {"total": 0, "overdue": overdue, "by_priority": {}}
    for row in rows:
        p = row["priority"]
        s = row["status"]
        c = row["cnt"]
        summary["total"] += c
        if p not in summary["by_priority"]:
            summary["by_priority"][p] = {"open": 0, "accepted": 0, "remediated": 0, "total": 0}
        summary["by_priority"][p][s] = summary["by_priority"][p].get(s, 0) + c
        summary["by_priority"][p]["total"] += c

    return summary


def rollup_by_project() -> list[dict]:
    """Multi-project heat map. Returns all projects with open finding counts."""
    findings_init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT project,
                   COUNT(*) as total,
                   SUM(CASE WHEN priority='P0' AND status='open' THEN 1 ELSE 0 END) as p0_open,
                   SUM(CASE WHEN priority='P1' AND status='open' THEN 1 ELSE 0 END) as p1_open,
                   SUM(CASE WHEN priority='P2' AND status='open' THEN 1 ELSE 0 END) as p2_open,
                   SUM(CASE WHEN priority='P3' AND status='open' THEN 1 ELSE 0 END) as p3_open,
                   SUM(CASE WHEN kev=1 THEN 1 ELSE 0 END) as kev_count,
                   SUM(CASE WHEN sla_deadline < date('now') AND status='open' THEN 1 ELSE 0 END) as overdue,
                   MAX(last_seen) as last_scan
            FROM findings
            WHERE deleted_at IS NULL
            GROUP BY project
            ORDER BY p0_open DESC, p1_open DESC, total DESC
            """,
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Private extraction helpers
# ---------------------------------------------------------------------------


def _extract_name(f: dict) -> str:
    return (
        f.get("name")
        or f.get("vulnerabilityName")
        or f.get("Title")
        or f.get("template-id")
        or f.get("checkID")
        or "Unnamed finding"
    )


def _extract_severity(f: dict) -> str:
    raw = (
        f.get("severity")
        or (f.get("info") or {}).get("severity")
        or f.get("Severity")
        or "unknown"
    )
    return str(raw).lower()


def _extract_cve(f: dict) -> str | None:
    import re
    pattern = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
    for field in ("name", "template-id", "checkID", "Title"):
        val = f.get(field) or ""
        m = pattern.search(str(val))
        if m:
            return m.group(0).upper()
    refs = f.get("references") or f.get("reference") or []
    if isinstance(refs, str):
        refs = [refs]
    for r in refs:
        m = pattern.search(str(r))
        if m:
            return m.group(0).upper()
    return None
