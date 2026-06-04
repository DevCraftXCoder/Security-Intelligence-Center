"""
soc_rollup.py — Multi-project SOC heat map and incident↔findings sync.

Usage:
    python C:/Za/sic/soc_rollup.py                    # print org-wide heat map
    python C:/Za/sic/soc_rollup.py --project dropstream  # single project summary
    python C:/Za/sic/soc_rollup.py --sync-incidents       # link open findings to incidents
    python C:/Za/sic/soc_rollup.py --json                 # output JSON instead of text
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Lazy imports from SIC modules
# ---------------------------------------------------------------------------

def _import(name):
    import importlib
    import sys as _sys
    sic_dir = str(Path(__file__).parent)
    if sic_dir not in _sys.path:
        _sys.path.insert(0, sic_dir)
    try:
        return importlib.import_module(name)
    except ImportError as e:
        print(f"[soc_rollup] Cannot import {name}: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Heat map display
# ---------------------------------------------------------------------------


def _grade(p0: int, p1: int, overdue: int) -> str:
    if p0 > 0 or overdue > 2:
        return "F"
    if p1 > 3:
        return "D"
    if p1 > 0:
        return "C"
    return "B"


def print_heat_map(rows: list[dict]) -> None:
    if not rows:
        print("  (no findings in DB — run sic_to_soc.py on a project first)")
        return

    print(f"\n  {'PROJECT':20}  {'P0':>4}  {'P1':>4}  {'P2':>4}  {'P3':>4}  {'KEV':>4}  {'OVER':>4}  {'GRD':>3}  LAST SCAN")
    print("  " + "-" * 78)
    for r in rows:
        g = _grade(r["p0_open"], r["p1_open"], r["overdue"])
        last = (r.get("last_scan") or "")[:10]
        print(
            f"  {r['project']:20}  {r['p0_open']:>4}  {r['p1_open']:>4}  "
            f"{r['p2_open']:>4}  {r['p3_open']:>4}  {r['kev_count']:>4}  "
            f"{r['overdue']:>4}  {g:>3}  {last}"
        )
    print()
    totals = {
        "p0": sum(r["p0_open"] for r in rows),
        "p1": sum(r["p1_open"] for r in rows),
        "kev": sum(r["kev_count"] for r in rows),
        "overdue": sum(r["overdue"] for r in rows),
    }
    print(f"  Org totals — P0:{totals['p0']}  P1:{totals['p1']}  "
          f"KEV:{totals['kev']}  Overdue:{totals['overdue']}")
    print()


def print_project_summary(summary: dict, project: str) -> None:
    print(f"\n  Project: {project}")
    print(f"  Total findings: {summary['total']}  Overdue: {summary['overdue']}")
    for p in ("P0", "P1", "P2", "P3"):
        d = summary.get("by_priority", {}).get(p)
        if not d:
            continue
        print(f"  {p}: {d['total']:>3} total  "
              f"open:{d.get('open',0)}  accepted:{d.get('accepted',0)}  "
              f"remediated:{d.get('remediated',0)}")
    print()


# ---------------------------------------------------------------------------
# Incident sync — auto-create incidents for P0/P1 findings without one
# ---------------------------------------------------------------------------


def sync_incidents(project: str | None = None, dry_run: bool = False) -> int:
    """Create incidents for P0/P1 open findings that have no incident linked.

    Returns count of incidents created (or would create in dry-run).
    """
    db_mod = _import("findings_db")
    if not db_mod:
        print("[soc_rollup] findings_db not available — cannot sync incidents", file=sys.stderr)
        return 0

    # We call incidents.py directly via sqlite rather than importing Flask blueprint
    import sqlite3
    import secrets

    DB_PATH = Path.home() / ".sic" / "state.db"
    if not DB_PATH.exists():
        print("[soc_rollup] state.db not found — run a scan first", file=sys.stderr)
        return 0

    db_mod.findings_init_db()

    filters: dict = {"status": "open"}
    if project:
        filters["project"] = project

    created = 0
    for priority in ("P0", "P1"):
        findings = db_mod.list_findings(
            project=project, priority=priority, status="open"
        )
        for f in findings:
            if f.get("incident_id"):
                continue  # already linked

            inc_severity = "P0" if priority == "P0" else "P1"
            title = f"[{f['project']}] {f['name'][:80]}"
            kev_note = " [KEV]" if f.get("kev") else ""
            epss_note = f" [EPSS:{f['epss']:.2f}]" if f.get("epss") and f["epss"] > 0.3 else ""
            desc = (
                f"Auto-created from finding {f['id']}. "
                f"First seen: {f.get('first_seen','')[:10]}. "
                f"SLA deadline: {f.get('sla_deadline','unset')}.{kev_note}{epss_note}"
            )

            if dry_run:
                print(f"  [dry-run] Would create {inc_severity} incident: {title}")
                created += 1
                continue

            try:
                conn = sqlite3.connect(str(DB_PATH))
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute("PRAGMA journal_mode=WAL")
                now = datetime.now(tz=timezone.utc).isoformat()
                inc_id = secrets.token_urlsafe(15)[:20]
                conn.execute(
                    """
                    INSERT INTO incidents
                    (id, severity, title, description, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, 'open', ?, ?)
                    """,
                    (inc_id, inc_severity, title, desc, now, now),
                )
                conn.commit()
                conn.close()
                db_mod.link_incident(f["id"], inc_id)
                print(f"  Created {inc_severity} incident {inc_id}: {title[:60]}")
                created += 1
            except Exception as e:
                print(f"  [soc_rollup] Failed to create incident for {f['id']}: {e}",
                      file=sys.stderr)

    return created


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-project SOC heat map and incident sync"
    )
    parser.add_argument("--project", default=None,
                        help="Filter to a single project slug")
    parser.add_argument("--sync-incidents", action="store_true",
                        help="Auto-create incidents for P0/P1 findings without one")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be done without making changes")
    parser.add_argument("--json", action="store_true",
                        help="Output JSON instead of text")
    args = parser.parse_args()

    db_mod = _import("findings_db")
    if not db_mod:
        print("[soc_rollup] findings_db unavailable — exiting", file=sys.stderr)
        sys.exit(1)

    if args.sync_incidents:
        n = sync_incidents(project=args.project, dry_run=args.dry_run)
        label = "would create" if args.dry_run else "created"
        print(f"\n  Incidents {label}: {n}")
        return

    if args.project:
        summary = db_mod.findings_summary(project=args.project)
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print_project_summary(summary, args.project)
    else:
        rows = db_mod.rollup_by_project()
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print_heat_map(rows)


if __name__ == "__main__":
    main()
