#!/usr/bin/env python3
"""sic_cli.py — Unified CLI for SIC→SOC tooling.

Single terminal entry point for day-to-day SOC operations:

  findings    query and manage findings (open P0+P1, filters, JSON)
  remediate   mark a finding as remediated (with optional evidence)
  accept      risk-accept a finding (reason + expiry)
  rollup      multi-project heat map (wraps soc_rollup.py)
  coverage    OWASP Top 10:2025 coverage report (by project or scan file)
  status      quick org-wide health summary

stdlib only. Sibling SIC modules (findings_db, cwe_owasp, soc_rollup,
sic_to_soc) are imported lazily — every command degrades gracefully with a
[sic_cli]-prefixed stderr message if a dependency is missing.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

# Ensure sibling modules resolve regardless of the caller's cwd.
sys.path.insert(0, str(Path(__file__).parent))


# ---------------------------------------------------------------------------
# Lazy imports / error reporting
# ---------------------------------------------------------------------------


def _err(msg: str) -> None:
    """Write an error line to stderr with the CLI prefix."""
    print(f"[sic_cli] {msg}", file=sys.stderr)


def _lazy(name: str) -> ModuleType | None:
    """Import a sibling SIC module by name; return None (and warn) on failure."""
    try:
        return importlib.import_module(name)
    except Exception as exc:  # noqa: BLE001 — non-fatal, reported to stderr
        _err(f"cannot import {name}: {exc}")
        return None


def _today() -> str:
    """Return today's UTC date as an ISO YYYY-MM-DD string."""
    return datetime.now(tz=timezone.utc).date().isoformat()


# ---------------------------------------------------------------------------
# findings — query and manage findings
# ---------------------------------------------------------------------------


def _is_overdue(finding: dict[str, Any]) -> bool:
    """True if an open finding's SLA deadline is in the past."""
    if finding.get("status") != "open":
        return False
    deadline = finding.get("sla_deadline")
    if not deadline:
        return False
    return str(deadline)[:10] < _today()


def cmd_findings(args: argparse.Namespace) -> int:
    db = _lazy("findings_db")
    if db is None:
        return 1

    # Default view (no explicit priority): open P0 + P1 only.
    priority = args.priority
    try:
        if priority:
            rows = db.list_findings(
                project=args.project,
                priority=priority,
                overdue_only=args.overdue,
            )
        else:
            rows = []
            for pri in ("P0", "P1"):
                rows.extend(
                    db.list_findings(
                        project=args.project,
                        priority=pri,
                        status="open",
                        overdue_only=args.overdue,
                    )
                )
    except Exception as exc:  # noqa: BLE001
        _err(f"findings query failed: {exc}")
        return 1

    if args.json:
        print(json.dumps(rows, indent=2))
        return 0

    if not rows:
        print("  (no matching findings)")
        return 0

    header = (
        f"  {'ID':20}  {'PROJECT':12}  {'P':2}  {'STATUS':10}  "
        f"{'SLA DEADLINE':12}  {'OVERDUE':7}  NAME"
    )
    print(header)
    print("  " + "-" * (len(header) - 2))
    for r in rows:
        overdue = "YES" if _is_overdue(r) else "no"
        deadline = (str(r.get("sla_deadline") or "")[:10]) or "-"
        name = str(r.get("name") or "")[:48]
        print(
            f"  {str(r.get('id') or '')[:20]:20}  "
            f"{str(r.get('project') or '')[:12]:12}  "
            f"{str(r.get('priority') or '')[:2]:2}  "
            f"{str(r.get('status') or '')[:10]:10}  "
            f"{deadline:12}  {overdue:7}  {name}"
        )
    print(f"\n  {len(rows)} finding(s)")
    return 0


# ---------------------------------------------------------------------------
# remediate — mark a finding remediated
# ---------------------------------------------------------------------------


def cmd_remediate(args: argparse.Namespace) -> int:
    db = _lazy("findings_db")
    if db is None:
        return 1

    finding = db.get_finding(args.finding_id)
    if finding is None:
        _err(f"finding not found: {args.finding_id}")
        return 1

    try:
        db.mark_remediated(args.finding_id)
    except Exception as exc:  # noqa: BLE001
        _err(f"mark_remediated failed: {exc}")
        return 1

    # Evidence storage: append to the description field (no schema change).
    if args.evidence:
        try:
            existing = str(finding.get("description") or "")
            updated = f"{existing}\n---\nEvidence: {args.evidence}"[:500]
            db.findings_init_db()
            import sqlite3  # noqa: PLC0415 — used only on the evidence path

            db_path = Path.home() / ".sic" / "state.db"
            conn = sqlite3.connect(str(db_path))
            try:
                conn.execute("PRAGMA busy_timeout=5000")
                conn.execute(
                    "UPDATE findings SET description=? WHERE id=?",
                    (updated, args.finding_id),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception as exc:  # noqa: BLE001 — evidence is best-effort
            _err(f"could not store evidence (finding still remediated): {exc}")

    print(f"  Remediated: {args.finding_id}  ({finding.get('name', '')[:60]})")
    if args.evidence:
        print(f"  Evidence: {args.evidence}")
    return 0


# ---------------------------------------------------------------------------
# accept — risk-accept a finding
# ---------------------------------------------------------------------------


def _valid_future_date(value: str) -> bool:
    try:
        parsed = date.fromisoformat(value[:10])
    except ValueError:
        return False
    return parsed > datetime.now(tz=timezone.utc).date()


def cmd_accept(args: argparse.Namespace) -> int:
    db = _lazy("findings_db")
    if db is None:
        return 1

    if not _valid_future_date(args.expires):
        _err(
            f"--expires must be a future date in YYYY-MM-DD form "
            f"(got '{args.expires}')"
        )
        return 1

    finding = db.get_finding(args.finding_id)
    if finding is None:
        _err(f"finding not found: {args.finding_id}")
        return 1

    try:
        db.accept_finding(args.finding_id, args.reason, args.expires)
    except Exception as exc:  # noqa: BLE001
        _err(f"accept_finding failed: {exc}")
        return 1

    print(f"  Risk-accepted: {args.finding_id}  ({finding.get('name', '')[:60]})")
    print(f"  Reason:  {args.reason}")
    print(f"  Expires: {args.expires}")
    return 0


# ---------------------------------------------------------------------------
# rollup — multi-project heat map (wraps soc_rollup.py)
# ---------------------------------------------------------------------------


def cmd_rollup(args: argparse.Namespace) -> int:
    rollup = _lazy("soc_rollup")
    db = _lazy("findings_db")
    if rollup is None or db is None:
        return 1

    if args.project:
        try:
            summary = db.findings_summary(project=args.project)
        except Exception as exc:  # noqa: BLE001
            _err(f"findings_summary failed: {exc}")
            return 1
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            rollup.print_project_summary(summary, args.project)
        return 0

    try:
        rows = db.rollup_by_project()
    except Exception as exc:  # noqa: BLE001
        _err(f"rollup_by_project failed: {exc}")
        return 1
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        rollup.print_heat_map(rows)
    return 0


# ---------------------------------------------------------------------------
# coverage — OWASP Top 10:2025 coverage report
# ---------------------------------------------------------------------------


def _coverage_from_project(db: ModuleType, project: str) -> dict[str, dict[str, int]]:
    """Group a project's findings by OWASP Top 10:2025 category.

    Only canonical 2025 categories are counted. A stored owasp_category from an
    older taxonomy (e.g. the 2021 list) is ignored in favour of re-deriving from
    the finding's CWE; if no 2025 category can be derived, the finding is
    counted as unmapped.
    """
    cwe = _lazy("cwe_owasp")
    valid = set(cwe.owasp_categories()) if cwe is not None else set()
    rows = db.list_findings(project=project, limit=1000)
    buckets: dict[str, dict[str, int]] = {}
    unmapped = 0
    for r in rows:
        category = r.get("owasp_category")
        if category not in valid and cwe is not None:
            category = cwe.get_owasp_category(r.get("cwe") or "")
        if category not in valid:
            unmapped += 1
            continue
        b = buckets.setdefault(
            category, {"total": 0, "open": 0, "accepted": 0, "remediated": 0}
        )
        b["total"] += 1
        status = str(r.get("status") or "open")
        b[status] = b.get(status, 0) + 1
    buckets["__unmapped__"] = {"total": unmapped}
    return buckets


def _coverage_from_scan(scan_path: str) -> dict[str, dict[str, int]]:
    """Group a raw scan file's findings by OWASP category via CWE extraction."""
    loader = _lazy("sic_to_soc")
    cwe = _lazy("cwe_owasp")
    if loader is None or cwe is None:
        return {}
    findings = loader.load_findings(scan_path)
    buckets: dict[str, dict[str, int]] = {}
    unmapped = 0
    for f in findings:
        extracted = cwe._extract_cwe(f)
        category = cwe.get_owasp_category(extracted) if extracted else None
        if not category:
            unmapped += 1
            continue
        b = buckets.setdefault(category, {"total": 0, "open": 0})
        b["total"] += 1
        b["open"] += 1
    buckets["__unmapped__"] = {"total": unmapped}
    return buckets


def cmd_coverage(args: argparse.Namespace) -> int:
    cwe = _lazy("cwe_owasp")
    if cwe is None:
        return 1

    if not args.project and not args.scan:
        _err("coverage requires either --project or --scan")
        return 1

    if args.scan:
        if not Path(args.scan).exists():
            _err(f"scan file not found: {args.scan}")
            return 1
        buckets = _coverage_from_scan(args.scan)
        label = f"scan: {Path(args.scan).name}"
    else:
        db = _lazy("findings_db")
        if db is None:
            return 1
        try:
            buckets = _coverage_from_project(db, args.project)
        except Exception as exc:  # noqa: BLE001
            _err(f"coverage query failed: {exc}")
            return 1
        label = f"project: {args.project}"

    unmapped = buckets.pop("__unmapped__", {"total": 0}).get("total", 0)

    if args.json:
        out = {
            "label": label,
            "categories": buckets,
            "unmapped": unmapped,
            "covered": len(buckets),
            "total_categories": 10,
        }
        print(json.dumps(out, indent=2))
        return 0

    print(f"\n  OWASP Top 10:2025 Coverage  -  {label}\n")
    for category in cwe.owasp_categories():
        b = buckets.get(category)
        name = category
        if b:
            parts = []
            for status in ("open", "accepted", "remediated"):
                if b.get(status):
                    parts.append(f"{status}:{b[status]}")
            detail = "(" + " ".join(parts) + ")" if parts else ""
            print(f"  {name:46} {b['total']:>2} findings  {detail}")
        else:
            print(f"  {name:46}  0 findings  - no coverage")

    covered = len(buckets)
    print(
        f"\n  Coverage: {covered}/10 categories  |  "
        f"Unmapped findings: {unmapped}  (no CWE detected)\n"
    )
    return 0


# ---------------------------------------------------------------------------
# status — quick health summary
# ---------------------------------------------------------------------------


def cmd_status(args: argparse.Namespace) -> int:
    db = _lazy("findings_db")
    if db is None:
        return 1

    try:
        rows = db.rollup_by_project()
    except Exception as exc:  # noqa: BLE001
        _err(f"rollup_by_project failed: {exc}")
        return 1

    if args.json:
        print(json.dumps(rows, indent=2))
        return 0

    if not rows:
        print("  (no findings in DB — run a scan first)")
        return 0

    total_open = 0
    total_p0 = 0
    total_overdue = 0
    total_kev = 0

    print(f"\n  SIC->SOC status  ({_today()})\n")
    for r in rows:
        open_count = (
            int(r.get("p0_open", 0))
            + int(r.get("p1_open", 0))
            + int(r.get("p2_open", 0))
            + int(r.get("p3_open", 0))
        )
        p0 = int(r.get("p0_open", 0))
        overdue = int(r.get("overdue", 0))
        kev = int(r.get("kev_count", 0))
        last_scan = (str(r.get("last_scan") or "")[:10]) or "never"

        total_open += open_count
        total_p0 += p0
        total_overdue += overdue
        total_kev += kev

        print(
            f"  {str(r.get('project') or ''):16}  "
            f"open:{open_count:<4} P0:{p0:<3} overdue:{overdue:<3} "
            f"KEV:{kev:<3} last_scan:{last_scan}"
        )

    print(
        f"\n  TOTAL  open:{total_open}  P0:{total_p0}  "
        f"overdue:{total_overdue}  KEV:{total_kev}\n"
    )
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sic_cli.py",
        description="Unified CLI for SIC→SOC tooling.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # findings
    p_find = sub.add_parser("findings", help="query and manage findings")
    p_find.add_argument("--project", default=None, help="filter by project slug")
    p_find.add_argument(
        "--priority", default=None, help="filter by priority (P0/P1/P2/P3)"
    )
    p_find.add_argument(
        "--overdue", action="store_true", help="only findings past SLA deadline"
    )
    p_find.add_argument("--json", action="store_true", help="output JSON")
    p_find.set_defaults(func=cmd_findings)

    # remediate
    p_rem = sub.add_parser("remediate", help="mark a finding as remediated")
    p_rem.add_argument("finding_id", help="finding id")
    p_rem.add_argument("--evidence", default=None, help="remediation evidence note")
    p_rem.set_defaults(func=cmd_remediate)

    # accept
    p_acc = sub.add_parser("accept", help="risk-accept a finding")
    p_acc.add_argument("finding_id", help="finding id")
    p_acc.add_argument("--reason", required=True, help="risk acceptance reason")
    p_acc.add_argument(
        "--expires", required=True, help="expiry date (YYYY-MM-DD, must be future)"
    )
    p_acc.set_defaults(func=cmd_accept)

    # rollup
    p_roll = sub.add_parser("rollup", help="multi-project heat map")
    p_roll.add_argument("--project", default=None, help="single project summary")
    p_roll.add_argument("--json", action="store_true", help="output JSON")
    p_roll.set_defaults(func=cmd_rollup)

    # coverage
    p_cov = sub.add_parser("coverage", help="OWASP Top 10:2025 coverage report")
    p_cov.add_argument("--project", default=None, help="coverage for a project")
    p_cov.add_argument("--scan", default=None, help="coverage for a scan JSON file")
    p_cov.add_argument("--json", action="store_true", help="output JSON")
    p_cov.set_defaults(func=cmd_coverage)

    # status
    p_stat = sub.add_parser("status", help="quick org-wide health summary")
    p_stat.add_argument("--json", action="store_true", help="output JSON")
    p_stat.set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        _err("interrupted")
        return 130
    except Exception as exc:  # noqa: BLE001 — top-level guard
        _err(f"unexpected error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
