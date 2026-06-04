"""
sla_alerts.py — Discord webhook alerts for findings that just crossed their SLA.

Scans open P0/P1 findings whose sla_deadline is today or yesterday, and posts a
Discord alert for each one that has not been alerted before. Sent alert IDs are
recorded in ~/.sic/sla_alerts_sent.json so the same finding is never pinged twice.

CLI:
    python sla_alerts.py [--dry-run] [--webhook URL]

Reads DISCORD_WEBHOOK_SOC from env when --webhook is not provided.
stdlib only — uses urllib for the webhook POST, no external deps.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).parent))

import findings_db  # noqa: E402

_SENT_PATH = Path.home() / ".sic" / "sla_alerts_sent.json"
_SIC_CLI = "python C:/Za/sic/sic_cli.py remediate"


def _today() -> date:
    return datetime.now(timezone.utc).date()


def _load_sent() -> set[str]:
    try:
        data = json.loads(_SENT_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return set(data.get("sent", []))
    except (FileNotFoundError, ValueError, OSError):
        pass
    return set()


def _save_sent(sent: set[str]) -> None:
    try:
        _SENT_PATH.parent.mkdir(parents=True, exist_ok=True)
        _SENT_PATH.write_text(
            json.dumps({"sent": sorted(sent), "updated": _today().isoformat()}, indent=2),
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"[sla_alerts] could not persist sent state: {exc}", file=sys.stderr)


def _deadline_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return None


def _format_message(finding: dict) -> str:
    project = finding.get("project", "unknown")
    priority = finding.get("priority", "P?")
    cve = finding.get("cve_id") or finding.get("name", "unnamed")
    deadline = (finding.get("sla_deadline") or "")[:10] or "unset"
    first_seen = (finding.get("first_seen") or "")[:10] or "unknown"
    kev = "YES" if finding.get("kev") else "no"
    fid = finding.get("id", "")
    return (
        f"🚨 SLA BREACH — {project} {priority}: {cve}\n"
        f"Deadline: {deadline} | First seen: {first_seen} | KEV: {kev}\n"
        f"Fix it: {_SIC_CLI} {fid}"
    )


def _post_discord(webhook_url: str, content: str) -> bool:
    payload = json.dumps({"content": content}).encode()
    req = Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except (URLError, OSError) as exc:
        print(f"[sla_alerts] Discord POST failed: {exc}", file=sys.stderr)
        return False


def check_and_alert(discord_webhook_url: str | None = None, dry_run: bool = False) -> int:
    """Check for P0/P1 findings that just crossed their SLA deadline.

    'Just crossed' = sla_deadline is today or yesterday AND alert not yet sent.
    Tracks sent alerts in ~/.sic/sla_alerts_sent.json to avoid duplicate pings.

    Returns count of alerts sent.
    """
    webhook = discord_webhook_url or os.environ.get("DISCORD_WEBHOOK_SOC")
    if not webhook and not dry_run:
        print("[sla_alerts] no webhook configured (set DISCORD_WEBHOOK_SOC or --webhook)",
              file=sys.stderr)
        return 0

    today = _today()
    yesterday = today - timedelta(days=1)
    window = {today, yesterday}

    sent = _load_sent()
    candidates: list[dict] = []
    for priority in ("P0", "P1"):
        for f in findings_db.list_findings(priority=priority, status="open"):
            dl = _deadline_date(f.get("sla_deadline"))
            if dl is not None and dl in window and f["id"] not in sent:
                candidates.append(f)

    count = 0
    for f in candidates:
        msg = _format_message(f)
        if dry_run:
            print(msg)
            print("---")
            count += 1
            continue
        if _post_discord(webhook, msg):
            sent.add(f["id"])
            count += 1

    if not dry_run and count:
        _save_sent(sent)

    return count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Discord SLA breach alerts for SIC findings."
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Print alerts that would be sent; do not POST or persist state.")
    parser.add_argument("--webhook", default=None,
                        help="Discord webhook URL (overrides DISCORD_WEBHOOK_SOC).")
    args = parser.parse_args()

    n = check_and_alert(discord_webhook_url=args.webhook, dry_run=args.dry_run)
    label = "would send" if args.dry_run else "sent"
    print(f"[sla_alerts] alerts {label}: {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
