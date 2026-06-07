#!/usr/bin/env python3
"""
sla_engine.py  --  Two-axis SLA model for SIC findings.

Remediation deadlines are driven by  exploitation_status x asset_tier.
When enrichment data is absent, fall back to a severity-only (P0-P3) SLA.

Field shapes (consistent with sic_to_soc.py):
    finding.severity / finding.Severity / finding.info.severity  -> raw severity
    finding.enrichment = {
        "kev":   bool,            # present in CISA KEV catalog
        "epss":  float,           # 0.0 - 1.0 exploit prediction score
        "force_p0": bool,         # operator override -> treat as KEV/critical
        "public_exploit": bool,   # public PoC / Metasploit module exists
    }

stdlib only, no external dependencies.
"""

from __future__ import annotations

import sys
from datetime import date, datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# SLA matrices
# ---------------------------------------------------------------------------

# exploitation_status x asset_tier -> days to remediate.
SLA_MATRIX: dict[str, dict[str, int]] = {
    #                  production  staging  internal  dev
    "kev":            {"production": 1, "staging": 2, "internal": 3, "dev": 7},
    "high_epss":      {"production": 3, "staging": 5, "internal": 7, "dev": 14},
    "public_exploit": {"production": 3, "staging": 7, "internal": 14, "dev": 30},
    "no_exploit":     {"production": 7, "staging": 14, "internal": 30, "dev": 90},
}

# Severity-only fallback (days) when no enrichment data is available.
SEVERITY_SLA: dict[str, int] = {
    "P0": 3,
    "P1": 7,
    "P2": 30,
    "P3": 90,
}

# EPSS threshold above which a finding is treated as high_epss.
HIGH_EPSS_THRESHOLD = 0.5

# exploitation_status -> the priority bucket it implies (for labelling).
_STATUS_PRIORITY: dict[str, str] = {
    "kev": "P0",
    "high_epss": "P1",
    "public_exploit": "P1",
    "no_exploit": "P2",
}

_STATUS_LABEL: dict[str, str] = {
    "kev": "KEV",
    "high_epss": "High EPSS",
    "public_exploit": "Public Exploit",
    "no_exploit": "No Known Exploit",
}

_VALID_TIERS = ("production", "staging", "internal", "dev")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _today() -> date:
    return datetime.now(timezone.utc).date()


def _normalize_tier(asset_tier: str | None) -> str:
    tier = (asset_tier or "production").strip().lower()
    if tier not in _VALID_TIERS:
        print(
            f"[sla_engine] unknown asset_tier {asset_tier!r}; "
            f"defaulting to 'production'",
            file=sys.stderr,
        )
        tier = "production"
    return tier


def _severity_to_priority(finding: dict) -> str:
    """Map a finding's raw severity string to a P0-P3 priority bucket."""
    raw = (
        finding.get("severity")
        or (finding.get("info") or {}).get("severity")
        or finding.get("Severity")
        or "unknown"
    )
    sev = str(raw).strip().lower()
    if sev in ("critical", "p0", "crit"):
        return "P0"
    if sev in ("high", "p1"):
        return "P1"
    if sev in ("medium", "moderate", "p2", "med"):
        return "P2"
    if sev in ("low", "p3", "info", "informational", "none"):
        return "P3"
    # Unknown severity -> treat conservatively as medium.
    return "P2"


def _exploitation_status(finding: dict) -> str | None:
    """Derive the exploitation_status axis from enrichment data.

    Returns one of the SLA_MATRIX keys, or None when enrichment is absent
    (so the caller can fall back to severity-only SLA).
    """
    enrichment = finding.get("enrichment")
    if not isinstance(enrichment, dict) or not enrichment:
        return None

    if enrichment.get("force_p0") or enrichment.get("kev"):
        return "kev"

    epss = enrichment.get("epss")
    try:
        if epss is not None and float(epss) >= HIGH_EPSS_THRESHOLD:
            return "high_epss"
    except (TypeError, ValueError):
        print(
            f"[sla_engine] invalid epss value {epss!r}; ignoring",
            file=sys.stderr,
        )

    if enrichment.get("public_exploit"):
        return "public_exploit"

    # Enrichment present but nothing indicates exploitability.
    return "no_exploit"


def _parse_first_seen(first_seen: str | None) -> date:
    if not first_seen:
        return _today()
    try:
        # Accept full ISO datetimes or plain ISO dates.
        cleaned = str(first_seen).strip()
        if "T" in cleaned:
            return datetime.fromisoformat(cleaned.replace("Z", "+00:00")).date()
        return date.fromisoformat(cleaned[:10])
    except (TypeError, ValueError):
        print(
            f"[sla_engine] invalid first_seen {first_seen!r}; using today",
            file=sys.stderr,
        )
        return _today()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def calculate_sla_deadline(
    finding: dict,
    asset_tier: str = "production",
    first_seen: str | None = None,
) -> dict:
    """Calculate the SLA deadline for a single finding.

    Returns a dict with deadline, days_allowed, exploitation_status,
    overdue / days_overdue, and a human-readable sla_label.
    """
    if not isinstance(finding, dict):
        print(
            f"[sla_engine] finding is not a dict ({type(finding).__name__}); "
            f"returning P3 fallback",
            file=sys.stderr,
        )
        finding = {}

    tier = _normalize_tier(asset_tier)
    started = _parse_first_seen(first_seen)
    status = _exploitation_status(finding)

    if status is not None:
        days_allowed = SLA_MATRIX[status][tier]
        exploit_priority = _STATUS_PRIORITY[status]
        severity_priority = _severity_to_priority(finding)
        priority = min(exploit_priority, severity_priority)
        status_out = status
        label_status = _STATUS_LABEL[status]
    else:
        # Severity-only fallback.
        priority = _severity_to_priority(finding)
        days_allowed = SEVERITY_SLA[priority]
        status_out = "unknown"
        label_status = "No Enrichment"

    deadline = started + timedelta(days=days_allowed)
    today = _today()
    days_overdue = max(0, (today - deadline).days)
    overdue = days_overdue > 0

    sla_label = f"{priority} · {days_allowed}d · {label_status}"

    return {
        "deadline": deadline.isoformat(),
        "days_allowed": days_allowed,
        "exploitation_status": status_out,
        "priority": priority,
        "overdue": overdue,
        "days_overdue": days_overdue,
        "sla_label": sla_label,
    }


def is_overdue(finding: dict, asset_tier: str = "production") -> bool:
    """Quick check whether a finding is past its SLA deadline."""
    first_seen = None
    if isinstance(finding, dict):
        first_seen = (
            finding.get("first_seen")
            or finding.get("firstSeen")
            or finding.get("created_at")
        )
    return calculate_sla_deadline(finding, asset_tier, first_seen)["overdue"]


def sla_summary(findings: list[dict], asset_tier: str = "production") -> dict:
    """Aggregate SLA stats across all findings."""
    if not isinstance(findings, list):
        print(
            f"[sla_engine] findings is not a list "
            f"({type(findings).__name__}); treating as empty",
            file=sys.stderr,
        )
        findings = []

    today = _today()
    week_out = today + timedelta(days=7)

    def _empty_bucket() -> dict:
        return {
            "total": 0,
            "overdue": 0,
            "due_today": 0,
            "due_this_week": 0,
            "on_track": 0,
        }

    by_priority = {p: _empty_bucket() for p in ("P0", "P1", "P2", "P3")}

    total = overdue = due_today = due_this_week = on_track = 0

    for finding in findings:
        if not isinstance(finding, dict):
            print(
                f"[sla_engine] skipping non-dict finding "
                f"({type(finding).__name__})",
                file=sys.stderr,
            )
            continue

        first_seen = (
            finding.get("first_seen")
            or finding.get("firstSeen")
            or finding.get("created_at")
        )
        result = calculate_sla_deadline(finding, asset_tier, first_seen)
        priority = result["priority"]
        deadline = date.fromisoformat(result["deadline"])

        bucket = by_priority.setdefault(priority, _empty_bucket())

        total += 1
        bucket["total"] += 1

        if result["overdue"]:
            overdue += 1
            bucket["overdue"] += 1
        elif deadline == today:
            due_today += 1
            bucket["due_today"] += 1
            # Due today still counts toward the week window.
            due_this_week += 1
            bucket["due_this_week"] += 1
        elif today < deadline <= week_out:
            due_this_week += 1
            bucket["due_this_week"] += 1
            on_track += 1
            bucket["on_track"] += 1
        else:
            on_track += 1
            bucket["on_track"] += 1

    return {
        "total": total,
        "overdue": overdue,
        "due_today": due_today,
        "due_this_week": due_this_week,
        "on_track": on_track,
        "by_priority": by_priority,
    }
