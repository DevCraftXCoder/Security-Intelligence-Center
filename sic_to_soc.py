#!/usr/bin/env python3
"""
sic_to_soc.py  --  SIC scan JSON -> SOC handoff HTML report

Builds a project-data JSON from SIC scan findings (grouped by severity into
P0/P1/P2/P3 control sections) and injects it into the SOC handoff template.

Usage:
    python C:/Za/sic/sic_to_soc.py \
        --scan     C:/Za/sic/_runs/scan-20260529-120000.json \
        --project  "FrxncoisApp" \
        --output   C:/Za/sic/_runs/qa/FrxncoisApp-soc-20260529-120000.html \
        [--template C:/Za/templates/soc-handoff/soc-handoff-template-blank.html]
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_TEMPLATE = "C:/Za/templates/soc-handoff/soc-handoff-template-blank.html"

# ---------------------------------------------------------------------------
# JSON loader (shared logic with sic_to_audit.py)
# ---------------------------------------------------------------------------

def _collect(obj):
    """Recursively collect dicts that look like individual findings.

    Handles three schemas beyond the generic nuclei/smart-scan format:
    - trivy: Results[].Vulnerabilities[] with VulnerabilityID/Severity/Title/Description
    - checkov: results.failed_checks[] with check_id/severity/resource/check_result
    """
    if isinstance(obj, list):
        out = []
        for item in obj:
            out.extend(_collect(item))
        return out
    if isinstance(obj, dict):
        # trivy: top-level Results array containing Vulnerabilities sub-arrays
        if "Results" in obj and isinstance(obj["Results"], list):
            out = []
            for result in obj["Results"]:
                vulns = result.get("Vulnerabilities") or []
                for v in vulns:
                    out.append({
                        "name":            v.get("VulnerabilityID") or v.get("Title") or "Unknown CVE",
                        "vulnerabilityName": v.get("Title") or v.get("VulnerabilityID") or "",
                        "severity":        (v.get("Severity") or "unknown").lower(),
                        "description":     v.get("Description") or "",
                        "template-id":     v.get("VulnerabilityID") or "",
                        "tags":            ["cve", "vulnerability"],
                        "references":      v.get("References") or [],
                        "_source":         "trivy",
                    })
            if out:
                return out

        # checkov: results.failed_checks[] (may appear as top-level results key)
        failed = (
            (obj.get("results") or {}).get("failed_checks")
            if isinstance(obj.get("results"), dict)
            else None
        )
        if isinstance(failed, list) and failed:
            out = []
            for fc in failed:
                sev = str(fc.get("severity") or "medium").lower()
                if sev not in ("critical", "high", "medium", "low", "info"):
                    sev = "medium"
                out.append({
                    "name":        fc.get("check_id") or "CKV_UNKNOWN",
                    "Title":       fc.get("check_id") or "Checkov finding",
                    "severity":    sev,
                    "description": (
                        f"Resource: {fc.get('resource') or 'unknown'}. "
                        f"File: {(fc.get('repo_file_path') or fc.get('file_path') or '')}. "
                        f"Lines: {fc.get('file_line_range') or ''}."
                    ),
                    "checkID":     fc.get("check_id") or "",
                    "tags":        ["misconfig", "iac"],
                    "_source":     "checkov",
                })
            if out:
                return out

        # Generic nuclei / smart-scan findings
        finding_keys = {"severity", "Severity", "vulnerabilityName", "name",
                        "template-id", "templateID", "Title", "checkID"}
        if finding_keys & obj.keys():
            sub = obj.get("findings") or obj.get("results") or obj.get("Vulnerabilities")
            if isinstance(sub, list):
                return _collect(sub)
            return [obj]
        out = []
        for v in obj.values():
            if isinstance(v, list):
                out.extend(_collect(v))
        return out
    return []


def load_findings(path):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    findings = []
    decoder = json.JSONDecoder()
    pos = 0
    while pos < len(text):
        while pos < len(text) and text[pos] in " \t\n\r":
            pos += 1
        if pos >= len(text):
            break
        try:
            obj, end = decoder.raw_decode(text, pos)
            pos = end
            findings.extend(_collect(obj))
        except json.JSONDecodeError:
            pos += 1
    return findings


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

def _sev(f):
    raw = (
        f.get("severity")
        or (f.get("info") or {}).get("severity")
        or f.get("Severity")
        or "unknown"
    )
    return str(raw).lower()


def _name(f):
    return (
        f.get("name")
        or f.get("vulnerabilityName")
        or f.get("Title")
        or f.get("template-id")
        or f.get("checkID")
        or "Unnamed finding"
    )


def _desc(f):
    return (
        f.get("description")
        or (f.get("info") or {}).get("description")
        or f.get("details")
        or f.get("Description")
        or "See scan output for details."
    )[:300]


def _ref(f):
    refs = f.get("references") or f.get("reference") or []
    if isinstance(refs, str):
        refs = [refs]
    cves = f.get("cvss") or f.get("cve") or f.get("CVE") or ""
    parts = list(refs[:2])
    if cves:
        parts.insert(0, str(cves))
    return " · ".join(parts)[:150] if parts else ""


# ---------------------------------------------------------------------------
# Week-over-week snapshot loader
# ---------------------------------------------------------------------------

def _load_prior_snapshots(project, runs_dir):
    """
    Find the most recent prior SOC report for this project in runs_dir/qa/,
    extract its snapshots array, and return it (or [] if none found).
    The snapshot structure matches the SOC template's week-navigation schema:
      [{score, checked, notes, evidence, timestamps, signoff}, ...]  (oldest first)
    """
    qa_dir = Path(runs_dir) / "qa"
    if not qa_dir.exists():
        return []

    slug_pattern = re.sub(r"[^a-z0-9]+", "-", project.lower()).strip("-")
    # Find all prior SOC HTML files for this project, sorted newest first
    candidates = sorted(
        qa_dir.glob(f"{project}-soc-*.html"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    # Also try slug-based names
    if not candidates:
        candidates = sorted(
            qa_dir.glob(f"*soc*.html"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        candidates = [p for p in candidates if slug_pattern in p.name.lower()]

    for candidate in candidates:
        try:
            html = candidate.read_text(encoding="utf-8", errors="replace")
            m = re.search(
                r'<script[^>]+id=["\']project-data["\'][^>]*>([\s\S]*?)</script>',
                html,
            )
            if not m:
                continue
            pd = json.loads(m.group(1))
            snapshots = pd.get("snapshots")
            if isinstance(snapshots, list):
                return snapshots
            # No snapshots key yet — extract just the score as a single prior entry
            controls = pd.get("controls", [])
            items = [i for s in controls for i in s.get("items", [])]
            if items:
                done = sum(1 for i in items if i.get("done"))
                score = round(done / len(items) * 100)
                return [{"score": score, "checked": {}, "notes": {}, "evidence": {},
                         "timestamps": {}, "signoff": {"name": "", "role": ""}}]
        except Exception:
            continue
    return []


# ---------------------------------------------------------------------------
# project-data builder
# ---------------------------------------------------------------------------

SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
SEV_TO_P   = {"critical": "p0", "high": "p1", "medium": "p2",
              "low": "p3", "info": "p3", "unknown": "p3"}
SEV_LABEL  = {
    "critical": "Critical Findings",
    "high":     "High Findings",
    "medium":   "Medium Findings",
    "low":      "Low / Info Findings",
    "info":     "Low / Info Findings",
    "unknown":  "Unclassified Findings",
}
SEV_TAG = {
    "critical": "P0-CRITICAL",
    "high":     "P1-HIGH",
    "medium":   "P2-MEDIUM",
    "low":      "P3-LOW",
    "info":     "P3-LOW",
    "unknown":  "P3-LOW",
}


def build_project_data(findings, project, slug, scan_path, now_iso, runs_dir=None):
    # Group findings by canonical severity
    buckets = {s: [] for s in SEV_ORDER}
    for f in findings:
        s = _sev(f)
        key = s if s in buckets else "unknown"
        buckets[key].append(f)

    # Build control sections (skip empty buckets, merge low+info)
    controls = []
    seen_low = False
    for sev in SEV_ORDER:
        items = buckets[sev]
        if not items:
            continue
        # Merge low and info into one section
        if sev in ("low", "info"):
            if seen_low:
                continue
            seen_low = True
            items = buckets["low"] + buckets["info"]

        section_id = f"sic-{sev}"
        ctrl_items = []
        for idx, f in enumerate(items, start=1):
            ctrl_items.append({
                "id":   f"{section_id}-{idx:03d}",
                "p":    SEV_TO_P.get(sev, "p3"),
                "done": False,
                "name": _name(f)[:80],
                "desc": _desc(f),
                "ref":  _ref(f),
            })

        controls.append({
            "id":    section_id,
            "tag":   SEV_TAG.get(sev, "FINDING"),
            "title": SEV_LABEL.get(sev, "Findings"),
            "items": ctrl_items,
        })

    total = sum(len(b) for b in buckets.values())
    crit  = len(buckets["critical"])
    high  = len(buckets["high"])

    # Derive scan filename for display
    scan_name = Path(scan_path).name if scan_path else "scan.json"

    project_data = {
        "project": {
            "name":     project.upper(),
            "slug":     slug,
            "repo":     scan_name,
            "commit":   now_iso[:10],
            "reportId": f"{slug.upper().replace('-','')}-SOC-{now_iso[:10]}",
            "version":  "v1",
        },
        "caseMetadata": {
            "status":       "monitoring",
            "severity":     "P0" if crit else ("P1" if high else "P2"),
            "urgency":      "critical" if crit else ("high" if high else "medium"),
            "owner":        "Security",
            "incidentLead": "--",
        },
        "summary": {
            "executive": (
                f"SIC automated scan completed {now_iso[:10]}. "
                f"{total} findings: {crit} critical, {high} high. "
                "All open items require remediation before sign-off."
            ),
            "businessImpact": (
                "Critical and High findings represent active attack surface. "
                "Remediate P0/P1 items before next release."
            ) if (crit or high) else "No critical or high findings detected.",
        },
        "scope": {
            "affected":   project,
            "confidence": "scan-derived",
        },
        "confidence": {
            "level":    "HIGH" if total > 0 else "MODERATE",
            "rationale": f"Automated SIC scan ({total} findings). Manual verification recommended for each item.",
        },
        "timeline": [
            {
                "ts":    now_iso,
                "tz":    "UTC",
                "event": f"SIC automated scan completed — {total} findings ({crit} critical, {high} high)",
                "actor": "sic_to_soc.py",
            }
        ],
        "actions": {
            "taken":              [f"Automated SIC scan run against {project}"],
            "containmentStatus":  "pending",
            "remediationStatus":  "pending",
            "pending":            (
                [f"Remediate {crit} critical findings immediately"] if crit else []
            ) + (
                [f"Address {high} high findings before next deploy"] if high else []
            ),
        },
        "communications": {"notified": [], "nextUpdate": ""},
        "closure": {
            "exitCriteria": "All P0 and P1 controls marked done; P2+ accepted or remediated.",
            "handingOffTo": "",
        },
        "attackMapping":        [],
        "detectionCoverage":    [],
        "activeThreatStatus":   {"signals": [], "lastUpdated": now_iso},
        "riskAcceptance":       [],
        "incidentLinkage":      [],
        "maturity": {
            "currentStage": 1,
            "priorStage":   0,
            "growthDelta": {
                "controlsAdded":          total,
                "attackCoverageDelta":     0,
                "openGapsDelta":          total,
                "activeThreats":          {"prior": 0, "current": crit + high},
            },
        },
        "harnessMap": {},
        "controls":   controls,
    }

    # Week-over-week: load prior snapshots and inject as history
    prior_snapshots = _load_prior_snapshots(project, runs_dir) if runs_dir else []
    if prior_snapshots:
        # Append prior weeks at offset -N ... -1; current week at 0 will be set
        # by the template's save-snapshot logic on first interaction.
        project_data["snapshots"] = prior_snapshots
        print(f"[sic_to_soc] Loaded {len(prior_snapshots)} prior snapshot(s) for week-over-week diff",
              file=sys.stderr)
    else:
        project_data["snapshots"] = []

    return project_data


# ---------------------------------------------------------------------------
# HTML injection (same mechanism as soc-reporter-mcp)
# ---------------------------------------------------------------------------

_PROJECT_DATA_RE = re.compile(
    r'<script\s+type="application/json"\s+id="project-data"[^>]*>[\s\S]*?</script>',
    re.IGNORECASE,
)


def inject_project_data(html, project_data):
    replacement = (
        '<script type="application/json" id="project-data">\n'
        + json.dumps(project_data, indent=2)
        + "\n</script>"
    )
    m = _PROJECT_DATA_RE.search(html)
    if m:
        # Use string split rather than re.sub to avoid backslash interpretation
        return html[:m.start()] + replacement + html[m.end():]
    if "</body>" in html:
        return html.replace("</body>", replacement + "\n</body>", 1)
    return html + "\n" + replacement


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Map SIC scan output to SOC handoff HTML report"
    )
    parser.add_argument("--scan",     required=True,
                        help="SIC scan JSON file (from sic/_runs/)")
    parser.add_argument("--project",  required=True,
                        help="Project display name (e.g. FrxncoisApp)")
    parser.add_argument("--output",   required=True,
                        help="Output HTML file path")
    parser.add_argument("--template", default=DEFAULT_TEMPLATE,
                        help=f"SOC handoff HTML template (default: {DEFAULT_TEMPLATE})")
    parser.add_argument("--slug",     default=None,
                        help="URL-safe project slug (derived from --project if omitted)")
    args = parser.parse_args()

    slug = args.slug or re.sub(r"[^a-z0-9]+", "-", args.project.lower()).strip("-")
    now  = datetime.now(timezone.utc).isoformat(timespec="seconds")

    print(f"[sic_to_soc] Loading {args.scan}")
    findings = load_findings(args.scan)
    print(f"[sic_to_soc] {len(findings)} findings parsed")

    runs_dir = str(Path(args.output).parent.parent)  # _runs/qa/../ = _runs/
    project_data = build_project_data(findings, args.project, slug, args.scan, now, runs_dir=runs_dir)
    total_controls = sum(len(s["items"]) for s in project_data["controls"])
    crit = project_data["caseMetadata"]["severity"]
    print(f"[sic_to_soc] Severity: {crit}  Controls: {total_controls} across {len(project_data['controls'])} section(s)")

    tpl = Path(args.template).read_text(encoding="utf-8", errors="replace")
    out = inject_project_data(tpl, project_data)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(out, encoding="utf-8")
    print(f"[sic_to_soc] Written -> {args.output}")
    print(f"[sic_to_soc] Open:   file:///{args.output.replace(chr(92), '/')}")


if __name__ == "__main__":
    main()
