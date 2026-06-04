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
# Optional enrichment imports (non-fatal if modules missing)
# ---------------------------------------------------------------------------


def _try_import(module_name: str):
    try:
        import importlib
        return importlib.import_module(module_name)
    except ImportError:
        return None

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
            # Results is authoritative: a vuln-free trivy scan returns [] here
            # rather than falling through and being mis-read as a single finding.
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
                sev = str(fc.get("severity") or "unknown").lower()
                if sev not in ("critical", "high", "medium", "low", "info"):
                    sev = "unknown"
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
        # recurse into nested list AND dict values — findings can be dict-nested
        out = []
        for v in obj.values():
            if isinstance(v, (list, dict)):
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

def _extract_project_data(html):
    """Pull the project-data JSON out of a prior SOC report.

    Strips HTML comments FIRST — the blank template ships a comment that mentions
    `<script id="project-data">` (no closing tag), which would otherwise hijack a
    naive regex and capture the real block's closing </script>. After stripping
    comments, an id-anchored match is robust to attribute order.
    Returns the parsed dict, or None.
    """
    html_nocomment = re.sub(r"<!--[\s\S]*?-->", "", html)
    m = re.search(
        r'<script\b[^>]*\bid=["\']project-data["\'][^>]*>([\s\S]*?)</script>',
        html_nocomment,
        re.IGNORECASE,
    )
    if not m:
        return None
    try:
        pd = json.loads(m.group(1).strip())
    except json.JSONDecodeError:
        return None
    return pd if isinstance(pd, dict) else None


def _load_prior_snapshots(project, slug, runs_dir, exclude=None):
    """
    Find the most recent prior SOC report for this project in runs_dir/qa/,
    extract its snapshots array, and return it (or [] if none found).
    The snapshot structure matches the SOC template's week-navigation schema:
      [{score, checked, notes, evidence, timestamps, signoff}, ...]  (oldest first)

    Globs both display-name and slug-named files, excludes the report currently
    being written, and logs parse skips to stderr (no silent swallowing).
    """
    qa_dir = Path(runs_dir) / "qa"
    if not qa_dir.exists():
        return []

    exclude_resolved = None
    if exclude:
        try:
            exclude_resolved = Path(exclude).resolve()
        except Exception:
            exclude_resolved = None

    # Gather candidates from display-name + slug patterns only (deduped).
    # A broad "*soc*.html" glob would cross-contaminate this project's history
    # with OTHER projects' reports, so the fallback is slug-substring-filtered.
    slug_lower = (slug or "").lower()
    seen, candidates = set(), []

    def _add(p):
        try:
            rp = p.resolve()
        except Exception:
            return
        if rp in seen or rp == exclude_resolved:
            return
        seen.add(rp)
        candidates.append(p)

    for pat in (f"{project}-soc-*.html", f"{slug}-soc-*.html"):
        for p in qa_dir.glob(pat):
            _add(p)
    # Slug-filtered broad fallback only if nothing matched the exact patterns
    if not candidates and slug_lower:
        for p in qa_dir.glob("*soc*.html"):
            if slug_lower in p.name.lower():
                _add(p)
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    for candidate in candidates:
        try:
            html = candidate.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"[sic_to_soc] could not read prior report {candidate.name}: {e}",
                  file=sys.stderr)
            continue
        pd = _extract_project_data(html)
        if pd is None:
            print(f"[sic_to_soc] no parseable project-data in {candidate.name}",
                  file=sys.stderr)
            continue
        snapshots = pd.get("snapshots")
        if isinstance(snapshots, list) and snapshots:
            return snapshots
        # No snapshots array yet — derive a single prior entry from the score
        controls = pd.get("controls", [])
        items = [i for s in controls for i in s.get("items", [])]
        if items:
            done = sum(1 for i in items if i.get("done"))
            score = round(done / len(items) * 100)
            return [{"score": score, "checked": {}, "notes": {}, "evidence": {},
                     "timestamps": {}, "signoff": {"name": "", "role": ""}}]
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


def build_project_data(findings, project, slug, scan_path, now_iso, runs_dir=None,
                       output_path=None, score_override=None, asset_tier="production",
                       skip_enrichment=False, skip_db=False):
    # --- Enrichment pipeline (CISA KEV + EPSS + NVD) ---
    if not skip_enrichment:
        enrichment_mod = _try_import("enrichment")
        if enrichment_mod:
            print("[sic_to_soc] Running enrichment pipeline...", file=sys.stderr)
            findings = enrichment_mod.enrich_findings(findings)
        else:
            print("[sic_to_soc] enrichment.py not found — skipping enrichment", file=sys.stderr)

    # --- CWE → OWASP mapping ---
    cwe_mod = _try_import("cwe_owasp")
    if cwe_mod:
        findings = cwe_mod.enrich_with_owasp(findings)

    # --- SLA calculation ---
    sla_mod = _try_import("sla_engine")

    # --- DB persistence ---
    db_mod = _try_import("findings_db") if not skip_db else None
    if db_mod:
        try:
            sla_map = {}
            if sla_mod:
                for f in findings:
                    import hashlib
                    enrichment_f = f.get("enrichment") or {}
                    name_f = (f.get("name") or f.get("vulnerabilityName") or
                              f.get("Title") or f.get("template-id") or
                              f.get("checkID") or "Unnamed finding")
                    cve_f = enrichment_f.get("cve_id") or None
                    import re as _re
                    if not cve_f:
                        for field in ("name", "template-id", "checkID", "Title"):
                            m = _re.search(r"CVE-\d{4}-\d+", str(f.get(field) or ""), _re.IGNORECASE)
                            if m:
                                cve_f = m.group(0).upper()
                                break
                    check_f = f.get("checkID") or f.get("check_id")
                    key = f"{slug}|{cve_f or check_f or ''}|{name_f[:40]}"
                    fp = hashlib.sha256(key.encode()).hexdigest()[:32]
                    sla_info = sla_mod.calculate_sla_deadline(f, asset_tier=asset_tier)
                    sla_map[fp] = sla_info
            db_mod.upsert_findings_batch(slug, findings, asset_tier=asset_tier, sla_map=sla_map)
            print(f"[sic_to_soc] Persisted {len(findings)} findings to DB (project={slug})",
                  file=sys.stderr)
        except Exception as e:
            print(f"[sic_to_soc] DB persistence failed (non-fatal): {e}", file=sys.stderr)

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
            enrichment = f.get("enrichment") or {}
            item: dict = {
                "id":   f"{section_id}-{idx:03d}",
                "p":    SEV_TO_P.get(sev, "p3"),
                "done": False,
                "name": _name(f)[:80],
                "desc": _desc(f),
                "ref":  _ref(f),
            }
            # Enrichment badges — surfaced in report UI
            if enrichment.get("kev"):
                item["kev"] = True
            if enrichment.get("epss") is not None:
                item["epss"] = enrichment["epss"]
            if enrichment.get("cvss_v3") is not None:
                item["cvss_v3"] = enrichment["cvss_v3"]
            if enrichment.get("cwe"):
                item["cwe"] = enrichment["cwe"]
            if enrichment.get("owasp_category"):
                item["owasp"] = enrichment["owasp_category"]
            if enrichment.get("force_p0") and sev != "critical":
                item["forced_p0"] = True  # escalated by KEV/EPSS
            # SLA label
            if sla_mod:
                sla_info = sla_mod.calculate_sla_deadline(f, asset_tier=asset_tier)
                item["sla"] = sla_info.get("sla_label")
                item["sla_deadline"] = sla_info.get("deadline")
                item["overdue"] = sla_info.get("overdue", False)
            ctrl_items.append(item)

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
        "attackMapping":        (
            cwe_mod.build_attack_mapping(findings) if cwe_mod else []
        ),
        "detectionCoverage":    [],
        "activeThreatStatus":   {"signals": [], "lastUpdated": now_iso},
        "riskAcceptance":       [],
        "incidentLinkage":      [],
        "slaSummary": (
            sla_mod.sla_summary(findings, asset_tier=asset_tier) if sla_mod else {}
        ),
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

    # ---- Week-over-week history -------------------------------------------
    # Current-week posture score: % of items remediated (done). Fresh scans
    # start at 0% (nothing remediated yet). score_override lets an upstream
    # runner (e.g. the weekly harness bridge) supply its own weighted score.
    all_items = [i for s in controls for i in s.get("items", [])]
    if score_override is not None:
        current_score = max(0, min(100, int(score_override)))
    elif all_items:
        done = sum(1 for i in all_items if i.get("done"))
        current_score = round(done / len(all_items) * 100)
    else:
        current_score = 0

    prior_snapshots = (
        _load_prior_snapshots(project, slug, runs_dir, exclude=output_path)
        if runs_dir else []
    )
    current_snapshot = {
        "score":      current_score,
        "checked":    {},
        "notes":      {},
        "evidence":   {},
        "timestamps": {},
        "signoff":    {"name": "", "role": ""},
        "week_of":    now_iso[:10],
    }

    # De-dup by ISO week: replace the trailing snapshot if it's the same week
    # rather than appending a duplicate (two scans in one week = one snapshot).
    def _iso_week(date_str):
        try:
            return tuple(datetime.fromisoformat(date_str[:10]).isocalendar()[:2])
        except Exception:
            return None

    cur_week = _iso_week(now_iso)
    if (prior_snapshots and cur_week is not None
            and _iso_week(prior_snapshots[-1].get("week_of", "")) == cur_week):
        snapshots = prior_snapshots[:-1] + [current_snapshot]
    else:
        snapshots = prior_snapshots + [current_snapshot]

    project_data["snapshots"] = snapshots
    if prior_snapshots:
        print(f"[sic_to_soc] Week-over-week: {len(prior_snapshots)} prior snapshot(s) "
              f"+ current (score {current_score})", file=sys.stderr)

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
    parser.add_argument("--score",    type=int, default=None,
                        help="Override current-week posture score (0-100) for the "
                             "week-over-week snapshot (used by the weekly harness bridge)")
    parser.add_argument("--asset-tier", default="production",
                        choices=["production", "staging", "internal", "dev"],
                        help="Asset tier for SLA calculation (default: production)")
    parser.add_argument("--no-enrichment", action="store_true",
                        help="Skip CISA KEV / EPSS / NVD enrichment (faster, offline)")
    parser.add_argument("--no-db", action="store_true",
                        help="Skip DB persistence (findings_db.py upsert)")
    args = parser.parse_args()

    slug = args.slug or re.sub(r"[^a-z0-9]+", "-", args.project.lower()).strip("-")
    now  = datetime.now(timezone.utc).isoformat(timespec="seconds")

    print(f"[sic_to_soc] Loading {args.scan}")
    findings = load_findings(args.scan)
    print(f"[sic_to_soc] {len(findings)} findings parsed")

    runs_dir = str(Path(args.output).parent.parent)  # _runs/qa/../ = _runs/
    project_data = build_project_data(
        findings, args.project, slug, args.scan, now,
        runs_dir=runs_dir, output_path=args.output, score_override=args.score,
        asset_tier=args.asset_tier,
        skip_enrichment=args.no_enrichment,
        skip_db=args.no_db,
    )
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
