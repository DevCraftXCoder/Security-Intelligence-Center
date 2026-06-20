#!/usr/bin/env python3
"""
sic_to_soc.py  --  SIC scan JSON -> SOC handoff HTML report

Builds a project-data JSON from SIC scan findings (grouped by severity into
P0/P1/P2/P3 control sections) and injects it into the SOC handoff template.

Usage:
    python sic_to_soc.py \
        --scan     ./_runs/scan-20260529-120000.json \
        --project  "MyProject" \
        --output   ./_runs/qa/MyProject-soc-20260529-120000.html \
        [--template ./templates/soc-handoff/soc-handoff-template-blank.html]

The template defaults to <sic_dir>/templates/soc-handoff/soc-handoff-template-blank.html
and can be overridden with --template or the SIC_SOC_TEMPLATE env var.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import project_config as _project_config_mod
    project_config = _project_config_mod
except ImportError:
    project_config = None
from scan_merge import _collect  # single authoritative finding collector

# Resolve the SOC handoff template relative to this module (portable across machines).
# Override via --template CLI flag or the SIC_SOC_TEMPLATE environment variable.
DEFAULT_TEMPLATE = os.environ.get(
    "SIC_SOC_TEMPLATE",
    str(Path(__file__).resolve().parent / "templates" / "soc-handoff" / "soc-handoff-template-blank.html"),
)

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
#
# Finding collection (`_collect`) is imported from scan_merge to keep a single
# authoritative implementation — it now also reads trivy Secrets[] and
# Misconfigurations[] in addition to Vulnerabilities[] and checkov failed_checks.
# ---------------------------------------------------------------------------


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


def _finding_fingerprint(f, slug):
    """SHA-256 fingerprint of a finding, matching findings_db._fingerprint().

    key = f"{slug}|{cve_or_check_id}|{name[:40]}" -> sha256[:32]

    Computed inline (no findings_db import) so the diff stays independent. The
    name/cve/check resolution mirrors the DB upsert path exactly so fingerprints
    are stable across both producers.
    """
    enrichment = f.get("enrichment") or {}
    name = (
        f.get("name") or f.get("vulnerabilityName") or f.get("Title")
        or f.get("template-id") or f.get("checkID") or "Unnamed finding"
    )
    cve = enrichment.get("cve_id") or None
    if not cve:
        for field in ("name", "template-id", "checkID", "Title"):
            m = re.search(r"CVE-\d{4}-\d+", str(f.get(field) or ""), re.IGNORECASE)
            if m:
                cve = m.group(0).upper()
                break
    check = f.get("checkID") or f.get("check_id")
    key = f"{slug}|{cve or check or ''}|{name[:40]}"
    return hashlib.sha256(key.encode()).hexdigest()[:32]


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


# ---------------------------------------------------------------------------
# Authoritative posture / score computation (single source of truth)
# ---------------------------------------------------------------------------


def verdict_for(score, scanned):
    """Single verdict mapping — one vocabulary for all consumers."""
    if not scanned:
        return "NET"
    if score >= 90:
        return "PASS"
    if score >= 70:
        return "REVIEW"
    if score >= 40:
        return "ATTENTION"
    return "BLOCK"


VERDICT_COLORS = {
    "PASS": 0x4ADE80,
    "REVIEW": 0xB89100,
    "ATTENTION": 0xF59E0B,
    "BLOCK": 0xFF3B3B,
    "NET": 0xB89100,
}


def compute_posture(all_items, net_sections, scanned, score_override=None):
    """Single authoritative score computation — inverse-risk model."""
    weights = {"p0": 40, "p1": 15, "p2": 5, "p3": 1}

    if not scanned:
        return {
            "score": 0,
            "verdict": "NET",
            "model": "net-only",
            "scanned": False,
            "weights": weights,
            "counts": {},
            "rationale": "Architecture-only analysis — no scanner data. Not yet assessed.",
        }

    # Count open items per priority
    counts = {p: {"open": 0, "total": 0} for p in weights}
    for item in all_items:
        p = (item.get("priority") or "").strip() or (item.get("p") or "").strip() or "p2"
        if p not in counts:
            p = "p2"
        counts[p]["total"] += 1
        is_done = item.get("done") or item.get("net_status") == "refuted"
        if not is_done:
            counts[p]["open"] += 1

    risk = sum(weights[p] * counts[p]["open"] for p in weights)
    max_risk = sum(weights[p] * counts[p]["total"] for p in weights)

    if score_override is not None:
        score = int(score_override)
    elif max_risk == 0:
        score = 100
    else:
        score = round(100 * (1 - risk / max_risk))

    score = max(0, min(100, score))
    verdict = verdict_for(score, scanned=True)

    open_p0 = counts["p0"]["open"]
    overdue_count = sum(1 for item in all_items if item.get("overdue"))
    overdue_str = f", {overdue_count} SLA overdue" if overdue_count else ""
    rationale = (
        f"Score {score}/100 — {open_p0} open P0 item(s){overdue_str}"
        if open_p0
        else f"Score {score}/100 — no open P0 items{overdue_str}"
    )

    return {
        "score": score,
        "verdict": verdict,
        "model": "inverse-risk",
        "scanned": True,
        "weights": weights,
        "counts": counts,
        "rationale": rationale,
    }


def stamp_score(html, posture):
    """Write <!--soc-score:NN--> and <!--soc-verdict:VV--> into the HTML head."""
    score = posture.get("score", 0) or 0
    verdict = posture.get("verdict", "NET")

    score_comment = f"<!--soc-score:{score}-->"
    verdict_comment = f"<!--soc-verdict:{verdict}-->"

    # Replace existing comments
    html = re.sub(r'<!--soc-score:\d+-->', score_comment, html)
    html = re.sub(r'<!--soc-verdict:\w+-->', verdict_comment, html)

    # If no existing comment, insert after <head>
    if score_comment not in html:
        html = html.replace('<head>', f'<head>\n{score_comment}\n{verdict_comment}', 1)
    elif verdict_comment not in html:
        html = html.replace(score_comment, f'{score_comment}\n{verdict_comment}', 1)

    return html


def compute_maturity(project_data: dict, prior_snapshots: list[dict]) -> dict:
    """Derive maturity stage and growthDelta from project_data signals + snapshot history.

    Stage thresholds (cumulative):
      1 LITE             — any controls present
      2 HARDENED         — attackMapping populated OR detectionCoverage populated
      3 VALIDATED        — >=2 snapshots exist (baseline + current)
      4 SOC-OBSERVABLE   — attackMapping AND detectionCoverage both populated
      5 ENTERPRISE SOC   — riskAcceptance + incidentLinkage + slaSummary all present

    GrowthDelta is auto-diffed against the most recent prior snapshot's stored counts.
    """
    controls = project_data.get("controls", [])
    total_controls = sum(len(s.get("items", [])) for s in controls)
    open_controls = sum(
        1 for s in controls for i in s.get("items", []) if not i.get("done")
    )
    attack_mapping = project_data.get("attackMapping") or []
    detection_coverage = project_data.get("detectionCoverage") or []
    risk_acceptance = project_data.get("riskAcceptance") or []
    incident_linkage = project_data.get("incidentLinkage") or []
    sla_summary = project_data.get("slaSummary") or {}

    # Derive current severity counts for activeThreats
    crit_high_current = 0
    for s in controls:
        if s.get("tag") in ("P0-CRITICAL", "P1-HIGH"):
            crit_high_current += len(s.get("items", []))

    # Compute current stage
    stage = 1
    if attack_mapping or detection_coverage:
        stage = max(stage, 2)
    if len(prior_snapshots) >= 1:
        stage = max(stage, 3)
    if attack_mapping and detection_coverage:
        stage = max(stage, 4)
    if risk_acceptance and incident_linkage and sla_summary:
        stage = max(stage, 5)

    # Diff against most recent prior snapshot
    prior = prior_snapshots[-1] if prior_snapshots else {}
    prior_stage = prior.get("stage", 0)
    prior_total = prior.get("total_controls", 0)
    prior_open = prior.get("open_controls", 0)
    prior_attack_len = prior.get("attack_mapping_len", 0)
    prior_crit_high = prior.get("crit_high", 0)

    growth_delta = {
        "controlsAdded": total_controls - prior_total,
        "attackCoverageDelta": len(attack_mapping) - prior_attack_len,
        "openGapsDelta": open_controls - prior_open,
        "activeThreats": {"prior": prior_crit_high, "current": crit_high_current},
    }

    return {
        "currentStage": stage,
        "priorStage": prior_stage,
        "growthDelta": growth_delta,
        # Carry-forward counts for next run to diff against
        "_snapshot_counts": {
            "stage": stage,
            "total_controls": total_controls,
            "open_controls": open_controls,
            "attack_mapping_len": len(attack_mapping),
            "crit_high": crit_high_current,
        },
    }


def build_project_data(findings, project, slug, scan_path, now_iso, runs_dir=None,
                       output_path=None, score_override=None, asset_tier="production",
                       skip_enrichment=False, skip_db=False, config=None, net=None,
                       scanners_run=None):
    # --- Suppression enforcement (.sic.yaml rules) ---
    if config and project_config:
        kept = [f for f in findings if not project_config.is_suppressed(f, config)]
        suppressed_n = len(findings) - len(kept)
        if suppressed_n:
            print(f"[sic_to_soc] {suppressed_n} findings suppressed by .sic.yaml rules",
                  file=sys.stderr)
        findings = kept

    # --- Net-based adjudication (Stage 2 / refined mode) ---
    project_data_net_extra = None
    if net is not None:
        try:
            from threat_catalog import adjudicate_net
            net = adjudicate_net(net, findings, scanners_run=scanners_run)
            # Build controls from net sections (proven ones become P0/P1/P2 sections)
            # untested sections are included with a distinct tag for report UI
            net_controls = []
            for section in net:
                status = section.get("status", "net")
                items = section.get("items", [])
                ctrl_items = []
                for idx, f in enumerate(items, start=1):
                    ctrl_items.append({
                        "id": f"{section['id']}-{idx:03d}",
                        "p": section.get("priority", "p2"),
                        "done": False,
                        "name": _name(f)[:80],
                        "desc": _desc(f),
                        "ref": _ref(f),
                        "net_section": section["id"],
                        "net_status": status,
                    })
                net_controls.append({
                    "id": section["id"],
                    "tag": section.get("tag", "NET"),
                    "title": section["title"],
                    "status": status,
                    "items": ctrl_items,
                    "cwe": section.get("cwe"),
                    "owasp": section.get("owasp"),
                    "mitre": section.get("mitre"),
                    "priority": section.get("priority", "p2"),
                    "description": section.get("description", ""),
                })
            # Attach net controls alongside severity-bucket controls
            # (the template decides which to display)
            project_data_net_extra = net_controls
        except Exception as e:
            print(
                f"[sic_to_soc] Net adjudication failed (non-fatal): {e}",
                file=sys.stderr,
            )
            project_data_net_extra = None

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
                    fp = _finding_fingerprint(f, slug)
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
            "name":     project,
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
        "maturity": {},  # filled below after prior_snapshots are loaded
        "harnessMap": {},
        "controls":   controls,
    }

    # ---- Authoritative posture / score -----------------------------------
    # The single source of truth for the report score + verdict. Uses the
    # inverse-risk model: open high-priority findings drive the score down.
    # score_override lets an upstream runner supply its own weighted score.
    #
    # When net adjudication ran, prefer the net controls (which carry per-item
    # priority + net_status, including refuted) so the posture reflects the
    # refined verdict rather than raw severity buckets.
    if project_data_net_extra is not None:
        posture_items = [
            i for s in project_data_net_extra for i in s.get("items", [])
        ]
    else:
        posture_items = [i for s in controls for i in s.get("items", [])]
    posture = compute_posture(
        posture_items,
        project_data_net_extra,
        scanned=True,
        score_override=score_override,
    )
    project_data["posture"] = posture
    current_score = posture["score"]

    prior_snapshots = (
        _load_prior_snapshots(project, slug, runs_dir, exclude=output_path)
        if runs_dir else []
    )

    # Compute maturity using actual prior snapshot counts
    maturity = compute_maturity(project_data, prior_snapshots)
    project_data["maturity"] = {
        "currentStage": maturity["currentStage"],
        "priorStage":   maturity["priorStage"],
        "growthDelta":  maturity["growthDelta"],
    }
    _snap_counts = maturity.get("_snapshot_counts", {})

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

    # ---- Scan diff vs previous scan ---------------------------------------
    # Fingerprint the current finding set and compare against the prior
    # snapshot's stored finding_fps to surface new / resolved / unchanged counts.
    current_fps = sorted({_finding_fingerprint(f, slug) for f in findings})
    prior_fps = []
    if prior_snapshots:
        raw_prior = prior_snapshots[-1].get("finding_fps") or []
        if isinstance(raw_prior, list):
            prior_fps = [str(x) for x in raw_prior]
    prior_set = set(prior_fps)
    current_set = set(current_fps)
    has_prior = bool(prior_fps)
    new_count = len(current_set - prior_set) if has_prior else len(current_set)
    resolved_count = len(prior_set - current_set) if has_prior else 0
    unchanged_count = len(current_set & prior_set) if has_prior else 0

    project_data["scanDiff"] = {
        "new":         new_count,
        "resolved":    resolved_count,
        "unchanged":   unchanged_count,
        "has_prior":   has_prior,
        "first_scan":  not has_prior,
        "current_fps": current_fps,
    }
    # Also stamp the current fingerprints onto the current snapshot so the next
    # scan can diff against this run.
    current_snapshot["finding_fps"] = current_fps
    # Stamp maturity counts onto current snapshot for next-run diffing
    current_snapshot.update(_snap_counts)
    if has_prior:
        print(f"[sic_to_soc] Scan diff: {new_count} new, {resolved_count} resolved, "
              f"{unchanged_count} unchanged", file=sys.stderr)

    if project_data_net_extra is not None:
        project_data["netControls"] = project_data_net_extra
        proven = [s for s in project_data_net_extra if s.get("status") == "proven"]
        untested = [s for s in project_data_net_extra if s.get("status") == "untested"]
        print(
            f"[sic_to_soc] Net: {len(proven)} proven, {len(untested)} untested sections",
            file=sys.stderr,
        )

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
    parser.add_argument("--project",  default=None,
                        help="Project display name (e.g. FrxncoisApp). Optional when "
                             "--project-path is given (derived from .sic.yaml).")
    parser.add_argument("--project-path", default=None,
                        help="Path to a project dir — auto-loads its .sic.yaml "
                             "(slug, asset_tier, suppressions). Registers from git "
                             "remote if no .sic.yaml is found.")
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
    parser.add_argument("--open", action="store_true",
                        help="Open the generated report in the default browser")
    parser.add_argument("--analyst", default="",
                        help="Analyst name for SOC report incidentLead field")
    parser.add_argument("--analyst-role", default="",
                        help="Analyst role for SOC report")
    parser.add_argument("--history-dir", default=None,
                        help="Directory containing prior SOC reports for week-over-week history "
                             "(default: parent of --output parent, i.e. _runs/)")
    args = parser.parse_args()

    # --- Resolve project config -------------------------------------------
    # Precedence for project path: explicit --project-path, else a registered
    # project matching the --project slug. When found, .sic.yaml auto-loads slug
    # + asset_tier + suppressions, so --slug / --asset-tier need not be passed.
    config = None
    project_path = args.project_path
    if not project_path and args.project and project_config is not None:
        candidate_slug = re.sub(r"[^a-z0-9]+", "-", args.project.lower()).strip("-")
        registered = project_config.get_project(candidate_slug)
        if registered and registered.get("path"):
            project_path = registered["path"]

    if project_path and project_config is not None:
        config = project_config.load_config(project_path)
        if config.get("_source") != "file":
            # No .sic.yaml — try to auto-populate the registry from git remote.
            project_config.register_from_git(project_path)
        print(f"[sic_to_soc] Loaded config for: {config.get('name')} "
              f"(tier={config.get('asset_tier')})", file=sys.stderr)

    # --- Resolve effective project / slug / asset_tier --------------------
    project = args.project or (config.get("name") if config else None)
    if not project:
        parser.error("either --project or --project-path is required")

    slug = (
        args.slug
        or (config.get("slug") if config else None)
        or re.sub(r"[^a-z0-9]+", "-", project.lower()).strip("-")
    )
    asset_tier = config.get("asset_tier") if config else args.asset_tier
    if asset_tier not in ("production", "staging", "internal", "dev"):
        asset_tier = args.asset_tier

    now  = datetime.now(timezone.utc).isoformat(timespec="seconds")

    print(f"[sic_to_soc] Loading {args.scan}")
    findings = load_findings(args.scan)
    print(f"[sic_to_soc] {len(findings)} findings parsed")

    runs_dir = args.history_dir or str(Path(args.output).parent.parent)  # _runs/qa/../ = _runs/
    project_data = build_project_data(
        findings, project, slug, args.scan, now,
        runs_dir=runs_dir, output_path=args.output, score_override=args.score,
        asset_tier=asset_tier,
        skip_enrichment=args.no_enrichment,
        skip_db=args.no_db,
        config=config,
    )
    if args.analyst:
        project_data["caseMetadata"]["incidentLead"] = args.analyst
        project_data["closure"]["handingOffTo"] = args.analyst
    if args.analyst_role:
        project_data["caseMetadata"]["analystRole"] = args.analyst_role
    total_controls = sum(len(s["items"]) for s in project_data["controls"])
    crit = project_data["caseMetadata"]["severity"]
    print(f"[sic_to_soc] Severity: {crit}  Controls: {total_controls} across {len(project_data['controls'])} section(s)")

    try:
        tpl = Path(args.template).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"[sic_to_soc] FATAL: could not read template {args.template}: {exc}",
              file=sys.stderr)
        sys.exit(1)
    out = inject_project_data(tpl, project_data)
    # Stamp the authoritative score + verdict into the HTML head so all
    # downstream consumers (soc_pipeline, dropstream) read one number.
    out = stamp_score(out, project_data.get("posture", {}))

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(out, encoding="utf-8")
    print(f"[sic_to_soc] Written -> {args.output}")
    output_fwd = args.output.replace(chr(92), "/")
    print(f"[sic_to_soc] Open:   file:///{output_fwd}")

    if args.open:
        print("[sic_to_soc] Opening in browser...", file=sys.stderr)
        try:
            import webbrowser
            webbrowser.open(f"file:///{output_fwd}")
        except Exception as e:
            print(f"[sic_to_soc] Could not open browser (non-fatal): {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
