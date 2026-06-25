#!/usr/bin/env python3
"""SOC report QA validator.

Usage: python qa_soc.py <project> <soc_report_path>

Runs 6 checks on a generated SOC handoff HTML report and exits non-zero on failure.
"""
import re
import sys
import json
from pathlib import Path


def main() -> None:
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <project> <soc_report_path>")
        sys.exit(1)

    _project = sys.argv[1]  # accepted for CLI parity; name is validated via project-data JSON
    report = Path(sys.argv[2])

    # 1. File exists and is > 50KB
    assert report.exists(), f"FAIL: SOC report not created: {report}"
    html = report.read_text(encoding="utf-8")
    size = len(html)
    print(f"[SOC-QA] File size: {size:,} bytes")
    assert size > 50_000, f"FAIL: SOC report too small ({size} bytes)"

    # 2. project-data script tag exists and is valid JSON.
    #    Use type="application/json" to avoid matching JS-comment text that
    #    mentions <script id="project-data"> as a string literal inside the
    #    Bridge loader block.
    m = re.search(
        r'<script\b[^>]*type=["\']application/json["\'][^>]*\bid=["\']project-data["\'][^>]*>'
        r'([\s\S]*?)</script>',
        html,
        re.I,
    )
    if not m:
        # fallback: reversed attribute order
        m = re.search(
            r'<script\b[^>]*\bid=["\']project-data["\'][^>]*type=["\']application/json["\'][^>]*>'
            r'([\s\S]*?)</script>',
            html,
            re.I,
        )
    assert m, "FAIL: <script id=\"project-data\"> tag missing"
    try:
        pd = json.loads(m.group(1).strip())
    except json.JSONDecodeError as e:
        print(f"FAIL: project-data JSON invalid — {e}")
        sys.exit(1)
    print("[SOC-QA] project-data JSON valid")

    # 3. project.name is non-empty
    name = (pd.get("project") or {}).get("name", "")
    assert name, "FAIL: project.name is empty"
    print(f"[SOC-QA] project.name = {name!r}")

    # 4. At least one control section with at least one item
    controls = pd.get("controls", [])
    assert controls, "FAIL: no control sections in project-data"
    items = [i for s in controls for i in s.get("items", [])]
    assert items, "FAIL: control sections have no items"
    print(f"[SOC-QA] {len(controls)} section(s), {len(items)} item(s)")

    # 5. Items with done: true must come from analyst-verified RESOLVED findings,
    #    not auto-passed by the scanner.  If incidentLead is populated, the analyst
    #    explicitly signed the report — done=true is intentional.  If incidentLead
    #    is missing/placeholder, done=true items are suspicious.
    auto_passed = [i["id"] for i in items if i.get("done") is True or i.get("done") == 1]
    incident_lead = (pd.get("caseMetadata") or {}).get("incidentLead", "")
    analyst_signed = bool(incident_lead and incident_lead not in ("--", "", "TBD"))
    if auto_passed and not analyst_signed:
        assert False, (
            f"FAIL: {len(auto_passed)} items auto-marked done without analyst sign-off: {auto_passed[:5]}"
        )
    if auto_passed:
        print(f"[SOC-QA] {len(auto_passed)} item(s) marked done (analyst-verified, signed by {incident_lead!r})")
    else:
        print("[SOC-QA] All items done=false (no auto-pass)")

    # 6. Week-over-week snapshots present and well-formed.
    #    sic_to_soc.py always injects the current week, so this is never empty —
    #    emptiness means the _load_prior_snapshots / build_project_data history path regressed.
    snaps = pd.get("snapshots")
    assert isinstance(snaps, list) and snaps, (
        "FAIL: snapshots missing/empty (week-over-week broken)"
    )
    assert all(isinstance(s.get("score"), int) for s in snaps), (
        "FAIL: snapshot missing integer score"
    )
    print(f"[SOC-QA] snapshots: {len(snaps)} week(s), scores={[s['score'] for s in snaps]}")

    # first_scan flag (improvement #8 in sic_to_soc.py)
    diff = pd.get("scanDiff", {})
    if "first_scan" in diff:
        print(f"[SOC-QA] first_scan={diff['first_scan']}")

    # 7. project.name must differ from the raw slug (display name was set)
    project_slug = (pd.get("project") or {}).get("slug", "")
    assert name != project_slug, (
        f"FAIL: project.name {name!r} equals slug {project_slug!r} — "
        "pass --project-name to set a human-readable display name"
    )
    print(f"[SOC-QA] project.name {name!r} != slug {project_slug!r} (display name set)")

    print()
    print("=== SOC QA RESULT: ALL 7 CHECKS PASSED ===")


if __name__ == "__main__":
    main()
