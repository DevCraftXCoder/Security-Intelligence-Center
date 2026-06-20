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
    #    Strip HTML comments first so the template's commented example block
    #    (which mentions id="project-data") cannot hijack the match.
    nc = re.sub(r"<!--[\s\S]*?-->", "", html)
    m = re.search(
        r'<script\b[^>]*\bid=["\']project-data["\'][^>]*>([\s\S]*?)</script>',
        nc,
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

    # 5. No item has done: true — scan output must not auto-pass anything
    auto_passed = [i["id"] for i in items if i.get("done") is True or i.get("done") == 1]
    assert not auto_passed, (
        f"FAIL: {len(auto_passed)} items auto-marked done: {auto_passed[:5]}"
    )
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

    print()
    print("=== SOC QA RESULT: ALL 6 CHECKS PASSED ===")


if __name__ == "__main__":
    main()
