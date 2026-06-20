#!/usr/bin/env python3
"""Audit report QA validator.

Usage: python qa_audit.py <project> <audit_report_path>

Runs 10 checks on a generated 3SIXTYCO. security audit HTML report
and exits non-zero on failure.
"""
import re
import sys
import json
from pathlib import Path


ALL_IDS = [
    "sp-01", "sp-02", "sp-03", "sp-04", "sp-05", "sp-06",
    "s-01",  "s-02",  "s-03",  "s-04",  "s-05",  "s-06",
    "sm-01", "sm-02", "sm-03", "sm-04", "sm-05", "sm-06",
    "app-01","app-02","app-03","app-04","app-05","app-06",
    "ap-01", "ap-02", "ap-03", "ap-04", "ap-05", "ap-06",
    "a-01",  "a-02",  "a-03",  "a-04",  "a-05",  "a-06",
    "bp-01", "bp-02", "bp-03", "bp-04", "bp-05", "bp-06",
]


def main() -> None:
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <project> <audit_report_path>")
        sys.exit(1)

    project = sys.argv[1]
    report = Path(sys.argv[2])

    assert report.exists(), f"FAIL: report file not created: {report}"
    html = report.read_text(encoding="utf-8")
    size = len(html)
    print(f"[QA] File size: {size:,} bytes")
    assert size > 60_000, f"FAIL: report too small ({size} bytes) — likely missing content"

    # 1. All 42 item IDs present in fill call
    missing = [i for i in ALL_IDS if i not in html]
    if missing:
        print(f"FAIL: missing item IDs: {missing}")
        sys.exit(1)
    print("[QA] All 42 item IDs present")

    # 2. window.AUDIT.fill injected
    assert "window.AUDIT.fill" in html, "FAIL: window.AUDIT.fill not injected"
    print("[QA] window.AUDIT.fill present")

    # 3. Fill block parseable + correct item count
    fill_match = re.search(r"window\.AUDIT\.fill\((\{.*?\})\)", html, re.DOTALL)
    assert fill_match, "FAIL: fill call not parseable"
    try:
        fill_data = json.loads(fill_match.group(1))
        passed = sum(1 for v in fill_data.values() if v.get("pass") is True)
        failed = sum(1 for v in fill_data.values() if v.get("pass") is False)
        manual = sum(1 for v in fill_data.values() if v.get("pass") is None)
        total  = len(fill_data)
        print(f"[QA] Fill data: {total} items — PASS={passed} FAIL={failed} MANUAL={manual}")
        assert total == 42, f"FAIL: expected 42 items in fill, got {total}"
    except json.JSONDecodeError as e:
        print(f"FAIL: fill JSON invalid — {e}")
        sys.exit(1)

    # 4. Score ring SVG present
    assert "score-ring" in html or "viewBox" in html, "FAIL: score ring SVG missing"
    print("[QA] Score ring SVG present")

    # 5. All 7 tier tokens present
    for tier in ["sp", "s-", "sm", "app", "ap", "a-", "bp"]:
        assert tier in html, f"FAIL: tier {tier!r} not found in HTML"
    print("[QA] All 7 tier tokens present")

    # 6. Project name injected (not empty placeholder)
    assert "Click to enter project name" not in html or "projEl.textContent" in html, \
        "FAIL: project name not set"
    print("[QA] Project name field set")

    # 7. localStorage key present
    assert "3sixtyco-sec-audit-v1" in html, "FAIL: localStorage key missing"
    print("[QA] localStorage key present")

    # 8. Print / export function present
    assert "window.print" in html, "FAIL: print function missing"
    print("[QA] Print function present")

    # 9. Scoring weights present
    assert all(w in html for w in ["p0", "p1", "p2", "p3"]), \
        "FAIL: priority weights missing"
    print("[QA] Priority weights (P0-P3) present")

    # 10. No broken template placeholders
    broken = re.findall(r"\{\{[A-Z_]+\}\}", html)
    assert not broken, f"FAIL: unfilled template placeholders: {broken}"
    print("[QA] No unfilled template placeholders")

    print()
    print("=== QA RESULT: ALL 10 CHECKS PASSED ===")
    print(f"Report: {report.resolve()}")
    print(
        f"Score:  {passed}/{total - manual} testable items passed "
        f"({int(passed / (total - manual) * 100) if total - manual else 0}%)"
    )
    if failed:
        print(f"Blockers: {failed} failing items — open report for details")


if __name__ == "__main__":
    main()
