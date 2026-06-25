"""
soc_pipeline.py — Two-stage WIDE NET -> REFINED VERDICT SOC pipeline for SIC.

Usage:
  python soc_pipeline.py --path /path/to/project --auto
  python soc_pipeline.py --path /path/to/project --net          # Stage 1 only
  python soc_pipeline.py --path /path/to/project --refine       # Stage 2 on existing scan
  python soc_pipeline.py --help
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

# Allow importing sibling modules when run directly
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _slug(project_path: str) -> str:
    return Path(project_path).name.lower().replace(" ", "-")


def _output_dir(base: str | None, slug: str) -> Path:
    if base:
        return Path(base)
    return _HERE / "_runs" / "qa"


_SOC_SCORE_RE = re.compile(r"<!--soc-score:(\d+)-->")
_SOC_VERDICT_RE = re.compile(r"<!--soc-verdict:(\w+)-->")


def _extract_posture(html_path: str) -> dict:
    """Read <!--soc-score:NN--> and <!--soc-verdict:VV--> from the output HTML.

    Scans the first 30 lines for the stamped comments. Falls back to the
    embedded project-data JSON `posture` block when comments are absent.
    Always returns a dict with at least `score`, `verdict`, `scanned` keys.
    """
    score: int | None = None
    verdict: str | None = None
    try:
        with open(html_path, encoding="utf-8") as f:
            for _ in range(30):
                line = f.readline()
                if not line:
                    break
                if score is None:
                    m = _SOC_SCORE_RE.search(line)
                    if m:
                        score = int(m.group(1))
                if verdict is None:
                    mv = _SOC_VERDICT_RE.search(line)
                    if mv:
                        verdict = mv.group(1)
                if score is not None and verdict is not None:
                    break
    except OSError:
        pass

    if score is not None or verdict is not None:
        return {
            "score": score if score is not None else 0,
            "verdict": verdict or "NET",
            "scanned": (verdict or "NET") != "NET",
        }

    # Fall back to embedded project-data posture JSON
    try:
        import sic_to_soc

        html = Path(html_path).read_text(encoding="utf-8", errors="replace")
        pd = sic_to_soc._extract_project_data(html)
        if pd and isinstance(pd.get("posture"), dict):
            posture = pd["posture"]
            return {
                "score": posture.get("score", 0) or 0,
                "verdict": posture.get("verdict", "NET"),
                "scanned": bool(posture.get("scanned", False)),
            }
    except (OSError, ImportError):
        pass

    return {"score": 0, "verdict": "NET", "scanned": False}


def stage1_net(
    project_path: str,
    output_base: str | None = None,
    template_path: str | None = None,
    project_name: str | None = None,
) -> dict:
    """Stage 1: Generate Wide-Net SOC template from architecture profile.

    Returns dict with keys: output_path, net, profile, slug
    """
    from project_config import detect_system_profile
    from threat_catalog import build_net
    import sic_to_soc

    slug = _slug(project_path)
    now = _now_iso()
    out_dir = _output_dir(output_base, slug)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(
        f"[soc_pipeline] Stage 1: detecting system profile for {project_path!r}",
        file=sys.stderr,
    )
    profile = detect_system_profile(project_path)
    components = profile.get("components", [])
    print(f"[soc_pipeline] Detected components: {components}", file=sys.stderr)

    net = build_net(profile)
    if not net:
        print(
            "[soc_pipeline] WARNING: no threat catalog sections matched — "
            "check detect_system_profile() detection signals",
            file=sys.stderr,
        )

    # Build skeleton project_data from net (no scanner findings yet)
    # Each net section becomes a control section with empty items
    skeleton_controls = []
    for section in net:
        skeleton_controls.append({
            "id":          section["id"],
            "tag":         section.get("tag", "NET"),
            "title":       section["title"],
            "status":      "net",
            "items":       [],
            "cwe":         section.get("cwe"),
            "owasp":       section.get("owasp"),
            "mitre":       section.get("mitre"),
            "priority":    section.get("priority", "p2"),
            "description": section.get("description", ""),
        })

    ts = now[:10].replace("-", "")
    slug_upper = slug.upper().replace("-", "")
    project_data = {
        "project": {
            "name":     project_name or slug.upper(),
            "slug":     slug,
            "repo":     Path(project_path).name,
            "commit":   now[:10],
            "reportId": f"{slug_upper}-SOC-NET-{ts}",
            "version":  "v1",
            "stage":    "wide-net",
        },
        "caseMetadata": {
            "status":       "net-pending",
            "severity":     "TBD",
            "urgency":      "tbd",
            "owner":        "Security",
            "incidentLead": "--",
        },
        "summary": {
            "executive": (
                f"Wide-Net SOC template generated {now[:10]} for {slug}. "
                f"{len(net)} threat classes identified from architecture profile "
                f"({', '.join(components)}). "
                "Run --refine to test each class against live scanner output."
            ),
            "businessImpact": (
                f"Architecture analysis identified {len(net)} potential attack surfaces. "
                "Refinement scan required to confirm exploitability."
            ),
        },
        "scope":      {"affected": slug, "confidence": "architecture-derived"},
        "confidence": {
            "level":    "MODERATE",
            "rationale": "Architecture-derived only — no scanner confirmation yet.",
        },
        "timeline": [{
            "ts":    now,
            "tz":    "UTC",
            "event": "Wide-Net SOC template generated",
            "actor": "soc_pipeline.py",
        }],
        "actions": {
            "taken":             [f"Architecture-derived threat net generated for {slug}"],
            "containmentStatus": "pending-scan",
            "remediationStatus": "pending-scan",
            "pending":           ["Run Stage 2 refinement scan to confirm findings"],
        },
        "communications":     {"notified": [], "nextUpdate": ""},
        "closure":            {
            "exitCriteria": (
                "All net sections adjudicated (proven/refuted); P0/P1 remediated."
            ),
            "handingOffTo": "",
        },
        "attackMapping":      [],
        "detectionCoverage":  [],
        "activeThreatStatus": {"signals": [], "lastUpdated": now},
        "riskAcceptance":     [],
        "incidentLinkage":    [],
        "slaSummary":         {},
        "maturity": {
            "currentStage": 1,
            "priorStage":   0,
            "growthDelta": {
                "controlsAdded":       len(net),
                "attackCoverageDelta": 0,
                "openGapsDelta":       len(net),
                "activeThreats":       {"prior": 0, "current": 0},
            },
        },
        "harnessMap":  {},
        "netControls": skeleton_controls,
        "controls":    skeleton_controls,
        "snapshots":   [],
        "scanDiff":    {"new": 0, "resolved": 0, "unchanged": 0, "has_prior": False},
    }

    # Wide-net stage is architecture-only — no scanner data, so the posture is
    # explicitly unscanned (verdict NET). No "score >= 95 -> PASS" shortcut.
    posture = sic_to_soc.compute_posture(
        all_items=[], net_sections=net, scanned=False
    )
    project_data["posture"] = posture

    out_path = out_dir / f"{slug}-soc-net-{ts}.html"
    tpl = template_path or sic_to_soc.DEFAULT_TEMPLATE
    try:
        template = Path(tpl).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"[soc_pipeline] FATAL: could not read template {tpl}: {exc}",
              file=sys.stderr)
        sys.exit(1)
    html = sic_to_soc.inject_project_data(template, project_data)
    html = sic_to_soc.stamp_score(html, posture)
    out_path.write_text(html, encoding="utf-8")
    print(f"[soc_pipeline] Stage 1 output: {out_path}", file=sys.stderr)

    return {"output_path": str(out_path), "net": net, "profile": profile, "slug": slug}


def stage2_refine(
    project_path: str,
    scan_json: str | None = None,
    output_base: str | None = None,
    template_path: str | None = None,
    analyst: str = "",
    analyst_role: str = "",
    output_path_override: str | None = None,
    asset_tier: str = "production",
    project_name: str | None = None,
) -> dict:
    """Stage 2: Run SIC scanner, adjudicate net, produce Refined Verdict report.

    Args:
        analyst: Analyst name — injected into caseMetadata.incidentLead and
            closure.handingOffTo so the one-command pipeline can sign the report.
        analyst_role: Analyst role — injected into caseMetadata.analystRole.
        output_path_override: Explicit output HTML path (default: auto-derived
            {slug}-soc-refined-{date}.html under the output dir).
        asset_tier: Asset tier for SLA calculation (default: production).

    Returns dict with keys: output_path, slug, proven_count, untested_count
    """
    from project_config import detect_system_profile
    from threat_catalog import build_net
    import soc_runner
    import sic_to_soc

    slug = _slug(project_path)
    now = _now_iso()
    out_dir = _output_dir(output_base, slug)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Register project if not already registered; auto-load display name from .sic.yaml
    try:
        from project_config import register_from_git, load_config
        register_from_git(project_path)
        if not project_name:
            cfg = load_config(project_path)
            if cfg.get("_source") == "file" and cfg.get("name"):
                project_name = cfg["name"]
    except Exception:
        pass

    profile = detect_system_profile(project_path)
    net = build_net(profile)

    # Run scanner or load existing scan JSON
    if scan_json and Path(scan_json).is_file():
        print(f"[soc_pipeline] Stage 2: loading existing scan {scan_json!r}", file=sys.stderr)
        try:
            with open(scan_json, encoding="utf-8") as f:
                merged = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"[soc_pipeline] FATAL: could not load scan JSON {scan_json}: {exc}",
                  file=sys.stderr)
            sys.exit(1)
        merged_path = scan_json
    else:
        print(
            f"[soc_pipeline] Stage 2: running SIC scanner on {project_path!r}",
            file=sys.stderr,
        )
        runner = soc_runner.SOCRunner(project_path=project_path)
        merged_path = runner.scan(str(out_dir))
        try:
            with open(merged_path, encoding="utf-8") as f:
                merged = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"[soc_pipeline] FATAL: could not load merged scan {merged_path}: {exc}",
                  file=sys.stderr)
            sys.exit(1)

    # Collect findings from merged JSON
    findings = sic_to_soc._collect(merged)
    print(
        f"[soc_pipeline] {len(findings)} findings collected from scanner",
        file=sys.stderr,
    )

    # Which scanners actually ran — used to distinguish refuted (scanner ran,
    # found nothing) from untested (scanner never ran for that surface).
    scanners_run = []
    if isinstance(merged, dict):
        meta = merged.get("merge_meta") or {}
        scanners_run = list(meta.get("sources") or [])

    ts = now[:10].replace("-", "")
    if output_path_override:
        out_path = Path(output_path_override)
        out_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_path = out_dir / f"{slug}-soc-refined-{ts}.html"

    # Build project_data with net-adjudication
    project_data = sic_to_soc.build_project_data(
        findings=findings,
        project=project_name or slug,
        slug=slug,
        scan_path=merged_path,
        now_iso=now,
        runs_dir=str(out_dir),
        output_path=str(out_path),
        asset_tier=asset_tier,
        net=net,
        scanners_run=scanners_run,
    )

    # Post-hoc analyst signature injection — mirrors sic_to_soc.py:921-924 so the
    # one-command pipeline can emit a signed report (build_project_data defaults
    # incidentLead/handingOffTo/analystRole to placeholders).
    if analyst:
        project_data.setdefault("caseMetadata", {})["incidentLead"] = analyst
        project_data.setdefault("closure", {})["handingOffTo"] = analyst
    if analyst_role:
        project_data.setdefault("caseMetadata", {})["analystRole"] = analyst_role

    tpl = template_path or sic_to_soc.DEFAULT_TEMPLATE
    try:
        template = Path(tpl).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"[soc_pipeline] FATAL: could not read template {tpl}: {exc}",
              file=sys.stderr)
        sys.exit(1)
    html = sic_to_soc.inject_project_data(template, project_data)
    html = sic_to_soc.stamp_score(html, project_data.get("posture", {}))
    out_path.write_text(html, encoding="utf-8")
    print(f"[soc_pipeline] Stage 2 output: {out_path}", file=sys.stderr)

    net_controls = project_data.get("netControls", [])
    proven = [s for s in net_controls if s.get("status") == "proven"]
    untested = [s for s in net_controls if s.get("status") == "untested"]

    return {
        "output_path":    str(out_path),
        "slug":           slug,
        "proven_count":   len(proven),
        "untested_count": len(untested),
    }


def _post_discord(
    webhook_url: str, embeds: list[dict], file_path: str | None = None
) -> bool:
    """Post a Discord webhook message with embed(s) and optional file attachment.

    File uploads use curl (urllib multipart triggers Discord 403); JSON-only
    posts use urllib directly.
    """
    if file_path and Path(file_path).exists():
        import subprocess

        payload_json = json.dumps({"embeds": embeds})
        try:
            result = subprocess.run(
                [
                    "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                    "-F", f"file=@{file_path}",
                    "-F", f"payload_json={payload_json}",
                    webhook_url,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
            if 200 <= code < 300:
                return True
            print(f"[soc_pipeline] Discord POST returned {code}", file=sys.stderr)
            return False
        except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
            print(f"[soc_pipeline] Discord POST (curl) failed: {exc}", file=sys.stderr)
            return False
    else:
        payload = json.dumps({"embeds": embeds}).encode()
        req = Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=15) as resp:
                return 200 <= resp.status < 300
        except (URLError, OSError) as exc:
            print(f"[soc_pipeline] Discord POST failed: {exc}", file=sys.stderr)
            return False


def _notify_discord(
    webhook_url: str,
    stage: str,
    slug: str,
    output_path: str,
    result: dict,
) -> None:
    """Send a Discord embed summarising the pipeline stage result.

    The score AND verdict are read from the stamped HTML (<!--soc-score:NN-->,
    <!--soc-verdict:VV-->) — the single authoritative posture computed by the
    Python score engine. The verdict picks the embed color via VERDICT_COLORS,
    so Discord never disagrees with the report. No hardcoded green PASS.
    """
    import os

    from sic_to_soc import VERDICT_COLORS

    posture = _extract_posture(output_path)
    score = posture.get("score")
    verdict = posture.get("verdict", "NET")
    scanned = posture.get("scanned", False)
    score_str = f"{score}/100" if (scanned and score is not None) else "N/A"
    color = VERDICT_COLORS.get(verdict, VERDICT_COLORS["NET"])

    if stage == "wide-net":
        net_count = len(result.get("net", []))
        components = result.get("profile", {}).get("components", [])
        if verdict == "NET":
            title = f"SOC NET -- {slug.upper()} — architecture-only, not yet assessed"
            desc = (
                f"**NET — architecture-only, not yet assessed**\n"
                f"**{net_count}** threat classes identified from architecture profile.\n"
                f"Components: {', '.join(components) or 'none'}\n\n"
                f"Run `--refine` to produce the Refined Verdict."
            )
        else:
            title = f"SOC Wide-Net -- {slug.upper()} ({score_str}, {verdict})"
            desc = (
                f"**Score: {score_str} - {verdict}**\n"
                f"**{net_count}** threat classes identified from architecture profile.\n"
                f"Components: {', '.join(components) or 'none'}\n\n"
                f"Run `--refine` to produce the Refined Verdict."
            )
        embed = {
            "title": title,
            "description": desc,
            "color": color,
            "fields": [
                {"name": "Stage", "value": "1 - Wide Net", "inline": True},
                {"name": "Score", "value": score_str, "inline": True},
                {"name": "Verdict", "value": verdict, "inline": True},
                {"name": "Sections", "value": str(net_count), "inline": True},
            ],
            "footer": {"text": f"3SIXTYCO. SOC Pipeline - {os.path.basename(output_path)}"},
        }
    else:
        proven = result.get("proven_count", 0)
        untested = result.get("untested_count", 0)
        embed = {
            "title": f"SOC Refined Verdict -- {slug.upper()} ({score_str}, {verdict})",
            "description": (
                f"**Score: {score_str} - {verdict}**\n"
                f"**{proven}** proven threat classes, **{untested}** untested.\n"
            ),
            "color": color,
            "fields": [
                {"name": "Stage", "value": "2 - Refined Verdict", "inline": True},
                {"name": "Score", "value": score_str, "inline": True},
                {"name": "Verdict", "value": verdict, "inline": True},
                {"name": "Proven", "value": str(proven), "inline": True},
                {"name": "Untested", "value": str(untested), "inline": True},
            ],
            "footer": {"text": f"3SIXTYCO. SOC Pipeline - {os.path.basename(output_path)}"},
        }

    ok = _post_discord(webhook_url, [embed], file_path=output_path)
    if ok:
        print(f"[soc_pipeline] Discord notification sent for {stage} "
              f"(score={score_str}, verdict={verdict})", file=sys.stderr)
    else:
        print(f"[soc_pipeline] Discord notification FAILED for {stage}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "SIC SOC Pipeline — WIDE NET -> REFINED VERDICT "
            "two-stage SOC report generation"
        )
    )
    parser.add_argument("--path", required=True, help="Project root path")
    parser.add_argument(
        "--net",
        action="store_true",
        help="Stage 1: generate Wide-Net template only",
    )
    parser.add_argument(
        "--refine",
        action="store_true",
        help="Stage 2: run scanner + produce Refined Verdict",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Run both Stage 1 and Stage 2 automatically",
    )
    parser.add_argument(
        "--scan-json",
        help="Optional: path to existing merged scan JSON (skips live scan)",
    )
    parser.add_argument(
        "--output-dir",
        help="Output directory (default: sic/_runs/qa/)",
    )
    parser.add_argument(
        "--template",
        default=None,
        help="Override SOC handoff HTML template path (default: sic/templates/soc-handoff/soc-handoff-template-blank.html)",
    )
    parser.add_argument(
        "--discord",
        action="store_true",
        help="Post results to the Discord SOC report channel (uses DISCORD_WEBHOOK_SOC env var)",
    )
    parser.add_argument(
        "--analyst",
        default="",
        help="Analyst name — signs the report (caseMetadata.incidentLead + closure.handingOffTo)",
    )
    parser.add_argument(
        "--analyst-role",
        default="",
        help="Analyst role/title for the signed report (caseMetadata.analystRole)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Explicit output HTML path for the Refined Verdict (default: auto-derived under output dir)",
    )
    parser.add_argument(
        "--asset-tier",
        default="production",
        help="Asset tier for SLA calculation (default: production)",
    )
    parser.add_argument(
        "--project-name",
        default=None,
        help="Project display name shown in the report (e.g. 'Security Intelligence Center'). "
             "Defaults to the directory name slug.",
    )
    parser.add_argument(
        "--copy-to",
        default=None,
        metavar="DEST",
        help="Copy the final Refined Verdict HTML to DEST after generation (e.g. ~/Documents/).",
    )
    parser.add_argument(
        "--qa",
        action="store_true",
        help="Run qa_soc.py against the generated Refined Verdict and fail the command on QA error",
    )
    args = parser.parse_args()

    if not (args.net or args.refine or args.auto):
        parser.error("Specify --net, --refine, or --auto")

    import os
    discord_url = ""
    if args.discord:
        # 1. Per-project webhook from .sic.yaml takes priority
        try:
            from project_config import load_config
            cfg = load_config(args.path)
            discord_url = (cfg.get("discord_webhook") or "").strip()
            if discord_url:
                print(f"[soc_pipeline] Using per-project Discord webhook from .sic.yaml")
        except Exception:
            pass

        # 2. Fall back to global env var
        if not discord_url:
            discord_url = (os.environ.get("DISCORD_WEBHOOK_SOC") or "").strip()

        if not discord_url:
            print(
                "[soc_pipeline] WARNING: --discord requested but no webhook found "
                "(set discord_webhook in .sic.yaml or DISCORD_WEBHOOK_SOC env var)",
                file=sys.stderr,
            )

    if args.auto or args.net:
        result1 = stage1_net(args.path, args.output_dir, args.template, project_name=args.project_name)
        print(f"Stage 1 complete: {result1['output_path']}")
        print(f"  Components: {result1['profile'].get('components', [])}")
        print(f"  Net sections: {len(result1['net'])}")
        if discord_url:
            _notify_discord(discord_url, "wide-net", result1["slug"], result1["output_path"], result1)

    if args.auto or args.refine:
        result2 = stage2_refine(
            args.path,
            args.scan_json,
            args.output_dir,
            args.template,
            analyst=args.analyst,
            analyst_role=args.analyst_role,
            output_path_override=args.output,
            asset_tier=args.asset_tier,
            project_name=args.project_name,
        )
        print(f"Stage 2 complete: {result2['output_path']}")
        print(f"  Proven: {result2['proven_count']}  Untested: {result2['untested_count']}")
        if args.analyst:
            print(f"  Signed by: {args.analyst}"
                  + (f" ({args.analyst_role})" if args.analyst_role else ""))
        if discord_url:
            _notify_discord(discord_url, "refined-verdict", result2["slug"], result2["output_path"], result2)

        # QA gate — one-command flow self-validates the signed artifact.
        if args.qa:
            import subprocess
            qa_path = Path(__file__).parent / "qa_soc.py"
            print(f"[soc_pipeline] Running QA gate: {qa_path.name}")
            qa = subprocess.run(
                [sys.executable, str(qa_path), result2["slug"], result2["output_path"]],
                capture_output=True, text=True,
            )
            sys.stdout.write(qa.stdout)
            sys.stderr.write(qa.stderr)
            if qa.returncode != 0:
                print("[soc_pipeline] FATAL: QA gate failed — report rejected",
                      file=sys.stderr)
                sys.exit(1)
            print("[soc_pipeline] QA gate passed")

        if args.copy_to:
            import shutil
            dest = Path(args.copy_to).expanduser()
            if dest.is_dir():
                dest = dest / Path(result2["output_path"]).name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(result2["output_path"], dest)
            print(f"[soc_pipeline] Report copied to: {dest}")


if __name__ == "__main__":
    main()
