#!/usr/bin/env python3
"""
scan_merge.py -- Multi-scanner result merging for SIC.

Merges the JSON outputs of several scanners (trivy-fs, trivy-image, checkov,
nuclei, secrets) into a single unified findings list. Findings are normalized
via the same `_collect()` logic used by sic_to_soc.py (copied here, not imported,
so this module stays independent of the SOC report pipeline), deduplicated by a
stable fingerprint, and stamped with their source scanner.

Output shape:
    {
      "findings": [ { ..., "_merge_source": "trivy-fs" }, ... ],
      "merge_meta": {
        "sources": ["trivy-fs", "checkov", ...],
        "total":   <count before dedup>,
        "deduped": <count after dedup>,
        "merged_at": "<ISO-8601 UTC>"
      }
    }

stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _err(msg: str) -> None:
    """Write a namespaced line to stderr."""
    print(f"[scan_merge] {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Finding collection (copied from sic_to_soc.py to keep merge independent)
# ---------------------------------------------------------------------------


def _collect(obj: Any) -> list[dict[str, Any]]:
    """Recursively collect dicts that look like individual findings.

    Handles three schemas beyond the generic nuclei/smart-scan format:
    - trivy: Results[].Vulnerabilities[] with VulnerabilityID/Severity/Title/Description
    - checkov: results.failed_checks[] with check_id/severity/resource/check_result
    """
    if isinstance(obj, list):
        out: list[dict[str, Any]] = []
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


def _load_findings(path: str) -> list[dict[str, Any]]:
    """Read a scanner JSON file and collect normalized findings.

    Mirrors sic_to_soc.load_findings: tolerates concatenated JSON documents by
    decoding objects one at a time and skipping malformed regions.
    """
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        _err(f"could not read scan file {path}: {exc}")
        return []

    findings: list[dict[str, Any]] = []
    decoder = json.JSONDecoder()
    pos = 0
    length = len(text)
    while pos < length:
        while pos < length and text[pos] in " \t\n\r":
            pos += 1
        if pos >= length:
            break
        try:
            obj, end = decoder.raw_decode(text, pos)
            pos = end
            findings.extend(_collect(obj))
        except json.JSONDecodeError:
            pos += 1
    return findings


# ---------------------------------------------------------------------------
# Fingerprint + source inference
# ---------------------------------------------------------------------------


def _name_of(f: dict[str, Any]) -> str:
    """Best-effort canonical name for a finding (matches sic_to_soc._name)."""
    return (
        f.get("name")
        or f.get("vulnerabilityName")
        or f.get("Title")
        or f.get("template-id")
        or f.get("checkID")
        or "Unnamed finding"
    )


def _severity_of(f: dict[str, Any]) -> str:
    """Best-effort severity for a finding (matches sic_to_soc._sev)."""
    raw = (
        f.get("severity")
        or (f.get("info") or {}).get("severity")
        or f.get("Severity")
        or "unknown"
    )
    return str(raw).lower()


def _fingerprint(f: dict[str, Any]) -> str:
    """Stable dedup key: SHA256(name[:40] + '|' + severity)[:16]."""
    name = str(_name_of(f))[:40]
    sev = _severity_of(f)
    key = f"{name}|{sev}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _source_label(scan_path: str, finding: dict[str, Any]) -> str:
    """Derive the scanner source label for a finding.

    Prefers the filename stem (which soc_runner writes as the scanner name),
    falling back to the finding's own `_source` hint, then 'unknown'.
    """
    stem = Path(scan_path).stem
    if stem:
        # soc_runner writes temp files named "<scanner>-<...>"; take the scanner prefix.
        return stem.split("-")[0] if "-" in stem else stem
    return str(finding.get("_source") or "unknown")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def merge_scans(scan_files: list[str], output_path: str) -> dict[str, Any]:
    """Merge multiple scanner JSON outputs into a single unified findings list.

    Reads each file, normalizes findings via `_collect`, deduplicates by
    fingerprint, tags each surviving finding with `_merge_source`, and writes
    the merged document to `output_path`.

    Returns the merged dict.
    """
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    sources: list[str] = []
    total = 0

    for scan_file in scan_files:
        label = Path(scan_file).stem.split("-")[0] if "-" in Path(scan_file).stem else Path(scan_file).stem
        if not Path(scan_file).is_file():
            _err(f"scan file missing — skipping: {scan_file}")
            continue
        if label and label not in sources:
            sources.append(label)

        findings = _load_findings(scan_file)
        for finding in findings:
            total += 1
            fp = _fingerprint(finding)
            if fp in seen:
                continue
            seen.add(fp)
            enriched = dict(finding)
            enriched["_merge_source"] = _source_label(scan_file, finding)
            enriched["_fingerprint"] = fp
            merged.append(enriched)

    result: dict[str, Any] = {
        "findings": merged,
        "merge_meta": {
            "sources": sources,
            "total": total,
            "deduped": len(merged),
            "merged_at": datetime.now(timezone.utc).isoformat(),
        },
    }

    try:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, sort_keys=False)
            fh.write("\n")
    except OSError as exc:
        _err(f"could not write merged output {output_path}: {exc}")

    return result


def merge_and_write(scan_files: list[str], output_dir: str, slug: str) -> str:
    """Convenience wrapper around merge_scans.

    Builds a timestamped output path under `output_dir` named
    `<slug>-merged-<YYYYMMDD-HHMMSS>.json`, runs the merge, and returns the path.
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe_slug = slug or "scan"
    output_path = str(Path(output_dir) / f"{safe_slug}-merged-{ts}.json")
    merge_scans(scan_files, output_path)
    return output_path


def _build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        prog="scan_merge",
        description="Merge multiple scanner JSON outputs into a unified findings list.",
    )
    parser.add_argument("scan_files", nargs="+", help="Scanner JSON files to merge.")
    parser.add_argument("--output", required=True, help="Path to write the merged JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    result = merge_scans(args.scan_files, args.output)
    meta = result["merge_meta"]
    _err(
        f"merged {meta['total']} findings -> {meta['deduped']} unique "
        f"from {len(meta['sources'])} source(s); wrote {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
