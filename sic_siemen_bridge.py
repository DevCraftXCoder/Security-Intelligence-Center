#!/usr/bin/env python3
"""
sic_siemen_bridge.py — SIC → SIEMen integration bridge (Gaps 1 + 2)

Bridges SIC scan findings into SIEMen's data layer:
  1. engagement_open — creates/registers a SIEMen engagement for a SIC scan
  2. push_findings   — transforms SIC finding dicts and batch-POSTs to SIEMen

Field mapping (SIC → SIEMen):
  title       ← name / vulnerabilityName / Title / template-id / checkID
  body        ← description / info.description / details / Description (capped 2000 chars)
  severity    ← severity / info.severity / Severity → remap unknown/none → "info"
  kind        ← "cve" if title matches CVE-YYYY-NNNNN, "control" if checkov, else "finding"
  external_id ← CVE id extracted from title/template-id/checkID (for dedup)
  asset       ← host / url / target / affected_component
  tags        ← [scanner, category] if available
  metadata    ← full raw finding dict

CLI usage:
    python sic_siemen_bridge.py \\
        --scan ./_runs/scan-20260101.json \\
        --engagement-name "Example Corp Pentest" \\
        [--client "Example Corp"] \\
        [--engagement-id "existing-uuid"] \\
        [--url https://siemen.frxncois.workers.dev] \\
        [--dry-run]

Library usage:
    from sic_siemen_bridge import SIEMenClient, push_scan_to_siemen

    client = SIEMenClient()  # reads SIEMEN_URL + SIEMEN_API_KEY from env
    eid = client.open_engagement("My Pentest", client="Acme")
    result = client.push_findings(eid, sic_findings)
    print(result)  # { stored, duplicates, errors, total_pushed }

Environment variables:
    SIEMEN_URL      — SIEMen base URL (default: https://siemen.frxncois.workers.dev)
    SIEMEN_API_KEY  — Bearer token for SIEMen /v1/* routes
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

try:
    from scan_merge import _collect  # SIC's authoritative finding collector
except ImportError:
    _collect = None  # allow import outside SIC context

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_SIEMEN_URL = "https://siemen.frxncois.workers.dev"
BATCH_SIZE = 100  # SIEMen /v1/findings/batch max

SEVERITY_REMAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "none": "info",
    "unknown": "info",
    "": "info",
}

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
CHECKOV_RE = re.compile(r"^CKV(_[A-Z]+)?_\d+$")


# ---------------------------------------------------------------------------
# Field helpers (mirrors sic_to_soc.py naming)
# ---------------------------------------------------------------------------

def _name(f: dict[str, Any]) -> str:
    return (
        f.get("name")
        or f.get("vulnerabilityName")
        or f.get("Title")
        or f.get("template-id")
        or f.get("checkID")
        or "Unnamed finding"
    )


def _desc(f: dict[str, Any]) -> str:
    raw = (
        f.get("description")
        or (f.get("info") or {}).get("description")
        or f.get("details")
        or f.get("Description")
        or "See scan output for details."
    )
    return str(raw)[:2000]


def _sev(f: dict[str, Any]) -> str:
    raw = (
        f.get("severity")
        or (f.get("info") or {}).get("severity")
        or f.get("Severity")
        or "unknown"
    )
    return SEVERITY_REMAP.get(str(raw).lower().strip(), "info")


def _kind(f: dict[str, Any]) -> str:
    title = _name(f)
    check_id = f.get("checkID") or f.get("check_id") or ""
    template_id = f.get("template-id") or ""

    # CVE match on common fields → "cve"
    for field in (title, template_id, check_id):
        if CVE_RE.search(str(field)):
            return "cve"

    # Checkov check ID → "control"
    if CHECKOV_RE.match(str(check_id).strip()):
        return "control"

    return "finding"


def _external_id(f: dict[str, Any]) -> str | None:
    """Extract CVE id for SIEMen dedup. Returns None if not found."""
    enrichment = f.get("enrichment") or {}
    if enrichment.get("cve_id"):
        return str(enrichment["cve_id"]).upper()
    for field in ("name", "template-id", "checkID", "Title", "vulnerabilityName"):
        val = f.get(field) or ""
        m = CVE_RE.search(str(val))
        if m:
            return m.group(0).upper()
    return None


def _asset(f: dict[str, Any]) -> str | None:
    return (
        f.get("host")
        or f.get("url")
        or f.get("target")
        or f.get("affected_component")
        or f.get("matched-at")
        or None
    )


def _tags(f: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    scanner = f.get("scanner") or f.get("tool") or ""
    if scanner:
        tags.append(str(scanner).lower())
    category = (
        f.get("category")
        or (f.get("info") or {}).get("tags")
        or f.get("check_type")
        or ""
    )
    if isinstance(category, list):
        tags.extend(str(t).lower() for t in category[:3])
    elif category:
        tags.append(str(category).lower())
    return list(dict.fromkeys(tags))[:5]  # dedup, cap at 5


def to_siemen_finding(f: dict[str, Any], engagement_id: str) -> dict[str, Any]:
    """Transform one SIC finding dict to a SIEMen finding_store payload."""
    return {
        "engagement_id": engagement_id,
        "kind": _kind(f),
        "title": _name(f)[:512],
        "body": _desc(f),
        "severity": _sev(f),
        "asset": _asset(f),
        "external_id": _external_id(f),
        "tags": _tags(f),
        "metadata": {k: v for k, v in f.items() if k not in ("enrichment",)},
    }


# ---------------------------------------------------------------------------
# SIEMenClient
# ---------------------------------------------------------------------------

class SIEMenClient:
    """HTTP client for SIEMen /v1/* endpoints. Reads config from env by default."""

    def __init__(self, url: str | None = None, api_key: str | None = None) -> None:
        self.url = (url or os.environ.get("SIEMEN_URL") or DEFAULT_SIEMEN_URL).rstrip("/")
        self.api_key = api_key or os.environ.get("SIEMEN_API_KEY") or ""
        if not self.api_key:
            logger.warning("[siemen-bridge] SIEMEN_API_KEY not set — requests will fail auth")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "sic-siemen-bridge/1.0",
        }

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.url}{path}"
        data = json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body_text = e.read().decode(errors="replace")
            raise RuntimeError(f"SIEMen POST {path} → HTTP {e.code}: {body_text}") from e

    def _get(self, path: str) -> dict[str, Any]:
        url = f"{self.url}{path}"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body_text = e.read().decode(errors="replace")
            raise RuntimeError(f"SIEMen GET {path} → HTTP {e.code}: {body_text}") from e

    def open_engagement(
        self,
        name: str,
        client: str | None = None,
        engagement_id: str | None = None,
        status: str = "active",
    ) -> str:
        """Create or upsert a SIEMen engagement. Returns the engagement_id."""
        payload: dict[str, Any] = {"name": name, "status": status}
        if client:
            payload["client"] = client
        if engagement_id:
            payload["engagement_id"] = engagement_id
        result = self._post("/v1/engagements", payload)
        eid = result.get("engagement_id")
        if not eid:
            raise RuntimeError(f"SIEMen engagement_open returned unexpected: {result}")
        logger.info("[siemen-bridge] engagement opened: %s (%s)", eid, name)
        return str(eid)

    def push_findings(
        self,
        engagement_id: str,
        sic_findings: list[dict[str, Any]],
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """
        Transform and batch-push SIC findings to SIEMen.
        Returns aggregated { stored, duplicates, errors, total_pushed }.
        """
        if not sic_findings:
            return {"stored": 0, "duplicates": 0, "errors": [], "total_pushed": 0}

        siemen_findings = [to_siemen_finding(f, engagement_id) for f in sic_findings]
        total = len(siemen_findings)

        if dry_run:
            logger.info("[siemen-bridge] DRY RUN: would push %d findings to %s", total, engagement_id)
            return {"stored": 0, "duplicates": 0, "errors": [], "total_pushed": total, "dry_run": True}

        stored = 0
        duplicates = 0
        all_errors: list[dict[str, Any]] = []

        for batch_start in range(0, total, BATCH_SIZE):
            batch = siemen_findings[batch_start : batch_start + BATCH_SIZE]
            try:
                result = self._post("/v1/findings/batch", {"findings": batch})
                stored += result.get("stored", 0)
                duplicates += result.get("duplicates", 0)
                for err in result.get("errors", []):
                    err["batch_offset"] = batch_start
                    all_errors.append(err)
            except RuntimeError as exc:
                logger.error("[siemen-bridge] batch %d–%d failed: %s", batch_start, batch_start + len(batch), exc)
                all_errors.append({"batch_start": batch_start, "error": str(exc)})

        logger.info(
            "[siemen-bridge] push complete: %d stored, %d duplicates, %d errors / %d total",
            stored, duplicates, len(all_errors), total,
        )
        return {
            "stored": stored,
            "duplicates": duplicates,
            "errors": all_errors,
            "total_pushed": total,
        }

    def get_report(self, engagement_id: str) -> dict[str, Any]:
        """Fetch the full engagement export (Gap 3 endpoint)."""
        return self._get(f"/v1/engagements/{engagement_id}/report")


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def push_scan_to_siemen(
    scan_path: str,
    engagement_name: str,
    client_name: str | None = None,
    engagement_id: str | None = None,
    siemen_url: str | None = None,
    api_key: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    End-to-end: load a SIC scan JSON, open an engagement, push findings.
    Returns { engagement_id, push_result }.
    """
    if _collect is None:
        raise ImportError(
            "scan_merge._collect not available — run this from within the sic/ directory "
            "or ensure scan_merge.py is importable."
        )

    # Load findings from scan JSON
    path = Path(scan_path)
    if not path.exists():
        raise FileNotFoundError(f"Scan file not found: {scan_path}")

    raw = path.read_text(encoding="utf-8", errors="replace")
    findings: list[dict[str, Any]] = []
    decoder = __import__("json").JSONDecoder()
    pos = 0
    while pos < len(raw):
        while pos < len(raw) and raw[pos] in " \t\n\r":
            pos += 1
        if pos >= len(raw):
            break
        try:
            obj, end = decoder.raw_decode(raw, pos)
            pos = end
            findings.extend(_collect(obj))
        except __import__("json").JSONDecodeError:
            pos += 1

    logger.info("[siemen-bridge] loaded %d findings from %s", len(findings), scan_path)

    client = SIEMenClient(url=siemen_url, api_key=api_key)
    if dry_run:
        logger.info("[siemen-bridge] dry-run: skipping engagement open + push")
        return {"engagement_id": engagement_id or "dry-run", "push_result": {"stored": 0, "duplicates": 0, "errors": [], "total_pushed": len(findings), "dry_run": True}}
    eid = client.open_engagement(engagement_name, client=client_name, engagement_id=engagement_id)
    push_result = client.push_findings(eid, findings, dry_run=dry_run)

    return {"engagement_id": eid, "push_result": push_result}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    parser = argparse.ArgumentParser(
        description="Bridge SIC scan findings into SIEMen's data layer."
    )
    parser.add_argument("--scan", required=True, help="Path to SIC scan JSON output file")
    parser.add_argument("--engagement-name", required=True, help="SIEMen engagement name")
    parser.add_argument("--client", default=None, help="Client name (optional)")
    parser.add_argument("--engagement-id", default=None, help="Reuse an existing engagement ID")
    parser.add_argument(
        "--url",
        default=os.environ.get("SIEMEN_URL", DEFAULT_SIEMEN_URL),
        help="SIEMen base URL",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("SIEMEN_API_KEY", ""),
        help="SIEMen API key (Bearer token)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Transform but do not push findings")
    args = parser.parse_args()

    if not args.api_key and not args.dry_run:
        print("ERROR: SIEMEN_API_KEY env var or --api-key required (or use --dry-run)", file=sys.stderr)
        sys.exit(1)

    result = push_scan_to_siemen(
        scan_path=args.scan,
        engagement_name=args.engagement_name,
        client_name=args.client,
        engagement_id=args.engagement_id,
        siemen_url=args.url,
        api_key=args.api_key,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _main()
