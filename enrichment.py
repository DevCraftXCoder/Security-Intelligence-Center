"""
enrichment.py — Self-contained enrichment pipeline for SIC scan findings.

Enriches raw scan findings (nuclei, hexstrike, etc.) with authoritative
vulnerability intelligence from three free public sources:

  1. CISA KEV  — Known Exploited Vulnerabilities catalog (actively exploited)
  2. EPSS      — Exploit Prediction Scoring System (probability of exploitation)
  3. NVD       — CVSS v3 base score + primary CWE + description

A finding is flagged ``force_p0`` when it is on the KEV catalog OR has an EPSS
score above 0.7 — these are the findings that should jump the priority queue.

Design constraints:
  - stdlib only (urllib.request) — the SIC scanner container is minimal and
    the ``requests`` library is not guaranteed installed.
  - every network call is wrapped in try/except — enrichment is best-effort.
    A network outage degrades gracefully to partial / empty enrichment, never
    raises out of the public functions.
  - all caches live under ``~/.sic/`` alongside the existing state.db.

Public API:
  - is_kev(cve_id)                       -> bool
  - get_epss_score(cve_id)               -> float | None
  - fetch_epss_batch(cve_ids)            -> dict[str, float]
  - get_nvd_data(cve_id)                 -> dict | None
  - extract_cve_ids(findings)            -> list[str]
  - enrich_findings(findings)            -> list[dict]
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SIC_DIR = Path.home() / ".sic"

_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_KEV_CACHE = _SIC_DIR / "kev_cache.json"
_KEV_TTL_SECONDS = 24 * 60 * 60  # 24 hours

_EPSS_URL = "https://api.first.org/data/v1/epss"
_EPSS_CACHE = _SIC_DIR / "epss_cache.json"
_EPSS_TTL_SECONDS = 24 * 60 * 60  # 24 hours
_EPSS_BATCH_SIZE = 100  # FIRST API accepts comma-joined CVE lists; chunk to be safe

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_CACHE_DIR = _SIC_DIR / "nvd_cache"
_NVD_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days
_NVD_SLEEP_NO_KEY = 0.6  # seconds between calls without an API key
_NVD_SLEEP_WITH_KEY = 0.05  # 50 req / 30s with key -> ~0.6s/req min; be gentle

_USER_AGENT = "SIC-Enrichment/1.0 (+https://frxncois.com/sic)"
_HTTP_TIMEOUT = 30  # seconds

# CVE pattern, case-insensitive (CVE-YYYY-NNNN+).
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Threshold above which an EPSS score forces P0 escalation.
_EPSS_FORCE_P0 = 0.7

# ---------------------------------------------------------------------------
# Module-level in-memory caches (populated lazily)
# ---------------------------------------------------------------------------

_kev_set: Optional[set[str]] = None
_epss_mem: dict[str, float] = {}


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _log(message: str) -> None:
    """Print an enrichment progress line to stderr."""
    print(f"[enrichment] {message}", file=sys.stderr, flush=True)


def _now_ts() -> float:
    """Return current UNIX timestamp (UTC)."""
    return datetime.now(tz=timezone.utc).timestamp()


def _ensure_dir() -> None:
    """Make sure the ~/.sic directory (and NVD cache subdir) exist."""
    _SIC_DIR.mkdir(parents=True, exist_ok=True)
    _NVD_CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _http_get_json(url: str, headers: Optional[dict[str, str]] = None) -> Optional[Any]:
    """Perform an HTTP GET and parse the body as JSON.

    Returns the parsed object, or None on any network / parse error
    (enrichment is best-effort and must never raise on a fetch failure).
    """
    req_headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            raw = resp.read()
        return json.loads(raw.decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        _log(f"network error fetching {url.split('?')[0]}: {exc}")
        return None
    except (ValueError, json.JSONDecodeError) as exc:
        _log(f"JSON parse error from {url.split('?')[0]}: {exc}")
        return None
    except Exception as exc:  # noqa: BLE001 - best-effort, never propagate
        _log(f"unexpected error fetching {url.split('?')[0]}: {exc}")
        return None


def _read_cache(path: Path) -> Optional[dict[str, Any]]:
    """Read a JSON cache file, returning None if missing or corrupt."""
    try:
        if not path.exists():
            return None
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        _log(f"cache read error {path.name}: {exc}")
        return None


def _write_cache(path: Path, data: dict[str, Any]) -> None:
    """Write a JSON cache file atomically (best-effort)."""
    try:
        _ensure_dir()
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(data, fh)
        tmp.replace(path)
    except OSError as exc:
        _log(f"cache write error {path.name}: {exc}")


def _cache_fresh(cache: Optional[dict[str, Any]], ttl_seconds: int) -> bool:
    """Return True if the cache has a fetched_at within ttl_seconds of now."""
    if not cache:
        return False
    fetched_at = cache.get("fetched_at")
    if not isinstance(fetched_at, (int, float)):
        return False
    return (_now_ts() - fetched_at) < ttl_seconds


def _normalize_cve(cve_id: str) -> str:
    """Uppercase and strip a CVE id for consistent keying."""
    return cve_id.strip().upper()


# ---------------------------------------------------------------------------
# 1. CISA KEV enrichment
# ---------------------------------------------------------------------------


def _load_kev_set(force_refresh: bool = False) -> set[str]:
    """Return the set of KEV CVE ids, loading / refreshing the cache as needed.

    The in-memory set is populated once per process. The on-disk cache refreshes
    when older than 24h. On total failure (no network, no cache) an empty set is
    returned so lookups simply report not-KEV rather than crashing.
    """
    global _kev_set

    if _kev_set is not None and not force_refresh:
        return _kev_set

    cache = _read_cache(_KEV_CACHE)
    if not force_refresh and _cache_fresh(cache, _KEV_TTL_SECONDS) and cache:
        ids = cache.get("cve_ids", [])
        _kev_set = {_normalize_cve(c) for c in ids if isinstance(c, str)}
        return _kev_set

    _log("Fetching KEV catalog...")
    payload = _http_get_json(_KEV_URL)

    if payload is None:
        # Network failed — fall back to stale cache if we have one.
        if cache and isinstance(cache.get("cve_ids"), list):
            _log("KEV fetch failed, using stale cache")
            _kev_set = {
                _normalize_cve(c) for c in cache["cve_ids"] if isinstance(c, str)
            }
        else:
            _log("KEV unavailable, proceeding without KEV data")
            _kev_set = set()
        return _kev_set

    vulns = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    cve_ids = [
        _normalize_cve(v["cveID"])
        for v in vulns
        if isinstance(v, dict) and isinstance(v.get("cveID"), str)
    ]
    _kev_set = set(cve_ids)

    _write_cache(
        _KEV_CACHE,
        {"fetched_at": _now_ts(), "count": len(cve_ids), "cve_ids": sorted(_kev_set)},
    )
    _log(f"KEV catalog loaded: {len(_kev_set)} CVEs")
    return _kev_set


def is_kev(cve_id: str) -> bool:
    """Return True if the given CVE is on the CISA KEV catalog."""
    if not cve_id:
        return False
    return _normalize_cve(cve_id) in _load_kev_set()


# ---------------------------------------------------------------------------
# 2. EPSS score enrichment
# ---------------------------------------------------------------------------


def _load_epss_cache() -> dict[str, Any]:
    """Load the EPSS disk cache structure, or a fresh empty structure."""
    cache = _read_cache(_EPSS_CACHE)
    if cache and isinstance(cache.get("scores"), dict):
        return cache
    return {"fetched_at": _now_ts(), "scores": {}}


def _save_epss_cache(scores: dict[str, float]) -> None:
    """Persist EPSS scores to disk with a fresh fetched_at."""
    _write_cache(_EPSS_CACHE, {"fetched_at": _now_ts(), "scores": scores})


def fetch_epss_batch(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS scores for a list of CVEs, returning {cve_id: probability}.

    Uses the FIRST.org batch endpoint (comma-joined cve param), chunked to keep
    URLs reasonable. Results are merged into the on-disk cache (24h TTL) and the
    process-level memory cache. CVEs absent from the response (no EPSS score)
    are simply omitted from the returned dict.
    """
    if not cve_ids:
        return {}

    normalized = sorted({_normalize_cve(c) for c in cve_ids if c})
    disk_cache = _load_epss_cache()
    cache_fresh = _cache_fresh(disk_cache, _EPSS_TTL_SECONDS)
    cached_scores: dict[str, float] = (
        disk_cache.get("scores", {}) if cache_fresh else {}
    )

    result: dict[str, float] = {}
    to_fetch: list[str] = []

    for cve in normalized:
        if cve in _epss_mem:
            result[cve] = _epss_mem[cve]
        elif cve in cached_scores:
            score = cached_scores[cve]
            _epss_mem[cve] = score
            result[cve] = score
        else:
            to_fetch.append(cve)

    if not to_fetch:
        return result

    fetched: dict[str, float] = {}
    for start in range(0, len(to_fetch), _EPSS_BATCH_SIZE):
        chunk = to_fetch[start : start + _EPSS_BATCH_SIZE]
        query = urllib.parse.urlencode({"cve": ",".join(chunk)})
        url = f"{_EPSS_URL}?{query}"
        payload = _http_get_json(url)
        if payload is None or not isinstance(payload, dict):
            continue
        for row in payload.get("data", []):
            if not isinstance(row, dict):
                continue
            cve = _normalize_cve(str(row.get("cve", "")))
            raw_score = row.get("epss")
            if not cve or raw_score is None:
                continue
            try:
                score = float(raw_score)
            except (TypeError, ValueError):
                continue
            fetched[cve] = score

    if fetched:
        result.update(fetched)
        _epss_mem.update(fetched)
        # Merge new scores into the persisted cache.
        merged = dict(cached_scores)
        merged.update(_epss_mem)
        _save_epss_cache(merged)

    return result


def get_epss_score(cve_id: str) -> Optional[float]:
    """Return the EPSS probability (0.0-1.0) for a CVE, or None if unavailable."""
    if not cve_id:
        return None
    cve = _normalize_cve(cve_id)
    if cve in _epss_mem:
        return _epss_mem[cve]
    scores = fetch_epss_batch([cve])
    return scores.get(cve)


# ---------------------------------------------------------------------------
# 3. NVD CVSS + CWE enrichment
# ---------------------------------------------------------------------------


def _nvd_cache_path(cve_id: str) -> Path:
    """Return the per-CVE NVD cache file path."""
    return _NVD_CACHE_DIR / f"{_normalize_cve(cve_id)}.json"


def _parse_nvd_payload(payload: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Extract {cvss_v3, cwe, description} from an NVD 2.0 API response."""
    vulns = payload.get("vulnerabilities", [])
    if not vulns or not isinstance(vulns, list):
        return None
    cve = vulns[0].get("cve", {}) if isinstance(vulns[0], dict) else {}
    if not isinstance(cve, dict):
        return None

    # --- CVSS v3 base score (prefer v3.1, fall back to v3.0) ---
    cvss_v3: Optional[float] = None
    metrics = cve.get("metrics", {}) if isinstance(cve.get("metrics"), dict) else {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if isinstance(entries, list) and entries:
            data = entries[0].get("cvssData", {}) if isinstance(entries[0], dict) else {}
            base = data.get("baseScore")
            if isinstance(base, (int, float)):
                cvss_v3 = float(base)
                break

    # --- Primary CWE ---
    cwe: Optional[str] = None
    for weakness in cve.get("weaknesses", []) or []:
        if not isinstance(weakness, dict):
            continue
        for desc in weakness.get("description", []) or []:
            if isinstance(desc, dict):
                value = desc.get("value")
                if isinstance(value, str) and value.upper().startswith("CWE-"):
                    cwe = value
                    break
        if cwe:
            break

    # --- English description ---
    description: Optional[str] = None
    for desc in cve.get("descriptions", []) or []:
        if isinstance(desc, dict) and desc.get("lang") == "en":
            value = desc.get("value")
            if isinstance(value, str):
                description = value
                break

    return {"cvss_v3": cvss_v3, "cwe": cwe, "description": description}


def get_nvd_data(cve_id: str) -> Optional[dict[str, Any]]:
    """Return {cvss_v3, cwe, description} for a CVE from NVD, or None.

    Results are cached per-CVE for 7 days. Honors NVD_API_KEY env var for the
    higher rate limit; without a key, the caller is responsible for spacing
    (this function sleeps the appropriate interval before each live request).
    """
    if not cve_id:
        return None
    cve = _normalize_cve(cve_id)
    cache_path = _nvd_cache_path(cve)

    cache = _read_cache(cache_path)
    if _cache_fresh(cache, _NVD_TTL_SECONDS) and cache:
        return cache.get("data")

    api_key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else None
    time.sleep(_NVD_SLEEP_WITH_KEY if api_key else _NVD_SLEEP_NO_KEY)

    query = urllib.parse.urlencode({"cveId": cve})
    url = f"{_NVD_URL}?{query}"
    payload = _http_get_json(url, headers=headers)

    if payload is None or not isinstance(payload, dict):
        # Fall back to stale cache if present.
        if cache and cache.get("data"):
            return cache.get("data")
        return None

    data = _parse_nvd_payload(payload)
    # Cache even a None result to avoid hammering NVD for unknown CVEs.
    _write_cache(cache_path, {"fetched_at": _now_ts(), "data": data})
    return data


# ---------------------------------------------------------------------------
# 5. CVE extraction helper
# ---------------------------------------------------------------------------


def extract_cve_ids(findings: list[dict]) -> list[str]:
    """Extract distinct CVE IDs referenced by a list of findings.

    Scans common nuclei / hexstrike fields where CVE ids appear: name,
    template-id / template_id, ref / reference / references, classification
    blocks (cve-id), tags, and matched-at. Returns a de-duplicated,
    uppercased list preserving first-seen order.
    """
    seen: dict[str, None] = {}

    def _scan(value: Any) -> None:
        if isinstance(value, str):
            for match in _CVE_RE.findall(value):
                seen.setdefault(_normalize_cve(match), None)
        elif isinstance(value, list):
            for item in value:
                _scan(item)
        elif isinstance(value, dict):
            for item in value.values():
                _scan(item)

    candidate_fields = (
        "name",
        "template-id",
        "template_id",
        "templateID",
        "ref",
        "reference",
        "references",
        "tags",
        "matched-at",
        "matched_at",
        "info",
        "classification",
        "cve",
        "cve-id",
        "cve_id",
        "description",
    )

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        for field in candidate_fields:
            if field in finding:
                _scan(finding[field])

    return list(seen.keys())


# ---------------------------------------------------------------------------
# 4. Top-level enrichment function
# ---------------------------------------------------------------------------


def _finding_cves(finding: dict) -> list[str]:
    """Return the CVE ids referenced by a single finding."""
    return extract_cve_ids([finding])


def enrich_findings(findings: list[dict]) -> list[dict]:
    """Enrich a list of findings in-place with KEV, EPSS, CVSS, CWE data.

    Adds an ``enrichment`` dict to each finding:
      - kev:       bool
      - epss:      float | None
      - cvss_v3:   float | None
      - cwe:       str | None
      - force_p0:  bool  (True if kev is True OR epss > 0.7)

    For findings referencing multiple CVEs, the strongest signal wins:
    kev = any CVE is KEV; epss = max EPSS; cvss_v3 = max CVSS; cwe = first found.

    Every source is best-effort: network failure for one source still allows
    the others to populate. Findings with no CVE reference get an enrichment
    block of all-None / False values so downstream consumers can rely on the
    key always being present.
    """
    if not findings:
        return findings

    # --- Phase 1: collect all CVEs across all findings ---
    all_cves = extract_cve_ids(findings)
    _log(f"{len(all_cves)} unique CVEs across {len(findings)} findings")

    if not all_cves:
        for finding in findings:
            if isinstance(finding, dict):
                finding["enrichment"] = {
                    "kev": False,
                    "epss": None,
                    "cvss_v3": None,
                    "cwe": None,
                    "force_p0": False,
                }
        return findings

    # --- Phase 2: warm the shared caches in bulk ---
    _load_kev_set()  # one fetch for the whole catalog
    epss_scores = fetch_epss_batch(all_cves)  # one batched fetch

    # NVD is per-CVE and rate-limited; build a lookup once so each CVE is
    # fetched at most once even if many findings reference it.
    nvd_lookup: dict[str, Optional[dict[str, Any]]] = {}
    if all_cves:
        _log(f"Fetching NVD data for {len(all_cves)} CVEs...")
        for cve in all_cves:
            nvd_lookup[cve] = get_nvd_data(cve)

    # --- Phase 3: stamp each finding ---
    enriched_count = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue

        cves = _finding_cves(finding)
        kev = False
        epss: Optional[float] = None
        cvss_v3: Optional[float] = None
        cwe: Optional[str] = None

        for cve in cves:
            if cve in _load_kev_set():
                kev = True

            score = epss_scores.get(cve)
            if score is not None:
                epss = score if epss is None else max(epss, score)

            nvd = nvd_lookup.get(cve)
            if isinstance(nvd, dict):
                base = nvd.get("cvss_v3")
                if isinstance(base, (int, float)):
                    cvss_v3 = float(base) if cvss_v3 is None else max(cvss_v3, float(base))
                if cwe is None and isinstance(nvd.get("cwe"), str):
                    cwe = nvd["cwe"]

        force_p0 = bool(kev or (epss is not None and epss > _EPSS_FORCE_P0))

        finding["enrichment"] = {
            "kev": kev,
            "epss": epss,
            "cvss_v3": cvss_v3,
            "cwe": cwe,
            "force_p0": force_p0,
        }
        if cves:
            enriched_count += 1

    _log(f"{enriched_count} CVEs enriched")
    return findings


# ---------------------------------------------------------------------------
# CLI entrypoint (manual testing)
# ---------------------------------------------------------------------------


def _main(argv: list[str]) -> int:
    """Read findings JSON from a file path or stdin, print enriched JSON."""
    if len(argv) > 1 and argv[1] not in ("-", "/dev/stdin"):
        try:
            with open(argv[1], "r", encoding="utf-8") as fh:
                findings = json.load(fh)
        except (OSError, ValueError) as exc:
            _log(f"failed to read findings from {argv[1]}: {exc}")
            return 1
    else:
        try:
            findings = json.load(sys.stdin)
        except ValueError as exc:
            _log(f"failed to parse stdin JSON: {exc}")
            return 1

    if not isinstance(findings, list):
        _log("input must be a JSON array of findings")
        return 1

    enriched = enrich_findings(findings)
    json.dump(enriched, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
