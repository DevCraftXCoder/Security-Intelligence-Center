"""
ai_grade.py — Flask Blueprint for AI-powered finding grading via Anthropic.

Routes:
    POST /api/ai/grade  — grade a security finding; returns remediation guidance

Cache: SQLite table ai_grade_cache, keyed by sha256(title+description)[:16], 7-day TTL.
Uses OPENROUTER_API_KEY (preferred) or ANTHROPIC_API_KEY. Returns 503 if neither is set.

Public helpers:
    ai_grade_init_db()  — idempotent schema creation; call from app startup
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Blueprint, jsonify, request

ai_grade_bp = Blueprint("sic_ai_grade", __name__, url_prefix="/api/ai")

_DB_PATH = Path.home() / ".sic" / "state.db"
_db_init_done: bool = False
_CACHE_TTL_DAYS = 7

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _db_path() -> Path:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return _DB_PATH


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_db_path()))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def ai_grade_init_db() -> None:
    """Create ai_grade_cache table if absent. Idempotent."""
    global _db_init_done
    if _db_init_done:
        return
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_grade_cache (
                cache_key   TEXT PRIMARY KEY,
                result_json TEXT NOT NULL,
                cached_at   TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ai_grade_cached_at ON ai_grade_cache(cached_at)"
        )
        conn.commit()
    _db_init_done = True


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


def _cache_key(title: str, description: str) -> str:
    """Return a 16-char sha256 hex prefix keyed on title+description."""
    digest = hashlib.sha256((title + description).encode()).hexdigest()
    return digest[:16]


def _cache_get(key: str) -> dict | None:
    """Return cached result dict if present and not expired, else None."""
    ai_grade_init_db()
    cutoff = (datetime.now(tz=timezone.utc) - timedelta(days=_CACHE_TTL_DAYS)).isoformat()
    with _connect() as conn:
        row = conn.execute(
            "SELECT result_json, cached_at FROM ai_grade_cache WHERE cache_key = ? AND cached_at >= ?",
            (key, cutoff),
        ).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["result_json"])
    except Exception:  # noqa: BLE001
        return None


def _cache_set(key: str, result: dict) -> None:
    """Upsert a grading result into the cache."""
    ai_grade_init_db()
    now = datetime.now(tz=timezone.utc).isoformat()
    payload = json.dumps(result)
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO ai_grade_cache (cache_key, result_json, cached_at)
            VALUES (?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET result_json=excluded.result_json, cached_at=excluded.cached_at
            """,
            (key, payload, now),
        )
        conn.commit()


def _evict_expired_cache() -> None:
    """Remove cache rows older than TTL. Best-effort — never raises."""
    try:
        cutoff = (datetime.now(tz=timezone.utc) - timedelta(days=_CACHE_TTL_DAYS)).isoformat()
        with _connect() as conn:
            conn.execute("DELETE FROM ai_grade_cache WHERE cached_at < ?", (cutoff,))
            conn.commit()
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Anthropic call
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a senior application security engineer. Given a security finding, return a JSON object \
(and nothing else) with these exact keys:
{
  "remediation": "<2-3 sentence fix guidance>",
  "confidence": <float 0.0-1.0, how confident you are in the assessment>,
  "false_positive_risk": "<low|medium|high>",
  "one_line_fix": "<single actionable command or code snippet>",
  "severity": "<critical|high|medium|low|info>"
}
Do not include markdown fences or any text outside the JSON object.\
"""


def _resolve_api_key() -> tuple[str, str]:
    """Return (api_key, provider) — prefers OpenRouter, falls back to Anthropic direct.

    Raises RuntimeError if neither key is set.
    """
    key = os.environ.get("OPENROUTER_API_KEY")
    if key:
        return key, "openrouter"
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key, "anthropic"
    raise RuntimeError("No AI API key configured — set OPENROUTER_API_KEY or ANTHROPIC_API_KEY")


def _call_openrouter(api_key: str, title: str, description: str, category: str, severity: str | None) -> dict:
    """Call OpenRouter chat completions endpoint. Raises on failure."""
    import requests as _requests  # noqa: PLC0415

    user_content = (
        f"Category: {category}\n"
        f"Title: {title}\n"
        f"Description: {description or '(none provided)'}\n"
    )
    if severity:
        user_content += f"Reported severity: {severity}\n"

    # LLM-specific remediation context
    if category.lower().startswith("llm") or (title or "").lower().startswith("llm"):
        user_content += (
            "\nContext: This is an LLM/AI security finding. Remediation should reference "
            "OWASP LLM Top 10 2025 controls, input/output guardrails, system prompt "
            "isolation, rate limiting per token budget, and output sanitization "
            "before downstream sink injection."
        )

    payload = {
        "model": "anthropic/claude-haiku-4-5",
        "max_tokens": 512,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
    }
    resp = _requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/DevCraftXCoder/SIC",
            "X-Title": "SIC Security Intelligence Center",
        },
        json=payload,
        timeout=30,
    )
    resp.raise_for_status()
    raw_text = resp.json()["choices"][0]["message"]["content"].strip()
    if raw_text.startswith("```"):
        lines = raw_text.splitlines()
        raw_text = "\n".join(line for line in lines if not line.startswith("```")).strip()
    return json.loads(raw_text)


def _call_anthropic_direct(api_key: str, title: str, description: str, category: str, severity: str | None) -> dict:
    """Call Anthropic API directly. Raises on failure."""
    import anthropic  # noqa: PLC0415

    client = anthropic.Anthropic(api_key=api_key)
    user_content = (
        f"Category: {category}\n"
        f"Title: {title}\n"
        f"Description: {description or '(none provided)'}\n"
    )
    if severity:
        user_content += f"Reported severity: {severity}\n"

    # LLM-specific remediation context
    if category.lower().startswith("llm") or (title or "").lower().startswith("llm"):
        user_content += (
            "\nContext: This is an LLM/AI security finding. Remediation should reference "
            "OWASP LLM Top 10 2025 controls, input/output guardrails, system prompt "
            "isolation, rate limiting per token budget, and output sanitization "
            "before downstream sink injection."
        )

    message = client.messages.create(
        model="claude-haiku-4-5-20251022",
        max_tokens=512,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    )
    raw_text = message.content[0].text.strip()
    if raw_text.startswith("```"):
        lines = raw_text.splitlines()
        raw_text = "\n".join(line for line in lines if not line.startswith("```")).strip()
    return json.loads(raw_text)


def _call_ai(title: str, description: str, category: str, severity: str | None) -> dict:
    """Route to OpenRouter or Anthropic direct depending on which key is set. Raises on failure."""
    api_key, provider = _resolve_api_key()
    if provider == "openrouter":
        result = _call_openrouter(api_key, title, description, category, severity)
    else:
        result = _call_anthropic_direct(api_key, title, description, category, severity)

    # Validate required keys; fill defaults for any missing
    result.setdefault("remediation", "No remediation provided.")
    result.setdefault("confidence", 0.5)
    result.setdefault("false_positive_risk", "medium")
    result.setdefault("one_line_fix", "")
    result.setdefault("severity", severity or "medium")

    # Clamp confidence to [0, 1]
    try:
        result["confidence"] = max(0.0, min(1.0, float(result["confidence"])))
    except (TypeError, ValueError):
        result["confidence"] = 0.5

    return result


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


def _grade_one(title: str, description: str, category: str, severity: str | None) -> dict:
    """Grade a single finding with caching. Returns the result dict (no Flask wrapping)."""
    title = (title or "").strip()
    description = (description or "").strip()
    category = (category or "uncategorized").strip()
    key = _cache_key(title, description)
    cached = _cache_get(key)
    if cached is not None:
        return {"cached": True, **cached}
    result = _call_ai(title, description, category, severity)
    _cache_set(key, result)
    return {"cached": False, **result}


_LETTER_GRADES = ["A", "B", "C", "D", "F"]


def _scan_letter_grade(findings: list) -> str:
    """Derive an overall letter grade from finding severities."""
    weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    if not findings:
        return "A"
    score = 0
    for f in findings:
        sev = ""
        if isinstance(f, dict):
            sev = str(f.get("severity", "")).lower()
        score += weights.get(sev, 1)
    if score == 0:
        return "A"
    if score <= 2:
        return "B"
    if score <= 5:
        return "C"
    if score <= 10:
        return "D"
    return "F"


def _grade_scan(scan_id: str) -> tuple[dict, int]:
    """Grade an entire scan's findings. Returns (response_dict, http_status)."""
    try:
        from scan_history import get_scan  # noqa: PLC0415
    except ImportError:
        return {"error": "scan_lookup_unavailable"}, 500

    scan = get_scan(scan_id)
    if scan is None:
        return {"error": "scan_not_found", "scan_id": scan_id}, 404

    findings = scan.get("findings") or []
    remediations: list[dict] = []
    # Grade up to 10 findings to bound AI cost/latency
    for f in findings[:10]:
        if not isinstance(f, dict):
            f = {"title": str(f)}
        f_title = f.get("title") or f.get("name") or f.get("id") or "Unnamed finding"
        f_desc = f.get("description") or f.get("detail") or ""
        f_cat = f.get("category") or f.get("type") or "security"
        f_sev = f.get("severity")
        try:
            graded = _grade_one(str(f_title), str(f_desc), str(f_cat), f_sev)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ai_grade: failed to grade finding %r: %s", f_title, exc)
            continue
        remediations.append({
            "title": str(f_title),
            "severity": graded.get("severity") or f_sev or "medium",
            "fix": graded.get("one_line_fix") or graded.get("remediation") or "",
            "description": graded.get("remediation") or "",
        })

    grade = _scan_letter_grade(findings)
    summary = f"Scan graded {grade} — {len(findings)} finding(s) analyzed."
    return {
        "scan_id": scan_id,
        "grade": grade,
        "summary": summary,
        "findings_count": len(findings),
        "remediations": remediations,
    }, 200


@ai_grade_bp.post("/grade")
def grade_finding_route():
    """POST /api/ai/grade — AI-grade a security finding or an entire scan.

    Two request contracts are supported:
      - Scan-level: {"scan_id": "..."} → {grade, summary, findings_count, remediations[]}
      - Finding-level: {"title","category","severity?","description?"} → remediation guidance.
    """
    if not os.environ.get("OPENROUTER_API_KEY") and not os.environ.get("ANTHROPIC_API_KEY"):
        return jsonify({"error": "AI_UNAVAILABLE", "message": "Set OPENROUTER_API_KEY or ANTHROPIC_API_KEY"}), 503

    body = request.get_json(silent=True) or {}

    # Scan-level grading path
    scan_id = body.get("scan_id")
    if scan_id and isinstance(scan_id, str) and scan_id.strip():
        try:
            resp, status = _grade_scan(scan_id.strip())
        except ImportError:
            return jsonify({"error": "AI_UNAVAILABLE", "message": "anthropic SDK not installed"}), 503
        except RuntimeError as exc:
            return jsonify({"error": "AI_UNAVAILABLE", "message": str(exc)}), 503
        except Exception as exc:  # noqa: BLE001
            logger.error("ai_grade: scan grade failed: %s", exc)
            return jsonify({"error": "AI_ERROR", "message": "Scan grading failed"}), 502
        _evict_expired_cache()
        return jsonify(resp), status

    # Finding-level grading path
    title = body.get("title")
    description = body.get("description", "")
    category = body.get("category")
    severity = body.get("severity")
    finding_id = body.get("finding_id")

    if not title or not isinstance(title, str) or not title.strip():
        return jsonify({"error": "title_required"}), 400
    if not category or not isinstance(category, str) or not category.strip():
        return jsonify({"error": "category_required"}), 400

    title = title.strip()
    description = (description or "").strip()
    category = category.strip()

    key = _cache_key(title, description)

    # Try cache first
    cached = _cache_get(key)
    if cached is not None:
        logger.debug("ai_grade cache hit: key=%s finding_id=%s", key, finding_id)
        return jsonify({"cached": True, "finding_id": finding_id, **cached})

    # Call API
    try:
        result = _call_ai(title, description, category, severity)
    except ImportError:
        return jsonify({"error": "AI_UNAVAILABLE", "message": "anthropic SDK not installed"}), 503
    except RuntimeError as exc:
        return jsonify({"error": "AI_UNAVAILABLE", "message": str(exc)}), 503
    except json.JSONDecodeError as exc:
        logger.error("ai_grade: failed to parse model response: %s", exc)
        return jsonify({"error": "AI_PARSE_ERROR", "message": "Model returned non-JSON output"}), 502
    except Exception as exc:  # noqa: BLE001
        logger.error("ai_grade: unexpected error: %s", exc)
        return jsonify({"error": "AI_ERROR", "message": "Upstream AI call failed"}), 502

    _cache_set(key, result)
    _evict_expired_cache()

    logger.info("ai_grade: graded finding title=%r category=%s", title, category)
    return jsonify({"cached": False, "finding_id": finding_id, **result})
