"""
feature_gates.py — Tier-based feature gating for the SIC security platform.

Provides:
  - TIER_LIMITS — canonical per-tier feature limits
  - get_tier_limit(tier, feature) -> Any
  - tier_rank(tier) -> int
  - current_user_tier() -> str
  - feature_enabled(feature) -> bool
  - @require_tier(min_tier) — Flask route decorator (401/402 on failure)
"""
from __future__ import annotations

import functools
import logging
import sqlite3
import time
from typing import Any

from flask import jsonify

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canonical product spec — single source of truth
# ---------------------------------------------------------------------------

TIER_LIMITS: dict[str, dict[str, Any]] = {
    "community": {
        "scan_history_days": 7,
        "max_seats": 1,
        "pdf_export": False,
        "sso": False,
        "shareable_reports": False,
        "concurrent_scans": 1,
        "api_tokens": 1,
    },
    "team": {
        "scan_history_days": 90,
        "max_seats": 5,
        "pdf_export": True,
        "sso": False,
        "shareable_reports": True,
        "concurrent_scans": 5,
        "api_tokens": 10,
    },
    "studio": {
        "scan_history_days": -1,   # unlimited
        "max_seats": -1,            # unlimited
        "pdf_export": True,
        "sso": True,
        "shareable_reports": True,
        "concurrent_scans": -1,
        "api_tokens": -1,
    },
}

_VALID_TIERS = ("community", "team", "studio")

# ---------------------------------------------------------------------------
# Tier utilities
# ---------------------------------------------------------------------------


def tier_rank(tier: str) -> int:
    """Return numeric rank for comparison: community=0, team=1, studio=2.

    Unknown tiers default to 0 (most restrictive).
    """
    return {"community": 0, "team": 1, "studio": 2}.get(tier, 0)


def get_tier_limit(tier: str, feature: str) -> Any:
    """Return the limit value for *feature* under *tier*.

    Falls back to the community limit when *tier* is unrecognised, and to
    ``None`` when *feature* is unknown (safe for callers that do ``if
    get_tier_limit(...):``).
    """
    safe_tier = tier if tier in _VALID_TIERS else "community"
    return TIER_LIMITS[safe_tier].get(feature)


# ---------------------------------------------------------------------------
# Session helpers (lazy imports — billing / auth may not exist yet)
# ---------------------------------------------------------------------------


def _get_session_email() -> str | None:
    """Return the email for the current Flask request session, or None."""
    try:
        from auth import get_session_email  # noqa: PLC0415
    except ImportError:
        logger.debug("auth module not available — no session email")
        return None
    return get_session_email()


def _resolve_tier(email: str) -> str:
    """Look up billing tier for *email*, defaulting to 'community'."""
    try:
        from billing import get_user_tier  # noqa: PLC0415
    except ImportError:
        logger.debug("billing module not available — defaulting tier to community")
        return "community"
    for _attempt in range(3):
        try:
            tier = get_user_tier(email)
            if tier not in _VALID_TIERS:
                logger.warning("get_user_tier returned unknown tier %r for %s", tier, email)
                return "community"
            return tier
        except sqlite3.OperationalError as _e:
            if "database is locked" in str(_e) and _attempt < 2:
                time.sleep(0.05 * (2 ** _attempt))
                continue
            logger.exception("get_user_tier SQLite lock error — defaulting to community")
            return "community"
        except Exception:
            logger.exception("get_user_tier raised — defaulting to community")
            return "community"
    return "community"


def current_user_tier() -> str:
    """Return the subscription tier for the current request's authenticated user.

    Resolution order:
      1. Get email from auth.get_session_email()
      2. Pass to billing.get_user_tier(email)
      3. Any failure at either step → "community"
    """
    email = _get_session_email()
    if not email:
        return "community"
    return _resolve_tier(email)


def feature_enabled(feature: str) -> bool:
    """Return True if the current user's tier permits *feature*.

    Works for boolean features (pdf_export, sso, shareable_reports).
    For numeric limits use get_tier_limit() directly.
    """
    tier = current_user_tier()
    value = get_tier_limit(tier, feature)
    # Numeric -1 means unlimited → enabled
    if isinstance(value, int):
        return value != 0
    return bool(value)


# ---------------------------------------------------------------------------
# @require_tier decorator
# ---------------------------------------------------------------------------


def require_tier(min_tier: str):
    """Flask route decorator that enforces a minimum subscription tier.

    Usage::

        @app.get("/api/reports/<id>/pdf")
        @require_tier("team")
        def download_pdf(id):
            ...

    Responses:
      - 401 ``{"error": "auth_required"}`` — no authenticated session
      - 402 ``{"error": "tier_required", ...}`` — tier below minimum
      - passthrough — tier meets or exceeds minimum
    """
    if min_tier not in _VALID_TIERS:
        raise ValueError(f"require_tier: unknown tier {min_tier!r}; must be one of {_VALID_TIERS}")

    required_rank = tier_rank(min_tier)

    def decorator(f):  # type: ignore[no-untyped-def]
        @functools.wraps(f)
        def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
            email = _get_session_email()
            if not email:
                return jsonify({"error": "auth_required"}), 401

            user_tier = _resolve_tier(email)
            if tier_rank(user_tier) < required_rank:
                return (
                    jsonify(
                        {
                            "error": "tier_required",
                            "required_tier": min_tier,
                            "current_tier": user_tier,
                            "upgrade_url": "/api/billing/checkout",
                        }
                    ),
                    402,
                )

            return f(*args, **kwargs)

        return wrapper

    return decorator
