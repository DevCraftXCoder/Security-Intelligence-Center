"""billing — Stripe billing module for the SIC Flask security platform.

Public API:
    billing_bp           Flask Blueprint; register with app.register_blueprint(billing_bp)
    init_db()            Ensure billing DB tables exist (idempotent, safe to call early)
    get_user_tier(email) Return "community" | "team" | "studio" for an email address.
                         Never raises; defaults to "community" when DB is empty or
                         Stripe env vars are unset.

Usage (from other modules):
    from billing import get_user_tier
    tier = get_user_tier("user@example.com")  # -> "community" | "team" | "studio"
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Startup guard: STRIPE_WEBHOOK_SECRET must be set before billing is loaded.
# Raising here causes blueprint registration to fail visibly rather than
# allowing the server to run in a state where all webhooks are silently broken.
# ---------------------------------------------------------------------------
_webhook_secret_value = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
if not _webhook_secret_value:
    raise RuntimeError(
        "STRIPE_WEBHOOK_SECRET must be set before starting billing routes. "
        "Without it, webhook signature verification is impossible and all "
        "tier-upgrade events will be rejected.  Set the env var and restart."
    )
del _webhook_secret_value  # do not keep secret in module-level scope

# Re-export public names at package level
try:
    from .db import get_tier as _get_tier
    from .db import init_db
    from .routes import billing_bp

    def get_user_tier(email: str) -> str:
        """Return the billing tier for *email*.

        Safe to call without an active Flask request context.
        Defaults to 'community' when the DB is empty or unavailable.
        """
        try:
            return _get_tier(email.strip().lower())
        except Exception:
            logger.debug(
                "get_user_tier: DB lookup failed for %s; returning community",
                email[:6] + "***" if len(email) > 6 else "***",
            )
            return "community"

    __all__ = ["billing_bp", "init_db", "get_user_tier"]

except Exception as _import_err:  # noqa: BLE001
    # Non-fatal: allow server to start even when stripe/deps are missing.
    # Routes will return 402 at request time with a clear error.
    logger.warning("billing module failed to import fully: %s", _import_err)

    from flask import Blueprint as _Blueprint

    billing_bp = _Blueprint("sic_billing_stub", __name__, url_prefix="/api/billing")

    def init_db() -> None:  # type: ignore[misc]
        """No-op stub — billing DB init unavailable."""

    def get_user_tier(email: str) -> str:  # type: ignore[misc]
        """Stub — always returns 'community' when billing module failed to load."""
        return "community"

    __all__ = ["billing_bp", "init_db", "get_user_tier"]
