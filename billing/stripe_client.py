"""billing/stripe_client.py — thin wrapper around the Stripe Python SDK.

All Stripe API calls are centralised here so routes stay thin.

Environment variables consumed (never logged):
    STRIPE_SECRET_KEY       — Stripe API key (sk_live_... or sk_test_...)
    STRIPE_PRICE_TEAM       — price_... ID for the Team tier ($29/mo)
    STRIPE_PRICE_STUDIO     — price_... ID for the Studio tier ($99/mo)
    STRIPE_WEBHOOK_SECRET   — whsec_... value for webhook signature verification

The module imports stripe lazily so the server does not crash on startup
when the stripe package is not installed.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

# Tier → Stripe Price ID mapping
_TIER_PRICE_MAP: dict[str, str] = {
    "team": "STRIPE_PRICE_TEAM",
    "studio": "STRIPE_PRICE_STUDIO",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _stripe():
    """Return the stripe module, raising ImportError with a clear message if absent."""
    try:
        import stripe  # noqa: PLC0415

        return stripe
    except ImportError as exc:
        raise ImportError(
            "stripe package is required for billing. "
            "Install it with: pip install 'stripe>=8.0.0'"
        ) from exc


def _secret_key() -> str:
    key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not key:
        raise EnvironmentError(
            "STRIPE_SECRET_KEY is not set. "
            "Billing routes are unavailable until this env var is configured."
        )
    logger.debug("STRIPE_SECRET_KEY is set (%d chars)", len(key))
    return key


def _price_id(tier: str) -> str:
    env_var = _TIER_PRICE_MAP.get(tier)
    if env_var is None:
        raise ValueError(f"Unknown billing tier: {tier!r}")
    price_id = os.environ.get(env_var, "")
    if not price_id:
        raise EnvironmentError(
            f"{env_var} is not set — cannot create checkout session for tier {tier!r}."
        )
    logger.debug("%s is set (%d chars)", env_var, len(price_id))
    return price_id


def _webhook_secret() -> str:
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    if not secret:
        raise EnvironmentError(
            "STRIPE_WEBHOOK_SECRET is not set — webhook signature verification disabled."
        )
    logger.debug("STRIPE_WEBHOOK_SECRET is set (%d chars)", len(secret))
    return secret


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_checkout_session(
    *,
    email: str,
    tier: str,
    success_url: str,
    cancel_url: str,
    customer_id: str | None = None,
) -> object:
    """Create a Stripe Checkout session for *tier*.

    Returns the full Stripe Session object on success.
    Raises EnvironmentError / stripe.error.StripeError on failure.
    """
    stripe = _stripe()
    stripe.api_key = _secret_key()
    price_id = _price_id(tier)

    params: dict = {
        "mode": "subscription",
        "line_items": [{"price": price_id, "quantity": 1}],
        "customer_email": email if not customer_id else None,
        "customer": customer_id or None,
        "success_url": success_url,
        "cancel_url": cancel_url,
        "subscription_data": {"metadata": {"sic_email": email, "sic_tier": tier}},
        "metadata": {"sic_email": email, "sic_tier": tier},
    }
    # Strip None values — Stripe SDK raises on explicit None for some fields
    params = {k: v for k, v in params.items() if v is not None}

    logger.info(
        "creating Stripe checkout for email=%.6s*** tier=%s", email[:6], tier
    )
    return stripe.checkout.Session.create(**params)


def create_portal_session(
    *,
    customer_id: str,
    return_url: str,
) -> object:
    """Create a Stripe Customer Portal session for self-service billing.

    Returns the full Stripe BillingPortal.Session object.
    """
    stripe = _stripe()
    stripe.api_key = _secret_key()
    logger.info("creating Stripe portal session for customer %s", customer_id)
    return stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=return_url,
    )


def construct_webhook_event(payload: bytes, sig_header: str) -> object:
    """Verify and parse an incoming Stripe webhook payload.

    Raises stripe.error.SignatureVerificationError if signature is invalid.
    """
    stripe = _stripe()
    stripe.api_key = _secret_key()
    return stripe.Webhook.construct_event(payload, sig_header, _webhook_secret())


# retrieve_subscription was removed (dead code — zero callers confirmed by grep).
# If needed in future, use: stripe.Subscription.retrieve(subscription_id)
