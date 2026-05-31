"""billing/routes.py — Flask Blueprint for Stripe billing.

Routes:
    POST /api/billing/checkout      — create Stripe Checkout session
    POST /api/billing/webhook       — Stripe webhook handler (signature verified)
    GET  /api/billing/subscription  — current user's subscription info
    POST /api/billing/portal        — create Stripe Customer Portal session
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import threading

import requests as _requests

from flask import Blueprint, jsonify, redirect, request

from auth import get_session_email, require_auth

from .db import (
    event_already_processed,
    get_subscription,
    init_db,
    record_event,
    upsert_subscription,
)
from .stripe_client import (
    construct_webhook_event,
    create_checkout_session,
    create_portal_session,
    get_price_id,  # noqa: F401 — exported for tests / admin tooling
)

billing_bp = Blueprint("sic_billing", __name__, url_prefix="/api/billing")

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Email validation
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

# ---------------------------------------------------------------------------
# Tier metadata
# ---------------------------------------------------------------------------

_VALID_PAID_TIERS = frozenset({"team", "studio"})


def _secrets_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(
        hashlib.sha256(a.encode()).digest(),
        hashlib.sha256(b.encode()).digest(),
    )
_ALL_VALID_TIERS = frozenset({"community", "team", "studio"})

# Stripe subscription statuses that map to an active paid subscription.
_ACTIVE_STATUSES = frozenset({"active", "trialing"})

# Canonical mapping from Stripe metadata tier label → DB tier value.
_TIER_LABEL_MAP: dict[str, str] = {
    "team": "team",
    "studio": "studio",
    "community": "community",
}


# ---------------------------------------------------------------------------
# Discord billing alert (P1-2)
# ---------------------------------------------------------------------------


def _discord_billing_alert(msg: str) -> None:
    """Fire a non-blocking Discord notification for billing failures.

    Uses DISCORD_WEBHOOK_URL env var (shared with scan_alerts.py).
    Silently no-ops when the env var is unset.
    """
    url = os.environ.get("DISCORD_WEBHOOK_URL")
    if not url:
        return

    def _post() -> None:
        try:
            _requests.post(
                url,
                json={"content": msg},
                timeout=4,
            )
        except Exception:  # noqa: BLE001
            logger.debug("discord billing alert failed (non-critical)")

    threading.Thread(target=_post, daemon=True).start()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _base_url() -> str:
    """Best-effort base URL for redirect construction."""
    host = request.host_url.rstrip("/")
    return host


def _email_from_event(event) -> str | None:
    """Extract the sic_email from a Stripe event object.

    Looks in session/subscription metadata, then falls back to
    customer_email (checkout.session) or customer details.
    """
    obj = event.get("data", {}).get("object", {})
    meta = obj.get("metadata") or {}
    email = meta.get("sic_email")
    if email:
        return email.strip().lower()

    # checkout.session carries customer_email
    if event.get("type") == "checkout.session.completed":
        email = obj.get("customer_email") or obj.get("customer_details", {}).get(
            "email"
        )
        if email:
            return email.strip().lower()

    return None


def _tier_from_status_and_meta(sub_obj) -> str:
    """Derive a DB tier from a Stripe Subscription object."""
    meta = sub_obj.get("metadata") or {}
    label = meta.get("sic_tier", "community").lower()
    tier = _TIER_LABEL_MAP.get(label, "community")
    status = sub_obj.get("status", "")
    # Downgrade to community if subscription is not active/trialing
    if status not in _ACTIVE_STATUSES:
        return "community"
    return tier


# ---------------------------------------------------------------------------
# Route: POST /api/billing/checkout
# ---------------------------------------------------------------------------


@billing_bp.post("/checkout")
@require_auth
def checkout():
    """Create a Stripe Checkout session for a paid tier upgrade.

    Body JSON:
        {"tier": "team" | "studio"}

    Returns:
        200  {"checkout_url": "https://checkout.stripe.com/..."}
        400  {"error": "invalid_tier"}
        402  {"error": "billing_unavailable", "detail": "..."}
        500  {"error": "internal_error"}
    """
    init_db()
    body = request.get_json(silent=True) or {}
    tier = body.get("tier")

    if tier not in _VALID_PAID_TIERS:
        return (
            jsonify(
                {
                    "error": "invalid_tier",
                    "detail": f"tier must be one of: {sorted(_VALID_PAID_TIERS)}",
                }
            ),
            400,
        )

    email = get_session_email()
    if not email:
        return jsonify({"error": "unauthorized"}), 401

    sub = get_subscription(email)
    customer_id: str | None = sub["stripe_customer_id"] if sub else None

    base = _base_url()
    success_url = f"{base}/dashboard/?billing=success"
    cancel_url = f"{base}/dashboard/?billing=cancelled"

    try:
        session = create_checkout_session(
            email=email,
            tier=tier,
            success_url=success_url,
            cancel_url=cancel_url,
            customer_id=customer_id,
        )
        return jsonify({"checkout_url": session.url}), 200
    except EnvironmentError as exc:
        logger.error("billing env misconfigured: %s", exc)
        return jsonify({"error": "billing_unavailable"}), 402
    except Exception as exc:
        logger.error("Unhandled billing error: %s", exc, exc_info=True)
        return jsonify({"error": "internal_error"}), 500


# ---------------------------------------------------------------------------
# Route: GET /api/billing/subscription
# ---------------------------------------------------------------------------


@billing_bp.get("/subscription")
@require_auth
def subscription():
    """Return the current user's subscription details.

    Returns:
        200  {
               "email": "...",
               "tier": "community" | "team" | "studio",
               "status": "active" | "canceled" | null,
               "current_period_end": <unix timestamp> | null
             }
    """
    init_db()
    email = get_session_email()
    if not email:
        return jsonify({"error": "unauthorized"}), 401

    sub = get_subscription(email)
    if sub is None:
        return (
            jsonify(
                {
                    "email": email,
                    "tier": "community",
                    "status": None,
                    "current_period_end": None,
                }
            ),
            200,
        )

    return (
        jsonify(
            {
                "email": email,
                "tier": sub["tier"],
                "status": sub["status"],
                "current_period_end": sub["current_period_end"],
            }
        ),
        200,
    )


# ---------------------------------------------------------------------------
# Route: POST /api/billing/portal
# ---------------------------------------------------------------------------


@billing_bp.post("/portal")
@require_auth
def portal():
    """Create a Stripe Customer Portal session for self-service billing management.

    Returns:
        200  {"portal_url": "https://billing.stripe.com/..."}
        400  {"error": "no_stripe_customer"}
        402  {"error": "billing_unavailable", "detail": "..."}
        500  {"error": "internal_error"}
    """
    init_db()
    email = get_session_email()
    if not email:
        return jsonify({"error": "unauthorized"}), 401

    sub = get_subscription(email)
    if not sub or not sub["stripe_customer_id"]:
        return (
            jsonify(
                {
                    "error": "no_stripe_customer",
                    "detail": "No Stripe customer on record for this account.",
                }
            ),
            400,
        )

    return_url = f"{_base_url()}/dashboard/?billing=portal"

    try:
        portal_session = create_portal_session(
            customer_id=sub["stripe_customer_id"],
            return_url=return_url,
        )
        return jsonify({"portal_url": portal_session.url}), 200
    except EnvironmentError as exc:
        logger.error("billing env misconfigured for portal: %s", exc)
        return jsonify({"error": "billing_unavailable"}), 402
    except Exception as exc:
        logger.error("Unhandled billing error: %s", exc, exc_info=True)
        return jsonify({"error": "internal_error"}), 500


# ---------------------------------------------------------------------------
# Route: POST /api/billing/webhook
# ---------------------------------------------------------------------------


@billing_bp.post("/webhook")
def webhook():
    """Stripe webhook handler.

    Verifies the Stripe-Signature header via STRIPE_WEBHOOK_SECRET.
    Processes these event types idempotently:
        checkout.session.completed      — provision tier after successful payment
        customer.subscription.updated   — sync tier / status changes
        customer.subscription.deleted   — downgrade to community
        invoice.payment_failed          — mark subscription status as past_due

    Returns 200 immediately for unknown/already-processed events (Stripe expects 2xx).
    Returns 400 on signature failure or malformed payload.
    """
    init_db()

    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", "")

    if not sig_header:
        logger.warning("webhook received without Stripe-Signature header")
        return jsonify({"error": "missing_signature"}), 400

    # --- Signature verification (non-negotiable) ---
    try:
        event = construct_webhook_event(payload, sig_header)
    except EnvironmentError as exc:
        logger.error("webhook secret env not configured: %s", exc)
        return jsonify({"error": "webhook_secret_not_configured"}), 400
    except Exception as exc:
        # Covers stripe.error.SignatureVerificationError and JSON decode failures
        logger.warning("webhook signature verification failed: %s", exc)
        return jsonify({"error": "invalid_signature"}), 400

    event_id: str = event.get("id", "")
    event_type: str = event.get("type", "")

    # --- Idempotency check ---
    if event_already_processed(event_id):
        logger.debug("webhook event %s already processed — skipping", event_id)
        return jsonify({"ok": True, "skipped": True}), 200

    logger.info("processing webhook event %s type=%s", event_id, event_type)

    email = _email_from_event(event)
    payload_str = json.dumps(dict(event), default=str)

    try:
        if event_type == "checkout.session.completed":
            _handle_checkout_completed(event, email)

        elif event_type == "customer.subscription.updated":
            _handle_subscription_updated(event, email)

        elif event_type == "customer.subscription.deleted":
            _handle_subscription_deleted(event, email)

        elif event_type == "invoice.paid":
            _handle_invoice_paid(event, email)

        elif event_type == "invoice.payment_failed":
            _handle_payment_failed(event, email)

        else:
            logger.debug("unhandled webhook event type: %s", event_type)

        # Record for idempotency after successful processing
        record_event(
            event_id=event_id,
            event_type=event_type,
            email=email,
            payload=payload_str,
        )

    except Exception:
        logger.exception(
            "error processing webhook event %s type=%s", event_id, event_type
        )
        # Return 500 so Stripe retries — do NOT record the event_id
        return jsonify({"error": "processing_failed"}), 500

    return jsonify({"ok": True}), 200


# ---------------------------------------------------------------------------
# Webhook event handlers (called from webhook() only)
# ---------------------------------------------------------------------------


def _send_provisioning_email(email: str, session_obj: dict) -> None:  # noqa: ARG001
    """Generate a magic link and email it to the customer after successful checkout."""
    import json as _json  # noqa: PLC0415
    import sqlite3 as _sqlite3  # noqa: PLC0415
    import time as _time  # noqa: PLC0415
    import urllib.request as _ur  # noqa: PLC0415

    try:
        from auth import _init_db, _iso, _make_token  # noqa: PLC0415

        _init_db()
        now = int(_time.time())
        expires = now + 900  # 15 minutes
        token = _make_token(email, now, expires)

        import hashlib as _hashlib  # noqa: PLC0415

        token_hash = _hashlib.sha256(token.encode()).hexdigest()

        from pathlib import Path as _Path  # noqa: PLC0415

        _db_path = _Path.home() / ".sic" / "state.db"
        with _sqlite3.connect(str(_db_path)) as _con:
            _con.execute(
                "INSERT OR IGNORE INTO auth_tokens "
                "(token_hash, email, issued_at, expires_at, used_at) "
                "VALUES (?, ?, ?, ?, NULL)",
                (token_hash, email, _iso(now), _iso(expires)),
            )
            _con.commit()

        _resend_key = os.environ.get("RESEND_API_KEY", "")
        _from = os.environ.get("SIC_ALERT_FROM", "")
        _base = os.environ.get("SIC_BASE_URL", "http://localhost:9888")
        _link = f"{_base}/auth/verify?token={token}"

        if _resend_key and _from:
            _payload = _json.dumps({
                "from": _from,
                "to": [email],
                "subject": "Welcome to SIC — your access link",
                "html": (
                    '<div style="font-family:DM Sans,sans-serif;background:#0a0a0a;color:#fff;'
                    'padding:40px;max-width:480px;margin:auto;border-radius:8px;">'
                    '<h2 style="color:#e94560;margin-top:0;">Welcome to SIC</h2>'
                    '<p style="color:#ccc;">Your subscription is active. '
                    "Click below to access your dashboard.</p>"
                    f'<a href="{_link}" style="display:inline-block;background:#e94560;color:#fff;'
                    'padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:600;'
                    'margin:16px 0;">Open SIC Dashboard</a>'
                    '<p style="color:#666;font-size:12px;margin-top:24px;">'
                    "This link expires in 15 minutes.</p>"
                    "</div>"
                ),
            }).encode()
            _req = _ur.Request(
                "https://api.resend.com/emails",
                data=_payload,
                headers={
                    "Authorization": f"Bearer {_resend_key}",
                    "Content-Type": "application/json",
                },
            )
            _ur.urlopen(_req, timeout=5)
            logger.info("provisioning email sent to %.6s*** via Resend", email[:6])
        else:
            logger.warning(
                "provisioning email not sent — RESEND_API_KEY or SIC_ALERT_FROM not set "
                "for email %.6s***",
                email[:6],
            )
    except Exception as _e:
        logger.warning("auto-provision email failed for %.6s***: %s", email[:6], _e)


def _handle_checkout_completed(event, email: str | None) -> None:
    """Provision or upgrade the subscription after a successful checkout."""
    obj = event["data"]["object"]

    if not email:
        logger.warning(
            "checkout.session.completed — no email extractable from event %s",
            event.get("id"),
        )
        return

    customer_id: str | None = obj.get("customer")
    subscription_id: str | None = obj.get("subscription")

    # Bug 3: Validate sic_tier metadata before provisioning.
    # Missing or unrecognised tier is suspicious (could indicate a tampered/malformed
    # session) — do not silently provision community access for a paid checkout.
    meta = obj.get("metadata") or {}
    sic_tier = meta.get("sic_tier")
    if not sic_tier or sic_tier not in ("community", "team", "studio"):
        print(
            f"[billing WARNING] checkout.session.completed missing valid sic_tier in "
            f"metadata. Session ID: {obj.get('id')}. Not provisioning."
        )
        logger.warning(
            "checkout.session.completed: sic_tier metadata missing or invalid "
            "(got %r) for session %s — not provisioning",
            sic_tier,
            obj.get("id", "unknown"),
        )
        _discord_billing_alert(
            f"**Billing alert — invalid sic_tier** `{sic_tier!r}` "
            f"in checkout session `{obj.get('id', '?')}`. Not provisioned."
        )
        return

    tier = _TIER_LABEL_MAP.get(sic_tier.lower(), "community")

    # Bug 2: Check payment_status — ACH/SEPA payments are async and won't be
    # marked "paid" immediately. Treat those as "pending" rather than "active".
    payment_status = obj.get("payment_status", "unpaid")
    subscription_status = "active" if payment_status == "paid" else "pending"

    # Bug 7: Fetch current_period_end directly from the Stripe Subscription object
    # so it is populated immediately (not waiting for subscription.updated event).
    current_period_end: int | None = None
    if subscription_id:
        try:
            import stripe as _stripe  # noqa: PLC0415
            sub = _stripe.Subscription.retrieve(subscription_id)
            current_period_end = sub.get("current_period_end")
        except Exception as _e:  # noqa: BLE001
            logger.warning(
                "Could not retrieve subscription period_end for %s: %s",
                subscription_id,
                _e,
            )

    billing_interval = meta.get("interval", "month")
    if billing_interval not in ("month", "year"):
        billing_interval = "month"

    upsert_subscription(
        email=email,
        stripe_customer_id=customer_id,
        stripe_subscription_id=subscription_id,
        tier=tier,
        status=subscription_status,
        current_period_end=current_period_end,
        billing_interval=billing_interval,
    )
    logger.info(
        "provisioned tier=%s interval=%s status=%s for email=%.6s***",
        tier,
        billing_interval,
        subscription_status,
        email[:6],
    )

    # Auto-provision: send a magic link so the customer can log in immediately
    _send_provisioning_email(email, obj)


def _handle_subscription_updated(event, email: str | None) -> None:
    """Sync subscription tier and status after any update."""
    sub_obj = event["data"]["object"]

    if not email:
        logger.warning(
            "customer.subscription.updated — no email extractable from event %s",
            event.get("id"),
        )
        return

    tier = _tier_from_status_and_meta(sub_obj)
    status = sub_obj.get("status")
    current_period_end: int | None = sub_obj.get("current_period_end")
    customer_id: str | None = sub_obj.get("customer")
    subscription_id: str | None = sub_obj.get("id")

    upsert_subscription(
        email=email,
        stripe_customer_id=customer_id,
        stripe_subscription_id=subscription_id,
        tier=tier,
        status=status,
        current_period_end=current_period_end,
    )
    logger.info(
        "subscription updated tier=%s status=%s for email=%.6s***",
        tier,
        status,
        email[:6],
    )


def _handle_subscription_deleted(event, email: str | None) -> None:
    """Downgrade to community tier when a subscription is cancelled/deleted."""
    sub_obj = event["data"]["object"]

    if not email:
        logger.warning(
            "customer.subscription.deleted — no email extractable from event %s",
            event.get("id"),
        )
        return

    customer_id: str | None = sub_obj.get("customer")
    subscription_id: str | None = sub_obj.get("id")

    upsert_subscription(
        email=email,
        stripe_customer_id=customer_id,
        stripe_subscription_id=subscription_id,
        tier="community",
        status="canceled",
        current_period_end=None,
    )
    logger.info(
        "subscription deleted — downgraded to community for email=%.6s***",
        email[:6],
    )


def _handle_payment_failed(event, email: str | None) -> None:
    """Mark subscription as past_due on invoice payment failure."""
    obj = event["data"]["object"]
    subscription_id: str | None = obj.get("subscription")
    customer_id: str | None = obj.get("customer")

    if not email:
        logger.warning(
            "invoice.payment_failed — no email extractable from event %s",
            event.get("id"),
        )
        return

    # Preserve existing tier — only update status
    sub = get_subscription(email)
    current_tier = sub["tier"] if sub else "community"

    upsert_subscription(
        email=email,
        stripe_customer_id=customer_id,
        stripe_subscription_id=subscription_id,
        tier=current_tier,
        status="past_due",
        current_period_end=sub["current_period_end"] if sub else None,
    )
    logger.warning(
        "payment failed — marked past_due for email=%.6s***", email[:6]
    )

    # P1-2: Alert billing failures to Discord so the operator is notified.
    amount_due: int = obj.get("amount_due", 0)
    failure_msg: str = obj.get("last_payment_error", {}).get("message", "unknown") if obj.get("last_payment_error") else "unknown"
    _discord_billing_alert(
        f"**Payment failed** for customer `{customer_id}` "
        f"| amount: ${amount_due / 100:.2f} "
        f"| reason: {failure_msg} "
        f"| event: {event.get('id', '?')}"
    )


def _handle_invoice_paid(event, email: str | None) -> None:
    """Keep subscription active and sync period_end on each successful invoice payment."""
    invoice = event.get("data", {}).get("object", {})
    customer_id: str | None = invoice.get("customer")
    subscription_id: str | None = invoice.get("subscription")
    lines = invoice.get("lines", {}).get("data", [])
    period_end: int | None = lines[0].get("period", {}).get("end") if lines else None

    if not email:
        logger.warning(
            "invoice.paid — no email extractable from event %s",
            event.get("id"),
        )
        return

    # Preserve the existing tier — only refresh status and period_end
    sub = get_subscription(email)
    current_tier = sub["tier"] if sub else "community"

    upsert_subscription(
        email=email,
        stripe_customer_id=customer_id,
        stripe_subscription_id=subscription_id,
        tier=current_tier,
        status="active",
        current_period_end=period_end,
    )
    logger.info(
        "invoice.paid — subscription kept active, period_end=%s for email=%.6s***",
        period_end,
        email[:6],
    )


# ---------------------------------------------------------------------------
# Public (unauthenticated) checkout — for visitors on sic-signup.html
# ---------------------------------------------------------------------------


_BILLING_API_KEY = os.getenv("BILLING_API_KEY", "")


@billing_bp.post("/public-checkout")
def public_checkout():
    """Public (unauthenticated) checkout endpoint — called from the operator's frontend CF Worker.

    Body JSON:
        {"email": "user@example.com", "tier": "team" | "studio"}

    Rate limited by IP via before_request (no per-route limiter needed here).
    Requires X-Billing-Key header matching BILLING_API_KEY env var.

    Returns:
        200  {"checkout_url": "https://checkout.stripe.com/..."}
        400  {"error": "invalid_tier"} | {"error": "missing_email"}
        401  {"error": "unauthorized"}
        402  {"error": "billing_unavailable"}
        500  {"error": "internal_error"}
    """
    # Bug 4: Machine-to-machine auth — always require BILLING_API_KEY.
    # When the key is unset in production, the endpoint must refuse traffic rather
    # than silently accept all requests (previous behaviour when env var was empty).
    if not _BILLING_API_KEY:
        if os.environ.get("SIC_ENV", "development") == "production":
            return jsonify(
                {"error": "BILLING_API_KEY not configured — set it in .env"}
            ), 503
        # Development: allow but warn so operators notice the misconfiguration.
        print(
            "[billing WARNING] BILLING_API_KEY is not set — "
            "M2M auth is disabled (development mode only)"
        )
    else:
        provided_key = request.headers.get("X-Billing-Key", "")
        if not provided_key or not _secrets_equal(provided_key, _BILLING_API_KEY):
            return jsonify({"error": "unauthorized"}), 401

    init_db()
    body = request.get_json(silent=True) or {}
    tier = body.get("tier")
    email = (body.get("email") or "").strip().lower()
    interval = (body.get("interval") or "month").strip().lower()

    if not email or not _EMAIL_RE.match(email):
        return jsonify(
            {"error": "missing_email", "detail": "A valid email is required."}
        ), 400

    if tier not in _VALID_PAID_TIERS:
        return jsonify(
            {
                "error": "invalid_tier",
                "detail": f"tier must be one of: {sorted(_VALID_PAID_TIERS)}",
            }
        ), 400

    if interval not in ("month", "year"):
        return jsonify(
            {"error": "invalid_interval", "detail": "interval must be 'month' or 'year'"}
        ), 400

    # Check if this email already has an active subscription
    sub = get_subscription(email)
    customer_id: str | None = sub["stripe_customer_id"] if sub else None

    base = _base_url()
    success_url = f"{base}/api/billing/public-checkout-success?tier={tier}"
    cancel_url = f"{base}/sic-signup?billing=cancelled"

    try:
        session = create_checkout_session(
            email=email,
            tier=tier,
            success_url=success_url,
            cancel_url=cancel_url,
            customer_id=customer_id,
            interval=interval,
        )
        return jsonify({"checkout_url": session.url}), 200
    except EnvironmentError as exc:
        logger.error("billing env misconfigured: %s", exc)
        return jsonify({"error": "billing_unavailable"}), 402
    except Exception as exc:
        logger.error("Unhandled billing error: %s", exc, exc_info=True)
        return jsonify({"error": "internal_error"}), 500


@billing_bp.get("/public-checkout-success")
def public_checkout_success():
    """Redirect after Stripe checkout — return user to sic-signup with success state."""
    tier = request.args.get("tier", "community")
    # Validate against known tiers — prevent open redirect via unvalidated query param.
    if tier not in _ALL_VALID_TIERS:
        tier = "community"
    base = _base_url()
    return redirect(f"{base}/sic-signup?billing=success&tier={tier}")
