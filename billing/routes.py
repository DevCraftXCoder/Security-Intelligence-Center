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
import urllib.parse

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

    # charge.refunded / charge.dispute.created carry billing_details.email and a
    # customer id, but rarely the sic_email metadata.  Try billing_details first,
    # then resolve the local subscription row by stripe_customer_id.
    email = (obj.get("billing_details") or {}).get("email") or obj.get("receipt_email")
    if email:
        return email.strip().lower()

    customer_id = obj.get("customer")
    if customer_id:
        resolved = _email_by_customer_id(customer_id)
        if resolved:
            return resolved

    return None


def _email_by_customer_id(customer_id: str) -> str | None:
    """Resolve a local subscription email from a Stripe customer id.

    Used for events (charges/disputes) that carry a customer id but no
    sic_email metadata.  Returns the email of the subscriptions row whose
    stripe_customer_id matches, or None.
    """
    if not customer_id:
        return None
    try:
        from .db import _connect  # noqa: PLC0415

        with _connect() as conn:
            row = conn.execute(
                "SELECT email FROM subscriptions WHERE stripe_customer_id = ? LIMIT 1",
                (customer_id,),
            ).fetchone()
        return row["email"] if row else None
    except Exception:  # noqa: BLE001
        logger.debug("could not resolve email for customer %s", customer_id)
        return None


def _tier_from_price_id(price_id: str) -> str | None:
    """Map a Stripe Price ID back to a SIC tier using configured env price IDs.

    Returns "team" / "studio" if the price matches a configured price env var,
    else None.  This is authoritative for plan up/downgrades made via the
    Stripe Customer Portal, which do NOT update subscription metadata — so the
    sic_tier metadata is stale after a portal swap (B5).

    Checks both interval (month/year) env vars for each tier.  get_price_id
    raises EnvironmentError when an env var is unset; we treat that as "no
    match" rather than failing the whole resolution.
    """
    if not price_id:
        return None
    for tier in ("team", "studio"):
        for interval in ("month", "year"):
            try:
                if get_price_id(tier, interval) == price_id:
                    return tier
            except (EnvironmentError, ValueError):
                continue
    return None


def _price_id_from_subscription(sub_obj) -> str | None:
    """Extract the active Price ID from a Stripe Subscription object."""
    items = (sub_obj.get("items") or {}).get("data") or []
    if not items:
        return None
    price = items[0].get("price") or {}
    return price.get("id")


# Statuses for which the PAID tier value should be preserved in the row so the
# downstream get_tier() grace logic can apply (e.g. past_due keeps the tier and
# get_tier honours the 7-day grace window before downgrading to community).
_GRACE_STATUSES = frozenset({"past_due"})


def _resolve_paid_tier(sub_obj) -> str:
    """Resolve the configured paid tier (team/studio) for a subscription object.

    B5: PRICE-based resolution first (authoritative for Customer-Portal plan
    swaps, which leave the sic_tier metadata stale), then fall back to the
    sic_tier metadata. Returns 'community' only when nothing resolves to a
    paid tier.
    """
    price_tier = _tier_from_price_id(_price_id_from_subscription(sub_obj))
    if price_tier:
        return price_tier
    meta = sub_obj.get("metadata") or {}
    label = meta.get("sic_tier", "community").lower()
    return _TIER_LABEL_MAP.get(label, "community")


def _tier_from_status_and_meta(sub_obj) -> str:
    """Derive the DB tier value to store from a Stripe Subscription object.

    - active / trialing  → the resolved paid tier (price-based, then metadata).
    - past_due           → preserve the paid tier so get_tier() can apply the
                           7-day grace window (B7 fix — previously this returned
                           community immediately, defeating the grace).
    - anything else      → community (canceled/unpaid/incomplete/etc.).

    Note: get_tier() is the single source of truth for *effective* access; this
    function only decides what tier value to persist on the row.
    """
    status = sub_obj.get("status", "")

    if status in _ACTIVE_STATUSES or status in _GRACE_STATUSES:
        return _resolve_paid_tier(sub_obj)

    # Terminal / non-entitled statuses → community.
    return "community"


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
    interval = (body.get("interval") or "month").strip().lower()
    if interval not in ("month", "year"):
        interval = "month"

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
            interval=interval,
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

        elif event_type == "payment_intent.payment_failed":
            _handle_payment_intent_failed(event, email)

        elif event_type in ("charge.refunded", "charge.dispute.created"):
            _handle_charge_revoked(event, email, event_type)

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
# Route: GET /api/billing/auth/me
# ---------------------------------------------------------------------------


@billing_bp.get("/auth/me")
def auth_me():
    """Called by the dashboard to verify the current session across origins.

    The main SIC server (hexstrike container, port 9888) does not expose
    /auth/me; this endpoint on the billing server (port 9015) fills that gap.
    Returns the authenticated user's email and tier, or 401 if not logged in.
    """
    email = get_session_email()
    if not email:
        return jsonify({"error": "unauthenticated"}), 401

    sub = get_subscription(email)
    tier = sub["tier"] if sub else "community"
    return jsonify({"email": email, "tier": tier}), 200


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
        expires = now + 86400  # 24 hours — post-payment link; user may not check email immediately
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
        # SIC is self-hosted (HYBRID model): the customer downloads and runs SIC
        # locally, then activates their license via the magic link below against
        # this hosted billing server. SIC_BASE_URL is the customer's local install
        # origin used to build the activation link.
        _base = os.environ.get("SIC_BASE_URL", "").rstrip("/")
        if not _base:
            logger.error(
                "_send_provisioning_email: SIC_BASE_URL is not set — cannot build a "
                "reachable activation link for customer %.6s***. "
                "Set SIC_BASE_URL to the publicly accessible origin of the local SIC "
                "instance (e.g. http://localhost:9888 for single-machine, or a customer "
                "tunnel URL for remote deployments). Aborting provisioning email.",
                email[:6],
            )
            _discord_billing_alert(
                f"**Provisioning email ABORTED** — `SIC_BASE_URL` is not set. "
                f"Customer `{email[:6]}***` paid but no activation link can be generated. "
                f"Set `SIC_BASE_URL` on the billing server and manually re-trigger provisioning."
            )
            return
        # SIC_DOWNLOAD_URL is the operator-hosted installer / Docker artifact the
        # customer downloads to run SIC on their own machine. Optional: if unset,
        # the email still sends the magic link and notes the download will follow.
        _download_url = os.environ.get("SIC_DOWNLOAD_URL", "")
        _link = f"{_base}/auth/verify?token={token}"

        if _resend_key and _from:
            # Download block: real link when SIC_DOWNLOAD_URL is set, otherwise a
            # "will follow" note so the email never references a missing artifact.
            if _download_url:
                _download_block = (
                    '<p style="color:#ccc;margin-top:8px;">'
                    "1. Download SIC and install it on your own machine:</p>"
                    f'<a href="{_download_url}" style="display:inline-block;background:#1a1a1a;'
                    "color:#fff;padding:12px 28px;border-radius:6px;text-decoration:none;"
                    'font-weight:600;margin:8px 0 16px;border:1px solid #333;">'
                    "Download SIC</a>"
                )
            else:
                _download_block = (
                    '<p style="color:#ccc;margin-top:8px;">'
                    "1. Install SIC on your own machine with "
                    '<code style="color:#e94560;">pip install sic-security</code> '
                    "(or the Docker scanner). Your download link will follow "
                    "shortly by email.</p>"
                )
            _payload = _json.dumps({
                "from": f"SIC Security <{_from}>",
                "to": [email],
                "subject": "Your SIC activation link is ready",
                "html": (
                    '<div style="font-family:DM Sans,sans-serif;background:#0a0a0a;color:#fff;'
                    'padding:48px 40px;max-width:500px;margin:auto;">'
                    '<p style="font-family:\'JetBrains Mono\',monospace;font-size:11px;'
                    'letter-spacing:.08em;color:#e94560;margin:0 0 24px;text-transform:uppercase;">'
                    "Security Intelligence Center</p>"
                    '<h1 style="font-size:22px;font-weight:700;margin:0 0 8px;color:#fff;">'
                    "Your subscription is active.</h1>"
                    '<p style="color:#999;font-size:15px;margin:0 0 32px;line-height:1.6;">'
                    "SIC runs on your own machine. Click the button below to activate your "
                    "license &mdash; this link is valid for 24 hours.</p>"
                    + _download_block
                    + '<a href="' + _link + '" style="display:inline-block;background:#e94560;'
                    'color:#fff;padding:14px 32px;text-decoration:none;font-weight:600;'
                    'font-size:15px;letter-spacing:.02em;margin:8px 0 32px;">'
                    "Activate My License &rarr;</a>"
                    '<hr style="border:none;border-top:1px solid #1a1a1a;margin:0 0 24px;">'
                    '<p style="color:#555;font-size:12px;line-height:1.6;margin:0;">'
                    "If you did not subscribe to SIC, you can safely ignore this email. "
                    "This link is single-use and expires in 24 hours.<br>"
                    "Questions? Reply to this email.</p>"
                    "</div>"
                ),
            }).encode()
            _req = _ur.Request(
                "https://api.resend.com/emails",
                data=_payload,
                headers={
                    "Authorization": f"Bearer {_resend_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "SIC-Billing/1.0",
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
            _discord_billing_alert(
                f"**Provisioning email skipped** — RESEND_API_KEY or SIC_ALERT_FROM not "
                f"configured. Customer `{email[:6]}***` paid but received no magic link. "
                f"Manual provisioning required."
            )
    except Exception as _e:
        logger.warning("auto-provision email failed for %.6s***: %s", email[:6], _e)


def _stale_access_grant(email: str | None, event_period_end: int | None) -> bool:
    """Return True if this event should be skipped because stored subscription state
    is already revoked/canceled AND the event's period_end is older than what we have.

    This prevents delayed or redelivered webhooks from re-granting access that was
    already revoked by a later subscription.deleted or subscription.updated event.
    """
    if not email:
        return False
    existing = get_subscription(email)
    if existing is None:
        return False  # No record — always process to provision
    revoked_statuses = ("canceled", "unpaid", "refunded", "disputed", "incomplete_expired")
    if existing["status"] not in revoked_statuses:
        return False  # Current status is not revoked — safe to process
    # Status is revoked: skip if the event period_end is older than what we already stored
    stored_end = existing["current_period_end"]
    if stored_end is not None and event_period_end is not None and event_period_end <= stored_end:
        logger.warning(
            "stale access-grant event skipped: stored period_end=%s event period_end=%s "
            "status=%s email=%.6s***",
            stored_end, event_period_end, existing["status"], email[:6],
        )
        return True
    return False


def _save_email_to_stats(email: str) -> None:
    """Fire-and-forget: log email to stats-server so HomeTab sees it."""
    stats_url = os.environ.get("STATS_SERVER_URL", "").rstrip("/")
    stats_secret = os.environ.get("STATS_SECRET", "")
    if not (email and stats_url and stats_secret):
        return

    def _post(url: str, secret: str, addr: str) -> None:
        try:
            import json as _json  # noqa: PLC0415
            import urllib.request as _ur  # noqa: PLC0415
            req = _ur.Request(
                f"{url}/save-email",
                data=_json.dumps({"email": addr}).encode(),
                headers={
                    "Content-Type": "application/json",
                    "x-stats-secret": secret,
                    "X-Requested-With": "XMLHttpRequest",
                },
                method="POST",
            )
            _ur.urlopen(req, timeout=5)
        except Exception as _e:  # noqa: BLE001
            logger.warning("stats-server email log failed (non-critical): %s", _e)

    threading.Thread(target=_post, args=(stats_url, stats_secret, email), daemon=True).start()


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

    # P1-3: stale/redelivered event guard — do not re-grant access that was already revoked
    if _stale_access_grant(email, obj.get("expires_at")):
        return

    # Bug 3: Validate sic_tier metadata before provisioning.
    # Missing or unrecognised tier is suspicious (could indicate a tampered/malformed
    # session) — do not silently provision community access for a paid checkout.
    meta = obj.get("metadata") or {}
    sic_tier = meta.get("sic_tier")
    if not sic_tier or sic_tier not in ("community", "team", "studio"):
        print(
            f"[billing WARNING] checkout.session.completed missing valid sic_tier in "
            f"metadata. Session ID: {obj.get('id')}. Provisioning community/pending_review."
        )
        logger.warning(
            "checkout.session.completed: sic_tier metadata missing or invalid "
            "(got %r) for session %s — provisioning community with pending_review status",
            sic_tier,
            obj.get("id", "unknown"),
        )
        _discord_billing_alert(
            f"**Billing alert — invalid sic_tier** `{sic_tier!r}` "
            f"in checkout session `{obj.get('id', '?')}`. "
            f"Provisioned community/pending_review for manual review."
        )
        upsert_subscription(
            email=email,
            stripe_customer_id=customer_id,
            stripe_subscription_id=subscription_id,
            tier="community",
            status="pending_review",
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
            _stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
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

    # P1-6: Auto-provision email in a background daemon thread so the webhook
    # handler returns 200 fast and Stripe does not retry due to timeout.
    threading.Thread(
        target=_send_provisioning_email,
        args=(email, obj),
        daemon=True,
    ).start()

    # Log email to stats-server (non-blocking — billing webhook must not fail over this)
    if email:
        _save_email_to_stats(email)


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

    # P1-3: stale/redelivered event guard — do not re-activate a revoked subscription
    if _stale_access_grant(email, period_end):
        return

    # Preserve the existing tier AND billing_interval — only refresh status and period_end.
    # Without passing billing_interval, upsert defaults it to "month" and an annual
    # subscription would be silently downgraded to monthly on its first renewal.
    sub = get_subscription(email)
    current_tier = sub["tier"] if sub else "community"
    current_interval = sub["billing_interval"] if sub else "month"

    upsert_subscription(
        email=email,
        stripe_customer_id=customer_id,
        stripe_subscription_id=subscription_id,
        tier=current_tier,
        status="active",
        current_period_end=period_end,
        billing_interval=current_interval,
    )
    logger.info(
        "invoice.paid — subscription kept active, period_end=%s for email=%.6s***",
        period_end,
        email[:6],
    )


def _handle_payment_intent_failed(event, email: str | None) -> None:
    """Mark subscription as incomplete on initial card decline (pre-subscription failure).

    payment_intent.payment_failed fires when a card is declined at checkout time,
    before a Stripe Subscription object exists.  invoice.payment_failed handles
    renewal failures — this handler covers the initial checkout decline.
    """
    obj = event["data"]["object"]
    customer_id: str | None = obj.get("customer")

    if not email:
        logger.warning(
            "payment_intent.payment_failed — no email extractable from event %s; "
            "user is still on checkout page and can retry",
            event.get("id"),
        )
        return

    sub = get_subscription(email)
    upsert_subscription(
        email=email,
        stripe_customer_id=customer_id,
        stripe_subscription_id=sub["stripe_subscription_id"] if sub else None,
        tier=sub["tier"] if sub else "community",
        status="incomplete",
        current_period_end=sub["current_period_end"] if sub else None,
    )
    failure_msg = (
        (obj.get("last_payment_error") or {}).get("message", "unknown")
    )
    logger.warning(
        "payment_intent.payment_failed — marked incomplete for email=%.6s*** reason=%s",
        email[:6],
        failure_msg,
    )
    _discord_billing_alert(
        f"**Payment intent failed** for customer `{customer_id}` "
        f"| reason: {failure_msg} "
        f"| event: {event.get('id', '?')}"
    )


def _handle_charge_revoked(event, email: str | None, event_type: str) -> None:
    """Revoke entitlement on refund or dispute (chargeback).

    B4: a refunded or disputed customer must lose paid access immediately.
    Previously these events were ignored, so a refunded user kept full tier
    access until the subscription separately cancelled (which may never
    happen for one-off refunds).

    For ``charge.refunded`` we only revoke on a FULL refund (refunded == amount)
    so a partial refund does not strip access.  ``charge.dispute.created``
    always revokes — a chargeback is adversarial and access should be cut
    immediately pending resolution.
    """
    obj = event["data"]["object"]
    customer_id: str | None = obj.get("customer")

    if not email:
        logger.warning(
            "%s — no email extractable from event %s; cannot revoke access",
            event_type,
            event.get("id"),
        )
        _discord_billing_alert(
            f"**{event_type}** received but no SIC email could be resolved "
            f"(customer `{customer_id}`, event `{event.get('id', '?')}`). "
            f"Manual review required — access NOT revoked automatically."
        )
        return

    # charge.refunded: only act on a full refund.
    if event_type == "charge.refunded":
        amount = obj.get("amount", 0) or 0
        amount_refunded = obj.get("amount_refunded", 0) or 0
        fully_refunded = bool(obj.get("refunded")) or (
            amount > 0 and amount_refunded >= amount
        )
        if not fully_refunded:
            logger.info(
                "charge.refunded (partial: %s/%s) for email=%.6s*** — "
                "access retained",
                amount_refunded,
                amount,
                email[:6],
            )
            _discord_billing_alert(
                f"**Partial refund** (${amount_refunded / 100:.2f} of "
                f"${amount / 100:.2f}) for `{email[:6]}***` — access retained "
                f"(event `{event.get('id', '?')}`)."
            )
            return

    sub = get_subscription(email)
    subscription_id = sub["stripe_subscription_id"] if sub else None
    revoke_status = "refunded" if event_type == "charge.refunded" else "disputed"

    upsert_subscription(
        email=email,
        stripe_customer_id=customer_id,
        stripe_subscription_id=subscription_id,
        tier="community",
        status=revoke_status,
        current_period_end=None,
    )
    logger.warning(
        "%s — revoked entitlement (tier→community, status=%s) for email=%.6s***",
        event_type,
        revoke_status,
        email[:6],
    )
    _discord_billing_alert(
        f"**Entitlement revoked** ({event_type}) for `{email[:6]}***` "
        f"— downgraded to community (event `{event.get('id', '?')}`)."
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
    # Validate request shape before auth — malformed input is rejected regardless
    # of key presence (leaking "email is invalid" is not a security risk and avoids
    # a confusing 503 when BILLING_API_KEY is absent in test / dev environments).
    body = request.get_json(silent=True) or {}
    tier = body.get("tier")
    email_raw = (body.get("email") or "").strip().lower()
    # An empty email is allowed (anonymous checkout — Stripe collects it on the
    # hosted page). But if a caller *provides* an email, it must be well-formed;
    # silently nulling a malformed address would proceed to Stripe and surface as
    # an opaque 500. Reject up front with 400 (consistent with portal_by_email /
    # public_trial validation).
    if email_raw and not _EMAIL_RE.match(email_raw):
        return jsonify({"error": "missing_email", "detail": "A valid email is required."}), 400

    # Bug 4: Machine-to-machine auth — always require BILLING_API_KEY.
    # When the key is unset in production, the endpoint must refuse traffic rather
    # than silently accept all requests (previous behaviour when env var was empty).
    if not _BILLING_API_KEY:
        if os.environ.get("SIC_ENV", "production") != "development":
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
    email: str | None = email_raw or None
    interval = (body.get("interval") or "month").strip().lower()

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

    # If email provided, check for existing subscription/customer
    sub = get_subscription(email) if email else None
    customer_id: str | None = sub["stripe_customer_id"] if sub else None

    _success_params = f"tier={tier}"
    if email:
        _success_params += f"&email={urllib.parse.quote(email, safe='')}"
    success_url = f"https://frxncois.com/api/billing/public-checkout-success?{_success_params}"
    cancel_url = "https://frxncois.com/sic-signup#pricing"

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


@billing_bp.post("/portal-by-email")
def portal_by_email():
    """Create a Stripe Customer Portal session for a customer identified by email.

    Called from the Next.js proxy (POST /api/sic/portal) — does not require a
    Flask session. Requires X-Billing-Key header matching BILLING_API_KEY.

    Body JSON:
        {"email": "user@example.com", "return_url": "https://..."}

    Returns:
        200  {"portal_url": "https://billing.stripe.com/..."}
        400  {"error": "no_stripe_customer"}
        401  {"error": "unauthorized"}
        402  {"error": "billing_unavailable"}
        500  {"error": "internal_error"}
    """
    if not _BILLING_API_KEY:
        if os.environ.get("SIC_ENV", "production") != "development":
            return jsonify({"error": "BILLING_API_KEY not configured"}), 503
        print("[billing WARNING] BILLING_API_KEY not set — M2M auth disabled (dev)")
    else:
        provided_key = request.headers.get("X-Billing-Key", "")
        if not provided_key or not _secrets_equal(provided_key, _BILLING_API_KEY):
            return jsonify({"error": "unauthorized"}), 401

    init_db()
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    if not email or not _EMAIL_RE.match(email):
        return jsonify({"error": "missing_email", "detail": "A valid email is required."}), 400

    return_url = body.get("return_url") or f"{_base_url()}/sic-payment-success"
    # Restrict return_url to allowed origins to prevent open redirect
    _allowed = os.environ.get("SIC_ALLOWED_RETURN_ORIGINS", "https://frxncois.com").split(",")
    from urllib.parse import urlparse as _urlparse  # noqa: PLC0415
    parsed = _urlparse(return_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if origin not in [o.strip() for o in _allowed]:
        return_url = f"{_base_url()}/sic-payment-success"

    sub = get_subscription(email)
    if not sub or not sub.get("stripe_customer_id"):
        return jsonify({"error": "no_stripe_customer", "detail": "No Stripe customer on record."}), 400

    try:
        portal_session = create_portal_session(
            customer_id=sub["stripe_customer_id"],
            return_url=return_url,
        )
        return jsonify({"portal_url": portal_session.url}), 200
    except EnvironmentError as exc:
        logger.error("billing env misconfigured for portal-by-email: %s", exc)
        return jsonify({"error": "billing_unavailable"}), 402
    except Exception as exc:
        logger.error("Unhandled portal-by-email error: %s", exc, exc_info=True)
        return jsonify({"error": "internal_error"}), 500


@billing_bp.get("/public-checkout-success")
def public_checkout_success():
    """Redirect after Stripe checkout — send user to dedicated payment success page."""
    tier = request.args.get("tier", "community")
    email = request.args.get("email", "")
    # Validate against known tiers — prevent open redirect via unvalidated query param.
    if tier not in _ALL_VALID_TIERS:
        tier = "community"
    base = _base_url()
    params = f"tier={tier}"
    if email and _EMAIL_RE.match(email):
        params += f"&email={urllib.parse.quote(email, safe='')}"
    return redirect(f"{base}/sic-payment-success?{params}")


# ---------------------------------------------------------------------------
# Community free trial — provision community tier without Stripe
# ---------------------------------------------------------------------------

_TRIAL_RATE: dict[str, list[float]] = {}  # IP → [timestamps] (in-memory, resets on restart)
_TRIAL_MAX = 3       # requests
_TRIAL_WINDOW = 3600  # seconds
_TRIAL_RATE_LAST_GC: float = 0.0  # epoch seconds of last GC sweep


@billing_bp.post("/public-trial")
def public_trial():
    """Provision a free Community tier account and send a magic link.

    No Stripe. Accepts only an email address.  Rate-limited to 3 requests per
    hour per IP to prevent abuse.

    Body: {"email": "user@example.com"}
    Returns: 200 {"ok": true} | 400 | 429 | 500
    """
    import time as _time  # noqa: PLC0415

    # M2M auth — same pattern as public_checkout / portal_by_email
    if not _BILLING_API_KEY:
        if os.environ.get("SIC_ENV", "production") != "development":
            return jsonify({"error": "BILLING_API_KEY not configured"}), 503
        print("[billing WARNING] BILLING_API_KEY not set — M2M auth disabled (dev)")
    else:
        provided_key = request.headers.get("X-Billing-Key", "")
        if not provided_key or not _secrets_equal(provided_key, _BILLING_API_KEY):
            return jsonify({"error": "unauthorized"}), 401

    ip = (
        request.headers.get("CF-Connecting-IP")
        or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or "unknown"
    )

    # Simple sliding-window rate limit (in-memory — resets on server restart)
    global _TRIAL_RATE_LAST_GC
    now = _time.time()
    bucket = _TRIAL_RATE.setdefault(ip, [])
    _TRIAL_RATE[ip] = [t for t in bucket if now - t < _TRIAL_WINDOW]
    if len(_TRIAL_RATE[ip]) >= _TRIAL_MAX:
        return jsonify({"error": "rate_limited", "detail": "Too many trial requests. Try again later."}), 429
    _TRIAL_RATE[ip].append(now)

    # Periodic GC: remove IPs whose window has fully expired to prevent unbounded growth.
    if now - _TRIAL_RATE_LAST_GC > _TRIAL_WINDOW:
        stale_ips = [k for k, v in _TRIAL_RATE.items() if not v or now - max(v) > _TRIAL_WINDOW]
        for k in stale_ips:
            _TRIAL_RATE.pop(k, None)
        _TRIAL_RATE_LAST_GC = now

    body = request.get_json(silent=True) or {}
    email_raw = (body.get("email") or "").strip().lower()
    if not email_raw or not _EMAIL_RE.match(email_raw):
        return jsonify({"error": "invalid_email"}), 400

    try:
        init_db()
        existing = get_subscription(email_raw)
        if existing:
            if existing.get("tier") in ("team", "studio"):
                # Already on a paid tier — don't downgrade, just re-send magic link
                threading.Thread(
                    target=_send_provisioning_email, args=(email_raw, {}), daemon=True
                ).start()
                return jsonify({"ok": True, "note": "existing_subscription"}), 200
            # Already community — idempotent re-send; no upsert needed
            threading.Thread(
                target=_send_provisioning_email, args=(email_raw, {}), daemon=True
            ).start()
            logger.info("community trial re-send for %.6s***", email_raw[:6])
            return jsonify({"ok": True, "note": "already_registered"}), 200

        upsert_subscription(
            email=email_raw,
            stripe_customer_id=None,
            stripe_subscription_id=None,
            tier="community",
            status="active",
        )
        threading.Thread(
            target=_send_provisioning_email, args=(email_raw, {}), daemon=True
        ).start()
        _save_email_to_stats(email_raw)
        logger.info("community trial provisioned for %.6s***", email_raw[:6])
        return jsonify({"ok": True}), 200
    except Exception as exc:
        logger.error("public-trial error: %s", exc, exc_info=True)
        return jsonify({"error": "internal_error"}), 500
