"""Tests for billing routes and stripe_client.py.

Coverage:
    1. Webhook with valid Stripe signature -> correct DB tier update
    2. Webhook with invalid/missing signature -> 400, no DB mutation
    3. Duplicate event ID -> idempotently no-op (200 ok, skipped=True)
    4. public-checkout-success with unknown tier -> redirects to safe default
    5. _studio_gated raises RuntimeError when feature_gates unavailable
    6. Email validation regex tightened (P1-3)
    7. Discord billing alert fires on invoice.payment_failed (P1-2)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_stripe_payload(event_type: str, data: dict[str, Any] | None = None) -> bytes:
    """Build a minimal Stripe event JSON payload."""
    event: dict[str, Any] = {
        "id": f"evt_test_{int(time.time())}",
        "type": event_type,
        "data": {
            "object": data or {},
        },
        "created": int(time.time()),
        "livemode": False,
    }
    return json.dumps(event).encode()


def _stripe_sig(payload: bytes, secret: str) -> str:
    """Produce a valid Stripe-Signature header value."""
    ts = int(time.time())
    signed = f"{ts}.{payload.decode()}"
    sig = hmac.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def app():
    """Create a minimal Flask app with the billing blueprint registered."""
    import os as _os
    import tempfile

    tmp = tempfile.mkdtemp()
    db_path = Path(tmp) / "state.db"

    env_patch = {
        "STRIPE_SECRET_KEY": "sk_test_dummy",
        "STRIPE_PRICE_TEAM": "price_team_dummy",
        "STRIPE_PRICE_STUDIO": "price_studio_dummy",
        "STRIPE_WEBHOOK_SECRET": "whsec_test_secret",
        "HOME": tmp,
    }

    with patch.dict(_os.environ, env_patch):
        # Patch DB path to temp dir
        with patch("billing.db._DB_PATH", db_path):
            from flask import Flask

            flask_app = Flask(__name__)
            flask_app.config["TESTING"] = True

            # Stub auth module imports so billing routes can load
            auth_mock = MagicMock()
            auth_mock.get_session_email = MagicMock(return_value="test@example.com")
            auth_mock.require_auth = lambda f: f  # pass-through decorator

            with patch.dict("sys.modules", {"auth": auth_mock}):
                # Reset DB init flag so each fixture gets a fresh schema
                import billing.db as _bdb  # noqa: PLC0415

                _bdb._db_init_done = False
                _bdb._DB_PATH = db_path

                from billing.routes import billing_bp  # noqa: PLC0415

                flask_app.register_blueprint(billing_bp)
                yield flask_app, str(db_path), env_patch


@pytest.fixture()
def client(app):
    flask_app, db_path, env = app
    with flask_app.test_client() as c:
        yield c, db_path, env


# ---------------------------------------------------------------------------
# 1. Valid webhook -> tier update
# ---------------------------------------------------------------------------


class TestWebhookValidSignature:
    def test_checkout_completed_provisions_team_tier(self, client) -> None:
        c, db_path, env = client
        secret = env["STRIPE_WEBHOOK_SECRET"]

        event_data = {
            "metadata": {"sic_email": "buyer@example.com", "sic_tier": "team"},
            "customer": "cus_test123",
            "subscription": "sub_test123",
        }
        payload = _make_stripe_payload("checkout.session.completed", event_data)
        sig = _stripe_sig(payload, secret)

        # Patch stripe signature verification to accept our HMAC
        with patch("billing.routes.construct_webhook_event") as mock_cwe:
            event_dict = json.loads(payload)
            mock_cwe.return_value = event_dict

            resp = c.post(
                "/api/billing/webhook",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": sig,
                },
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get("ok") is True
        assert not data.get("skipped")

        # Verify DB was updated
        from billing.db import get_subscription  # noqa: PLC0415

        sub = get_subscription("buyer@example.com")
        assert sub is not None
        assert sub["tier"] == "team"
        assert sub["stripe_customer_id"] == "cus_test123"


# ---------------------------------------------------------------------------
# 2. Invalid signature -> 400, no DB mutation
# ---------------------------------------------------------------------------


class TestWebhookInvalidSignature:
    def test_bad_signature_returns_400(self, client) -> None:
        c, db_path, env = client
        payload = _make_stripe_payload("checkout.session.completed", {"metadata": {"sic_email": "attacker@example.com"}})

        with patch("billing.routes.construct_webhook_event") as mock_cwe:
            mock_cwe.side_effect = Exception("Invalid signature")

            resp = c.post(
                "/api/billing/webhook",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": "t=1,v1=bad",
                },
            )

        assert resp.status_code == 400
        data = resp.get_json()
        assert "invalid_signature" in data.get("error", "")

    def test_missing_signature_header_returns_400(self, client) -> None:
        c, db_path, env = client
        payload = _make_stripe_payload("checkout.session.completed")

        resp = c.post(
            "/api/billing/webhook",
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        assert resp.status_code == 400
        data = resp.get_json()
        assert "missing_signature" in data.get("error", "")

    def test_bad_signature_does_not_mutate_db(self, client) -> None:
        c, db_path, env = client
        payload = _make_stripe_payload("checkout.session.completed", {"metadata": {"sic_email": "victim@example.com", "sic_tier": "studio"}})

        with patch("billing.routes.construct_webhook_event") as mock_cwe:
            mock_cwe.side_effect = Exception("Signature mismatch")

            c.post(
                "/api/billing/webhook",
                data=payload,
                headers={"Content-Type": "application/json", "Stripe-Signature": "t=1,v1=forgery"},
            )

        from billing.db import get_subscription  # noqa: PLC0415

        sub = get_subscription("victim@example.com")
        assert sub is None, "DB must not be mutated on signature failure"


# ---------------------------------------------------------------------------
# 3. Duplicate event ID -> idempotent no-op
# ---------------------------------------------------------------------------


class TestWebhookIdempotency:
    def test_duplicate_event_skipped(self, client) -> None:
        c, db_path, env = client

        event_data = {
            "metadata": {"sic_email": "dup@example.com", "sic_tier": "team"},
            "customer": "cus_dup",
            "subscription": "sub_dup",
        }
        payload = _make_stripe_payload("checkout.session.completed", event_data)
        event_dict = json.loads(payload)
        event_id = event_dict["id"]

        # Pre-record the event_id as already processed
        from billing.db import init_db, record_event  # noqa: PLC0415

        init_db()
        record_event(
            event_id=event_id,
            event_type="checkout.session.completed",
            email="dup@example.com",
            payload="{}",
        )

        # Patch at the routes import site (where construct_webhook_event is used)
        with patch("billing.routes.construct_webhook_event") as mock_cwe:
            mock_cwe.return_value = event_dict

            resp = c.post(
                "/api/billing/webhook",
                data=payload,
                headers={"Content-Type": "application/json", "Stripe-Signature": "t=1,v1=sig"},
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get("skipped") is True


# ---------------------------------------------------------------------------
# 4. public-checkout-success with unknown tier -> safe default
# ---------------------------------------------------------------------------


class TestPublicCheckoutSuccess:
    def test_unknown_tier_redirects_to_community(self, client) -> None:
        c, _db, _env = client
        resp = c.get("/api/billing/public-checkout-success?tier=evil%2F..%2F")
        assert resp.status_code in (301, 302)
        location = resp.headers.get("Location", "")
        assert "community" in location
        assert "evil" not in location

    def test_valid_tier_passes_through(self, client) -> None:
        c, _db, _env = client
        resp = c.get("/api/billing/public-checkout-success?tier=studio")
        assert resp.status_code in (301, 302)
        location = resp.headers.get("Location", "")
        assert "studio" in location

    def test_missing_tier_defaults_to_community(self, client) -> None:
        c, _db, _env = client
        resp = c.get("/api/billing/public-checkout-success")
        assert resp.status_code in (301, 302)
        location = resp.headers.get("Location", "")
        assert "community" in location


# ---------------------------------------------------------------------------
# 5. _studio_gated raises RuntimeError when feature_gates unavailable
# ---------------------------------------------------------------------------


class TestStudioGatedFailClosed:
    def test_raises_runtime_error_on_import_failure(self) -> None:
        """When feature_gates cannot be imported, SSO blueprint must not load silently."""
        # Temporarily hide feature_gates from sys.modules
        saved = sys.modules.pop("feature_gates", None)
        sso_routes_saved = sys.modules.pop("sso.routes", None)

        try:
            with patch.dict("sys.modules", {"feature_gates": None}):
                with pytest.raises((RuntimeError, ImportError)):
                    import importlib  # noqa: PLC0415
                    import sso.routes as _sr  # noqa: PLC0415

                    importlib.reload(_sr)
        finally:
            # Restore
            if saved is not None:
                sys.modules["feature_gates"] = saved
            if sso_routes_saved is not None:
                sys.modules["sso.routes"] = sso_routes_saved


# ---------------------------------------------------------------------------
# 6. Email validation regex (P1-3)
# ---------------------------------------------------------------------------


class TestEmailValidation:
    _valid = [
        "user@example.com",
        "user.name+tag@sub.domain.org",
        "a@b.co",
    ]
    _invalid = [
        "notanemail",
        "@nodomain.com",
        "user@",
        "user @example.com",
        "user@domain",
        "",
    ]

    def test_valid_emails_accepted(self, client) -> None:
        c, _db, _env = client
        from billing.routes import _EMAIL_RE  # noqa: PLC0415

        for email in self._valid:
            assert _EMAIL_RE.match(email), f"Expected valid: {email}"

    def test_invalid_emails_rejected(self, client) -> None:
        c, _db, _env = client
        from billing.routes import _EMAIL_RE  # noqa: PLC0415

        for email in self._invalid:
            assert not _EMAIL_RE.match(email), f"Expected invalid: {email}"

    def test_public_checkout_rejects_invalid_email(self, client) -> None:
        c, _db, _env = client
        resp = c.post(
            "/api/billing/public-checkout",
            json={"email": "notanemail", "tier": "team"},
        )
        assert resp.status_code == 400
        assert "missing_email" in resp.get_json().get("error", "")


# ---------------------------------------------------------------------------
# 7. Discord billing alert fires on invoice.payment_failed (P1-2)
# ---------------------------------------------------------------------------


class TestDiscordBillingAlert:
    def test_alert_fires_on_payment_failed(self, client) -> None:
        c, db_path, env = client

        event_data = {
            "subscription": "sub_fail",
            "customer": "cus_fail",
            "amount_due": 2900,
            "metadata": {"sic_email": "payer@example.com"},
        }
        payload = _make_stripe_payload("invoice.payment_failed", event_data)
        event_dict = json.loads(payload)

        # Pre-seed the subscription so get_subscription returns a row
        from billing.db import init_db, upsert_subscription  # noqa: PLC0415

        init_db()
        upsert_subscription(
            email="payer@example.com",
            stripe_customer_id="cus_fail",
            stripe_subscription_id="sub_fail",
            tier="team",
            status="active",
        )

        alerts_sent: list[str] = []

        def _capture_alert(msg: str) -> None:
            alerts_sent.append(msg)

        with patch("billing.routes._discord_billing_alert", side_effect=_capture_alert):
            with patch("billing.routes.construct_webhook_event") as mock_cwe:
                mock_cwe.return_value = event_dict

                resp = c.post(
                    "/api/billing/webhook",
                    data=payload,
                    headers={"Content-Type": "application/json", "Stripe-Signature": "t=1,v1=sig"},
                )

        assert resp.status_code == 200
        assert len(alerts_sent) == 1
        assert "cus_fail" in alerts_sent[0]

    def test_alert_noop_when_discord_url_unset(self) -> None:
        import os as _os  # noqa: PLC0415

        from billing.routes import _discord_billing_alert  # noqa: PLC0415

        with patch.dict(_os.environ, {}, clear=True):
            # Should not raise even when DISCORD_WEBHOOK_URL is absent
            _discord_billing_alert("test message")


# ---------------------------------------------------------------------------
# 8. Missing sic_tier in metadata defaults to community
# ---------------------------------------------------------------------------


class TestMissingSicTierDefaultsToCommunity:
    def test_checkout_missing_sic_tier_defaults_to_community(self, client) -> None:
        """checkout.session.completed with no sic_tier in metadata must provision community tier."""
        c, db_path, env = client
        secret = env["STRIPE_WEBHOOK_SECRET"]

        # Metadata has sic_email but NO sic_tier
        event_data = {
            "metadata": {"sic_email": "notieruser@example.com"},
            "customer": "cus_notier",
            "subscription": "sub_notier",
        }
        payload = _make_stripe_payload("checkout.session.completed", event_data)
        event_dict = json.loads(payload)

        with patch("billing.routes.construct_webhook_event") as mock_cwe:
            mock_cwe.return_value = event_dict

            resp = c.post(
                "/api/billing/webhook",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": _stripe_sig(payload, secret),
                },
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get("ok") is True

        from billing.db import get_subscription  # noqa: PLC0415

        sub = get_subscription("notieruser@example.com")
        assert sub is not None, "Subscription row must be created even without sic_tier"
        assert sub["tier"] == "community", (
            f"Expected tier='community' when sic_tier missing, got tier='{sub['tier']}'"
        )
